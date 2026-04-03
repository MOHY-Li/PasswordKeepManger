# Phase 2: Vault Operations 设计文档

**日期**: 2026-04-04
**状态**: 设计阶段
**基于**: Phase 1 (Rust Core Library) 已完成

---

## 1. 概述

Phase 2 实现保险库的核心操作功能，包括解锁流程、条目管理、暴力破解防护和导入导出。

### 1.1 目标

| 功能 | 描述 |
|------|------|
| Vault 解锁 | 密码 + 密钥文件 → MasterKey |
| Entry CRUD | 创建、读取、更新、删除密码条目 |
| 暴力破解防护 | 指数退避策略的锁定机制 |
| 导入/导出 | JSON 格式的数据备份 |
| C FFI 接口 | 简单的手动 FFI 函数 |

### 1.2 设计决策

| 决策点 | 选择 | 理由 |
|--------|------|------|
| 密钥管理 | VaultHandle 句柄模式 | 明确的所有权，支持多保险库 |
| 锁定策略 | 指数退避 | 安全性随失败次数指数增长 |
| Nonce 策略 | 每字段独立 | 最安全的加密方案 |
| 导出模式 | 基本模式优先 | 便于调试，后续可扩展 |
| FFI 方式 | 简单 C FFI | Phase 2 专注 Rust，Flutter 桥接留待后续 |

---

## 2. 架构设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                        Simple C FFI                         │
│  passkeep_create_vault(), passkeep_unlock_vault(), ...      │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                     VaultManager (全局单例)                  │
│  VaultHandle ↦ VaultSession 映射                            │
└────────────────────────────┬────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ EntryService  │   │ LockState     │   │ Import/Export │
│  (CRUD)       │   │  (Protection) │   │  (Backup)     │
└───────────────┘   └───────────────┘   └───────────────┘
        │                    │                    │
        └────────────────────┼────────────────────┘
                             ▼
                    ┌─────────────────┐
                    │  Database       │
                    │  (SQLite)       │
                    └─────────────────┘
```

### 2.2 VaultManager 设计

```rust
/// 不透明的句柄类型
pub type VaultHandle = u64;

/// 全局保险库管理器（线程安全）
/// 使用 RwLock 保护内部 HashMap，支持多读单写
pub struct VaultManager {
    next_handle: AtomicU64,
    vaults: RwLock<HashMap<VaultHandle, Arc<Mutex<VaultSession>>>>,
}
// Send + Sync 自动由 RwLock、HashMap、AtomicU64 推导，无需手动实现

/// 全局单例实例（使用 lazy_static 或 once_cell）
static GLOBAL_MANAGER: Lazy<Arc<VaultManager>> = Lazy::new(|| {
    Arc::new(VaultManager::new())
});

/// 单个保险库会话
/// 注意：实现了 ZeroizeOnDrop，确保密钥在内存中被安全清除
#[derive(ZeroizeOnDrop)]
pub struct VaultSession {
    master_key: MasterKey,     // 自动 zeroize
    db: VaultDb,                // 持有数据库连接
    config_path: PathBuf,
    keyfile_path: PathBuf,
}

/// 数据库句柄
#[derive(Clone)]
pub struct VaultDb {
    pub conn: Arc<Mutex<rusqlite::Connection>>,
}

impl VaultDb {
    pub fn new(conn: Arc<Mutex<rusqlite::Connection>>) -> Self {
        // 启用 WAL 模式以支持更好的并发性能
        let conn_guard = conn.lock().unwrap();
        conn_guard.execute("PRAGMA journal_mode=WAL", []).ok();
        drop(conn_guard);
        Self { conn }
    }
}
```

**线程安全保证**：
- `VaultManager` 使用 `RwLock` 保护内部状态，实现 `Send + Sync`
- 全局单例使用 `lazy_static` 初始化，FFI 可通过 `global_manager()` 访问
- `VaultSession` 包装在 `Arc<Mutex<>>` 中，支持多线程访问
- `master_key` 在 `VaultSession` drop 时自动清零

**核心 API**:
```rust
impl VaultManager {
    pub fn new() -> Self;
    
    // 利用 RwLock 内部可变性，&self 即可
    pub fn create_vault(&self, ...) -> Result<VaultHandle, PassKeepError>;
    pub fn unlock_vault(&self, ...) -> Result<VaultHandle, PassKeepError>;
    pub fn lock_vault(&self, handle: VaultHandle) -> Result<(), PassKeepError>;
    
    // 获取会话的 Arc 克隆（支持跨线程传递）
    pub fn get_session(&self, handle: VaultHandle) -> Option<Arc<Mutex<VaultSession>>>;
    
    // 内部使用：获取可变引用（需要写锁）
    fn with_session_mut<F, R>(&self, handle: VaultHandle, f: F) -> Option<R>
    where
        F: FnOnce(&mut VaultSession) -> R;
}

// 全局访问器
pub fn global_manager() -> Arc<VaultManager> {
    GLOBAL_MANAGER.clone()
}
```

### 2.3 LockState 设计

```rust
/// 暴力破解防护状态（存储在数据库 vault_metadata 表中）
pub struct LockState {
    pub failed_attempts: u32,
    pub lock_until: Option<i64>,  // Unix 时间戳
    pub last_attempt_at: i64,
}

impl LockState {
    /// 计算锁定时长（秒）- 指数退避
    /// 第 3 次失败: 30 秒
    /// 第 4 次失败: 60 秒
    /// 第 5 次失败: 120 秒 (2 分钟)
    pub fn calculate_lock_duration(&self) -> i64 {
        if self.failed_attempts < 3 {
            return 0;
        }
        let base = 30i64;
        let exponent = (self.failed_attempts - 3).min(10) as u32;
        base * (1 << exponent)  // 最多约 8.5 小时
    }

    /// 检查是否被锁定
    pub fn is_locked(&self) -> bool {
        if let Some(until) = self.lock_until {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            now < until
        } else {
            false
        }
    }
}
```

**锁定时间表**：
| 失败次数 | 锁定时长 | 计算公式 |
|----------|----------|----------|
| 1-2 | 无锁定 | 0 秒 |
| 3 | 30 秒 | 30 × 2⁰ |
| 4 | 1 分钟 | 30 × 2¹ |
| 5 | 2 分钟 | 30 × 2² |
| 6 | 4 分钟 | 30 × 2³ |
| 7 | 8 分钟 | 30 × 2⁴ |
| 8 | 16 分钟 | 30 × 2⁵ |
| 9 | 32 分钟 | 30 × 2⁶ |
| 10 | 64 分钟 (~1 小时) | 30 × 2⁷ |
| 11 | 128 分钟 (~2 小时) | 30 × 2⁸ |
| 12 | 256 分钟 (~4 小时) | 30 × 2⁹ |
| 13+ | 512 分钟 (~8.5 小时，封顶) | 30 × 2¹⁰ |

**持久化设计**：
- LockState 存储在 `vault_metadata` 表中，而非独立 JSON 文件
- 避免文件与数据库之间的竞态条件
- 解锁验证时在同一事务中读取和更新

---

## 3. 数据库 Schema 更新

### 3.1 新增字段

```sql
-- 为每个敏感字段添加独立的 nonce（单独存储，不嵌入密文中）

-- 新表的行直接添加 nonce 列（已有表需要迁移）
ALTER TABLE entries ADD COLUMN password_nonce BLOB;  -- 不设置默认值
ALTER TABLE entries ADD COLUMN url_nonce BLOB;
ALTER TABLE entries ADD COLUMN notes_nonce BLOB;

-- vault_metadata 表新增锁定状态字段
ALTER TABLE vault_metadata ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vault_metadata ADD COLUMN lock_until INTEGER;
ALTER TABLE vault_metadata ADD COLUMN last_attempt_at INTEGER;

-- 为现有条目生成随机 nonce（一次性迁移）
UPDATE entries SET password_nonce = randomblob(12) WHERE password_nonce IS NULL;
UPDATE entries SET url_nonce = randomblob(12) WHERE url_encrypted IS NOT NULL AND url_nonce IS NULL;
UPDATE entries SET notes_nonce = randomblob(12) WHERE notes_encrypted IS NOT NULL AND notes_nonce IS NULL;

-- 注意：SQLite 不支持 ALTER COLUMN SET NOT NULL
-- 新建条目时在应用层强制校验 nonce 不为空
```

### 3.2 加密数据存储格式

**Nonce 策略**：nonce 单独存储在专用列中，不嵌入密文

```
存储格式：
- password_encrypted: [ciphertext | tag(16B)]
- password_nonce: BLOB(12B)
- url_encrypted: [ciphertext | tag(16B)]
- url_nonce: BLOB(12B)
- notes_encrypted: [ciphertext | tag(16B)]
- notes_nonce: BLOB(12B)

加密时：AES-256-GCM(password, key, nonce) → (ciphertext, tag)
解密时：读取 nonce 和加密数据，使用 AES-256-GCM 解密
```

---

## 4. 模块设计

### 4.1 Vault 模块

**文件**: `passkeep-core/src/vault/mod.rs`

| 组件 | 职责 |
|------|------|
| `VaultManager` | 管理所有保险库会话 |
| `VaultSession` | 单个保险库的状态 |
| `unlock.rs` | 解锁流程逻辑 |

**核心 API**:
```rust
impl VaultManager {
    pub fn new() -> Self;
    
    // 利用 RwLock 内部可变性，所有方法使用 &self
    pub fn create_vault(&self, ...) -> Result<VaultHandle, PassKeepError>;
    pub fn unlock_vault(&self, ...) -> Result<VaultHandle, PassKeepError>;
    pub fn lock_vault(&self, handle: VaultHandle) -> Result<(), PassKeepError>;
    
    // 获取会话的 Arc 克隆（用于后续操作）
    pub fn get_session(&self, handle: VaultHandle) -> Option<Arc<Mutex<VaultSession>>>;
    
    // 内部使用：在锁内执行操作
    fn with_session<F, R>(&self, handle: VaultHandle, f: F) -> Result<R, PassKeepError>
    where
        F: FnOnce(&VaultSession) -> Result<R, PassKeepError>;
}

// 全局访问器
pub fn global_manager() -> Arc<VaultManager> {
    GLOBAL_MANAGER.clone()
}
```

### 4.2 LockState 模块

**文件**: `passkeep-core/src/storage/lock_state.rs`

| 组件 | 职责 |
|------|------|
| `LockState` | 防护状态结构 |

**核心 API**（与数据库集成）:
```rust
impl LockState {
    // 从数据库行加载
    pub fn from_row(row: &rusqlite::Row) -> Result<Self, PassKeepError>;
    
    // 记录失败，返回新的锁定时长
    pub fn record_failure(&mut self) -> Duration;
    
    // 记录成功，重置失败计数
    pub fn record_success(&mut self);
    
    // 检查是否被锁定
    pub fn is_locked(&self) -> bool;
    
    // 获取剩余锁定时间
    pub fn remaining_lock_time(&self) -> Duration;
}

// 数据库辅助函数
impl LockState {
    // 在事务中读取 LockState
    pub fn load_from_db(conn: &Connection) -> Result<Self, PassKeepError>;
    
    // 在事务中保存 LockState
    pub fn save_to_db(&self, conn: &Connection) -> Result<(), PassKeepError>;
}
```

**VaultManager 内部方法**：
```rust
impl VaultManager {
    // 内部使用：在读锁内执行只读操作
    fn with_session<F, R>(&self, handle: VaultHandle, f: F) -> Result<R, PassKeepError>
    where
        F: FnOnce(&VaultSession) -> Result<R, PassKeepError>;
    
    // 内部使用：在写锁内执行可变操作
    fn with_session_mut<F, R>(&self, handle: VaultHandle, f: F) -> Result<R, PassKeepError>
    where
        F: FnOnce(&mut VaultSession) -> Result<R, PassKeepError>;
}
```

### 4.3 EntryService 模块

**文件**: `passkeep-core/src/storage/entry_service.rs`

| 组件 | 职责 |
|------|------|
| `EntryService` | 条目 CRUD 操作 |

**核心 API**:
```rust
impl EntryService {
    // 接收 VaultDb 和 MasterKey（按值转移，获取所有权）
    pub fn new(db: VaultDb, master_key: MasterKey) -> Self;
    
    // 注意：使用 &self 但内部通过 Arc<Mutex<>> 修改数据库
    // 这是 Rust 惯用的模式，对外不可变接口，内部可变性
    pub fn create(&self, input: &EntryInput) -> Result<String, PassKeepError>;
    pub fn get(&self, id: &str) -> Result<Entry, PassKeepError>;
    pub fn list(&self) -> Result<Vec<EntryMetadata>, PassKeepError>;
    pub fn search(&self, query: &str) -> Result<Vec<EntryMetadata>, PassKeepError>;
    pub fn update(&self, id: &str, input: &EntryInput) -> Result<(), PassKeepError>;
    pub fn delete(&self, id: &str) -> Result<(), PassKeepError>;
    
    // 批量操作：在单个事务中执行，原子性保证
    pub fn create_batch(&self, entries: &[EntryInput]) -> Result<Vec<String>, PassKeepError>;
}
```

**MasterKey 类型定义**：
```rust
use zeroize::Zeroize;

/// 主密钥类型（32 字节，自动清零）
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; 32]);

// 为方便使用，实现一些方法
impl MasterKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
```

### 4.4 Import/Export 模块

**文件**: `passkeep-core/src/import_export/*.rs`

| 文件 | 职责 |
|------|------|
| `format.rs` | JSON 格式定义 |
| `export.rs` | 导出逻辑（基本模式） |
| `import.rs` | 导入逻辑（支持 cross-vault） |

**导出格式**（encrypt_full_file = false）:
```json
{
  "metadata": {
    "format": "passkeep-export",
    "version": 1,
    "exported_at": 1712188800,
    "kdf_params": { ... },
    "verification_value_encrypted": "base64...",
    "verification_nonce": "base64...",
    "integrity_hash": "blake3_hash_base64"
  },
  "entries": [
    {
      "id": "uuid",
      "title": "明文标题",
      "username": "明文用户名",
      "password_encrypted": "base64...",
      "url_preview": "前50字符",
      "url_encrypted": "base64...",
      "notes_encrypted": "base64...",
      "password_nonce": "base64...",
      "url_nonce": "base64...",
      "notes_nonce": "base64...",
      "folder_id": "uuid",
      "tags": ["tag1"],
      "created_at": 1712188800,
      "updated_at": 1712188800
    }
  ],
  "folders": [ ... ]
}
```

**完整性验证**：
- `integrity_hash`: entries + folders 数组的 BLAKE3 哈希值（base64 编码）
  - 计算方法：对 JSON 中的 `entries` 和 `folders` 字段序列化后计算 BLAKE3
  - 导出时在写入 metadata 之前计算
  - 导入时先验证哈希，再处理条目
- `verification_value_encrypted`: 固定值 "PASSKEEP-VERIFICATION" 加密后的结果，用于验证 master_key 正确性

**导入冲突策略**：
| 策略 | 描述 |
|------|------|
| `Skip` | 跳过 ID 冲突的条目，保留现有数据 |
| `Overwrite` | 用导入数据覆盖现有条目 |
| `Rename` | 为导入条目生成新 UUID（推荐） |
| `Abort` | 遇到冲突时取消整个导入操作 |

默认策略：`Rename`（避免数据丢失）

### 4.5 FFI 模块

**文件**: `passkeep-core/src/ffi/simple.rs`

**错误处理设计**：
- 每个函数返回错误码（`i32`），0 表示成功，非零表示错误类型
- 最后的错误消息存储在线程局部存储中
- `passkeep_get_last_error()` 返回指向错误消息的 `*const c_char` 指针
- 调用方负责复制字符串（C 字符串生命周期到下一次 FFI 调用）

**错误码定义**：
```rust
#[repr(i32)]
pub enum ErrorCode {
    Success = 0,
    WrongPassword = 1,
    VaultLocked = 2,
    KeyFileNotFound = 3,
    KeyFileInvalid = 4,
    DatabaseLocked = 5,
    EntryNotFound = 6,
    InvalidHandle = 7,
    // ... 更多错误码
}
```

**FFI 函数列表**：
| 函数 | 描述 |
|------|------|
| `passkeep_create_vault` | 创建新保险库，返回 VaultHandle |
| `passkeep_unlock_vault` | 解锁现有保险库，返回 VaultHandle |
| `passkeep_lock_vault` | 锁定保险库 |
| `passkeep_is_locked` | 检查锁定状态 |
| `passkeep_get_lock_remaining` | 获取剩余锁定时间（秒） |
| `passkeep_create_entry` | 创建条目 |
| `passkeep_get_entry` | 获取条目 |
| `passkeep_list_entries` | 列出条目 |
| `passkeep_update_entry` | 更新条目 |
| `passkeep_delete_entry` | 删除条目 |
| `passkeep_export_vault` | 导出保险库 |
| `passkeep_import_vault` | 导入保险库 |
| `passkeep_close_vault` | 关闭保险库（释放句柄） |
| `passkeep_get_last_error` | 获取最后的错误消息（返回 *const c_char） |

**内存管理说明**：
- `passkeep_get_last_error()` 返回指向线程局部存储中错误消息的 `*const c_char` 指针
- **调用方必须复制字符串内容**：指针在下一次 FFI 调用时失效
- 推荐调用方立即使用 `strncpy()` 或类似函数复制内容
- **不要 free() 返回的指针**：内存由 Rust 管理
- 典型用法模式：
  ```c
  const char* err = passkeep_get_last_error();
  if (err) {
      // 立即复制到自己的缓冲区
      strncpy(my_buffer, err, sizeof(my_buffer) - 1);
      // 不要调用 free(err)
  }
  ```

---

## 5. 解锁流程

```
用户输入主密码 + 密钥文件路径
        ↓
打开数据库连接（启用 WAL 模式）
        ↓
在同一事务中读取 vault_metadata（包括 LockState）
        ↓
检查 LockState 是否被锁定
        ↓ (如果锁定)
返回 VaultLocked 错误，附带剩余秒数
        ↓ (如果未锁定)
读取并验证密钥文件
        ↓
从数据库读取 kdf_params
        ↓
argon_salt = HKDF-Expand-SHA256(
    salt=kdf_salt,
    ikm=keyfile_secret,
    info=b"passkeep-argon2-salt",
    output_len=32
)
        ↓
master_key = Argon2id(
    password=master_password,
    salt=argon_salt,
    params=kdf_params
)
        ↓
解密 master_key_check 验证
        ↓
        ├── SUCCESS → 创建 VaultSession，返回 VaultHandle
        │              更新 vault_metadata (failed_attempts = 0)
        │
        └── FAILURE → failed_attempts++
                     更新 lock_until
                     提交事务
                     返回 WrongPassword 错误
```

**HKDF 参数说明**：
- Hash 算法：SHA-256
- Salt 长度：32 字节（来自 kdf_params.salt）
- IKM 长度：32 字节（来自密钥文件）
- Info：固定字符串 `"passkeep-argon2-salt"`
- 输出长度：32 字节（argon_salt）

---

## 6. 任务分解

### 6.1 Phase 2 任务列表

| 任务 | 描述 | 依赖 |
|------|------|------|
| 2.1 | VaultManager + VaultHandle 系统 | Phase 1 |
| 2.2 | 数据库 schema 迁移（v2） | Phase 1 |
| 2.3 | LockState 暴力破解防护（数据库存储） | 2.2 |
| 2.4 | 解锁流程实现 | 2.1, 2.3 |
| 2.5 | EntryService CRUD | 2.4 |
| 2.6 | 备份管理（自动/手动策略） | 2.5 |
| 2.7 | 导出功能（基本模式 + 完整性验证） | 2.5 |
| 2.8 | 导入功能（冲突策略） | 2.7 |
| 2.9 | 简单 C FFI（错误码设计） | 2.1-2.8 |

### 6.2 备份管理详细设计

**备份策略**：
- **自动备份**：每次修改操作后触发，但有限流（同一秒内最多备份一次）
- **手动备份**：用户主动触发的完整备份（立即执行）
- **保留数量**：最多保留 5 个最新备份
- **命名规则**：`vault_<timestamp>.db`

**备份位置**（跨平台）：
```rust
use dirs::data_dir;

fn backup_dir() -> PathBuf {
    let base = data_dir()
        .unwrap_or_else(|| std::env::temp_dir());  // 降级到系统临时目录（通常可写）
    let mut path = base;
    path.push("passkeep");
    path.push("backups");
    path
}
```

**VaultDb 初始化**：
```rust
impl VaultDb {
    pub fn new(conn: Arc<Mutex<rusqlite::Connection>>) -> Self {
        // 在连接初始化时启用 WAL 模式
        let db = conn.clone();
        let conn_guard = db.lock().unwrap();
        conn_guard.execute("PRAGMA journal_mode=WAL", []).ok();
        drop(conn_guard);
        Self { conn: db }
    }
}
```

**防抖实现**：
```rust
use std::sync::atomic::{AtomicI64, Ordering};

pub struct BackupManager {
    last_backup_at: AtomicI64,  // Unix 时间戳
}

impl BackupManager {
    // 检查是否需要备份（同一秒内只备份一次）
    // 使用 compare_exchange_weak 原子操作避免 TOCTOU 竞态
    fn should_backup(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        let mut last = self.last_backup_at.load(Ordering::Acquire);
        while now > last {
            // 尝试原子更新 last_backup_at 为 now
            // 如果 last 被其他线程修改过，compare_exchange_weak 会返回 Err 中的实际值
            // 这确保只有一个线程能成功更新并执行备份
            match self.last_backup_at.compare_exchange_weak(
                last,
                now,
                Ordering::AcqRel,  // 成功时写内存
                Ordering::Acquire, // 失败时读取最新值
            ) {
                Ok(_) => return true,   // 我们成功更新了 last，现在 > last，执行备份
                Err(actual) => last = actual,  // 其他线程已更新，用新值重试
            }
        }
        false  // now <= last，已在同一秒内备份过
    }
}
```

**备份清理**：
- 创建新备份前检查现有备份数量
- 超过 5 个时删除最旧的备份
- 使用 SQLite VACUUM INTO 创建干净的备份副本
- 使用 `fslock` 保护备份写入过程，防止并发损坏

---

## 7. 文件组织

```
passkeep-core/src/
├── vault/
│   ├── mod.rs           # VaultManager, VaultHandle, VaultSession
│   ├── unlock.rs        # 解锁流程
│   └── handle.rs        # VaultHandle 生成和管理
├── storage/
│   ├── lock_state.rs    # 暴力破解防护（更新）
│   ├── entry_service.rs # Entry CRUD（新建）
│   ├── backup.rs        # 备份管理（新建）
│   └── migrations.rs    # Schema 迁移（新建）
├── import_export/
│   ├── format.rs        # JSON 格式定义（更新）
│   ├── export.rs        # 导出逻辑（更新）
│   └── import.rs        # 导入逻辑（更新）
└── ffi/
    └── simple.rs        # 简单 C FFI（新建）
```

---

## 8. 测试策略

### 8.1 单元测试

| 组件 | 测试覆盖 |
|------|----------|
| VaultManager | 句柄生成/释放、会话管理 |
| LockState | 锁定时间计算、失败记录 |
| EntryService | CRUD 操作、加密/解密 |
| Export/Import | JSON 序列化、cross-vault |

### 8.2 集成测试

| 场景 | 描述 |
|------|------|
| 完整解锁流程 | 创建保险库 → 锁定 → 解锁 |
| 失败重试 | 多次错误密码 → 验证锁定 |
| 条目生命周期 | 创建 → 读取 → 更新 → 删除 |
| 导出导入 | 导出 → 导入验证一致性 |

---

## 9. 依赖更新

```toml
[dependencies]
# Phase 1 现有依赖...
aes-gcm = "0.10"
argon2 = "0.5"
getrandom = "0.2"
hkdf = "0.12"
blake3 = "1.5"
rusqlite = { version = "0.32", features = ["bundled"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "2.0"
uuid = { version = "1.10", features = ["v4", "serde"] }
zeroize = "1.8"
subtle = "2.6"

# Phase 2 新增依赖...
fslock = "0.2.1"           # 文件锁（备份文件写入保护）
dirs = "5.0"               # 跨平台路径获取

# 异步支持（可选 feature，Phase 3 预留）
tokio = { version = "1.40", features = ["sync", "rt-multi-thread"], optional = true }

[features]
default = []
async = ["tokio"]           # 启用异步支持（Phase 3：flutter_rust_bridge 异步 FFI）
# Phase 2 不使用此 feature，保持依赖最小化

[dev-dependencies]
tempfile = "3.13"
```

**数据库连接说明**：
- SQLite 本身支持多读单写，配合 WAL 模式
- 对于密码管理器的使用场景（单用户、单实例为主），单个连接足够
- `Arc<Mutex<Connection>>` 提供 FFI 多线程安全访问
- 未来如需多实例支持，可引入 r2d2 连接池
