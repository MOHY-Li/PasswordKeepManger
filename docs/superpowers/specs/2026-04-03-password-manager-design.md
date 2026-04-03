# PassKeep 密码管理器设计文档

**日期**: 2026-04-03
**状态**: 设计阶段 v4
**作者**: Claude + 用户协作

---

## 1. 项目概述

### 1.1 目标

构建一个**个人使用的跨平台密码管理器**，具有以下特点：
- 纯离线存储，不依赖任何云服务
- 先进的加密算法保护用户数据
- 支持 macOS、Windows、Linux 桌面平台

### 1.2 核心功能

| 功能 | 描述 |
|------|------|
| 存储/查看密码 | 安全存储和查看各类账户密码 |
| 搜索 | 快速查找密码条目 |
| 分类 | 文件夹和标签组织 |
| 密码生成器 | 生成强随机密码 |
| 自动复制 | 一键复制密码到剪贴板（30秒后清除） |
| 浏览器集成 | 未来扩展方向 |

### 1.3 认证方式

**主密码 + 密钥文件** 双因素认证：
- 用户设置一个主密码
- 系统生成一个密钥文件（32字节随机数据）
- 两者结合才能解锁保险库

---

## 2. 威胁模型

### 2.1 威胁场景

| 威胁 | 防护措施 | 备注 |
|------|----------|------|
| 硬盘被盗/设备丢失 | 数据库文件加密 | 需要 master_key 解密 |
| 内存转储攻击 | 敏感数据使用 `zeroize` | 进程退出时清理 |
| 剪贴板窃取 | 30秒自动清除 | 限制泄露窗口 |
| 截屏/录屏 | 窗口防截屏属性 | OS 级别防护，Linux 有限 |
| 暴力破解主密码 | Argon2id 高成本 KDF | 延迟攻击 |
| 密钥文件被复制 | 主密码仍需输入 | 双因素认证 |
| 数据库文件替换 | HMAC 完整性校验 | 检测篡改 |
| 时间攻击 | 常量时间比较 | 密码验证 |
| 侧信道攻击（缓存） | 使用常数时间密码原语 | 有限防护 |

### 2.2 不在防护范围内的威胁

| 威胁 | 原因 |
|------|------|
| 键盘记录器 | 主密码输入时可能被记录 |
| 内存完整的恶意软件 | 如有 root/admin 权限，可读取进程内存 |
| 物理胁迫 | 无法抵抗强迫交出密码 |
| 丢设备后未检测的备份 | 用户需要手动清理旧备份 |

---

## 3. 架构设计

### 3.1 整体架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Flutter Desktop App                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      UI Layer (Dart)                        │   │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐    │   │
│  │  │  Home   │ │  Vault   │ │Generate  │ │  Settings    │    │   │
│  │  │  Screen │ │  Screen  │ │  Screen  │ │   Screen     │    │   │
│  │  └─────────┘ └──────────┘ └──────────┘ └──────────────┘    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                         ┌────▼────┐                                 │
│                         │ FFI Bridge│                                │
│                         │ (async)    │                               │
│                         └────┬────┘                                 │
└──────────────────────────────┼──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                       Rust Core Library                            │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   FFI Export Layer                          │   │
│  └───────────────────────────┬─────────────────────────────────┘   │
│  ┌───────────────────────────▼─────────────────────────────────┐   │
│  │                      Domain Layer                           │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐   │   │
│  │  │  Vault   │  │  Entry   │  │  Folder  │  │  Metadata  │   │   │
│  │  │  Model   │  │  Model   │  │  Model   │  │    Model   │   │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   Security Layer                            │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │   │
│  │  │   AES-256    │  │   Argon2id   │  │   Key File       │  │   │
│  │  │  Encryption  │  │   KDF        │  │   Handler        │  │   │
│  │  │  (GCM Mode)  │  │              │  │                  │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   Storage Layer                             │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │   │
│  │  │   SQLite     │  │   File I/O   │  │   Export/Import  │  │   │
│  │  │   Database   │  │(Key+Security)│  │   (Encrypted)    │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 核心原则

1. **安全边界**：所有加密/解密操作在 Rust 中完成，Flutter 只处理 UI
2. **最小权限**：Rust 核心库只暴露必要的 FFI 接口
3. **内存安全**：敏感数据使用 `zeroize` 清理
4. **逐条目加密**：每条密码独立加密，避免一次性解密整个数据库
5. **防御深度**：多层安全防护，任何一层失效不代表系统崩溃
6. **异步优先**：耗时操作（KDF、数据库 I/O）使用异步 FFI 避免 UI 阻塞

---

## 4. 核心组件

### 4.1 Rust Core Library (`passkeep-core/`)

| 模块 | 职责 |
|------|------|
| `ffi/` | 导出 C-ABI 接口给 Flutter 调用 |
| `crypto/` | 加密/解密、密钥派生、随机数生成 |
| `storage/` | SQLite 数据库、文件 I/O |
| `models/` | Vault、Entry、Folder 等数据模型 |
| `import_export/` | 导入/导出功能 |

### 4.2 Flutter Desktop App (`passkeep-app/`)

| 层级 | 组件 |
|------|------|
| **UI Screens** | HomeScreen, VaultScreen, EntryForm, PasswordGenerator, Settings |
| **State Management** | **Riverpod**（推荐：编译时安全、更好的测试支持） |
| **FFI Bridge** | `passkeep_ffi.dart` - 使用 `flutter_rust_bridge` 自动生成，异步调用 |
| **Services** | VaultService, ClipboardService |

### 4.3 数据结构

```rust
// 加密后的单个条目存储格式
pub struct EncryptedEntry {
    pub id: String,
    pub title: String,                  // 明文：用于数据库索引和搜索
    pub username_encrypted: Vec<u8>,    // 加密：用户名
    pub password_encrypted: Vec<u8>,    // 加密：密码
    pub url_encrypted: Option<Vec<u8>>, // 加密：URL
    pub notes_encrypted: Option<Vec<u8>>, // 加密：备注
    pub nonce: [u8; 12],                // AES-GCM nonce（每个条目唯一）
    pub folder_id: Option<String>,      // 明文：分类ID
    pub tags: Vec<String>,              // 明文：标签
    pub created_at: i64,
    pub updated_at: i64,
}

// 主密钥派生参数（使用 HKDF-Extract 扩展）
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KdfParams {
    pub salt: [u8; 32],        // HKDF salt
    pub mem_cost_kib: u32,     // 内存成本
    pub time_cost: u32,        // 迭代次数
    pub parallelism: u32,      // 并行度
}

// 密钥文件磁盘格式
//
// 文件结构 (字节序: Little Endian):
// [0-3]    Magic: "PKEY" (0x59454B50)
// [4-7]    Version: u32 (当前 = 1)
// [8-39]   Secret: [u8; 32] - 密钥材料
// [40-71]  Checksum: [u8; 32] - BLAKE3(secret || version)
// Total: 72 bytes
//
// 校验和使用 BLAKE3（不需要密钥），校验文件完整性。
pub const KEYFILE_MAGIC: &[u8; 4] = b"PKEY";
pub const KEYFILE_VERSION: u32 = 1;
pub const KEYFILE_SIZE: usize = 72;

pub struct KeyFile {
    pub version: u32,
    pub secret: [u8; 32],      // 32字节随机密钥材料
    pub checksum: [u8; 32],    // BLAKE3 输出完整 32 字节
}

// 保险库元数据
pub struct VaultMetadata {
    pub version: u32,
    pub kdf_params: KdfParams,
    pub created_at: i64,
    pub updated_at: i64,
    pub entry_count: u32,
}

// 主密钥（内存中，使用 Zeroizing 包装）
pub type MasterKey = Zeroizing<[u8; 32]>;

// ============ FFI 数据结构 ============

/// 用于创建/更新条目的输入（包含明文敏感数据）
#[derive(Serialize, Deserialize, Debug)]
pub struct EntryInput {
    pub id: Option<String>,        // None 表示新建，Some 表示更新
    pub title: String,
    pub username: String,           // 明文
    pub password: String,           // 明文
    pub url: Option<String>,        // 明文
    pub notes: Option<String>,      // 明文
    pub folder_id: Option<String>,
    pub tags: Vec<String>,
}

/// 条目元数据（不含敏感信息，可直接显示）
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EntryMetadata {
    pub id: String,
    pub title: String,
    pub url_preview: Option<String>, // URL 的前 50 字符
    pub username: String,           // 用户名可明文存储用于识别
    pub folder_id: Option<String>,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// 完整条目（包含解密后的敏感数据）
#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,           // 明文（仅在需要时返回）
    pub url: Option<String>,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

// ============ 密码生成器配置 ============

/// 密码生成器配置
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PasswordGeneratorConfig {
    /// 密码长度（默认 20）
    pub length: u8,

    /// 字符集选项
    pub character_sets: CharacterSets,

    /// 排除相似字符（如 0/O, 1/l/I）
    pub exclude_similar: bool,

    /// 排除模糊字符（如 {}, [], (), /, \, ", ', `, ,, ;, :, ., <, >）
    pub exclude_ambiguous: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CharacterSets {
    pub uppercase: bool,    // A-Z
    pub lowercase: bool,    // a-z
    pub digits: bool,       // 0-9
    pub symbols: bool,      // !@#$%^&*()_+-=[]{}|;:,.<>?
    pub custom: String,     // 自定义字符集（优先使用）
}

impl Default for PasswordGeneratorConfig {
    fn default() -> Self {
        Self {
            length: 20,
            character_sets: CharacterSets {
                uppercase: true,
                lowercase: true,
                digits: true,
                symbols: true,
                custom: String::new(),
            },
            exclude_similar: true,
            exclude_ambiguous: false,
        }
    }
}
```

---

## 5. 文件系统布局

### 5.1 数据目录结构

```
~/.passkeep/                          # 配置目录
├── database/
│   ├── vault.db                      # 主数据库（加密内容）
│   └── vault.db.lock                 # SQLite 锁文件
├── keys/
│   └── keyfile.pkey                  # 密钥文件
├── security/
│   └── lock_state.json               # 暴力破解防护状态（明文）
├── backups/
│   ├── vault_20260403_143000.db      # 时间戳命名的备份（最多 5 个）
│   └── vault_20260403_120000.db
└── exports/
    └── export_20260403.json.enc      # 加密导出文件
```

### 5.2 暴力破解防护状态文件

```json
// security/lock_state.json (明文，不包含敏感信息)
{
  "failed_attempts": 2,
  "lock_until": 1712188800,
  "last_attempt_at": 1712188600
}
```

**设计理由**：此文件独立于加密数据库，即使密码错误也能读写。攻击者无法通过修改此文件绕过锁定，因为真正的防护是 Argon2id 的计算成本。

---

## 6. 主密钥派生

### 6.1 派生公式

使用 HKDF 增强（防止边界攻击）：

```rust
// Step 1: 从密钥文件和主密码提取盐值
let hkdf_salt = hkdf_extract(
    ikm = keyfile_secret || kdf_salt,  // 64 字节输入
    salt = None,                        // 使用默认盐
); // 输出 32 字节

// Step 2: 使用 Argon2id 派生主密钥
master_key = Argon2id(
    password = master_password,
    salt = hkdf_salt,                   // 32 字节
    mem_cost = kdf_params.mem_cost_kib,
    time_cost = kdf_params.time_cost,
    parallelism = kdf_params.parallelism,
    output_length = 32 bytes
);
```

**说明**：
- `keyfile_secret`: 32字节，从密钥文件读取
- `kdf_salt`: 32字节，创建保险库时生成，存储在数据库中
- HKDF-Extract 提供明确的边界，防止拼接攻击
- 使用 `hkdf` crate 实现

### 6.2 密钥文件验证流程

```rust
fn validate_keyfile(path: &Path) -> Result<KeyFile, PassKeepError> {
    let data = fs::read(path)?;

    // 1. 检查文件大小
    if data.len() != KEYFILE_SIZE {
        return Err(PassKeepError::KeyFileInvalid);
    }

    // 2. 检查 magic
    if data[0..4] != KEYFILE_MAGIC {
        return Err(PassKeepError::KeyFileInvalid);
    }

    // 3. 检查版本
    let version = u32::from_le_bytes(data[4..8].try_into()?);
    if version != KEYFILE_VERSION {
        return Err(PassKeepError::KeyFileVersionMismatch);
    }

    // 4. 提取 secret 和 checksum
    let secret: [u8; 32] = data[8..40].try_into()?;
    let stored_checksum: [u8; 32] = data[40..72].try_into()?;

    // 5. 计算并验证 checksum
    let mut hasher = blake3::Hasher::new();
    hasher.update(&secret);
    hasher.update(&version.to_le_bytes());
    let computed_checksum = hasher.finalize();

    if computed_checksum.as_bytes() != &stored_checksum {
        return Err(PassKeepError::KeyFileCorrupted);
    }

    Ok(KeyFile { version, secret, checksum: stored_checksum })
}
```

---

## 7. 数据库设计

### 7.1 SQLite 表结构

```sql
-- 启用外键约束（必须在每次连接时设置）
PRAGMA foreign_keys = ON;

-- 保险库元数据表（单行）
CREATE TABLE vault_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL,
    kdf_salt BLOB NOT NULL,        -- 32 bytes
    kdf_mem_cost INTEGER NOT NULL,
    kdf_time_cost INTEGER NOT NULL,
    kdf_parallelism INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 加密条目表
CREATE TABLE entries (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,           -- 明文，用于搜索
    username_encrypted BLOB NOT NULL,
    password_encrypted BLOB NOT NULL,
    url_encrypted BLOB,
    notes_encrypted BLOB,
    nonce BLOB NOT NULL UNIQUE,    -- 12 bytes, UNIQUE 约束防止重用
    folder_id TEXT,
    tags TEXT,                     -- JSON 数组，明文
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- 文件夹表
CREATE TABLE folders (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    icon TEXT,
    parent_id TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE
);

-- 主密钥校验值（用于验证解锁是否成功）
CREATE TABLE master_key_check (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    value_encrypted BLOB NOT NULL,  -- 用 master_key 加密的已知值
    nonce BLOB NOT NULL UNIQUE       -- 对应的 nonce
);

-- 数据库版本/迁移历史
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);
```

### 7.2 索引设计

```sql
-- 搜索优化
CREATE INDEX idx_entries_title ON entries(title COLLATE NOCASE);
CREATE INDEX idx_entries_tags ON entries(tags);
CREATE INDEX idx_entries_folder ON entries(folder_id);

-- 文件夹查询优化
CREATE INDEX idx_folders_parent ON folders(parent_id);
```

### 7.3 Nonce 冲突处理

当创建新条目时：
1. 生成随机 12 字节 nonce
2. 尝试插入到数据库
3. 如果因 UNIQUE 约束失败（nonce 冲突）：
   - 重新生成 nonce
   - 最多重试 10 次
   - 10 次后仍失败则返回 `NonceGenerationFailed` 错误

**概率分析**：12 字节随机数的冲突概率约为 2^-96，实际中不可能发生。UNIQUE 约束是防御性编程。

---

## 8. FFI 接口规范

### 8.1 初始化与解锁

```rust
/// 初始化新的保险库
#[frb(async)]
pub async fn init_vault(
    config_path: String,
    master_password: String,
    keyfile_path: String,
    kdf_params: KdfParams,
) -> Result<VaultMetadata, PassKeepError>

/// 解锁现有保险库（异步，耗时操作）
#[frb(async)]
pub async fn unlock_vault(
    config_path: String,
    master_password: String,
    keyfile_path: String,
) -> Result<VaultMetadata, PassKeepError>

/// 锁定保险库（清除内存中的密钥）
#[frb(sync)]
pub fn lock_vault()

/// 检查锁定状态
#[frb(sync)]
pub fn is_locked() -> bool

/// 获取剩余锁定时间（秒）
#[frb(sync)]
pub fn get_lock_remaining_seconds() -> i64
```

### 8.2 条目操作

```rust
/// 创建条目
#[frb(async)]
pub async fn create_entry(entry: EntryInput) -> Result<String, PassKeepError>

/// 获取条目（返回解密后的明文）
#[frb(async)]
pub async fn get_entry(id: String) -> Result<Entry, PassKeepError>

/// 列出所有条目（仅返回元数据，不解密敏感字段）
#[frb(async)]
pub async fn list_entries() -> Result<Vec<EntryMetadata>, PassKeepError>

/// 搜索条目
#[frb(async)]
pub async fn search_entries(query: String) -> Result<Vec<EntryMetadata>, PassKeepError>

/// 更新条目
#[frb(async)]
pub async fn update_entry(id: String, entry: EntryInput) -> Result<(), PassKeepError>

/// 删除条目
#[frb(async)]
pub async fn delete_entry(id: String) -> Result<(), PassKeepError>

/// 批量删除条目
#[frb(async)]
pub async fn delete_entries(ids: Vec<String>) -> Result<usize, PassKeepError>
```

### 8.3 密钥轮换

```rust
/// 修改主密码
#[frb(async)]
pub async fn change_master_password(
    old_password: String,
    new_password: String,
) -> Result<(), PassKeepError>
```

### 8.4 密码生成器

```rust
/// 生成随机密码
#[frb(sync)]
pub fn generate_password(config: PasswordGeneratorConfig) -> Result<String, PassKeepError>

/// 估算密码强度（返回熵值）
#[frb(sync)]
pub fn estimate_password_strength(password: String) -> f64
```

---

## 9. 数据流

### 9.1 解锁流程（含暴力破解防护）

```
用户输入主密码 + 选择密钥文件
    ↓
Rust: 读取 security/lock_state.json
    ↓
检查 current_time < lock_until?
    YES → 返回 VaultLocked 错误，显示剩余时间
    NO  → 继续
    ↓
Rust: 读取密钥文件，验证 BLAKE3 校验和
    ↓
Rust: 从数据库读取 kdf_salt 和参数
    ↓
Rust: hkdf_salt = HKDF-Extract(keyfile_secret || kdf_salt)
    ↓
Rust: master_key = Argon2id(master_password, hkdf_salt, params) [异步]
    ↓
Rust: 尝试用 master_key 解密 master_key_check.value_encrypted
    ↓
    SUCCESS → 更新 lock_state.json (failed_attempts = 0)
              在内存中保留 master_key (Zeroizing 类型)
              返回 VaultMetadata
    ↓
    FAILURE → failed_attempts++
              delay = min(2^failed_attempts, 300) 秒
              lock_until = current_time + delay
              更新 lock_state.json
              返回 WrongPassword 错误
```

### 9.2 保存密码流程

```rust
Flutter UI → VaultService.create_entry(EntryInput)
    ↓
Rust FFI: 生成新的 12 字节随机 nonce
    ↓
Rust: 尝试插入，检查 nonce 唯一性
    冲突 → 重新生成（最多 10 次）
    ↓
Rust: FOR EACH sensitive_field:
        encrypted = AES-256-GCM(plaintext, master_key, nonce)
    ↓
storage::save_entry(EncryptedEntry { nonce, encrypted_fields... })
    ↓
创建数据库备份（滚动策略）
```

### 9.3 密钥轮换流程

```
用户请求修改主密码
    ↓
验证旧主密码（解锁验证）
    ↓
FOR EACH entry IN database:
    1. 读取 entry.nonce, entry.*_encrypted
    2. 用旧 master_key 解密
    3. 生成新的 nonce
    4. 用新 master_key 重新加密
    5. 更新 entry
    ↓
重新加密 master_key_check
    ↓
创建标记备份 vault_<timestamp>_pre_keychange.db
    ↓
删除所有旧备份（包括 _pre_keychange 之外的备份）
    ↓
更新数据库 metadata
```

---

## 10. 安全设计

### 10.1 加密方案

| 数据 | 加密方式 | 说明 |
|------|----------|------|
| 主密码派生密钥 | HKDF + Argon2id | HKDF 防拼接攻击，Argon2id 抗 GPU |
| 各字段内容 | AES-256-GCM | 每条目独立 nonce，AEAD 模式 |
| 密钥文件 | 随机 32 字节 | 作为主密码派生的额外输入 |
| Nonce 生成 | CSPRNG (getrandom) | 每条目 12 字节，UNIQUE 约束 |
| 密钥文件校验 | BLAKE3 | 32 字节，完整性验证 |

### 10.2 Argon2id 参数配置

| 级别 | 内存 | 迭代 | 并行度 | 预计时间 | 适用场景 |
|------|------|------|--------|----------|----------|
| 低 | 128MB | 2 | 2 | ~200ms | 低端设备 |
| 中（默认） | 256MB | 3 | 4 | ~500ms | 标准设备 |
| 高 | 1GB | 5 | 8 | ~2s | 高性能设备 |

### 10.3 暴力破解防护

```rust
// 延迟计算（指数退避，上限 5 分钟）
fn calculate_lockout_delay(failed_attempts: u32) -> u64 {
    let exponent = failed_attempts.min(8);  // 2^8 = 256
    let delay_secs = (1u64 << exponent).min(300);
    delay_secs
}
```

| 失败次数 | 延迟时间 |
|----------|----------|
| 1 | 2 秒 |
| 2 | 4 秒 |
| 3 | 8 秒 |
| 4 | 16 秒 |
| 5 | 32 秒 |
| 6+ | 64 秒 ~ 5 分钟（最大） |

### 10.4 备份策略

| 策略 | 说明 |
|------|------|
| 备份频率 | 每次修改操作后 |
| 保留数量 | 最多 5 个滚动备份 |
| 命名格式 | `vault_YYYYMMDD_HHMMSS.db` |
| 清理策略 | 创建新备份时，删除最旧的备份 |
| 密钥轮换 | 创建 `_pre_keychange` 标记备份后，删除所有其他备份 |

**统一策略**：保留最新的 5 个备份。密钥轮换后，所有旧备份都被视为不安全，因此全部删除（除了刚创建的标记备份）。

### 10.5 安全措施

| 措施 | 实现方式 |
|------|----------|
| 内存清理 | 敏感数据使用 `Zeroizing<Vec<u8>>` 包装 |
| 密钥不落地 | 派生的主密钥只存在于内存，不写入任何文件 |
| 防剪贴板泄露 | 复制后 30 秒自动清除 |
| 防截屏录屏 | macOS: `NSWindowSharingNone`<br>Windows: `SetWindowDisplayAffinity`<br>Linux: **有限支持**（Wayland 协议限制） |
| 自动锁定 | 无操作 5 分钟后清除内存中的 master_key |
| 防重放攻击 | Nonce 数据库 UNIQUE 约束 |

### 10.6 平台特定说明

**剪贴板处理**：
- **macOS/Windows**: 标准 clipboard API，30 秒后清除
- **Linux (X11)**: 同时处理 primary selection 和 clipboard
- **Linux (Wayland)**: 仅 clipboard（Wayland 协议限制）

**防截屏**：
- **macOS**: `NSWindowSharingNone` 完全支持
- **Windows**: `SetWindowDisplayAffinity` 完全支持
- **Linux**: **不支持**（X11/Wayland 无标准 API）

---

## 11. 并发访问与崩溃恢复

### 11.1 SQLite 并发配置

```rust
fn open_database(path: &Path) -> Result<Connection, PassKeepError> {
    let conn = Connection::open(path)?;

    // 启用 WAL 模式（更好的并发性）
    conn.execute("PRAGMA journal_mode=WAL", [])?;

    // 启用外键约束
    conn.execute("PRAGMA foreign_keys=ON", [])?;

    // 设置 busy_timeout（等待锁的最长时间）
    conn.execute("PRAGMA busy_timeout=5000", [])?;

    Ok(conn)
}
```

### 11.2 崩溃恢复

| 场景 | 恢复机制 |
|------|----------|
| 写入过程中崩溃 | SQLite WAL 自动回滚未完成的事务 |
| 数据库损坏 | 检测损坏后提示用户从备份恢复 |
| 密钥文件损坏 | 提示用户从备份恢复（如有） |
| 应用崩溃重启 | 内存状态丢失，需要重新解锁 |

### 11.3 事务一致性

```rust
conn.transaction(|tx| {
    tx.execute(...)?;
    tx.execute(...)?;
    create_backup(tx)?;
    Ok(())
})?;
```

---

## 12. 导入/导出格式

### 12.1 加密导出格式 (JSON)

```json
{
  "format": "passkeep-export",
  "version": 1,
  "exported_at": 1712188800,
  "kdf_params": {
    "salt": "base64...",
    "mem_cost_kib": 262144,
    "time_cost": 3,
    "parallelism": 4
  },
  "entries": [
    {
      "id": "uuid",
      "title": "明文标题",
      "username_encrypted": "base64...",
      "password_encrypted": "base64...",
      "url_encrypted": "base64...",
      "notes_encrypted": "base64...",
      "nonce": "base64...",
      "folder_id": "uuid",
      "tags": ["tag1", "tag2"]
    }
  ],
  "folders": [
    {
      "id": "uuid",
      "name": "文件夹名",
      "icon": "folder",
      "parent_id": null
    }
  ]
}
```

---

## 13. 错误处理

```rust
#[derive(Debug, thiserror::Error)]
pub enum PassKeepError {
    // 认证相关
    #[error("Incorrect master password")]
    WrongPassword,

    #[error("Key file not found: {0}")]
    KeyFileNotFound(String),

    #[error("Invalid key file format")]
    KeyFileInvalid,

    #[error("Key file is corrupted")]
    KeyFileCorrupted,

    #[error("Unsupported key file version: {0}")]
    KeyFileVersionMismatch(u32),

    #[error("Vault is locked. Try again in {0} seconds")]
    VaultLocked(i64),

    // 加密相关
    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("Failed to generate unique nonce after 10 attempts")]
    NonceGenerationFailed,

    // 存储相关
    #[error("Database is locked")]
    DatabaseLocked,

    #[error("Database is corrupted")]
    DatabaseCorrupted,

    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("Backup failed")]
    BackupFailed,

    // 系统相关
    #[error("Unauthorized access")]
    UnauthorizedAccess,

    #[error("Disk full")]
    DiskFull,

    #[error("Invalid KDF parameters")]
    InvalidKdfParams,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}
```

---

## 14. 性能指标

| 指标 | 目标 | 测量方式 |
|------|------|----------|
| 解锁时间 | < 1s（默认配置） | 从输入密码到主界面加载 |
| 搜索响应 | < 100ms | 本地搜索 1000+ 条目 |
| 保存条目 | < 200ms | 从点击保存到完成写入 |
| 复制密码 | < 50ms | 点击复制到剪贴板可用 |
| 内存占用 | < 100MB | 空闲状态（不含 master_key） |
| 启动时间 | < 2s | 从启动到锁定界面 |

---

## 15. 项目结构

```
passkeep/
├── passkeep-core/              # Rust 核心库
│   ├── Cargo.toml
│   ├── src/
│   │   ├── ffi/               # FFI 导出层
│   │   │   └── lib.rs
│   │   ├── crypto/            # 加密模块
│   │   │   ├── mod.rs
│   │   │   ├── aes.rs
│   │   │   ├── argon2.rs
│   │   │   ├── hkdf.rs
│   │   │   └── rng.rs
│   │   ├── storage/           # 存储模块
│   │   │   ├── mod.rs
│   │   │   ├── database.rs
│   │   │   └── schema.sql
│   │   ├── models/            # 数据模型
│   │   │   ├── mod.rs
│   │   │   ├── vault.rs
│   │   │   ├── entry.rs
│   │   │   └── password.rs
│   │   ├── import_export/     # 导入导出
│   │   │   ├── mod.rs
│   │   │   └── json_format.rs
│   │   └── lib.rs
│   └── tests/                 # 集成测试
│       ├── crypto_tests.rs
│       └── fuzz/              # 模糊测试
│           ├── encrypt_target.rs
│           └── kdf_target.rs
│
├── passkeep-app/               # Flutter 应用
│   ├── pubspec.yaml
│   ├── lib/
│   │   ├── main.dart
│   │   ├── screens/           # 页面
│   │   │   ├── home/
│   │   │   ├── vault/
│   │   │   ├── settings/
│   │   │   └── password_generator/
│   │   ├── widgets/           # 通用组件
│   │   ├── providers/         # Riverpod providers
│   │   ├── services/          # 服务层
│   │   │   ├── vault_service.dart
│   │   │   └── clipboard_service.dart
│   │   ├── models/            # Dart 数据模型
│   │   ├── l10n/              # 国际化
│   │   └── ffi/               # FFI 绑定（自动生成）
│   ├── test/                  # 测试
│   │   ├── widgets/
│   │   └── integration/
│   └── linux/
│       ├── flutter/
│       └── packages/          # Linux 特定资源
│
├── .github/                    # CI/CD
│   └── workflows/
│       ├── rust-audit.yml     # 依赖安全审计
│       ├── test.yml
│       └── release.yml
│
├── docs/                       # 文档
│   └── superpowers/specs/
│
├── scripts/                    # 构建脚本
│   ├── build-all.sh
│   └── audit-deps.sh
│
└── README.md
```

---

## 16. 技术依赖

### 16.1 Rust 依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| `aes-gcm` | ^0.10 | AES-256-GCM 加密 |
| `argon2` | ^0.5 | 密钥派生 |
| `hkdf` | ^0.12 | HKDF-Extract |
| `blake3` | ^1.5 | 密钥文件校验和 |
| `rusqlite` | ^0.30 | SQLite 数据库 |
| `zeroize` | ^1.6 | 安全内存清理 |
| `serde` | ^1.0 | 序列化 |
| `thiserror` | ^1.0 | 错误处理 |
| `getrandom` | ^0.2 | 随机数生成 |
| `flutter_rust_bridge` | ^2.0 | FFI 代码生成 |

### 16.2 Flutter 依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| `flutter_rust_bridge` | ^2.0 | FFI 代码生成 |
| `riverpod` | ^2.4 | 状态管理 |
| `flutter_local_notifications` | ^16.0 | 剪贴板清除通知 |

---

## 17. 测试策略

### 17.1 测试覆盖率目标

| 层级 | 测试类型 | 覆盖目标 | 工具 |
|------|----------|----------|------|
| Rust Core | 单元测试 | 90%+ | cargo test |
| Rust Core | 集成测试 | 关键流程 | cargo test |
| Rust Core | 模糊测试 | 加密/解密 | libFuzzer |
| Flutter App | 单元测试 | 80%+ | flutter test |
| Flutter App | Widget 测试 | 主要页面 | flutter test |
| Flutter App | 集成测试 | 完整流程 | integration_test |

### 17.2 关键测试场景

- **加密往返**：明文 → 加密 → 解密 → 明文
- **密钥派生**：相同输入产生相同密钥
- **nonce 唯一性**：重用 nonce 应返回错误
- **导入/导出**：导出后导入验证完整性
- **FFI 内存**：长时间运行无内存泄漏
- **nonce 冲突处理**：模拟冲突后重新生成

### 17.3 模糊测试目标

| 目标 | 输入范围 | 预期行为 |
|------|----------|----------|
| 加密函数 | 任意长度字节串 | 绝不崩溃 |
| KDF 函数 | 任意密码长度 | 绝不崩溃 |
| 数据库解析 | 损坏的 SQLite 文件 | 返回错误 |
| 密钥文件解析 | 任意字节文件 | 返回错误 |

---

## 18. CI/CD 与安全审计

### 18.1 CI 流水线

```yaml
# .github/workflows/ci.yml
on: [push, pull_request]
jobs:
  rust:
    - cargo fmt --check
    - cargo clippy -- -D warnings
    - cargo test
  flutter:
    - flutter analyze
    - flutter test
  security:
    - cargo audit
```

### 18.2 安全审计

| 工具 | 频率 | 作用 |
|------|------|------|
| `cargo audit` | 每次 CI | 检查 Rust 依赖漏洞 |
| `cargo-deny` | 每周 | 许可证检查 |
| 手动代码审查 | 每个 PR | 安全敏感代码双人审查 |

---

## 19. 用户体验

| 场景 | 处理方式 |
|------|----------|
| 首次启动 | 引导创建主密码 + 生成密钥文件 |
| 忘记主密码 | 明确警告：数据无法恢复 |
| 数据库损坏 | 自动检测备份文件，提示恢复 |
| 密码强度提示 | 实时显示熵值 |

---

## 20. 未来扩展方向

1. **浏览器扩展** - WebSocket 本地通信
2. **移动端** - 共享 Rust 核心库
3. **YubiKey 支持** - 硬件密钥
4. **SSH 密钥管理**
5. **TOTP 代码**
