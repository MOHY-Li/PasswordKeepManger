# PassKeep 密码管理器设计文档

**日期**: 2026-04-03
**状态**: 设计阶段 v9
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
| 数据库文件替换 | AES-GCM 认证标签 | 检测篡改 |
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
// ============ 数据库存储结构 ============

// 加密后的单个条目存储格式
pub struct EncryptedEntry {
    pub id: String,
    pub title: String,                  // 明文：用于数据库索引和搜索
    pub username: String,               // 明文：用户名通常不是敏感信息
    pub password_encrypted: Vec<u8>,    // 加密：密码（敏感）
    pub url_preview: String,            // 明文：URL 前 50 字符（用于显示）
    pub url_encrypted: Option<Vec<u8>>, // 加密：完整 URL（可能包含敏感信息）
    pub notes_encrypted: Option<Vec<u8>>, // 加密：备注
    pub nonce: [u8; 12],                // AES-GCM nonce（每个条目唯一）
    pub folder_id: Option<String>,      // 明文：分类ID
    pub tags: Vec<String>,              // 明文：标签
    pub created_at: i64,
    pub updated_at: i64,
}

// 主密钥派生参数
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KdfParams {
    pub salt: [u8; 32],        // 数据库盐值（用于 HKDF）
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
    pub password: String,           // 明文（敏感）
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
    pub username: String,           // 明文：用户名不是敏感信息
    pub url_preview: String,        // 明文：URL 前 50 字符
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
    pub url: Option<String>,        // 完整 URL
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
    /// 密码长度（默认 20，范围 8-128）
    pub length: u8,

    /// 字符集选项
    pub character_sets: CharacterSets,

    /// 排除相似字符（如 0/O, 1/l/I）
    pub exclude_similar: bool,

    /// 排除模糊字符
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

// ============ 导入配置 ============

/// 导入选项
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ImportOptions {
    /// 如何处理 ID 冲突
    pub conflict_resolution: ConflictResolution,

    /// 是否验证每个条目的加密完整性
    pub verify_integrity: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ConflictResolution {
    /// 跳过冲突的条目
    Skip,
    /// 覆盖现有条目
    Overwrite,
    /// 为导入的条目生成新 ID
    Rename,
    /// 取消整个导入操作
    Abort,
}

// ============ 导入导出元数据 ============

/// 导出文件的加密元数据（用于跨 vault 导入）
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExportMetadata {
    /// 格式标识
    pub format: String,
    /// 版本号
    pub version: u32,
    /// 导出时间戳
    pub exported_at: i64,
    /// 源 vault 的 KDF 参数
    pub kdf_params: KdfParams,
    /// 加密的验证值
    pub verification_value_encrypted: Vec<u8>,
    pub verification_nonce: Vec<u8>,
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

---

## 6. 主密钥派生

### 6.1 派生公式（使用 HKDF）

```rust
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

// hkdf crate 0.12 的正确 API
// info 参数类型是 &[&[u8]]，不是 &[u8]
let hkdf = Hkdf::<Sha256>::new(Some(&kdf_salt), &keyfile_secret);
let mut argon_salt = [0u8; 32];
hkdf.expand(&[b"passkeep-argon2-salt"], &mut argon_salt)
    .map_err(|_| PassKeepError::KeyDerivationFailed)?;

// Step 2: 使用派生的 salt 调用 Argon2id
let mut master_key_bytes = Zeroizing::new([0u8; 32]);
let master_key = argon2::Argon2::new(
    argon2::Algorithm::Argon2id,
    argon2::Version::V0x13,
    argon2::Params::new(
        kdf_params.mem_cost_kib,
        kdf_params.time_cost,
        kdf_params.parallelism,
        None
    ).map_err(|_| PassKeepError::InvalidKdfParams)?
)
.hash_password_into(
    master_password.as_bytes(),
    &argon_salt,
    &mut **master_key_bytes,
)
.map_err(|_| PassKeepError::KeyDerivationFailed)?;

// master_key_bytes 现在包含派生的主密钥
```

**API 说明**：
- `Hkdf::new(salt, ikm)` - 创建 HKDF 实例，salt 参数可选
- `hkdf.expand(info, output)` - 输出派生密钥，返回 `Result<(), InvalidLength>`
  - `info` 参数类型是 `&[&[u8]]`，用于绑定派生上下文
  - 可以传递多个 info 片段，例如 `&[b"app-name", b"purpose"]`

### 6.2 密钥文件验证流程

```rust
fn validate_keyfile(path: &Path) -> Result<KeyFile, PassKeepError> {
    let data = fs::read(path)?;

    if data.len() != KEYFILE_SIZE {
        return Err(PassKeepError::KeyFileInvalid);
    }

    if data[0..4] != KEYFILE_MAGIC {
        return Err(PassKeepError::KeyFileInvalid);
    }

    let version = u32::from_le_bytes(data[4..8].try_into()?);
    if version != KEYFILE_VERSION {
        return Err(PassKeepError::KeyFileVersionMismatch);
    }

    let secret: [u8; 32] = data[8..40].try_into()?;
    let stored_checksum: [u8; 32] = data[40..72].try_into()?;

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
-- 启用外键约束
PRAGMA foreign_keys = ON;

-- 保险库元数据表
CREATE TABLE vault_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL,
    kdf_salt BLOB NOT NULL,
    kdf_mem_cost INTEGER NOT NULL,
    kdf_time_cost INTEGER NOT NULL,
    kdf_parallelism INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 加密条目表
CREATE TABLE entries (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    username TEXT NOT NULL,
    password_encrypted BLOB NOT NULL,
    url_preview TEXT NOT NULL,        -- 明文：URL 前 50 字符
    url_encrypted BLOB,
    notes_encrypted BLOB,
    nonce BLOB NOT NULL UNIQUE,
    folder_id TEXT,
    tags TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- 自动设置时间戳触发器
CREATE TRIGGER set_entries_timestamps
AFTER INSERT ON entries
BEGIN
    UPDATE entries SET
        created_at = CAST(strftime('%s', 'now') AS INTEGER),
        updated_at = CAST(strftime('%s', 'now') AS INTEGER)
    WHERE id = NEW.id;
END;

CREATE TRIGGER update_entries_timestamp
AFTER UPDATE ON entries
BEGIN
    UPDATE entries SET updated_at = CAST(strftime('%s', 'now') AS INTEGER)
    WHERE id = NEW.id;
END;

-- 文件夹表
CREATE TABLE folders (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    icon TEXT,
    parent_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE
);

-- 文件夹时间戳触发器
CREATE TRIGGER set_folders_timestamps
AFTER INSERT ON folders
BEGIN
    UPDATE folders SET
        created_at = CAST(strftime('%s', 'now') AS INTEGER),
        updated_at = CAST(strftime('%s', 'now') AS INTEGER)
    WHERE id = NEW.id;
END;

CREATE TRIGGER update_folders_timestamp
AFTER UPDATE ON folders
BEGIN
    UPDATE folders SET updated_at = CAST(strftime('%s', 'now') AS INTEGER)
    WHERE id = NEW.id;
END;

-- 主密钥校验值
CREATE TABLE master_key_check (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    value_encrypted BLOB NOT NULL,
    nonce BLOB NOT NULL UNIQUE
);

-- 数据库版本
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);
```

### 7.2 索引设计

```sql
CREATE INDEX idx_entries_title ON entries(title COLLATE NOCASE);
CREATE INDEX idx_entries_username ON entries(username COLLATE NOCASE);
CREATE INDEX idx_entries_tags ON entries(tags);
CREATE INDEX idx_entries_folder ON entries(folder_id);
CREATE INDEX idx_folders_parent ON folders(parent_id);
```

---

## 8. FFI 接口规范

### 8.1 初始化与解锁

```rust
#[frb(async)]
pub async fn init_vault(
    config_path: String,
    master_password: String,
    keyfile_path: String,
    kdf_params: KdfParams,
) -> Result<VaultMetadata, PassKeepError>

#[frb(async)]
pub async fn unlock_vault(
    config_path: String,
    master_password: String,
    keyfile_path: String,
) -> Result<VaultMetadata, PassKeepError>

#[frb(sync)]
pub fn lock_vault()

#[frb(sync)]
pub fn is_locked() -> bool

#[frb(sync)]
pub fn get_lock_remaining_seconds() -> i64
```

### 8.2 条目操作

```rust
#[frb(async)]
pub async fn create_entry(entry: EntryInput) -> Result<String, PassKeepError>

#[frb(async)]
pub async fn get_entry(id: String) -> Result<Entry, PassKeepError>

#[frb(async)]
pub async fn list_entries() -> Result<Vec<EntryMetadata>, PassKeepError>

#[frb(async)]
pub async fn search_entries(query: String) -> Result<Vec<EntryMetadata>, PassKeepError>

#[frb(async)]
pub async fn update_entry(id: String, entry: EntryInput) -> Result<(), PassKeepError>

#[frb(async)]
pub async fn delete_entry(id: String) -> Result<(), PassKeepError>

#[frb(async)]
pub async fn delete_entries(ids: Vec<String>) -> Result<usize, PassKeepError>
```

### 8.3 密钥轮换

```rust
#[frb(async)]
pub async fn change_master_password(
    old_password: String,
    new_password: String,
) -> Result<(), PassKeepError>
```

### 8.4 密码生成器

```rust
#[frb(sync)]
pub fn generate_password(config: PasswordGeneratorConfig) -> Result<String, PassKeepError>

#[frb(sync)]
pub fn estimate_password_strength(password: String) -> f64
```

### 8.5 导入/导出

```rust
/// 导出保险库
#[frb(async)]
pub async fn export_vault(
    output_path: String,
    encrypt_full_file: bool,  // 是否加密整个 JSON 文件
) -> Result<String, PassKeepError>

/// 导入保险库
#[frb(async)]
pub async fn import_vault(
    input_path: String,
    options: ImportOptions,
    source_password: Option<String>,
    source_keyfile_path: Option<String>,  // 跨 vault 导入时需要
) -> Result<ImportResult, PassKeepError>

/// 读取导出文件元数据
#[frb(sync)]
pub fn read_export_metadata(input_path: String) -> Result<ExportMetadata, PassKeepError>

/// 导入结果
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportResult {
    pub imported: usize,
    pub skipped: usize,
    pub overwritten: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}
```

---

## 9. 数据流

### 9.1 解锁流程

```
用户输入主密码 + 选择密钥文件
    ↓
读取 security/lock_state.json
    ↓
检查 lock_until
    ↓
读取密钥文件，验证校验和
    ↓
从数据库读取 kdf_salt 和参数
    ↓
argon_salt = HKDF-Expand(salt=kdf_salt, ikm=keyfile_secret, info="passkeep-argon2-salt")
    ↓
master_key = Argon2id(master_password, argon_salt, params)
    ↓
解密 master_key_check
    ↓
    SUCCESS → 更新 lock_state，保留 master_key
    FAILURE → failed_attempts++，更新 lock_until
```

### 9.2 保存密码流程

```
Flutter UI → VaultService.create_entry(EntryInput)
    ↓
生成 nonce
    ↓
加密 password, url, notes
    ↓
生成 url_preview（URL 前 50 字符，明文）
    ↓
保存到数据库（触发器自动设置时间戳）
    ↓
创建备份
```

### 9.3 导出流程

```
用户请求导出
    ↓
检查 encrypt_full_file 选项
    ↓
    TRUE → 导出前用 master_key 加密整个 JSON
    FALSE → 仅敏感字段加密，title/username/tags 明文
    ↓
创建 ExportMetadata
    ↓
序列化并写入文件
```

**安全说明**：
- `encrypt_full_file = true`：整个 JSON 文件用 AES-GCM 加密，最安全
- `encrypt_full_file = false`：仅 password/url/notes 加密，title/username 明文，便于查看

### 9.4 导入流程

```
用户选择导入文件
    ↓
read_export_metadata() 读取元数据
    ↓
比较 kdf_params 与当前 vault
    ↓
    相同 → source_keyfile_path = None，使用当前 master_key
    ↓
    不同 → 判断密钥文件是否相同
           ↓
           密钥文件相同 → source_keyfile_path = None
                        仅需 source_password
                        用当前密钥文件 + 源密码派生源 master_key
           ↓
           密钥文件不同 → 需要 source_password + source_keyfile_path
                         用源密钥文件 + 源密码派生源 master_key
    ↓
使用获得的 master_key 解密文件内容
    ↓
验证 verification_value_encrypted
    ↓
FOR EACH entry:
    用当前 vault 的 master_key 重新加密敏感字段
    生成新的 nonce
    插入到当前数据库
    ↓
返回 ImportResult
```

**跨 vault 导入的密钥文件逻辑**：
- 如果仅 kdf_params 不同但使用相同密钥文件：只需 `source_password`
- 如果密钥文件也不同：需要 `source_password` + `source_keyfile_path`

---

## 10. 安全设计

### 10.1 加密方案

| 数据 | 加密方式 |
|------|----------|
| 主密钥派生 | HKDF + Argon2id |
| 密码/URL/备注 | AES-256-GCM |
| 密钥文件校验 | BLAKE3 |

### 10.2 数据字段存储策略

| 字段 | 存储方式 | 理由 |
|------|----------|------|
| title | 明文 | 搜索需要 |
| username | 明文 | 搜索/显示需要 |
| password | 加密 | 核心敏感 |
| url_preview | 明文（前50字符） | 显示需要 |
| url_encrypted | 加密 | 完整 URL 可能敏感 |
| notes | 加密 | 可能敏感 |
| tags | 明文 | 搜索需要 |

### 10.3 导出文件安全选项

| 选项 | 说明 | 安全性 |
|------|------|--------|
| `encrypt_full_file = true` | 整个 JSON 用 AES-GCM 加密 | 最高 |
| `encrypt_full_file = false` | 仅敏感字段加密 | 中等 |

### 10.4 备份策略

- 每次修改后备份
- 最多保留 5 个
- 密钥轮换后删除旧备份

---

## 11. 并发与崩溃恢复

### 11.1 SQLite 配置

```rust
fn open_database(path: &Path) -> Result<Connection, PassKeepError> {
    let conn = Connection::open(path)?;
    conn.execute("PRAGMA journal_mode=WAL", [])?;
    conn.execute("PRAGMA foreign_keys=ON", [])?;
    conn.execute("PRAGMA busy_timeout=5000", [])?;
    Ok(conn)
}
```

### 11.2 崩溃恢复

| 场景 | 恢复机制 |
|------|----------|
| 写入崩溃 | SQLite WAL 回滚 |
| 数据库损坏 | 提示从备份恢复 |
| 应用崩溃 | 需重新解锁 |

### 11.3 并发保护

**lock_state.json 并发控制**：

由于多个应用实例可能同时运行，`lock_state.json` 需要并发保护：

```rust
use fslock::LockFile;

fn update_lock_state(state: &LockState) -> Result<(), PassKeepError> {
    let lock_path = config_dir.join("security").join("lock_state.json");
    let lock_file = LockFile::open(&lock_path)
        .map_err(|_| PassKeepError::LockStateUpdateFailed)?;

    // 独占锁，防止其他实例同时修改
    lock_file.lock().map_err(|_| PassKeepError::LockStateUpdateFailed)?;

    // 读取-修改-写入
    let current = read_lock_state(&lock_path)?;
    let updated = apply_failed_attempt(&current);
    write_lock_state(&lock_path, &updated)?;

    lock_file.unlock().map_err(|_| PassKeepError::LockStateUpdateFailed)?;
    Ok(())
}
```

**说明**：
- 使用文件锁确保 `lock_state.json` 的原子更新
- 如果文件锁失败，视为锁定状态，拒绝操作
- 单实例运行时锁操作是轻量级的

---

## 12. 测试策略

### 12.1 测试覆盖率目标

| 层级 | 测试类型 | 覆盖目标 | 工具 |
|------|----------|----------|------|
| Rust Core | 单元测试 | 90%+ | cargo test |
| Rust Core | 集成测试 | 关键流程 | cargo test |
| Rust Core | 模糊测试 | 加密/解密 | libFuzzer |
| Flutter App | 单元测试 | 80%+ | flutter test |
| Flutter App | Widget 测试 | 主要页面 | flutter test |
| Flutter App | 集成测试 | 完整流程 | integration_test |

### 12.2 关键测试场景

- **加密往返**：明文 → 加密 → 解密 → 明文，验证一致性
- **密钥派生**：相同输入产生相同密钥，不同输入产生不同密钥
- **HKDF 正确性**：验证 HKDF-Expand 输出符合预期
- **nonce 唯一性**：尝试重用 nonce 应返回错误
- **nonce 冲突处理**：模拟冲突后重新生成
- **数据库锁定/解锁**：验证 master_key 清除后的锁定状态
- **导入导出**：导出后导入验证数据完整性
- **跨 vault 导入**：不同 kdf_params 的导入流程
- **时间戳触发器**：验证 created_at/updated_at 自动设置
- **FFI 内存**：长时间运行无内存泄漏
- **并发访问**：多操作同时执行的数据一致性

### 12.3 模糊测试目标

| 目标 | 输入范围 | 预期行为 |
|------|----------|----------|
| 加密函数 | 任意长度字节串 | 绝不崩溃，返回错误或有效密文 |
| KDF 函数 | 任意密码长度 | 绝不崩溃，执行时间合理 |
| HKDF 函数 | 任意 salt/ikm 组合 | 绝不崩溃 |
| 数据库解析 | 损坏的 SQLite 文件 | 返回 DatabaseCorrupted 错误 |
| 密钥文件解析 | 任意字节文件 | 返回 KeyFileInvalid 错误 |
| 导入文件解析 | 损坏的 JSON 文件 | 返回 InvalidExportFormat 错误 |

---

## 13. CI/CD 与安全审计

### 13.1 CI 流水线

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  rust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cargo fmt --check
      - run: cargo clippy -- -D warnings
      - run: cargo test --all-features
      - run: cargo audit

  flutter:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
      - run: flutter analyze
      - run: flutter test
      - run: flutter test integration_test/

  fuzz:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cargo install cargo-fuzz
      - run: cargo fuzz run encrypt_target -- -max_total_time=60
```

### 13.2 安全审计

| 工具 | 频率 | 作用 |
|------|------|------|
| `cargo audit` | 每次 CI | 检查 Rust 依赖漏洞 |
| `cargo-deny` | 每周 | 许可证检查、依赖审计 |
| `flutter pub dependency_validator` | 每次 CI | Flutter 依赖检查 |
| 手动代码审查 | 每个 PR | 安全敏感代码双人审查 |

### 13.3 发布前检查清单

- [ ] 所有测试通过
- [ ] 无依赖漏洞
- [ ] FFI 边界测试通过
- [ ] 内存泄漏检测
- [ ] 性能基准测试达标
- [ ] 跨平台测试

---

## 14. 导入/导出格式

### 14.1 导出格式 (JSON)

```json
{
  "metadata": {
    "format": "passkeep-export",
    "version": 1,
    "exported_at": 1712188800,
    "kdf_params": { ... },
    "verification_value_encrypted": "base64...",
    "verification_nonce": "base64..."
  },
  "entries": [
    {
      "id": "uuid",
      "title": "明文标题（如果 encrypt_full_file=false）",
      "username": "明文用户名（如果 encrypt_full_file=false）",
      "password_encrypted": "base64...",
      "url_preview": "前50字符（如果 encrypt_full_file=false）",
      "url_encrypted": "base64...",
      "notes_encrypted": "base64...",
      "nonce": "base64...",
      "folder_id": "uuid",
      "tags": ["tag1"],
      "created_at": 1712188800,
      "updated_at": 1712188800
    }
  ],
  "folders": [ ... ]
}
```

### 14.2 完全加密格式

当 `encrypt_full_file = true` 时，整个 JSON 被加密为：

```
PassKeepEncryptedFile {
    version: u8 = 1,
    nonce: [u8; 12],
    encrypted_data: Vec<u8>,  // AES-GCM(above_json, master_key, nonce)
}
```

---

## 15. 错误处理

```rust
use thiserror::Error;
use serde::{Serialize, Deserialize};

#[derive(Debug, Error)]
pub enum PassKeepError {
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

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("Failed to update lock state file")]
    LockStateUpdateFailed,

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("Failed to generate unique nonce")]
    NonceGenerationFailed,

    #[error("Database is locked")]
    DatabaseLocked,

    #[error("Database is corrupted")]
    DatabaseCorrupted,

    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("Backup failed")]
    BackupFailed,

    #[error("Invalid export file format")]
    InvalidExportFormat,

    #[error("Export file version mismatch")]
    ExportVersionMismatch,

    #[error("Import cancelled")]
    ImportCancelled,

    #[error("Source vault password required")]
    SourcePasswordRequired,

    #[error("Source key file required")]
    SourceKeyFileRequired,

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

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
```

---

## 16. 性能指标

| 指标 | 目标 |
|------|------|
| 解锁时间 | < 1s |
| 搜索响应 | < 100ms |
| 保存条目 | < 200ms |
| 内存占用 | < 100MB |

---

## 17. 技术依赖

### 17.1 Rust 依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| `aes-gcm` | ^0.10 | AES-256-GCM |
| `argon2` | ^0.5 | 密钥派生 |
| `hkdf` | ^0.12 | HKDF |
| `sha2` | ^0.10 | HKDF 哈希 |
| `blake3` | ^1.5 | 密钥文件校验 |
| `rusqlite` | ^0.30 | SQLite |
| `zeroize` | ^1.6 | 内存清理 |
| `serde` | ^1.0 | 序列化 |
| `serde_json` | ^1.0 | JSON |
| `thiserror` | ^2.0 | 错误处理 |
| `uuid` | ^1.0 | UUID |
| `fslock` | ^0.2 | 文件锁（lock_state 并发保护） |
| `flutter_rust_bridge` | ^2.0 | FFI |

### 17.2 Flutter 依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| `flutter_rust_bridge` | ^2.0 | FFI |
| `riverpod` | ^2.4 | 状态管理 |
| `super_clipboard` | ^0.8 | 剪贴板 |

---

## 18. 用户体验

| 场景 | 处理方式 |
|------|----------|
| 首次启动 | 引导创建主密码 + 密钥文件 |
| 忘记主密码 | 警告：数据无法恢复 |
| 跨 vault 导入 | 提示输入源密码和密钥文件 |
| 导出选项 | 让用户选择是否完全加密 |

---

## 19. 未来扩展

1. 浏览器扩展
2. 移动端
3. YubiKey 支持
4. SSH 密钥管理
5. TOTP 代码
