# PassKeep 密码管理器设计文档

**日期**: 2026-04-03
**状态**: 设计阶段 v2
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

## 2. 架构设计

### 2.1 整体架构

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
│                         │ (dart:ffi)│                               │
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
│  │  │   Database   │  │   (Key File) │  │   (JSON/CSV)     │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 核心原则

1. **安全边界**：所有加密/解密操作在 Rust 中完成，Flutter 只处理 UI
2. **最小权限**：Rust 核心库只暴露必要的 FFI 接口
3. **内存安全**：敏感数据使用 `zeroize` 清理
4. **逐条目加密**：每条密码独立加密，避免一次性解密整个数据库

---

## 3. 核心组件

### 3.1 Rust Core Library (`passkeep-core/`)

| 模块 | 职责 |
|------|------|
| `ffi/` | 导出 C-ABI 接口给 Flutter 调用 |
| `crypto/` | 加密/解密、密钥派生、随机数生成 |
| `storage/` | SQLite 数据库、文件 I/O |
| `models/` | Vault、Entry、Folder 等数据模型 |
| `import_export/` | 导入/导出功能 |

### 3.2 Flutter Desktop App (`passkeep-app/`)

| 层级 | 组件 |
|------|------|
| **UI Screens** | HomeScreen, VaultScreen, EntryForm, PasswordGenerator, Settings |
| **State Management** | **Riverpod**（推荐：编译时安全、更好的测试支持） |
| **FFI Bridge** | `passkeep_ffi.dart` - 使用 `flutter_rust_bridge` 自动生成 |
| **Services** | VaultService, ClipboardService |

### 3.3 数据结构

```rust
// 加密后的单个条目存储格式
pub struct EncryptedEntry {
    pub id: String,                    // 明文：用于数据库索引
    pub title: String,                  // 明文：用于搜索显示
    pub username_encrypted: Vec<u8>,    // 加密：用户名
    pub password_encrypted: Vec<u8>,    // 加密：密码
    pub url_encrypted: Option<Vec<u8>>, // 加密：URL
    pub notes_encrypted: Option<Vec<u<u8>>>, // 加密：备注
    pub nonce: [u8; 12],                // AES-GCM nonce（每个条目唯一）
    pub folder_id: Option<String>,      // 明文：分类ID
    pub tags: Vec<String>,              // 明文：标签
    pub created_at: i64,
    pub updated_at: i64,
}

// 主密钥派生参数
pub struct KdfParams {
    pub salt: [u8; 32],        // 随机盐值
    pub mem_cost_kib: u32,     // 内存成本（默认 262144 KiB = 256MB）
    pub time_cost: u32,        // 迭代次数（默认 3）
    pub parallelism: u32,      // 并行度（默认 4）
}

// 密钥文件格式
pub struct KeyFile {
    pub version: u32,
    pub secret: [u8; 32],      // 32字节随机密钥
    pub checksum: [u8; 32],    // HMAC-SHA256 校验和
}

// 保险库元数据
pub struct VaultMetadata {
    pub version: u32,
    pub kdf_params: KdfParams,
    pub created_at: i64,
    pub updated_at: i64,
    pub entry_count: u32,
}
```

---

## 4. 数据库设计

### 4.1 SQLite 表结构

```sql
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
    nonce BLOB NOT NULL,           -- 12 bytes, unique per entry
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

-- 暴力破解防护表
CREATE TABLE security_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lock_until INTEGER NOT NULL DEFAULT 0  -- Unix timestamp
);

-- 数据库版本/迁移历史
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);
```

### 4.2 索引设计

```sql
-- 搜索优化
CREATE INDEX idx_entries_title ON entries(title COLLATE NOCASE);
CREATE INDEX idx_entries_tags ON entries(tags);
CREATE INDEX idx_entries_folder ON entries(folder_id);

-- 文件夹查询优化
CREATE INDEX idx_folders_parent ON folders(parent_id);
```

---

## 5. 数据流

### 5.1 解锁流程

```
用户输入主密码 + 读取密钥文件
    ↓
Rust: storage::get_kdf_params() → 从数据库读取 salt 和参数
    ↓
Rust: crypto::derive_master_key(
        master_password,
        key_file_secret,
        salt,
        mem_cost, time_cost, parallelism
    ) → 使用 Argon2id 派生
    ↓
Rust: crypto::decrypt_master_keycheck(encrypted_check, master_key)
    ↓
成功 → 在内存中保留 master_key (Zeroizing 类型)
      → 重置 failed_attempts 计数
失败 → failed_attempts++, 计算延迟时间
```

### 5.2 保存密码流程

```
Flutter UI → VaultService.addEntry(plaintext_entry)
    ↓
Rust FFI: 生成新的 12 字节随机 nonce
    ↓
Rust: crypto::encrypt_field(plaintext, master_key, nonce)
    ↓
storage::save_entry(EncryptedEntry { nonce, encrypted_fields... })
    ↓
自动创建数据库备份
```

### 5.3 读取密码流程

```
Flutter UI → VaultService.getEntry(id)
    ↓
Rust FFI → storage::load_entry(id)
    ↓
crypto::decrypt_field(encrypted_data, master_key, nonce)
    ↓
返回明文 Entry
    ↓
Flutter: 显示 + 自动复制到剪贴板（30秒后清除）
```

### 5.4 密钥轮换流程（修改主密码）

```
用户请求修改主密码
    ↓
验证旧主密码（通过现有 master_key 解密检查）
    ↓
用户输入新主密码
    ↓
使用新主密码 + 原密钥文件 派生 new_master_key
    ↓
FOR EACH entry:
    用旧 master_key 解密
    用新 master_key 重新加密（生成新 nonce）
    ↓
更新数据库中的 kdf_params（可选：生成新 salt）
    ↓
备份数据库（轮换前）
```

---

## 6. 安全设计

### 6.1 加密方案

| 数据 | 加密方式 | 说明 |
|------|----------|------|
| 主密码派生密钥 | Argon2id | mem: 256MB, time: 3, parallelism: 4 (可配置) |
| 各字段内容 | AES-256-GCM | 每条目独立 nonce，AEAD 模式内置认证 |
| 密钥文件 | 随机 32 字节 | 作为主密码派生的额外输入 |
| Nonce 生成 | CSPRNG (getrandom) | 每条目 12 字节，唯一性由随机性保证 |

**AES-256-GCM 说明**：
- GCM 模式是 AEAD（认证加密），内置数据完整性校验
- 无需额外的 HMAC 层，认证标签（16字节）与密文一起存储
- Nonce 必须 12 字节以达到最佳性能和安全性

### 6.2 Argon2id 参数配置

参数应根据用户硬件能力可配置（在设置中提供"安全级别"选项）：

| 级别 | 内存 | 迭代 | 并行度 | 预计时间 | 适用场景 |
|------|------|------|--------|----------|----------|
| 低 | 64MB | 2 | 2 | ~100ms | 低端设备 |
| 中（默认） | 256MB | 3 | 4 | ~500ms | 标准设备 |
| 高 | 1GB | 5 | 8 | ~2s | 高性能设备 |

Salt 生成与存储：
- 创建保险库时生成 32 字节随机 salt
- Salt 以明文存储在 `vault_metadata` 表中
- 修改主密码时可选择重新生成 salt

### 6.3 暴力破解防护

| 机制 | 实现方式 | 存储位置 |
|------|----------|----------|
| 失败计数 | 每次失败 `failed_attempts++` | `security_state` 表 |
| 指数退避 | 2^n 秒延迟，n=失败次数 | 内存计算 |
| 强制锁定 | 5次失败后锁定30秒 | `security_state.lock_until` |

**说明**：`security_state` 表存储在加密数据库内，攻击者无法直接修改计数器。即使删除数据库文件，攻击者仍然需要破解加密。

### 6.4 安全措施

| 措施 | 实现方式 |
|------|----------|
| 内存清理 | 敏感数据使用 `Zeroizing<Vec<u8>>` 包装 |
| 密钥不落地 | 派生的主密钥只存在于内存，不写入任何文件 |
| 防剪贴板泄露 | 复制后 30 秒自动清除 |
| 防截屏录屏 | macOS: `NSWindowSharingNone`, Windows: `SetWindowDisplayAffinity` |
| 自动锁定 | 无操作 5 分钟后清除内存中的 master_key |
| 数据库备份 | 每次修改后在同目录创建 `.bak` 文件 |
| 安全退出 | 应用退出时清除所有敏感数据 |

### 6.5 错误处理

```rust
pub enum PassKeepError {
    // 认证相关
    WrongPassword,
    KeyFileNotFound,
    KeyFileInvalid,
    VaultLocked(i64),  // 参数：解锁时间戳

    // 加密相关
    EncryptionFailed,
    DecryptionFailed,
    InvalidNonce,

    // 存储相关
    DatabaseLocked,
    DatabaseCorrupted,
    EntryNotFound,
    BackupFailed,

    // 系统相关
    UnauthorizedAccess,
    DiskFull,
    InvalidKdfParams,
}
```

---

## 7. 性能指标

| 指标 | 目标 | 测量方式 |
|------|------|----------|
| 解锁时间 | < 1s（默认配置） | 从输入密码到主界面加载 |
| 搜索响应 | < 100ms | 本地搜索 1000+ 条目 |
| 保存条目 | < 200ms | 从点击保存到完成写入 |
| 复制密码 | < 50ms | 点击复制到剪贴板可用 |
| 内存占用 | < 100MB | 空闲状态（不含 master_key） |
| 启动时间 | < 2s | 从启动到锁定界面 |

---

## 8. 项目结构

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
│   │   │   └── rng.rs
│   │   ├── storage/           # 存储模块
│   │   │   ├── mod.rs
│   │   │   ├── database.rs
│   │   │   └── schema.sql
│   │   ├── models/            # 数据模型
│   │   │   ├── mod.rs
│   │   │   ├── vault.rs
│   │   │   └── entry.rs
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

## 9. 技术依赖

### 9.1 Rust 依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| `aes-gcm` | ^0.10 | AES-256-GCM 加密 |
| `argon2` | ^0.5 | 密钥派生 |
| `rusqlite` | ^0.30 | SQLite 数据库 |
| `zeroize` | ^1.6 | 安全内存清理 |
| `serde` | ^1.0 | 序列化 |
| `thiserror` | ^1.0 | 错误处理 |
| `getrandom` | ^0.2 | 随机数生成 |
| `flutter_rust_bridge` | ^2.0 | FFI 代码生成 |

### 9.2 Flutter 依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| `flutter_rust_bridge` | ^2.0 | FFI 代码生成 |
| `riverpod` | ^2.4 | 状态管理 |
| `flutter_local_notifications` | ^16.0 | 剪贴板清除通知 |
| `flutter_l10n` | - | 内置国际化 |

---

## 10. 测试策略

### 10.1 测试覆盖率目标

| 层级 | 测试类型 | 覆盖目标 | 工具 |
|------|----------|----------|------|
| Rust Core | 单元测试 | 90%+ | cargo test |
| Rust Core | 集成测试 | 关键流程 | cargo test |
| Rust Core | 模糊测试 | 加密/解密 | libFuzzer |
| Flutter App | 单元测试 | 80%+ | flutter test |
| Flutter App | Widget 测试 | 主要页面 | flutter test |
| Flutter App | 集成测试 | 完整流程 | integration_test |

### 10.2 关键测试场景

- **加密往返**：明文 → 加密 → 解密 → 明文，验证一致性
- **密钥派生**：相同输入产生相同密钥，不同输入产生不同密钥
- **数据库锁定/解锁**：验证 master_key 清除后的锁定状态
- **导入/导出**：导出后导入，验证数据完整性
- **FFI 内存**：长时间运行无内存泄漏
- **并发访问**：多个操作同时执行的数据一致性

### 10.3 模糊测试目标

| 目标 | 输入范围 | 预期行为 |
|------|----------|----------|
| 加密函数 | 任意长度字节串 | 绝不崩溃，返回错误或有效密文 |
| KDF 函数 | 任意密码长度 | 绝不崩溃，执行时间合理 |
| 数据库解析 | 损坏的 SQLite 文件 | 返回 DatabaseCorrupted 错误 |

---

## 11. CI/CD 与安全审计

### 11.1 CI 流水线

```yaml
# .github/workflows/ci.yml
on: [push, pull_request]
jobs:
  rust:
    - cargo fmt --check
    - cargo clippy -- -D warnings
    - cargo test
    - cargo fuzz ...  # 如果有 fuzzer
  flutter:
    - flutter analyze
    - flutter test
    - flutter test integration_test
  security:
    - cargo audit  # 依赖漏洞扫描
    - flutter pub run dependency_validator
```

### 11.2 安全审计

| 工具 | 频率 | 作用 |
|------|------|------|
| `cargo audit` | 每次 CI | 检查 Rust 依赖漏洞 |
| `cargo-deny` | 每周 | 许可证检查、依赖审计 |
| `flutter pub dependency_validator` | 每次 CI | Flutter 依赖检查 |
| 手动代码审查 | 每个 PR | 安全敏感代码双人审查 |

### 11.3 发布前检查清单

- [ ] 所有测试通过
- [ ] 无依赖漏洞
- [ ] FFI 边界测试通过
- [ ] 内存泄漏检测（Valgrind/Instruments）
- [ ] 性能基准测试达标
- [ ] 跨平台测试（macOS/Windows/Linux）

---

## 12. 国际化与无障碍

### 12.1 国际化 (i18n)

- 使用 Flutter 内置 `flutter_localizations`
- 首批支持：简体中文、英文
- 所有用户可见字符串通过 `AppLocalizations` 访问
- 日期/时间格式本地化

### 12.2 无障碍 (a11y)

- 所有交互元素添加 `Semantics` 标签
- 支持键盘导航
- 支持屏幕阅读器（macOS VoiceOver, Windows Narrator）
- 高对比度模式支持
- 字体大小缩放支持

---

## 13. 用户体验

| 场景 | 处理方式 |
|------|----------|
| 首次启动 | 引导创建主密码 + 生成密钥文件 → 备份提醒 |
| 忘记主密码 | 明确警告：数据无法恢复，提示检查备份 |
| 数据库损坏 | 自动检测备份文件，提示恢复 |
| 导入导出 | 支持加密 JSON 格式，导出前验证文件完整性 |
| 密码强度提示 | 实时显示密码强度条（熵值估算） |
| 自动保存 | 编辑后自动保存，减少手动操作 |

---

## 14. 数据同步

由于采用离线优先设计，多设备间同步采用**手动导入/导出**方式：
- 用户可将数据导出为加密的 JSON 文件
- 通过 U 盘、网盘等方式传输到其他设备
- 在目标设备上导入该文件
- 导入时验证文件完整性和格式版本

---

## 15. 版本管理与迁移

### 15.1 数据库版本

- `vault_metadata.version` 存储当前数据库格式版本
- 启动时检查版本，必要时执行迁移

### 15.2 迁移策略

- 每次数据库结构变更更新版本号
- 提供向前迁移脚本
- 保留向后兼容性（至少一个版本）
- 迁移前自动备份

---

## 16. 未来扩展方向

1. **浏览器扩展** - WebSocket 本地通信，自动填充网页表单
2. **移动端** - 共享 Rust 核心库，Flutter 原生支持
3. **YubiKey 支持** - 硬件密钥作为第三认证因素
4. **SSH 密钥管理** - 扩展支持 SSH 密钥存储
5. **TOTP 代码** - 内置双因素认证码生成器
