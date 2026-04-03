-- 保险库元数据表
CREATE TABLE IF NOT EXISTS vault_metadata (
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
CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    username TEXT NOT NULL,
    password_encrypted BLOB NOT NULL,
    url_preview TEXT NOT NULL,
    url_encrypted BLOB,
    notes_encrypted BLOB,
    nonce BLOB NOT NULL UNIQUE,
    folder_id TEXT,
    tags TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- 时间戳触发器
CREATE TRIGGER IF NOT EXISTS set_entries_timestamps
AFTER INSERT ON entries
BEGIN
    UPDATE entries SET
        created_at = CAST(strftime('%s', 'now') AS INTEGER),
        updated_at = CAST(strftime('%s', 'now') AS INTEGER)
    WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_entries_timestamp
AFTER UPDATE ON entries
BEGIN
    UPDATE entries SET updated_at = CAST(strftime('%s', 'now') AS INTEGER)
    WHERE id = NEW.id;
END;

-- 文件夹表
CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    icon TEXT,
    parent_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE
);

-- 文件夹时间戳触发器
CREATE TRIGGER IF NOT EXISTS set_folders_timestamps
AFTER INSERT ON folders
BEGIN
    UPDATE folders SET
        created_at = CAST(strftime('%s', 'now') AS INTEGER),
        updated_at = CAST(strftime('%s', 'now') AS INTEGER)
    WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_folders_timestamp
AFTER UPDATE ON folders
BEGIN
    UPDATE folders SET updated_at = CAST(strftime('%s', 'now') AS INTEGER)
    WHERE id = NEW.id;
END;

-- 主密钥校验值
CREATE TABLE IF NOT EXISTS master_key_check (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    value_encrypted BLOB NOT NULL,
    nonce BLOB NOT NULL UNIQUE
);

-- 数据库版本
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_entries_title ON entries(title COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_entries_username ON entries(username COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_entries_tags ON entries(tags);
CREATE INDEX IF NOT EXISTS idx_entries_folder ON entries(folder_id);
CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);

