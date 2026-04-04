-- Schema v2: 为每个敏感字段添加独立的 nonce
-- 添加暴力破解防护状态到 vault_metadata

-- 为 entries 表添加 nonce 列
ALTER TABLE entries ADD COLUMN password_nonce BLOB NOT NULL DEFAULT X'000000000000000000000000';
ALTER TABLE entries ADD COLUMN url_nonce BLOB;
ALTER TABLE entries ADD COLUMN notes_nonce BLOB;

-- 为 vault_metadata 表添加锁定状态字段
ALTER TABLE vault_metadata ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vault_metadata ADD COLUMN lock_until INTEGER;
ALTER TABLE vault_metadata ADD COLUMN last_attempt_at INTEGER;

-- 更新 schema 版本
INSERT INTO schema_migrations (version, applied_at)
VALUES (2, CAST(strftime('%s', 'now') AS INTEGER));
