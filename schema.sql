-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    created_at INTEGER NOT NULL
);

-- 卡密表（可重置版本）
CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    owner_id INTEGER,
    hwid TEXT,
    used_count INTEGER DEFAULT 0,
    reset_at INTEGER,
    created_at INTEGER NOT NULL,
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'exhausted', 'revoked')),
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- 访问令牌表
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    key_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (key_id) REFERENCES keys(id)
);

-- 管理员账号表
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- 管理员会话令牌表
CREATE TABLE IF NOT EXISTS admin_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    admin_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (admin_id) REFERENCES admins(id)
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key);
CREATE INDEX IF NOT EXISTS idx_keys_hwid ON keys(hwid);
CREATE INDEX IF NOT EXISTS idx_keys_owner ON keys(owner_id);
CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
