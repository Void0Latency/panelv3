-- VoidLatency / Fire Panel schema (matches voidlatency-core.js ensureSchema)
-- Optional: the worker also auto-creates these on first request. Idempotent.

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  uuid TEXT,
  limit_gb REAL,
  expiry_days INTEGER,
  ips TEXT,
  connection_type TEXT,
  tls TEXT,
  port INTEGER,
  used_gb REAL DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  last_active INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  fingerprint TEXT DEFAULT 'chrome',
  config_name TEXT
);

CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password_hash TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS inbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  remark TEXT,
  enable INTEGER DEFAULT 1,
  protocol TEXT DEFAULT 'vless',
  listen TEXT DEFAULT '',
  port INTEGER,
  network TEXT DEFAULT 'ws',
  security TEXT DEFAULT 'tls',
  path TEXT DEFAULT '/',
  host TEXT DEFAULT '',
  uuid TEXT,
  up INTEGER DEFAULT 0,
  down INTEGER DEFAULT 0,
  total INTEGER DEFAULT 0,
  expiry_time INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS outbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tag TEXT UNIQUE,
  remark TEXT,
  protocol TEXT DEFAULT 'freedom',
  address TEXT DEFAULT '',
  port INTEGER DEFAULT 0,
  auth TEXT DEFAULT '',
  enable INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS routing_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  enable INTEGER DEFAULT 1,
  remark TEXT,
  inbound_tag TEXT DEFAULT '',
  outbound_tag TEXT DEFAULT 'direct',
  domain TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  port TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  address TEXT,
  port INTEGER,
  api_port INTEGER DEFAULT 62789,
  remark TEXT,
  type TEXT DEFAULT 'xray',
  enable INTEGER DEFAULT 1
);

INSERT OR IGNORE INTO outbounds (tag, remark, protocol) VALUES ('direct','Direct','freedom');
INSERT OR IGNORE INTO outbounds (tag, remark, protocol) VALUES ('block','Block','blackhole');
INSERT OR IGNORE INTO settings (key, value) VALUES ('proxy_ip','proxyip.cmliussss.net');
INSERT OR IGNORE INTO settings (key, value) VALUES ('theme','dark');
