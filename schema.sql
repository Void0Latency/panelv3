CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  uuid TEXT,
  limit_gb REAL,
  expiry_days INTEGER,
  ips TEXT,
  connection_type TEXT,
  tls TEXT,
  port TEXT,
  used_gb REAL DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  last_active INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  fingerprint TEXT DEFAULT 'chrome',
  config_name TEXT,
  email TEXT,
  comment TEXT,
  inbound_id INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS inbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  uuid TEXT,
  protocol TEXT,
  port INTEGER,
  path TEXT,
  host TEXT,
  is_active INTEGER DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  outbound_tag TEXT,
  routing_rule_id INTEGER DEFAULT 0,
  limit_gb REAL,
  expiry_days INTEGER,
  max_ips INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS outbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  protocol TEXT,
  settings TEXT,
  tag TEXT,
  is_active INTEGER DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS routing_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  inbound_tag TEXT,
  outbound_tag TEXT,
  domain TEXT,
  ip TEXT,
  is_active INTEGER DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  address TEXT,
  port INTEGER,
  api_key TEXT,
  is_active INTEGER DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clean_ips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  address TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password_hash TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP,
  role TEXT DEFAULT 'admin'
);

CREATE TABLE IF NOT EXISTS traffic_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  bytes INTEGER,
  direction TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS system_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT,
  message TEXT,
  data TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('panel_version', '3.4.1');
INSERT OR IGNORE INTO settings (key, value) VALUES ('theme', 'dark');
INSERT OR IGNORE INTO settings (key, value) VALUES ('proxy_ip', 'proxyip.cmliussss.net');
