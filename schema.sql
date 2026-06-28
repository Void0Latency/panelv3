-- ============================================
-- VoidLatency Panel v3.4.1 - Complete Schema
-- ============================================

-- Users table
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

-- Inbounds table
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

-- Outbounds table
CREATE TABLE IF NOT EXISTS outbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  protocol TEXT,
  settings TEXT,
  tag TEXT,
  is_active INTEGER DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Routing rules table
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

-- Nodes table
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  address TEXT,
  port INTEGER,
  api_key TEXT,
  is_active INTEGER DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Clean IPs table
CREATE TABLE IF NOT EXISTS clean_ips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  address TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Settings table
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Admins table
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password_hash TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP,
  role TEXT DEFAULT 'admin'
);

-- Traffic logs table
CREATE TABLE IF NOT EXISTS traffic_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  bytes INTEGER,
  direction TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- System events table
CREATE TABLE IF NOT EXISTS system_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT,
  message TEXT,
  data TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- INDEXES
-- ============================================

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_users_last_active ON users(last_active);
CREATE INDEX IF NOT EXISTS idx_users_inbound ON users(inbound_id);

CREATE INDEX IF NOT EXISTS idx_inbounds_name ON inbounds(name);
CREATE INDEX IF NOT EXISTS idx_inbounds_active ON inbounds(is_active);

CREATE INDEX IF NOT EXISTS idx_outbounds_tag ON outbounds(tag);
CREATE INDEX IF NOT EXISTS idx_outbounds_active ON outbounds(is_active);

CREATE INDEX IF NOT EXISTS idx_routing_active ON routing_rules(is_active);

CREATE INDEX IF NOT EXISTS idx_nodes_active ON nodes(is_active);

CREATE INDEX IF NOT EXISTS idx_traffic_logs_username ON traffic_logs(username);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_timestamp ON traffic_logs(timestamp);

CREATE INDEX IF NOT EXISTS idx_system_events_timestamp ON system_events(timestamp);

-- ============================================
-- DEFAULT DATA
-- ============================================

-- Default settings
INSERT OR IGNORE INTO settings (key, value) VALUES 
  ('panel_version', '3.4.1'),
  ('theme', 'dark'),
  ('proxy_ip', 'proxyip.cmliussss.net'),
  ('frag_len', '20-30'),
  ('frag_int', '1-2');

-- Default outbounds
INSERT OR IGNORE INTO outbounds (name, protocol, settings, tag, is_active) VALUES 
  ('Direct', 'freedom', '{"domainStrategy":"AsIs"}', 'direct', 1),
  ('Block', 'blackhole', '{"response":{"type":"none"}}', 'block', 1);

-- Default inbound (sample)
INSERT OR IGNORE INTO inbounds (name, uuid, protocol, port, path, host, is_active, limit_gb, expiry_days) 
SELECT 'Default', '11111111-1111-1111-1111-111111111111', 'vless', 443, '/', 'example.com', 1, NULL, NULL
WHERE NOT EXISTS (SELECT 1 FROM inbounds WHERE name = 'Default');

-- Sample admin (password: admin123) - will be replaced on first setup
INSERT OR IGNORE INTO admins (username, password_hash, role) 
VALUES ('admin', '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 'admin');
-- Note: This is SHA-256 of "admin123" - user should change on first login
