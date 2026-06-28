-- ============================================
-- VOIDLATENCY PANEL v3.4.1 - FULL DATABASE
-- ============================================

-- ============================================
-- USERS TABLE - Main user accounts
-- ============================================
DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  uuid TEXT NOT NULL,
  limit_gb REAL DEFAULT 0,
  expiry_days INTEGER DEFAULT 30,
  ips TEXT,
  connection_type TEXT DEFAULT 'vless',
  tls TEXT DEFAULT 'tls',
  port TEXT DEFAULT '443',
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

-- ============================================
-- INBOUNDS TABLE - VLESS tunnels
-- ============================================
DROP TABLE IF EXISTS inbounds;
CREATE TABLE inbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  uuid TEXT NOT NULL,
  protocol TEXT DEFAULT 'vless',
  port INTEGER DEFAULT 443,
  path TEXT DEFAULT '/',
  host TEXT DEFAULT '',
  is_active INTEGER DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  outbound_tag TEXT DEFAULT '',
  routing_rule_id INTEGER DEFAULT 0,
  limit_gb REAL DEFAULT 0,
  expiry_days INTEGER DEFAULT 0,
  max_ips INTEGER DEFAULT 0
);

-- ============================================
-- OUTBOUNDS TABLE
-- ============================================
DROP TABLE IF EXISTS outbounds;
CREATE TABLE outbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  protocol TEXT DEFAULT 'freedom',
  settings TEXT DEFAULT '{}',
  tag TEXT UNIQUE NOT NULL,
  is_active INTEGER DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- ROUTING RULES TABLE
-- ============================================
DROP TABLE IF EXISTS routing_rules;
CREATE TABLE routing_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  inbound_tag TEXT NOT NULL,
  outbound_tag TEXT NOT NULL,
  domain TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  is_active INTEGER DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- NODES TABLE - Remote servers
-- ============================================
DROP TABLE IF EXISTS nodes;
CREATE TABLE nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  port INTEGER DEFAULT 443,
  api_key TEXT DEFAULT '',
  is_active INTEGER DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_check TIMESTAMP
);

-- ============================================
-- CLEAN IPS TABLE - Additional IPs for subscription
-- ============================================
DROP TABLE IF EXISTS clean_ips;
CREATE TABLE clean_ips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  address TEXT NOT NULL UNIQUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- SETTINGS TABLE - Panel configuration
-- ============================================
DROP TABLE IF EXISTS settings;
CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- ADMINS TABLE - Panel administrators
-- ============================================
DROP TABLE IF EXISTS admins;
CREATE TABLE admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP,
  role TEXT DEFAULT 'admin'
);

-- ============================================
-- TRAFFIC LOGS TABLE
-- ============================================
DROP TABLE IF EXISTS traffic_logs;
CREATE TABLE traffic_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  bytes INTEGER DEFAULT 0,
  direction TEXT DEFAULT 'down',
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- SYSTEM EVENTS TABLE
-- ============================================
DROP TABLE IF EXISTS system_events;
CREATE TABLE system_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  message TEXT,
  data TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- DEFAULT DATA
-- ============================================
-- Insert default settings
INSERT OR IGNORE INTO settings (key, value) VALUES 
  ('panel_version', '3.4.1'),
  ('theme', 'dark'),
  ('proxy_ip', 'proxyip.cmliussss.net'),
  ('frag_len', '20-30'),
  ('frag_int', '1-2');

-- Insert default outbounds
INSERT OR IGNORE INTO outbounds (name, protocol, settings, tag) VALUES 
  ('Freedom', 'freedom', '{}', 'freedom'),
  ('Blackhole', 'blackhole', '{}', 'blackhole'),
  ('Proxy', 'vless', '{}', 'proxy');

-- Insert default inbound
INSERT OR IGNORE INTO inbounds (name, uuid, protocol, port, path) VALUES 
  ('Default', 'default-uuid-0000-0000-000000000000', 'vless', 443, '/');

-- Insert default routing rule
INSERT OR IGNORE INTO routing_rules (name, inbound_tag, outbound_tag) VALUES 
  ('Default Route', 'default', 'freedom');
