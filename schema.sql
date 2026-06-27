-- fire.js schema (Fire Panel v3.0.0)
-- Note: fire.js also auto-creates these tables on first request (ensureSchema),
-- so running this file is optional but recommended for a clean first deploy.

-- Admins
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password_hash TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Settings (key/value)
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

-- Inbounds
CREATE TABLE IF NOT EXISTS inbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  remark TEXT,
  enable INTEGER DEFAULT 1,
  listen TEXT DEFAULT '',
  port INTEGER,
  protocol TEXT DEFAULT 'vless',
  settings TEXT DEFAULT '{}',
  stream_settings TEXT DEFAULT '{}',
  sniffing TEXT DEFAULT '{}',
  tag TEXT,
  up INTEGER DEFAULT 0,
  down INTEGER DEFAULT 0,
  total INTEGER DEFAULT 0,
  expiry_time INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Clients (one inbound has many clients) — source of truth for the proxy
CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  inbound_id INTEGER,
  enable INTEGER DEFAULT 1,
  email TEXT,
  uuid TEXT,
  password TEXT,
  total_gb REAL DEFAULT 0,
  used_gb REAL DEFAULT 0,
  expiry_time INTEGER DEFAULT 0,
  sub_id TEXT,
  last_active INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Outbounds
CREATE TABLE IF NOT EXISTS outbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tag TEXT UNIQUE,
  remark TEXT,
  protocol TEXT,
  settings TEXT DEFAULT '{}',
  stream_settings TEXT DEFAULT '{}',
  enable INTEGER DEFAULT 1
);

-- Routing rules (send matching traffic from inbounds through an outbound)
CREATE TABLE IF NOT EXISTS routing_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  enable INTEGER DEFAULT 1,
  remark TEXT,
  inbound_tags TEXT DEFAULT '[]',
  outbound_tag TEXT DEFAULT 'direct',
  domain TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  port TEXT DEFAULT '',
  protocol TEXT DEFAULT '',
  type TEXT DEFAULT 'field'
);

-- Nodes (relay servers)
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  address TEXT,
  port INTEGER,
  api_port INTEGER DEFAULT 62789,
  remark TEXT,
  enable INTEGER DEFAULT 1,
  type TEXT DEFAULT 'xray'
);

-- Xray config (single row)
CREATE TABLE IF NOT EXISTS xray_config (
  id INTEGER PRIMARY KEY,
  config TEXT DEFAULT '{}'
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_clients_uuid ON clients(uuid);
CREATE INDEX IF NOT EXISTS idx_clients_inbound ON clients(inbound_id);
CREATE INDEX IF NOT EXISTS idx_clients_email ON clients(email);
CREATE INDEX IF NOT EXISTS idx_inbounds_tag ON inbounds(tag);

-- Default outbounds
INSERT OR IGNORE INTO outbounds (tag, remark, protocol, settings) VALUES
  ('direct', 'Direct', 'freedom', '{"domainStrategy":"AsIs"}'),
  ('block', 'Block', 'blackhole', '{"response":{"type":"none"}}');

-- Default settings
INSERT OR IGNORE INTO settings (key, value) VALUES
  ('proxy_ip', 'proxyip.cmliussss.net'),
  ('theme', 'dark'),
  ('panel_version', '3.0.0');
