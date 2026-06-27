// db.js - admins + database service
var ADMINS = [];
async function loadAdmins(env) {
  try {
    const result = await env.VL_DB.prepare("SELECT * FROM admins").all();
    ADMINS = result.results || [];
  } catch (e) {
    await env.VL_DB.prepare(`
      CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `).run();
    ADMINS = [];
  }
}

var schemaEnsured = false;
var cachedPanelPassword = null;
var DbService = {
  async ensureSchema(db) {
    if (schemaEnsured) return;
    try {
      await db.prepare(`
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
        )
      `).run();
    } catch (e) {}
    try {
      await db.prepare("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1").run();
    } catch (e) {}
    try {
      await db.prepare("ALTER TABLE users ADD COLUMN last_active INTEGER").run();
    } catch (e) {}
    try {
      await db.prepare("ALTER TABLE users ADD COLUMN fingerprint TEXT DEFAULT 'chrome'").run();
    } catch (e) {}
    try {
      await db.prepare("ALTER TABLE users ADD COLUMN config_name TEXT").run();
    } catch (e) {}
    try {
      await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run();
    } catch (e) {}
    try {
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS admins (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          password_hash TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
    } catch (e) {}
    // ===== FIRE: inbounds / outbounds / routing / nodes =====
    try { await db.prepare("CREATE TABLE IF NOT EXISTS inbounds (id INTEGER PRIMARY KEY AUTOINCREMENT, remark TEXT, enable INTEGER DEFAULT 1, protocol TEXT DEFAULT 'vless', listen TEXT DEFAULT '', port INTEGER, network TEXT DEFAULT 'ws', security TEXT DEFAULT 'tls', path TEXT DEFAULT '/', host TEXT DEFAULT '', uuid TEXT, up INTEGER DEFAULT 0, down INTEGER DEFAULT 0, total INTEGER DEFAULT 0, expiry_time INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)").run(); } catch (e) {}
    try { await db.prepare("CREATE TABLE IF NOT EXISTS outbounds (id INTEGER PRIMARY KEY AUTOINCREMENT, tag TEXT UNIQUE, remark TEXT, protocol TEXT DEFAULT 'freedom', address TEXT DEFAULT '', port INTEGER DEFAULT 0, auth TEXT DEFAULT '', enable INTEGER DEFAULT 1)").run(); } catch (e) {}
    try { await db.prepare("CREATE TABLE IF NOT EXISTS routing_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, enable INTEGER DEFAULT 1, remark TEXT, inbound_tag TEXT DEFAULT '', outbound_tag TEXT DEFAULT 'direct', domain TEXT DEFAULT '', ip TEXT DEFAULT '', port TEXT DEFAULT '')").run(); } catch (e) {}
    try { await db.prepare("CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, address TEXT, port INTEGER, api_port INTEGER DEFAULT 62789, remark TEXT, type TEXT DEFAULT 'xray', enable INTEGER DEFAULT 1)").run(); } catch (e) {}
    try {
      const c = await db.prepare("SELECT COUNT(*) as n FROM outbounds").first();
      if (!c || c.n === 0) {
        await db.prepare("INSERT INTO outbounds (tag, remark, protocol) VALUES ('direct','Direct','freedom')").run();
        await db.prepare("INSERT INTO outbounds (tag, remark, protocol) VALUES ('block','Block','blackhole')").run();
      }
    } catch (e) {}
    schemaEnsured = true;
  },
  async getPanelPassword(db) {
    if (cachedPanelPassword !== null) return cachedPanelPassword;
    try {
      const row = await db.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
      cachedPanelPassword = row ? row.value : "";
      return cachedPanelPassword || null;
    } catch (e) {
      return null;
    }
  },
  async setPanelPassword(db, password) {
    await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_password', ?)").bind(password).run();
    cachedPanelPassword = password;
  },
  async verifyApiAuth(request, env) {
    const cookies = request.headers.get("Cookie") || "";
    const sessionCookie = cookies.split(";").find((c) => c.trim().startsWith("panel_session="));
    if (!sessionCookie) return false;
    const sessionToken = sessionCookie.split("=")[1].trim();
    
    // Check if it's an admin ID
    await loadAdmins(env);
    const admin = ADMINS.find(a => String(a.id) === sessionToken);
    if (admin) return true;
    
    // Check if it's the panel password
    const storedHash = await this.getPanelPassword(env.VL_DB);
    if (storedHash && sessionToken === storedHash) return true;
    
    return false;
  },
  async sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }
};

export { ADMINS, loadAdmins, DbService };
