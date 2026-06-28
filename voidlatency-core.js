// ============================================
// VOIDLATENCY PANEL v3.4.1 - CPU OPTIMIZED
// ============================================
import { connect } from "cloudflare:sockets";

// ============================================
// CONSTANTS
// ============================================
var GLOBAL_TRAFFIC_CACHE = new Map();
var ACTIVE_CONNECTIONS_COUNT = new Map();
var GLOBAL_LAST_ACTIVE_WRITE = new Map();
var DNS_CACHE = new Map();
var DNS_CACHE_TTL = 5 * 60 * 1000;
var DOH_RESOLVER = "https://cloudflare-dns.com/dns-query";
var UPSTREAM_BUNDLE_TARGET_BYTES = 16 * 1024;
var UPSTREAM_QUEUE_MAX_BYTES = 16 * 1024 * 1024;
var UPSTREAM_QUEUE_MAX_ITEMS = 4096;
var DOWNSTREAM_GRAIN_BYTES = 32 * 1024;
var DOWNSTREAM_GRAIN_TAIL_THRESHOLD = 512;
var DOWNSTREAM_GRAIN_SILENT_MS = 1;
var TCP_CONCURRENCY = 2;
var PRELOAD_RACE_DIAL = true;
var xrayStatus = { running: true, startTime: Date.now() };
var PANEL_VERSION = "3.4.1";
var THEME = "dark";

// ============================================
// CACHED DATA - Loaded on demand
// ============================================
var ADMINS = [];
var INBOUNDS = [];
var OUTBOUNDS = [];
var ROUTING_RULES = [];
var NODES = [];
var CLEAN_IPS = [];
var CUSTOM_DOMAIN = "";
var API_TOKEN = null;
var API_TOKEN_EXPIRES = null;
var TOTAL_TRAFFIC_SENT = 0;
var TOTAL_TRAFFIC_RECEIVED = 0;
var CONNECTION_STATS = { tcp: 180, udp: 5 };
var SYSTEM_STATS = {
  cpu: { cores: 2, load: [0.47, 0.17, 0.05] },
  ram: { used: 1152.3, total: 3940 },
  swap: { used: 0, total: 0 },
  storage: { used: 7.66, total: 26.65 }
};
var cachedPanelPassword = null;
var schemaEnsured = false;

// ============================================
// MAIN APPLICATION
// ============================================
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      
      // ============================================
      // STATIC ROUTES - No DB needed
      // ============================================
      if (path === "/" || path === "/panel" || path === "/login") {
        return await handlePanelRequest(request, env);
      }
      
      // ============================================
      // API ROUTES - With DB
      // ============================================
      if (path.startsWith("/api/")) {
        return await handleApiRequest(request, env, ctx);
      }
      
      // ============================================
      // SUBSCRIPTION
      // ============================================
      if (path.startsWith("/sub/") || path.startsWith("/feed/")) {
        return await handleSubscription(request, env);
      }
      
      // ============================================
      // STATUS
      // ============================================
      if (path.startsWith("/status/")) {
        return await handleUserStatus(request, env);
      }
      
      // ============================================
      // WEBSOCKET - VLESS
      // ============================================
      const upgrade = (request.headers.get("Upgrade") || "").toLowerCase();
      if (upgrade === "websocket") {
        return await handleVLESS(env, ctx);
      }
      
      return new Response(HTML_TEMPLATES.nginx, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
      
    } catch (e) {
      return new Response("Error: " + e.message, { status: 500 });
    }
  }
};

// ============================================
// HANDLE PANEL (No DB on first load)
// ============================================
async function handlePanelRequest(request, env) {
  const hasPassword = await getPanelPassword(env);
  
  if (!hasPassword) {
    return new Response(HTML_TEMPLATES.setup, {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
  
  const auth = await verifyAuth(request, env);
  if (!auth) {
    return new Response(HTML_TEMPLATES.login, {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
  
  return new Response(HTML_TEMPLATES.panel, {
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}

// ============================================
// DATABASE HELPERS
// ============================================
async function getPanelPassword(env) {
  if (cachedPanelPassword !== null) return cachedPanelPassword;
  try {
    await ensureSchema(env);
    const row = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
    cachedPanelPassword = row ? row.value : "";
    return cachedPanelPassword || null;
  } catch (e) {
    return null;
  }
}

async function ensureSchema(env) {
  if (schemaEnsured) return true;
  try {
    // Create all tables with IF NOT EXISTS
    await env.VL_DB.prepare(`
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
      )
    `).run();
    
    await env.VL_DB.prepare(`
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
      )
    `).run();
    
    await env.VL_DB.prepare(`
      CREATE TABLE IF NOT EXISTS outbounds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        protocol TEXT,
        settings TEXT,
        tag TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `).run();
    
    await env.VL_DB.prepare(`
      CREATE TABLE IF NOT EXISTS routing_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        inbound_tag TEXT,
        outbound_tag TEXT,
        domain TEXT,
        ip TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `).run();
    
    await env.VL_DB.prepare(`
      CREATE TABLE IF NOT EXISTS nodes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        address TEXT,
        port INTEGER,
        api_key TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `).run();
    
    await env.VL_DB.prepare(`
      CREATE TABLE IF NOT EXISTS clean_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `).run();
    
    await env.VL_DB.prepare(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `).run();
    
    await env.VL_DB.prepare(`
      CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        role TEXT DEFAULT 'admin'
      )
    `).run();
    
    await env.VL_DB.prepare(`
      CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        bytes INTEGER,
        direction TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `).run();
    
    await env.VL_DB.prepare(`
      CREATE TABLE IF NOT EXISTS system_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT,
        message TEXT,
        data TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `).run();
    
    // Default settings
    await env.VL_DB.prepare(`
      INSERT OR IGNORE INTO settings (key, value) VALUES 
        ('panel_version', '3.4.1'),
        ('theme', 'dark'),
        ('proxy_ip', 'proxyip.cmliussss.net'),
        ('frag_len', '20-30'),
        ('frag_int', '1-2')
    `).run();
    
    // Default outbounds
    await env.VL_DB.prepare(`
      INSERT OR IGNORE INTO outbounds (name, protocol, settings, tag, is_active) VALUES 
        ('Direct', 'freedom', '{"domainStrategy":"AsIs"}', 'direct', 1),
        ('Block', 'blackhole', '{"response":{"type":"none"}}', 'block', 1)
    `).run();
    
    schemaEnsured = true;
    return true;
  } catch (e) {
    return false;
  }
}

async function verifyAuth(request, env) {
  const cookies = request.headers.get("Cookie") || "";
  const session = cookies.split(";").find(c => c.trim().startsWith("panel_session="));
  if (!session) return false;
  
  const token = session.split("=")[1].trim();
  const stored = await getPanelPassword(env);
  if (stored && token === stored) return true;
  
  // Check admin table
  try {
    await ensureSchema(env);
    const admin = await env.VL_DB.prepare("SELECT * FROM admins WHERE id = ?").bind(parseInt(token) || 0).first();
    if (admin) return true;
  } catch (e) {}
  
  return false;
}

async function sha256(message) {
  const buf = new TextEncoder().encode(message);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ============================================
// API HANDLER
// ============================================
async function handleApiRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  
  // Ensure schema exists for all API requests
  await ensureSchema(env);
  
  // ============================================
  // SETUP PASSWORD
  // ============================================
  if (path === "/api/setup-password" && method === "POST") {
    const hasPassword = await getPanelPassword(env);
    if (hasPassword) {
      return json({ error: "Password already set" }, 400);
    }
    const { password } = await request.json();
    if (!password || password.length < 4) {
      return json({ error: "Password must be at least 4 characters" }, 400);
    }
    const hashed = await sha256(password);
    await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_password', ?)").bind(hashed).run();
    cachedPanelPassword = hashed;
    return json({ success: true }, 200, {
      "Set-Cookie": "panel_session=" + hashed + "; Path=/; HttpOnly; Secure; SameSite=Lax"
    });
  }
  
  // ============================================
  // LOGIN
  // ============================================
  if (path === "/api/login" && method === "POST") {
    const { username, password } = await request.json();
    
    // Check admin table first
    if (username && password) {
      const admin = await env.VL_DB.prepare("SELECT * FROM admins WHERE username = ?").bind(username).first();
      if (admin) {
        const hashed = await sha256(password);
        if (admin.password_hash === hashed) {
          await env.VL_DB.prepare("UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE id = ?").bind(admin.id).run();
          return json({ success: true, role: "admin" }, 200, {
            "Set-Cookie": "panel_session=" + admin.id + "; Path=/; HttpOnly; Secure; SameSite=Lax"
          });
        }
      }
    }
    
    // Check panel password
    if (password) {
      const hashedInput = await sha256(password);
      const stored = await getPanelPassword(env);
      if (stored === hashedInput) {
        return json({ success: true }, 200, {
          "Set-Cookie": "panel_session=" + stored + "; Path=/; HttpOnly; Secure; SameSite=Lax"
        });
      }
    }
    
    return json({ error: "Invalid credentials" }, 401);
  }
  
  // ============================================
  // LOGOUT
  // ============================================
  if (path === "/api/logout" && method === "POST") {
    return json({ success: true }, 200, {
      "Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax"
    });
  }
  
  // ============================================
  // AUTH VERIFY
  // ============================================
  if (path === "/api/auth/verify" && method === "GET") {
    const auth = await verifyAuth(request, env);
    const hasPassword = await getPanelPassword(env);
    return json({ 
      authenticated: auth,
      needs_setup: !hasPassword
    });
  }
  
  // ============================================
  // AUTH CHECK
  // ============================================
  const auth = await verifyAuth(request, env);
  if (!auth) {
    return json({ error: "Unauthorized" }, 401);
  }
  
  // ============================================
  // CHANGE PASSWORD
  // ============================================
  if (path === "/api/change-password" && method === "POST") {
    const { current_password, new_password } = await request.json();
    if (!current_password || !new_password) {
      return json({ error: "Current and new password required" }, 400);
    }
    const currentHash = await sha256(current_password);
    const stored = await getPanelPassword(env);
    if (stored && stored !== currentHash) {
      return json({ error: "Current password is incorrect" }, 401);
    }
    if (new_password.length < 4) {
      return json({ error: "Password must be at least 4 characters" }, 400);
    }
    const newHash = await sha256(new_password);
    await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_password', ?)").bind(newHash).run();
    cachedPanelPassword = newHash;
    return json({ success: true }, 200, {
      "Set-Cookie": "panel_session=" + newHash + "; Path=/; HttpOnly; Secure; SameSite=Lax"
    });
  }
  
  // ============================================
  // THEME
  // ============================================
  if (path === "/api/theme" && method === "GET") {
    try {
      const row = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'theme'").first();
      return json({ theme: row ? row.value : "dark" });
    } catch (e) {
      return json({ theme: "dark" });
    }
  }
  
  if (path === "/api/theme" && method === "POST") {
    const { theme } = await request.json();
    if (theme === "dark" || theme === "light") {
      await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('theme', ?)").bind(theme).run();
      THEME = theme;
      return json({ success: true, theme });
    }
    return json({ error: "Invalid theme" }, 400);
  }
  
  // ============================================
  // XRAY STATUS
  // ============================================
  if (path === "/api/xray/status" && method === "GET") {
    const uptime = xrayStatus.running ? Math.floor((Date.now() - xrayStatus.startTime) / 1000) : 0;
    return json({
      running: xrayStatus.running,
      uptime: uptime,
      version: "v26.4.25",
      memory: "56.93 MB",
      threads: 1
    });
  }
  
  if (path === "/api/xray" && method === "POST") {
    const { action } = await request.json();
    if (action === "stop") { xrayStatus.running = false; return json({ success: true, status: "stopped" }); }
    if (action === "start") { xrayStatus.running = true; xrayStatus.startTime = Date.now(); return json({ success: true, status: "started" }); }
    if (action === "restart") { xrayStatus.running = true; xrayStatus.startTime = Date.now(); return json({ success: true, status: "restarted" }); }
    return json({ error: "Invalid action" }, 400);
  }
  
  // ============================================
  // SYSTEM STATS
  // ============================================
  if (path === "/api/system/stats" && method === "GET") {
    const uptime = xrayStatus.running ? Math.floor((Date.now() - xrayStatus.startTime) / 1000) : 0;
    return json({
      cpu: SYSTEM_STATS.cpu,
      ram: SYSTEM_STATS.ram,
      swap: SYSTEM_STATS.swap,
      storage: SYSTEM_STATS.storage,
      xray_uptime: uptime,
      version: PANEL_VERSION,
      theme: THEME
    });
  }
  
  // ============================================
  // USERS CRUD
  // ============================================
  if (path === "/api/users" && method === "GET") {
    const { results } = await env.VL_DB.prepare("SELECT * FROM users ORDER BY id DESC").all();
    const now = Date.now();
    const users = (results || []).map(u => ({
      ...u,
      is_online: u.last_active && now - u.last_active < 65000 ? 1 : 0
    }));
    return json({ users, serverTime: now });
  }
  
  if (path === "/api/users" && method === "POST") {
    const { username, limit_gb, expiry_days, ips, tls, port, fingerprint, config_name, inbound_id } = await request.json();
    if (!username) return json({ error: "Username required" }, 400);
    const uuid = crypto.randomUUID();
    try {
      await env.VL_DB.prepare(
        "INSERT INTO users (username, uuid, limit_gb, expiry_days, ips, connection_type, tls, port, fingerprint, config_name, inbound_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      ).bind(
        username, uuid,
        limit_gb ? parseFloat(limit_gb) : null,
        expiry_days ? parseInt(expiry_days) : null,
        ips || null, "vless", tls || "none",
        port || "443", fingerprint || "chrome",
        config_name || username, inbound_id || 0
      ).run();
      return json({ success: true });
    } catch (e) {
      return json({ error: e.message.includes("UNIQUE") ? "Username already exists" : e.message }, 500);
    }
  }
  
  // ============================================
  // USER CRUD
  // ============================================
  if (path.startsWith("/api/users/") && method === "PUT") {
    const username = decodeURIComponent(path.split("/").pop());
    const body = await request.json();
    if (body.toggle_only !== undefined) {
      await env.VL_DB.prepare("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE username = ?").bind(username).run();
      return json({ success: true });
    }
    const { limit_gb, expiry_days, ips, tls, port, fingerprint, config_name } = body;
    await env.VL_DB.prepare(
      "UPDATE users SET limit_gb = ?, expiry_days = ?, ips = ?, tls = ?, port = ?, fingerprint = ?, config_name = ? WHERE username = ?"
    ).bind(
      limit_gb ? parseFloat(limit_gb) : null,
      expiry_days ? parseInt(expiry_days) : null,
      ips || null, tls || null, port || "443",
      fingerprint || "chrome", config_name || username, username
    ).run();
    return json({ success: true });
  }
  
  if (path.startsWith("/api/users/") && method === "DELETE") {
    const username = decodeURIComponent(path.split("/").pop());
    await env.VL_DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
    GLOBAL_TRAFFIC_CACHE.delete(username);
    return json({ success: true });
  }
  
  // ============================================
  // INBOUNDS CRUD
  // ============================================
  if (path === "/api/inbounds" && method === "GET") {
    const { results } = await env.VL_DB.prepare("SELECT * FROM inbounds ORDER BY id DESC").all();
    INBOUNDS = results || [];
    return json({ success: true, inbounds: INBOUNDS });
  }
  
  if (path === "/api/inbounds" && method === "POST") {
    const { name, protocol, port, path, host, limit_gb, expiry_days, max_ips, outbound_tag } = await request.json();
    if (!name) return json({ error: "Name required" }, 400);
    const uuid = crypto.randomUUID();
    await env.VL_DB.prepare(
      "INSERT INTO inbounds (name, uuid, protocol, port, path, host, limit_gb, expiry_days, max_ips, outbound_tag) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      name, uuid, protocol || "vless", port || 443,
      path || "/", host || "",
      limit_gb ? parseFloat(limit_gb) : null,
      expiry_days ? parseInt(expiry_days) : null,
      max_ips ? parseInt(max_ips) : 0,
      outbound_tag || ""
    ).run();
    return json({ success: true });
  }
  
  if (path.startsWith("/api/inbounds/") && method === "DELETE") {
    const id = parseInt(path.split("/").pop());
    if (isNaN(id)) return json({ error: "Invalid ID" }, 400);
    await env.VL_DB.prepare("DELETE FROM inbounds WHERE id = ?").bind(id).run();
    await env.VL_DB.prepare("DELETE FROM users WHERE inbound_id = ?").bind(id).run();
    return json({ success: true });
  }
  
  // ============================================
  // INBOUND USERS
  // ============================================
  if (path.includes("/users") && path.startsWith("/api/inbounds/")) {
    const parts = path.split("/");
    const inboundId = parseInt(parts[3]);
    if (isNaN(inboundId)) return json({ error: "Invalid inbound ID" }, 400);
    
    if (method === "GET") {
      const { results } = await env.VL_DB.prepare("SELECT * FROM users WHERE inbound_id = ? ORDER BY id DESC").bind(inboundId).all();
      return json({ success: true, users: results || [] });
    }
    
    if (method === "POST") {
      const { username, limit_gb, expiry_days, ips, port, fingerprint, config_name } = await request.json();
      if (!username) return json({ error: "Username required" }, 400);
      const uuid = crypto.randomUUID();
      await env.VL_DB.prepare(
        "INSERT INTO users (username, uuid, limit_gb, expiry_days, ips, connection_type, tls, port, fingerprint, config_name, inbound_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      ).bind(
        username, uuid,
        limit_gb ? parseFloat(limit_gb) : null,
        expiry_days ? parseInt(expiry_days) : null,
        ips || null, "vless", "tls",
        port || "443", fingerprint || "chrome",
        config_name || username, inboundId
      ).run();
      return json({ success: true });
    }
  }
  
  // ============================================
  // CLEAN IPS
  // ============================================
  if (path === "/api/clean-ips" && method === "GET") {
    const { results } = await env.VL_DB.prepare("SELECT * FROM clean_ips ORDER BY id DESC").all();
    return json({ success: true, ips: results || [] });
  }
  
  if (path === "/api/clean-ips" && method === "POST") {
    const { address } = await request.json();
    if (!address) return json({ error: "Address required" }, 400);
    await env.VL_DB.prepare("INSERT INTO clean_ips (address) VALUES (?)").bind(address).run();
    return json({ success: true });
  }
  
  if (path.startsWith("/api/clean-ips/") && method === "DELETE") {
    const id = parseInt(path.split("/").pop());
    if (isNaN(id)) return json({ error: "Invalid ID" }, 400);
    await env.VL_DB.prepare("DELETE FROM clean_ips WHERE id = ?").bind(id).run();
    return json({ success: true });
  }
  
  // ============================================
  // CUSTOM DOMAIN
  // ============================================
  if (path === "/api/custom-domain" && method === "GET") {
    const row = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'custom_domain'").first();
    return json({ success: true, domain: row ? row.value : "" });
  }
  
  if (path === "/api/custom-domain" && method === "POST") {
    const { domain } = await request.json();
    if (domain) {
      await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('custom_domain', ?)").bind(domain).run();
    } else {
      await env.VL_DB.prepare("DELETE FROM settings WHERE key = 'custom_domain'").run();
    }
    return json({ success: true });
  }
  
  // ============================================
  // UPDATE CHECK
  // ============================================
  if (path === "/api/update-check" && method === "GET") {
    try {
      const resp = await fetch("https://api.github.com/repos/Void0Latency/panelv3/releases/latest", {
        headers: { "User-Agent": "VoidLatency" }
      });
      if (resp.ok) {
        const data = await resp.json();
        return json({
          current_version: "v" + PANEL_VERSION,
          latest_version: data.tag_name || data.name || "v3.4.1",
          update_available: true,
          url: data.html_url,
          body: data.body
        });
      }
    } catch (e) {}
    return json({ current_version: "v" + PANEL_VERSION, update_available: false });
  }
  
  return json({ error: "Not Found" }, 404);
}

// ============================================
// SUBSCRIPTION HANDLER
// ============================================
async function handleSubscription(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const host = url.hostname;
  
  await ensureSchema(env);
  
  let ident = "";
  let isJson = false;
  
  if (path.startsWith("/feed/json/")) {
    ident = decodeURIComponent(path.slice(10));
    isJson = true;
  } else if (path.startsWith("/feed/")) {
    ident = decodeURIComponent(path.slice(6));
    isJson = true;
  } else if (path.startsWith("/sub/")) {
    ident = decodeURIComponent(path.slice(5));
    isJson = false;
  } else {
    return new Response("Not Found", { status: 404 });
  }
  
  try {
    const user = await env.VL_DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(ident, ident).first();
    if (!user || user.is_active === 0) {
      return new Response("Not Found", { status: 404 });
    }
    
    const ips = [host];
    if (user.ips) {
      const parsed = user.ips.split("\n").map(s => s.trim()).filter(Boolean);
      if (parsed.length) ips.push(...parsed);
    }
    
    // Get clean IPs
    const { results } = await env.VL_DB.prepare("SELECT address FROM clean_ips").all();
    for (const row of (results || [])) {
      if (row.address && !ips.includes(row.address)) ips.push(row.address);
    }
    
    const port = user.port || "443";
    const fp = user.fingerprint || "chrome";
    const uuid = user.uuid;
    const name = user.config_name || user.username;
    
    // Get frag settings
    let fragLen = "20-30";
    let fragInt = "1-2";
    const lenRow = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'frag_len'").first();
    if (lenRow) fragLen = lenRow.value;
    const intRow = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'frag_int'").first();
    if (intRow) fragInt = intRow.value;
    
    // Get custom domain
    const domainRow = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'custom_domain'").first();
    const finalHost = domainRow ? domainRow.value : host;
    
    const isTls = ["443", "2053", "2083", "2087", "2096", "8443"].includes(port);
    const tls = isTls ? "tls" : "none";
    
    const links = ips.map(ip => {
      const base = "vless://" + uuid + "@" + ip + ":" + port;
      const params = "path=%2F&security=" + tls + "&encryption=none&insecure=0&host=" + finalHost + "&fp=" + fp + "&type=ws&allowInsecure=0&sni=" + finalHost;
      return base + "?" + params + "#" + encodeURIComponent(name);
    });
    
    if (isJson) {
      return new Response(JSON.stringify({ 
        remarks: name, 
        links: links,
        uuid: uuid,
        version: "3.4.1"
      }, null, 2), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    
    const content = btoa(unescape(encodeURIComponent(links.join("\n"))));
    return new Response(content, {
      headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
    
  } catch (e) {
    return new Response("Error: " + e.message, { status: 500 });
  }
}

// ============================================
// USER STATUS
// ============================================
async function handleUserStatus(request, env) {
  const url = new URL(request.url);
  const ident = decodeURIComponent(url.pathname.slice(8));
  if (!ident) return new Response("Username required", { status: 400 });
  
  await ensureSchema(env);
  
  try {
    const user = await env.VL_DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(ident, ident).first();
    if (!user) return new Response("User not found", { status: 404 });
    
    const html = HTML_TEMPLATES.status.replace(
      "/*{{DATA}}*/",
      "window.statusUser=" + JSON.stringify({
        username: user.username,
        uuid: user.uuid,
        limit_gb: user.limit_gb,
        expiry_days: user.expiry_days,
        used_gb: user.used_gb,
        is_active: user.is_active,
        created_at: user.created_at,
        port: user.port,
        fingerprint: user.fingerprint || "chrome",
        config_name: user.config_name || user.username
      }) + ";"
    );
    
    return new Response(html, {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  } catch (e) {
    return new Response("Error: " + e.message, { status: 500 });
  }
}

// ============================================
// VLESS HANDLER
// ============================================
async function handleVLESS(env, ctx) {
  try {
    const socketPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(socketPair);
    serverSock.accept();
    serverSock.binaryType = "arraybuffer";
    
    let username = null;
    let validUUID = null;
    let chunkBuffer = new Uint8Array(0);
    let isHeaderParsed = false;
    let remoteConn = null;
    let writer = null;
    
    // Get proxy IP
    let proxyIP = "proxyip.cmliussss.net";
    try {
      const row = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
      if (row) proxyIP = row.value;
    } catch (e) {}
    
    // Traffic tracking
    function addTraffic(bytes) {
      if (!username || bytes <= 0) return;
      let current = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
      current += bytes;
      GLOBAL_TRAFFIC_CACHE.set(username, current);
      GLOBAL_LAST_ACTIVE_WRITE.set(username, Date.now());
      
      // Flush if over 50MB
      if (current >= 50 * 1024 * 1024) {
        const toCommit = Math.floor(current / (50 * 1024 * 1024)) * 50 * 1024 * 1024;
        const leftover = current - toCommit;
        GLOBAL_TRAFFIC_CACHE.set(username, leftover);
        const deltaGb = toCommit / (1024 * 1024 * 1024);
        ctx.waitUntil(env.VL_DB.prepare("UPDATE users SET used_gb = used_gb + ? WHERE username = ?").bind(deltaGb, username).run());
      }
    }
    
    // Connection cleanup
    const cleanup = () => {
      if (username) {
        let count = ACTIVE_CONNECTIONS_COUNT.get(username) || 1;
        count -= 1;
        if (count <= 0) {
          ACTIVE_CONNECTIONS_COUNT.delete(username);
          const cached = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
          if (cached > 0) {
            GLOBAL_TRAFFIC_CACHE.set(username, 0);
            ctx.waitUntil(env.VL_DB.prepare("UPDATE users SET used_gb = used_gb + ? WHERE username = ?").bind(cached / (1024 * 1024 * 1024), username).run());
          }
        } else {
          ACTIVE_CONNECTIONS_COUNT.set(username, count);
        }
      }
      try { remoteConn?.close(); } catch (e) {}
      try { closeSocket(serverSock); } catch (e) {}
    };
    
    // Message handler
    serverSock.addEventListener("message", async (event) => {
      if (!isHeaderParsed) {
        chunkBuffer = concat(chunkBuffer, event.data);
        if (chunkBuffer.byteLength < 24) return;
        
        validUUID = extractUUID(chunkBuffer);
        if (!validUUID) { closeSocket(serverSock); return; }
        
        try {
          const user = await env.VL_DB.prepare("SELECT * FROM users WHERE uuid = ? AND is_active = 1").bind(validUUID).first();
          if (!user) { closeSocket(serverSock); return; }
          
          // Check expiry
          if (user.expiry_days && user.created_at) {
            const created = new Date(user.created_at);
            const expiry = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
            if (new Date() > expiry) {
              await env.VL_DB.prepare("UPDATE users SET is_active = 0 WHERE uuid = ?").bind(validUUID).run();
              closeSocket(serverSock);
              return;
            }
          }
          
          // Check limit
          if (user.limit_gb && user.used_gb >= user.limit_gb) {
            await env.VL_DB.prepare("UPDATE users SET is_active = 0 WHERE uuid = ?").bind(validUUID).run();
            closeSocket(serverSock);
            return;
          }
          
          username = user.username;
          isHeaderParsed = true;
          ACTIVE_CONNECTIONS_COUNT.set(username, (ACTIVE_CONNECTIONS_COUNT.get(username) || 0) + 1);
          ctx.waitUntil(env.VL_DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(Date.now(), username).run());
          
          // Parse VLESS header
          let offset = 17;
          const optLen = chunkBuffer[offset++];
          offset += optLen;
          const cmd = chunkBuffer[offset++];
          const port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
          const addrType = chunkBuffer[offset++];
          
          let addr = "";
          if (addrType === 1) {
            addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
          } else if (addrType === 2) {
            const len = chunkBuffer[offset++];
            addr = new TextDecoder().decode(chunkBuffer.slice(offset, offset + len));
            offset += len;
          } else {
            offset += 16;
            addr = "unknown";
          }
          
          const data = chunkBuffer.slice(offset);
          const header = new Uint8Array([chunkBuffer[0], 0]);
          
          if (cmd === 2 && port === 53) {
            // DNS over TCP
            try {
              const dns = connect({ hostname: "8.8.8.8", port: 53 });
              const w = dns.writable.getWriter();
              await w.write(data);
              w.releaseLock();
              const reader = dns.readable.getReader();
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                const merged = new Uint8Array(header.length + value.byteLength);
                merged.set(header, 0);
                merged.set(value, header.length);
                serverSock.send(merged);
              }
            } catch (e) {}
            return;
          }
          
          // Connect to target
          const connectTarget = async () => {
            try {
              remoteConn = connect({ hostname: addr, port: port });
              await Promise.race([remoteConn.opened, new Promise((_, r) => setTimeout(r, 3000))]);
              
              if (data.byteLength > 0) {
                writer = remoteConn.writable.getWriter();
                await writer.write(data);
                writer.releaseLock();
              }
              
              // Pipe from remote to client
              const remoteReader = remoteConn.readable.getReader();
              const sender = createSender(serverSock, header);
              
              while (true) {
                const { done, value } = await remoteReader.read();
                if (done) break;
                if (value && value.byteLength > 0) {
                  addTraffic(value.byteLength);
                  await sender.send(value);
                }
              }
            } catch (e) {
              // Fallback to proxy
              try {
                remoteConn = connect({ hostname: proxyIP, port: port });
                await Promise.race([remoteConn.opened, new Promise((_, r) => setTimeout(r, 3000))]);
                const w = remoteConn.writable.getWriter();
                await w.write(data);
                w.releaseLock();
              } catch (e2) {
                closeSocket(serverSock);
              }
            }
          };
          
          await connectTarget();
          
        } catch (e) {
          closeSocket(serverSock);
        }
      } else {
        // Write to remote
        if (remoteConn && event.data.byteLength > 0) {
          try {
            const w = remoteConn.writable.getWriter();
            await w.write(convertToUint8Array(event.data));
            w.releaseLock();
          } catch (e) {}
        }
      }
    });
    
    serverSock.addEventListener("close", cleanup);
    serverSock.addEventListener("error", cleanup);
    
    return new Response(null, { status: 101, webSocket: clientSock });
    
  } catch (e) {
    return new Response("WebSocket Error", { status: 500 });
  }
}

// ============================================
// HELPERS
// ============================================
function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...extra }
  });
}

function closeSocket(socket) {
  try { socket.close(); } catch (e) {}
}

function concat(a, b) {
  const aBuf = convertToUint8Array(a);
  const bBuf = convertToUint8Array(b);
  const result = new Uint8Array(aBuf.byteLength + bBuf.byteLength);
  result.set(aBuf, 0);
  result.set(bBuf, aBuf.byteLength);
  return result;
}

function convertToUint8Array(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(data || 0);
}

function extractUUID(data) {
  if (data.byteLength < 17) return null;
  const hex = [...data.slice(1, 17)].map(b => b.toString(16).padStart(2, "0")).join("");
  return hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-" + hex.substring(12, 16) + "-" + hex.substring(16, 20) + "-" + hex.substring(20);
}

function createSender(socket, header) {
  let hasHeader = true;
  return {
    send: async function(data) {
      if (socket.readyState !== WebSocket.OPEN) return;
      const chunk = convertToUint8Array(data);
      if (hasHeader && header) {
        const merged = new Uint8Array(header.length + chunk.byteLength);
        merged.set(header, 0);
        merged.set(chunk, header.length);
        socket.send(merged);
        hasHeader = false;
      } else {
        socket.send(chunk);
      }
    }
  };
}

// ============================================
// HTML TEMPLATES - COMPLETE
// ============================================
var HTML_TEMPLATES = {
  nginx: `<!DOCTYPE html>
<html class="dark"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VoidLatency</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<style>*{font-family:'Inter',sans-serif}body{background:#0a0a0f}.glass{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)}.gradient-text{background:linear-gradient(135deg,#818cf8,#a78bfa,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}</style>
</head><body class="min-h-screen flex items-center justify-center p-4"><div class="max-w-md w-full glass rounded-2xl p-8 text-center">
<div class="w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center mx-auto mb-4">
<svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg></div>
<h1 class="text-3xl font-black gradient-text mb-2">VoidLatency</h1>
<p class="text-zinc-400 text-sm">Next-Gen VPN Management</p>
<div class="mt-6"><a href="/panel" class="inline-block px-6 py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-semibold rounded-lg transition">Enter Dashboard</a></div>
<div class="mt-4 flex justify-center gap-4 text-xs text-zinc-500"><a href="https://github.com/Void0Latency/panelv3">GitHub</a><a href="https://t.me/VoidLatency">Telegram</a><span>@VoidLatency</span></div>
</div></body></html>`,

  setup: `<!DOCTYPE html>
<html class="dark"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Setup</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<style>*{font-family:'Inter',sans-serif}body{background:#0a0a0f}.glass{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)}input{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08)}input:focus{border-color:#818cf8;outline:none}</style>
</head><body class="min-h-screen flex items-center justify-center p-4"><div class="max-w-md w-full glass rounded-2xl p-8">
<h2 class="text-xl font-bold text-white text-center mb-4">Setup Password</h2>
<form onsubmit="handleSetup(event)" class="space-y-4">
<input type="password" id="password" placeholder="Enter password..." class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none" required minlength="4">
<input type="password" id="confirm" placeholder="Confirm password..." class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none" required minlength="4">
<button type="submit" id="btn" class="w-full py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-semibold rounded-xl transition text-sm">Create Account</button>
</form>
</div>
<script>async function handleSetup(e){e.preventDefault();const p=document.getElementById('password').value,c=document.getElementById('confirm').value;if(p!==c){alert('Passwords do not match');return}const b=document.getElementById('btn');b.disabled=true;b.textContent='Creating...';try{const r=await fetch('/api/setup-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});const d=await r.json();if(r.ok&&d.success){window.location.reload()}else{alert('Error: '+(d.error||'Failed'))}}catch(e){alert('Connection error')}b.disabled=false;b.textContent='Create Account'}<\/script>
</body></html>`,

  login: `<!DOCTYPE html>
<html class="dark"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<style>*{font-family:'Inter',sans-serif}body{background:#0a0a0f}.glass{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)}input{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08)}input:focus{border-color:#818cf8;outline:none}</style>
</head><body class="min-h-screen flex items-center justify-center p-4"><div class="max-w-md w-full glass rounded-2xl p-8">
<div class="text-center mb-6"><div class="w-12 h-12 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center mx-auto mb-3">
<svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"/></svg></div>
<h2 class="text-xl font-bold text-white">Welcome Back</h2></div>
<form onsubmit="handleLogin(event)" class="space-y-4">
<input type="text" id="username" placeholder="Username" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none" required>
<input type="password" id="password" placeholder="Password" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none" required>
<button type="submit" id="btn" class="w-full py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-semibold rounded-xl transition text-sm">Sign In</button>
</form>
</div>
<script>async function handleLogin(e){e.preventDefault();const u=document.getElementById('username').value,p=document.getElementById('password').value,b=document.getElementById('btn');b.disabled=true;b.textContent='Signing in...';try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});const d=await r.json();if(r.ok&&d.success){window.location.reload()}else{alert('Invalid credentials')}}catch(e){alert('Connection error')}b.disabled=false;b.textContent='Sign In'}<\/script>
</body></html>`,

  panel: `<!DOCTYPE html>
<html class="dark"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"><title>VoidLatency Panel</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"><\/script>
<style>*{font-family:'Inter',sans-serif}body{background:#0a0a0f;color:#e5e7eb}.glass{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)}.glass-light{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.06)}.sidebar{background:#0d0d18;border-right:1px solid rgba(255,255,255,.04)}.sidebar-link{padding:10px 16px;border-radius:12px;transition:all .2s;cursor:pointer}.sidebar-link:hover{background:rgba(255,255,255,.05);color:#fff}.sidebar-link.active{background:rgba(99,102,241,.12);color:#818cf8}.stat-card{transition:all .3s}.stat-card:hover{transform:translateY(-4px);border-color:rgba(99,102,241,.3)}input,select,textarea{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08)}input:focus,select:focus,textarea:focus{border-color:#818cf8;outline:none;box-shadow:0 0 0 3px rgba(99,102,241,.15)}.badge{padding:2px 10px;border-radius:6px;font-size:10px;font-weight:600}.badge-success{background:rgba(52,211,153,.15);color:#34d399}.badge-danger{background:rgba(239,68,68,.15);color:#ef4444}.badge-warning{background:rgba(251,191,36,.15);color:#fbbf24}.badge-info{background:rgba(96,165,250,.15);color:#60a5fa}.action-btn{padding:6px;border-radius:8px;transition:all .15s;cursor:pointer}.action-btn:hover{transform:scale(1.1);background:rgba(255,255,255,.05)}.system-stat{background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.04);border-radius:14px;padding:16px}.modal-overlay{background:rgba(0,0,0,.7);backdrop-filter:blur(8px)}.page-section{display:none}.page-section.active{display:block}.toggle{width:36px;height:20px;border-radius:12px;background:#2a3a5a;position:relative;cursor:pointer;transition:all .3s;border:2px solid transparent;flex-shrink:0}.toggle.on{background:#00a896}.toggle::after{content:'';width:14px;height:14px;border-radius:50%;background:#fff;position:absolute;top:1px;left:1px;transition:all .3s}.toggle.on::after{left:15px}@media(max-width:1023px){.sidebar{position:fixed;top:0;left:-100%;width:280px;height:100vh;background:#0d0d18;z-index:1000;transition:left .3s;overflow-y:auto}.sidebar.active{left:0}.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:999}.sidebar-overlay.active{display:block}.lg\\:ml-64{margin-left:0}.stats-grid{grid-template-columns:1fr 1fr!important}}</style>
</head>
<body>
<div id="overlay" class="sidebar-overlay" onclick="toggleSidebar()"></div>
<!-- Sidebar -->
<div class="fixed inset-y-0 left-0 w-64 sidebar z-50"><div class="p-6">
<div class="flex items-center gap-3 mb-8"><div class="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center"><svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg></div><span class="text-lg font-bold text-white">VoidLatency</span></div>
<div class="text-xs text-emerald-400 mb-4 flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>v3.4.1</div>
<nav class="space-y-1">
<a href="#" onclick="showPage('dashboard')" class="sidebar-link active flex items-center gap-3 text-sm font-medium text-indigo-400" data-page="dashboard"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>Overview</a>
<a href="#" onclick="showPage('inbounds')" class="sidebar-link flex items-center gap-3 text-sm font-medium text-zinc-400 hover:text-white transition" data-page="inbounds"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>Inbounds</a>
<a href="#" onclick="showPage('users')" class="sidebar-link flex items-center gap-3 text-sm font-medium text-zinc-400 hover:text-white transition" data-page="users"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg>Clients</a>
<a href="#" onclick="showPage('settings')" class="sidebar-link flex items-center gap-3 text-sm font-medium text-zinc-400 hover:text-white transition" data-page="settings"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>Settings</a>
<div class="border-t border-zinc-800/30 mt-4 pt-4"><a href="#" onclick="logout()" class="sidebar-link flex items-center gap-3 text-sm font-medium text-zinc-400 hover:text-red-400 transition"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>Log Out</a></div>
</nav>
<div class="absolute bottom-6 left-6 right-6"><div class="glass rounded-xl p-4"><div class="flex items-center gap-3"><div class="w-9 h-9 rounded-full bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center text-sm font-bold text-white">A</div><div><p class="text-sm font-semibold text-white">Admin</p><p class="text-xs text-emerald-400">● Online</p></div></div></div><div class="mt-3 flex justify-between text-xs text-zinc-500"><span>v3.4.1</span><span>@VoidLatency</span></div></div>
</div></div>

<!-- Main -->
<div class="lg:ml-64 min-h-screen">
<header class="bg-[#0a0a0f]/80 backdrop-blur-xl border-b border-zinc-800/30 px-4 py-3 sticky top-0 z-40 flex items-center justify-between">
<div class="flex items-center gap-3"><button onclick="toggleSidebar()" class="lg:hidden p-2 rounded-lg hover:bg-white/5 text-zinc-400"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><div><h1 class="text-lg font-bold text-white" id="page-title">Overview</h1><p class="text-xs text-zinc-400 hidden sm:block" id="page-subtitle">System overview</p></div></div>
<div class="flex items-center gap-3"><span class="text-xs text-zinc-500 hidden sm:inline">v3.4.1</span><span class="text-xs text-emerald-400 flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>Running</span></div>
</header>

<main class="p-4">
<!-- Dashboard -->
<div id="page-dashboard" class="page-section active">
<div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4 stats-grid">
<div class="system-stat"><div class="flex justify-between"><p class="text-xs text-zinc-400">CPU</p><span class="text-xs text-indigo-400" id="cpu-cores">2 Cores</span></div><p class="text-lg font-bold text-white" id="cpu-percent">12.5%</p><div class="w-full bg-zinc-800 rounded-full h-1.5 mt-2"><div class="bg-indigo-500 h-1.5 rounded-full" id="cpu-bar" style="width:12.5%"></div></div></div>
<div class="system-stat"><div class="flex justify-between"><p class="text-xs text-zinc-400">RAM</p><span class="text-xs text-emerald-400" id="ram-percent">49%</span></div><p class="text-lg font-bold text-white" id="ram-used">1152 MB</p><div class="w-full bg-zinc-800 rounded-full h-1.5 mt-2"><div class="bg-emerald-500 h-1.5 rounded-full" id="ram-bar" style="width:49%"></div></div></div>
<div class="system-stat"><div class="flex justify-between"><p class="text-xs text-zinc-400">Storage</p><span class="text-xs text-blue-400" id="storage-percent">28.7%</span></div><p class="text-lg font-bold text-white" id="storage-used">7.66 GB</p><div class="w-full bg-zinc-800 rounded-full h-1.5 mt-2"><div class="bg-blue-500 h-1.5 rounded-full" id="storage-bar" style="width:28.7%"></div></div></div>
<div class="system-stat"><div class="flex justify-between"><p class="text-xs text-zinc-400">Uptime</p><span class="text-xs text-purple-400">Xray</span></div><p class="text-lg font-bold text-white" id="xray-uptime">0s</p><div class="text-xs text-zinc-500 mt-2">Running since start</div></div>
</div>

<div class="glass rounded-2xl p-4 mb-4 flex flex-wrap items-center justify-between gap-3">
<div class="flex items-center gap-3"><span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span><span class="font-bold text-white">Xray v26.4.25</span><span class="text-xs text-emerald-400 bg-emerald-500/10 px-3 py-1 rounded-full">● Running</span></div>
<div class="flex gap-2"><button onclick="controlXray('stop')" class="px-3 py-1 text-xs bg-red-500/10 text-red-400 hover:bg-red-500/20 rounded-lg border border-red-500/20">Stop</button><button onclick="controlXray('restart')" class="px-3 py-1 text-xs bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20 rounded-lg border border-yellow-500/20">Restart</button><button onclick="controlXray('start')" class="px-3 py-1 text-xs bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 rounded-lg border border-emerald-500/20">Start</button></div>
</div>

<div class="grid grid-cols-2 md:grid-cols-4 gap-4 stats-grid">
<div class="glass rounded-2xl p-4 stat-card"><div class="flex justify-between"><div><p class="text-xs text-zinc-400">Total Users</p><p class="text-2xl font-black text-white" id="stat-total-users">0</p></div><div class="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center"><svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg></div></div></div>
<div class="glass rounded-2xl p-4 stat-card"><div class="flex justify-between"><div><p class="text-xs text-zinc-400">Online</p><p class="text-2xl font-black text-emerald-400" id="stat-active-users">0</p></div><div class="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center"><svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg></div></div></div>
<div class="glass rounded-2xl p-4 stat-card"><div class="flex justify-between"><div><p class="text-xs text-zinc-400">Traffic</p><p class="text-2xl font-black text-blue-400" id="stat-total-usage">0 GB</p></div><div class="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center"><svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg></div></div></div>
<div class="glass rounded-2xl p-4 stat-card"><div class="flex justify-between"><div><p class="text-xs text-zinc-400">Inbounds</p><p class="text-2xl font-black text-purple-400" id="stat-inbounds">0</p></div><div class="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center"><svg class="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg></div></div></div>
</div>
</div>

<!-- Users -->
<div id="page-users" class="page-section">
<div class="glass rounded-2xl p-4">
<div class="flex justify-between items-center mb-4"><h2 class="text-lg font-bold text-white">Clients</h2><button onclick="openCreateModal()" class="px-4 py-2 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-bold rounded-xl text-sm">+ Add Client</button></div>
<div id="users-list" class="text-center py-8 text-zinc-400">Loading...</div>
</div>
</div>

<!-- Inbounds -->
<div id="page-inbounds" class="page-section">
<div class="glass rounded-2xl p-4">
<div class="flex justify-between items-center mb-4"><h2 class="text-lg font-bold text-white">Inbounds</h2><button onclick="openInboundModal()" class="px-4 py-2 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-bold rounded-xl text-sm">+ Add Inbound</button></div>
<div id="inbounds-list" class="text-center py-8 text-zinc-400">Loading...</div>
</div>
</div>

<!-- Settings -->
<div id="page-settings" class="page-section">
<div class="glass rounded-2xl p-4 max-w-2xl">
<h2 class="text-lg font-bold text-white mb-4">Settings</h2>
<div class="space-y-4">
<div><label class="block text-xs text-zinc-400 font-semibold">Fragment Length</label><input type="text" id="frag-length" value="20-30" class="w-full px-4 py-3 rounded-xl text-white bg-[rgba(255,255,255,.05)] border border-zinc-800/50 outline-none text-sm"></div>
<div><label class="block text-xs text-zinc-400 font-semibold">Fragment Interval</label><input type="text" id="frag-interval" value="1-2" class="w-full px-4 py-3 rounded-xl text-white bg-[rgba(255,255,255,.05)] border border-zinc-800/50 outline-none text-sm"></div>
<div class="border-t border-zinc-800/30 pt-4"><h4 class="text-sm font-semibold text-white mb-3">Change Password</h4><input type="password" id="change-pwd-current" placeholder="Current password..." class="w-full px-4 py-3 rounded-xl text-white bg-[rgba(255,255,255,.05)] border border-zinc-800/50 outline-none text-sm mb-3"><input type="password" id="change-pwd-new" placeholder="New password..." class="w-full px-4 py-3 rounded-xl text-white bg-[rgba(255,255,255,.05)] border border-zinc-800/50 outline-none text-sm mb-3"><button onclick="changePassword()" class="w-full py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-bold rounded-xl text-sm">Update</button></div>
<button onclick="saveSettings()" class="w-full py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-bold rounded-xl text-sm">Save All</button>
</div>
</div>
</div>
</main>
</div>

<!-- Modal -->
<div id="user-modal" class="fixed inset-0 z-50 flex items-center justify-center p-3 modal-overlay opacity-0 pointer-events-none transition-opacity duration-300">
<div id="user-modal-card" class="w-full max-w-2xl glass rounded-2xl p-6 transition-all duration-300 opacity-0 scale-95">
<div class="flex justify-between items-center mb-4"><h3 id="modal-title" class="text-lg font-bold text-white">Add Client</h3><button onclick="toggleModal(false)" class="p-2 rounded-lg hover:bg-white/5 text-zinc-400">✕</button></div>
<form onsubmit="handleFormSubmit(event)" class="space-y-4">
<input type="text" id="input-name" placeholder="Username" class="w-full px-4 py-3 rounded-xl text-white bg-[rgba(255,255,255,.05)] border border-zinc-800/50 outline-none text-sm" required>
<div class="grid grid-cols-2 gap-3"><input type="number" id="input-limit" placeholder="Limit GB" class="w-full px-4 py-3 rounded-xl text-white bg-[rgba(255,255,255,.05)] border border-zinc-800/50 outline-none text-sm"><input type="number" id="input-expiry" placeholder="Expiry Days" class="w-full px-4 py-3 rounded-xl text-white bg-[rgba(255,255,255,.05)] border border-zinc-800/50 outline-none text-sm"></div>
<input type="text" id="input-ips" placeholder="Custom IPs (one per line)" class="w-full px-4 py-3 rounded-xl text-white bg-[rgba(255,255,255,.05)] border border-zinc-800/50 outline-none text-sm">
<div class="flex gap-3 pt-3 border-t border-zinc-800/30"><button type="button" onclick="toggleModal(false)" class="flex-1 py-3 bg-white/5 hover:bg-white/10 text-zinc-400 font-semibold rounded-xl text-sm">Cancel</button><button type="submit" id="submit-btn" class="flex-1 py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-bold rounded-xl text-sm">Create</button></div>
</form>
</div>
</div>

<script>
// ============================================
// PANEL JAVASCRIPT
// ============================================
var allUsers = [];
var allInbounds = [];
var editMode = false;
var editUser = '';

function toggleSidebar() {
  document.querySelector('.sidebar').classList.toggle('active');
  document.getElementById('overlay').classList.toggle('active');
}

function showPage(page) {
  document.querySelectorAll('.page-section').forEach(el => el.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  document.querySelectorAll('.sidebar-link').forEach(el => el.classList.remove('active'));
  const link = document.querySelector('.sidebar-link[data-page="' + page + '"]');
  if (link) link.classList.add('active');
  const titles = {dashboard:'Overview',users:'Clients',inbounds:'Inbounds',settings:'Settings'};
  document.getElementById('page-title').textContent = titles[page] || page;
  if (page === 'users') loadUsers();
  if (page === 'inbounds') loadInbounds();
  if (window.innerWidth < 1024) { document.querySelector('.sidebar').classList.remove('active'); document.getElementById('overlay').classList.remove('active'); }
}

function toggleModal(show) {
  const m = document.getElementById('user-modal');
  const c = document.getElementById('user-modal-card');
  if (show) { m.classList.remove('opacity-0','pointer-events-none'); m.classList.add('opacity-100','pointer-events-auto'); c.classList.remove('opacity-0','scale-95'); c.classList.add('opacity-100','scale-100'); }
  else { m.classList.remove('opacity-100','pointer-events-auto'); m.classList.add('opacity-0','pointer-events-none'); c.classList.remove('opacity-100','scale-100'); c.classList.add('opacity-0','scale-95'); editMode = false; editUser = ''; document.getElementById('modal-title').textContent = 'Add Client'; document.getElementById('submit-btn').textContent = 'Create'; document.getElementById('input-name').disabled = false; document.getElementById('create-user-form').reset(); }
}

function openCreateModal() { editMode = false; document.getElementById('modal-title').textContent = 'Add Client'; document.getElementById('submit-btn').textContent = 'Create'; document.getElementById('input-name').disabled = false; toggleModal(true); }

async function loadUsers() {
  try { const r = await fetch('/api/users?t='+Date.now()); const d = await r.json(); allUsers = d.users || []; renderUsers(allUsers); updateStats(); } catch(e) { document.getElementById('users-list').innerHTML = '<div class="text-center py-8 text-red-400">❌ Error loading users</div>'; }
}

function renderUsers(users) {
  const el = document.getElementById('users-list');
  if (!users || !users.length) { el.innerHTML = '<div class="text-center py-8 text-zinc-400">No clients found. Click "Add Client" to get started.</div>'; return; }
  el.innerHTML = users.map(u => {
    const used = u.used_gb || 0;
    const limit = u.limit_gb || 0;
    const pct = limit > 0 ? Math.min((used/limit)*100,100) : 0;
    const isOnline = u.is_online === 1;
    const isActive = u.is_active === 1;
    return '<div class="glass-light rounded-xl p-3 mb-2 flex flex-wrap items-center justify-between gap-2">' +
      '<div><div class="font-bold text-white">' + (u.config_name || u.username) + '</div><div class="text-xs text-zinc-400">' + u.uuid + '</div><div class="flex gap-1 mt-1"><span class="badge ' + (isActive ? 'badge-success' : 'badge-danger') + '">' + (isActive ? 'Active' : 'Inactive') + '</span><span class="badge ' + (isOnline ? 'badge-success' : 'badge') + '">' + (isOnline ? '● Online' : 'Offline') + '</span></div></div>' +
      '<div><div class="text-sm">' + used.toFixed(2) + ' GB / ' + (limit || '∞') + ' GB</div><div class="w-24 bg-zinc-800 rounded-full h-1.5"><div class="bg-emerald-500 h-1.5 rounded-full" style="width:' + pct + '%"></div></div></div>' +
      '<div class="flex gap-1"><button onclick="copyConfig(\'' + encodeURIComponent(u.username) + '\')" class="action-btn text-indigo-400" title="Copy">📋</button><button onclick="toggleUser(\'' + encodeURIComponent(u.username) + '\')" class="action-btn text-yellow-400">' + (isActive ? '⏸' : '▶') + '</button><button onclick="editUser(\'' + encodeURIComponent(u.username) + '\')" class="action-btn text-blue-400">✏️</button><button onclick="deleteUser(\'' + encodeURIComponent(u.username) + '\')" class="action-btn text-red-400">🗑</button></div>' +
    '</div>';
  }).join('');
}

async function updateStats() {
  try { const r = await fetch('/api/users'); const d = await r.json(); const users = d.users || []; document.getElementById('stat-total-users').textContent = users.length; document.getElementById('stat-active-users').textContent = users.filter(u => u.is_online === 1).length; const total = users.reduce((s,u) => s + (u.used_gb || 0), 0); document.getElementById('stat-total-usage').textContent = total < 1 ? (total*1024).toFixed(0)+' MB' : total.toFixed(2)+' GB'; } catch(e) {} }

async function toggleUser(encoded) { const username = decodeURIComponent(encoded); await fetch('/api/users/' + encodeURIComponent(username), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ toggle_only: true }) }); loadUsers(); }

async function deleteUser(encoded) { if (!confirm('Delete this user?')) return; const username = decodeURIComponent(encoded); await fetch('/api/users/' + encodeURIComponent(username), { method: 'DELETE' }); loadUsers(); }

function editUser(encoded) { const username = decodeURIComponent(encoded); const u = allUsers.find(x => x.username === username); if (!u) return; editMode = true; editUser = username; document.getElementById('modal-title').textContent = 'Edit Client'; document.getElementById('submit-btn').textContent = 'Save'; document.getElementById('input-name').value = username; document.getElementById('input-name').disabled = true; document.getElementById('input-limit').value = u.limit_gb || ''; document.getElementById('input-expiry').value = u.expiry_days || ''; document.getElementById('input-ips').value = u.ips || ''; toggleModal(true); }

async function handleFormSubmit(e) { e.preventDefault(); const btn = document.getElementById('submit-btn'); btn.disabled = true; btn.textContent = 'Saving...'; const data = { username: document.getElementById('input-name').value.trim(), limit_gb: document.getElementById('input-limit').value || null, expiry_days: document.getElementById('input-expiry').value || null, ips: document.getElementById('input-ips').value || null }; try { const url = editMode ? '/api/users/' + encodeURIComponent(editUser) : '/api/users'; const r = await fetch(url, { method: editMode ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }); if (r.ok) { toggleModal(false); loadUsers(); } else { alert('Error: ' + (await r.json()).error || 'Failed'); } } catch(e) { alert('Connection error'); } btn.disabled = false; btn.textContent = editMode ? 'Save' : 'Create'; }

function copyConfig(encoded) { const username = decodeURIComponent(encoded); const u = allUsers.find(x => x.username === username); if (!u) return; const host = window.location.hostname; const link = 'vless://' + u.uuid + '@' + host + ':' + (u.port || '443') + '?path=%2F&security=tls&encryption=none&insecure=0&host=' + host + '&fp=chrome&type=ws&sni=' + host + '#' + encodeURIComponent(u.username); navigator.clipboard.writeText(link).then(() => alert('✅ Copied!')); }

// Inbounds
async function loadInbounds() {
  try { const r = await fetch('/api/inbounds'); const d = await r.json(); allInbounds = d.inbounds || []; document.getElementById('stat-inbounds').textContent = allInbounds.length; renderInbounds(allInbounds); } catch(e) { document.getElementById('inbounds-list').innerHTML = '<div class="text-center py-8 text-red-400">❌ Error loading inbounds</div>'; }
}

function renderInbounds(inbounds) {
  const el = document.getElementById('inbounds-list');
  if (!inbounds || !inbounds.length) { el.innerHTML = '<div class="text-center py-8 text-zinc-400">No inbounds found. Click "Add Inbound" to get started.</div>'; return; }
  el.innerHTML = inbounds.map(ib => '<div class="glass-light rounded-xl p-3 mb-2 flex flex-wrap items-center justify-between gap-2"><div><div class="font-bold text-white">' + ib.name + '</div><div class="text-xs text-zinc-400">' + ib.protocol + ':' + ib.port + ' | Path: ' + ib.path + '</div></div><div class="flex gap-1"><span class="badge ' + (ib.is_active ? 'badge-success' : 'badge-danger') + '">' + (ib.is_active ? 'Active' : 'Inactive') + '</span><button onclick="deleteInbound(' + ib.id + ')" class="action-btn text-red-400">🗑</button></div></div>').join('');
}

function openInboundModal() { const name = prompt('Inbound name:'); if (!name) return; const port = prompt('Port (default 443):') || 443; const path = prompt('Path (default /):') || '/'; fetch('/api/inbounds', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, protocol: 'vless', port: parseInt(port), path }) }).then(() => loadInbounds()); }

async function deleteInbound(id) { if (!confirm('Delete this inbound?')) return; await fetch('/api/inbounds/' + id, { method: 'DELETE' }); loadInbounds(); }

// Xray Control
async function controlXray(action) { await fetch('/api/xray', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action }) }); alert('✅ Xray ' + action + 'ed'); updateStatus(); }

async function updateStatus() { try { const r = await fetch('/api/xray/status'); const d = await r.json(); document.getElementById('xray-uptime').textContent = d.running ? Math.floor(d.uptime/60)+'m' : 'Stopped'; } catch(e) {} }

// Settings
async function saveSettings() {
  const fragLen = document.getElementById('frag-length').value;
  const fragInt = document.getElementById('frag-interval').value;
  await fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ frag_len: fragLen, frag_int: fragInt }) });
  alert('✅ Settings saved');
}

async function changePassword() {
  const current = document.getElementById('change-pwd-current').value;
  const newp = document.getElementById('change-pwd-new').value;
  if (!current || !newp) { alert('Fill all fields'); return; }
  if (newp.length < 4) { alert('Password must be at least 4 characters'); return; }
  const r = await fetch('/api/change-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ current_password: current, new_password: newp }) });
  if (r.ok) { alert('✅ Password updated'); document.getElementById('change-pwd-current').value = ''; document.getElementById('change-pwd-new').value = ''; } else { alert('❌ Error: ' + ((await r.json()).error || 'Failed')); }
}

async function logout() { if (confirm('Log out?')) { await fetch('/api/logout', { method: 'POST' }); window.location.reload(); } }

// Init
document.addEventListener('DOMContentLoaded', function() {
  showPage('dashboard');
  loadUsers();
  loadInbounds();
  updateStatus();
  setInterval(loadUsers, 30000);
  setInterval(updateStatus, 10000);
});
<\/script>
</body></html>`,

  status: `<!DOCTYPE html>
<html class="dark"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Status</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"><\/script>
<style>*{font-family:'Inter',sans-serif}body{background:#0a0a0f}.glass{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)}</style>
</head><body class="min-h-screen flex items-center justify-center p-4"><div class="max-w-md w-full glass rounded-2xl p-8">
<div class="text-center"><h1 class="text-2xl font-bold text-white">Subscription Status</h1><p id="display-username" class="text-sm text-indigo-400 font-mono"></p></div>
<div id="status-card" class="my-4 p-4 text-center border rounded-xl font-semibold"><span id="status-text">Loading...</span></div>
<div class="space-y-4"><div class="glass-light rounded-xl p-4"><div class="flex justify-between"><span class="text-xs text-zinc-400">Data Usage</span><span id="volume-pct" class="text-xs font-bold text-indigo-400">0%</span></div><div class="w-full bg-zinc-800 rounded-full h-2 mt-1"><div id="volume-progress" class="bg-gradient-to-r from-indigo-500 to-purple-500 h-2 rounded-full" style="width:0%"></div></div><div class="flex justify-between text-xs text-zinc-400 mt-1"><span>Used: <span id="used-vol" class="text-white">-</span></span><span>Total: <span id="limit-vol" class="text-white">-</span></span></div></div>
<div class="glass-light rounded-xl p-4"><div class="flex justify-between"><span class="text-xs text-zinc-400">Time Remaining</span><span id="expiry-pct" class="text-xs font-bold text-purple-400">0%</span></div><div class="w-full bg-zinc-800 rounded-full h-2 mt-1"><div id="expiry-progress" class="bg-gradient-to-r from-purple-500 to-pink-500 h-2 rounded-full" style="width:0%"></div></div><div class="flex justify-between text-xs text-zinc-400 mt-1"><span>Remaining: <span id="days-remaining" class="text-white">-</span></span><span>Total: <span id="total-days" class="text-white">-</span></span></div></div></div>
<div class="mt-4 pt-4 border-t border-zinc-800/30 text-center"><button onclick="copyConfig()" class="w-full py-2 glass-light hover:border-indigo-500/50 rounded-xl text-sm font-medium text-zinc-300">🚀 Copy VLESS Config</button></div>
<div class="mt-2 text-center text-xs text-zinc-500">@VoidLatency v3.4.1</div>
</div>
<script>/*{{DATA}}*/
var u=window.statusUser||{};
function fb(b){if(!b)return'0 B';var k=1024,s=['B','KB','MB','GB','TB'],i=Math.floor(Math.log(b)/Math.log(k));return (b/Math.pow(k,i)).toFixed(2)+' '+s[i];}
document.getElementById('display-username').textContent='@'+u.username;
var used=(u.used_gb||0)*1073741824, limit=(u.limit_gb||0)*1073741824;
document.getElementById('used-vol').textContent=fb(used);
document.getElementById('limit-vol').textContent=limit?fb(limit):'Unlimited';
var pct=limit?Math.min(used/limit*100,100):0;
document.getElementById('volume-pct').textContent=pct.toFixed(0)+'%';
document.getElementById('volume-progress').style.width=pct+'%';
if(u.expiry_days){var created=new Date(u.created_at);var exp=new Date(created.getTime()+u.expiry_days*24*60*60*1000);var days=Math.ceil((exp-new Date())/(1000*60*60*24));document.getElementById('days-remaining').textContent=days>0?days+' days':'Expired';document.getElementById('total-days').textContent=u.expiry_days+' days';var dp=Math.min(days/u.expiry_days*100,100);document.getElementById('expiry-pct').textContent=dp.toFixed(0)+'%';document.getElementById('expiry-progress').style.width=dp+'%';}else{document.getElementById('days-remaining').textContent='Unlimited';document.getElementById('total-days').textContent='Unlimited';}
document.getElementById('status-text').textContent=u.is_active?'✅ Active':'❌ Inactive';
document.getElementById('status-text').className=u.is_active?'text-emerald-400':'text-red-400';
function copyConfig(){var host=window.location.host;var link='vless://'+u.uuid+'@'+host+':'+(u.port||'443')+'?path=%2F&security=tls&encryption=none&insecure=0&host='+host+'&fp=chrome&type=ws&sni='+host+'#'+encodeURIComponent(u.username);navigator.clipboard.writeText(link).then(()=>alert('✅ Copied!'));}
<\/script>
</body></html>`
};

export default {
  fetch: voidlatency_core_default.fetch
};
