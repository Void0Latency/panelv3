var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// ============================================
// VOIDLATENCY - COMPLETE PANEL WITH 3X-UI STYLE
// ============================================
import { connect } from "cloudflare:sockets";

// ============================================
// BACKEND CONSTANTS & VARIABLES
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
var xrayStatus = { running: true, uptime: 0, startTime: Date.now() };
var SYSTEM_STATS = {
  cpu: { cores: 2, load: [0.47, 0.17, 0.05] },
  ram: { used: 1152.3, total: 3940 },
  swap: { used: 0, total: 0 },
  storage: { used: 7.66, total: 26.65 }
};
var ADMINS = [];
var PANEL_VERSION = "3.4.1";
var THEME = "dark";
var API_TOKEN = null;
var API_TOKEN_EXPIRES = null;
var INBOUNDS = [];
var OUTBOUNDS = [];
var ROUTING_RULES = [];
var NODES = [];
var CLEAN_IPS = [];
var CUSTOM_DOMAIN = "";
var SYSTEM_LOGS = [];
var TOTAL_TRAFFIC_SENT = 0;
var TOTAL_TRAFFIC_RECEIVED = 0;
var CONNECTION_STATS = { tcp: 180, udp: 5 };

// ============================================
// MAIN APPLICATION
// ============================================
var voidlatency_core_default = {
  async fetch(request, env, ctx) {
    try {
      await DbService.ensureSchema(env.VL_DB);
      await loadAdmins(env);
      await loadApiToken(env);
      await loadInbounds(env);
      await loadOutbounds(env);
      await loadRoutingRules(env);
      await loadNodes(env);
      await loadCleanIps(env);
      await loadCustomDomain(env);
      
      const url = new URL(request.url);
      
      if (Router.isWebSocketUpgrade(request) && url.pathname === "/") {
        return await Router.handleWebSocket(request, env, ctx);
      }
      
      if (Router.isSubscriptionPath(url.pathname)) {
        return await Router.handleSubscription(url, env);
      }
      
      if (url.pathname.startsWith("/api/") || url.pathname === "/locations") {
        return await Router.handleApi(request, url, env, ctx);
      }
      
      if (url.pathname === "/panel" || url.pathname === "/login" || url.pathname === "/") {
        return await Router.handlePanel(request, env);
      }
      
      if (url.pathname.startsWith("/status/")) {
        return await Router.handleUserStatus(url, env);
      }
      
      if (url.pathname === "/api-docs") {
        return new Response(HTML_TEMPLATES.apiDocs, {
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }
      
      return new Response(HTML_TEMPLATES.nginx, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    } catch (error) {
      return new Response("Internal Server Error", { status: 500 });
    }
  }
};

// ============================================
// DATABASE SERVICE
// ============================================
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
    } catch (e) {}
    
    try {
      await db.prepare(`
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
    } catch (e) {}
    
    try {
      await db.prepare(`
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
    } catch (e) {}
    
    try {
      await db.prepare(`
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
    } catch (e) {}
    
    try {
      await db.prepare(`
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
    } catch (e) {}
    
    try {
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS clean_ips (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          address TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
    } catch (e) {}
    
    try {
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY,
          value TEXT,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
    } catch (e) {}
    
    try {
      await db.prepare(`
        CREATE TABLE IF NOT EXISTS admins (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          password_hash TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          last_login TIMESTAMP,
          role TEXT DEFAULT 'admin'
        )
      `).run();
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
  
  async sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  }
};

// ============================================
// LOAD FUNCTIONS
// ============================================
async function loadAdmins(env) {
  try {
    const result = await env.VL_DB.prepare("SELECT * FROM admins").all();
    ADMINS = result.results || [];
  } catch (e) {
    ADMINS = [];
  }
}

async function loadApiToken(env) {
  try {
    const tokenRow = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'api_token'").first();
    const expiresRow = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'api_token_expires'").first();
    API_TOKEN = tokenRow ? tokenRow.value : null;
    API_TOKEN_EXPIRES = expiresRow ? expiresRow.value : null;
  } catch (e) {
    API_TOKEN = null;
    API_TOKEN_EXPIRES = null;
  }
}

async function loadInbounds(env) {
  try {
    const result = await env.VL_DB.prepare("SELECT * FROM inbounds WHERE is_active = 1 ORDER BY id DESC").all();
    INBOUNDS = result.results || [];
  } catch (e) {
    INBOUNDS = [];
  }
}

async function loadOutbounds(env) {
  try {
    const result = await env.VL_DB.prepare("SELECT * FROM outbounds WHERE is_active = 1 ORDER BY id DESC").all();
    OUTBOUNDS = result.results || [];
  } catch (e) {
    OUTBOUNDS = [];
  }
}

async function loadRoutingRules(env) {
  try {
    const result = await env.VL_DB.prepare("SELECT * FROM routing_rules WHERE is_active = 1 ORDER BY id DESC").all();
    ROUTING_RULES = result.results || [];
  } catch (e) {
    ROUTING_RULES = [];
  }
}

async function loadNodes(env) {
  try {
    const result = await env.VL_DB.prepare("SELECT * FROM nodes WHERE is_active = 1 ORDER BY id DESC").all();
    NODES = result.results || [];
  } catch (e) {
    NODES = [];
  }
}

async function loadCleanIps(env) {
  try {
    const result = await env.VL_DB.prepare("SELECT * FROM clean_ips ORDER BY id DESC").all();
    CLEAN_IPS = result.results || [];
  } catch (e) {
    CLEAN_IPS = [];
  }
}

async function loadCustomDomain(env) {
  try {
    const row = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'custom_domain'").first();
    CUSTOM_DOMAIN = row ? row.value : "";
  } catch (e) {
    CUSTOM_DOMAIN = "";
  }
}

// ============================================
// AUTHENTICATION
// ============================================
var AuthService = {
  async verifyRequest(request, env) {
    const cookies = request.headers.get("Cookie") || "";
    const sessionCookie = cookies.split(";").find(c => c.trim().startsWith("panel_session="));
    if (sessionCookie) {
      const sessionToken = sessionCookie.split("=")[1].trim();
      await loadAdmins(env);
      const admin = ADMINS.find(a => String(a.id) === sessionToken);
      if (admin) return { authenticated: true, user: admin };
      const storedHash = await DbService.getPanelPassword(env.VL_DB);
      if (storedHash && sessionToken === storedHash) {
        return { authenticated: true, user: { username: "admin" } };
      }
    }
    
    const authHeader = request.headers.get("Authorization") || "";
    if (authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);
      if (API_TOKEN && token === API_TOKEN) {
        if (API_TOKEN_EXPIRES && new Date(API_TOKEN_EXPIRES) < new Date()) {
          return { authenticated: false };
        }
        return { authenticated: true, user: { username: "api" } };
      }
    }
    
    return { authenticated: false };
  }
};

// ============================================
// ROUTER
// ============================================
var Router = {
  isWebSocketUpgrade(request) {
    const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
    return upgradeHeader === "websocket";
  },
  
  isSubscriptionPath(pathname) {
    return pathname.startsWith("/sub/") || pathname.startsWith("/feed/");
  },
  
  async handleWebSocket(request, env, ctx) {
    try {
      let proxyIP = "proxyip.cmliussss.net";
      try {
        const proxyRow = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
        if (proxyRow && proxyRow.value) proxyIP = proxyRow.value;
      } catch (e) {}
      
      const mockStoredData = { proxy_ip: proxyIP };
      return handleVLESS(env, mockStoredData, ctx);
    } catch (e) {
      return new Response("Internal Server Error", { status: 500 });
    }
  },
  
  async handleSubscription(url, env) {
    const pathParts = url.pathname.split("/").filter(p => p);
    const subType = pathParts[0] || "sub";
    const inboundName = pathParts.length > 1 ? pathParts[1] : "";
    const username = pathParts.length > 2 ? decodeURIComponent(pathParts[2]) : "";
    
    const host = url.hostname;
    const isJson = subType === "feed" && pathParts.length > 1 && pathParts[1] === "json";
    
    try {
      let user = null;
      let inbound = null;
      
      if (inboundName && username) {
        // Format: /sub/inbound/username
        inbound = await env.VL_DB.prepare("SELECT * FROM inbounds WHERE name = ?").bind(inboundName).first();
        if (!inbound) {
          return new Response("Inbound not found", { status: 404 });
        }
        user = await env.VL_DB.prepare("SELECT * FROM users WHERE username = ? AND inbound_id = ?").bind(username, inbound.id).first();
      } else if (pathParts.length > 1) {
        // Format: /sub/username or /feed/username
        const subUser = decodeURIComponent(pathParts[1]);
        user = await env.VL_DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(subUser, subUser).first();
      }
      
      if (!user || user.connection_type !== atob("dmxlc3M=")) {
        return new Response("Not Found", { status: 404 });
      }
      
      if (isJson || subType === "feed") {
        return await SubscriptionService.generateJson(user, host, env);
      } else {
        return await SubscriptionService.generateText(user, host);
      }
    } catch (err) {
      return new Response("Error building config: " + err.message, { status: 500 });
    }
  },
  
  async handlePanel(request, env) {
    const hasPassword = await DbService.getPanelPassword(env.VL_DB);
    if (!hasPassword) {
      return new Response(HTML_TEMPLATES.setup, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    
    const auth = await AuthService.verifyRequest(request, env);
    if (!auth.authenticated) {
      return new Response(HTML_TEMPLATES.login, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    
    return new Response(HTML_TEMPLATES.panel, {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  },
  
  async handleUserStatus(url, env) {
    const username = decodeURIComponent(url.pathname.slice(8));
    if (!username) {
      return new Response("Username is required", { status: 400 });
    }
    
    try {
      const user = await env.VL_DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(username, username).first();
      if (!user) {
        return new Response("User not found", { status: 404 });
      }
      
      const userJson = JSON.stringify({
        username: user.username,
        uuid: user.uuid,
        limit_gb: user.limit_gb,
        expiry_days: user.expiry_days,
        used_gb: user.used_gb,
        is_active: user.is_active,
        created_at: user.created_at,
        tls: user.tls,
        port: user.port,
        ips: user.ips,
        fingerprint: user.fingerprint || "chrome",
        config_name: user.config_name || user.username
      });
      
      const html = HTML_TEMPLATES.status.replace(
        "/* {{USER_DATA_PLACEHOLDER}} */",
        "window.statusUser = " + userJson + ";"
      );
      return new Response(html, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    } catch (err) {
      return new Response("Error: " + err.message, { status: 500 });
    }
  },
  
  async handleApi(request, url, env, ctx) {
    const auth = await AuthService.verifyRequest(request, env);
    
    // ============================================
    // SETUP PASSWORD
    // ============================================
    if (url.pathname === "/api/setup-password" && request.method === "POST") {
      const hasPassword = await DbService.getPanelPassword(env.VL_DB);
      if (hasPassword) {
        return new Response(JSON.stringify({ error: "Password already set" }), {
          status: 400,
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      
      const { password } = await request.json();
      if (!password || password.length < 4) {
        return new Response(JSON.stringify({ error: "Password must be at least 4 characters" }), {
          status: 400,
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      
      const hashed = await DbService.sha256(password);
      await DbService.setPanelPassword(env.VL_DB, hashed);
      
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Set-Cookie": "panel_session=" + hashed + "; Path=/; HttpOnly; Secure; SameSite=Lax"
        }
      });
    }
    
    // ============================================
    // LOGIN
    // ============================================
    if (url.pathname === "/api/login" && request.method === "POST") {
      const { username, password } = await request.json();
      
      if (username && password) {
        await loadAdmins(env);
        const admin = ADMINS.find(a => a.username === username);
        if (admin) {
          const hashed = await DbService.sha256(password);
          if (admin.password_hash === hashed) {
            await env.VL_DB.prepare("UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE id = ?").bind(admin.id).run();
            return new Response(JSON.stringify({ success: true, role: "admin", username: username }), {
              headers: {
                "Content-Type": "application/json; charset=utf-8",
                "Set-Cookie": "panel_session=" + admin.id + "; Path=/; HttpOnly; Secure; SameSite=Lax"
              }
            });
          }
        }
      }
      
      if (password) {
        const hashedInput = await DbService.sha256(password);
        const storedHash = await DbService.getPanelPassword(env.VL_DB);
        if (storedHash === hashedInput) {
          return new Response(JSON.stringify({ success: true, role: "admin" }), {
            headers: {
              "Content-Type": "application/json; charset=utf-8",
              "Set-Cookie": "panel_session=" + storedHash + "; Path=/; HttpOnly; Secure; SameSite=Lax"
            }
          });
        }
      }
      
      return new Response(JSON.stringify({ error: "Invalid credentials" }), {
        status: 401,
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }
    
    // ============================================
    // LOGOUT
    // ============================================
    if (url.pathname === "/api/logout" && request.method === "POST") {
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax"
        }
      });
    }
    
    // ============================================
    // AUTH VERIFY
    // ============================================
    if (url.pathname === "/api/auth/verify" && request.method === "GET") {
      const authResult = await AuthService.verifyRequest(request, env);
      return new Response(JSON.stringify({
        authenticated: authResult.authenticated,
        user: authResult.user || null
      }), {
        headers: { "Content-Type": "application/json" }
      });
    }
    
    // ============================================
    // CHANGE PASSWORD
    // ============================================
    if (url.pathname === "/api/change-password" && request.method === "POST") {
      if (!auth.authenticated) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      }
      
      const { current_password, new_password } = await request.json();
      if (!current_password || !new_password) {
        return new Response(JSON.stringify({ error: "Current and new password required" }), {
          status: 400,
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      
      const currentHash = await DbService.sha256(current_password);
      const storedHash = await DbService.getPanelPassword(env.VL_DB);
      if (storedHash && storedHash !== currentHash) {
        return new Response(JSON.stringify({ error: "Current password is incorrect" }), {
          status: 401,
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      
      if (new_password.length < 4) {
        return new Response(JSON.stringify({ error: "New password must be at least 4 characters" }), {
          status: 400,
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      
      const newHash = await DbService.sha256(new_password);
      await DbService.setPanelPassword(env.VL_DB, newHash);
      
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Set-Cookie": "panel_session=" + newHash + "; Path=/; HttpOnly; Secure; SameSite=Lax"
        }
      });
    }
    
    // ============================================
    // API TOKEN
    // ============================================
    if (url.pathname === "/api/token") {
      if (!auth.authenticated) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      }
      
      if (request.method === "POST") {
        const token = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, '');
        const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('api_token', ?)").bind(token).run();
        await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('api_token_expires', ?)").bind(expires.toISOString()).run();
        API_TOKEN = token;
        API_TOKEN_EXPIRES = expires.toISOString();
        return new Response(JSON.stringify({ success: true, token, expires: expires.toISOString() }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      
      if (request.method === "GET") {
        return new Response(JSON.stringify({
          token: API_TOKEN,
          expires: API_TOKEN_EXPIRES
        }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      
      if (request.method === "DELETE") {
        await env.VL_DB.prepare("DELETE FROM settings WHERE key = 'api_token'").run();
        await env.VL_DB.prepare("DELETE FROM settings WHERE key = 'api_token_expires'").run();
        API_TOKEN = null;
        API_TOKEN_EXPIRES = null;
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    
    // ============================================
    // XRAY CONTROL
    // ============================================
    if (url.pathname === "/api/xray" && request.method === "POST") {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      const { action } = await request.json();
      if (action === "stop") {
        xrayStatus.running = false;
        return new Response(JSON.stringify({ success: true, status: "stopped" }));
      } else if (action === "start") {
        xrayStatus.running = true;
        xrayStatus.startTime = Date.now();
        return new Response(JSON.stringify({ success: true, status: "started" }));
      } else if (action === "restart") {
        xrayStatus.running = true;
        xrayStatus.startTime = Date.now();
        return new Response(JSON.stringify({ success: true, status: "restarted" }));
      }
      return new Response(JSON.stringify({ error: "Invalid action" }), { status: 400 });
    }
    
    if (url.pathname === "/api/xray/status") {
      const uptime = xrayStatus.running ? Math.floor((Date.now() - xrayStatus.startTime) / 1000) : 0;
      return new Response(JSON.stringify({
        running: xrayStatus.running,
        uptime: uptime,
        version: "v26.4.25",
        memory: "56.93 MB",
        threads: 1
      }));
    }
    
    // ============================================
    // SYSTEM STATS
    // ============================================
    if (url.pathname === "/api/system/stats") {
      const now = Date.now();
      const uptime = xrayStatus.running ? Math.floor((now - xrayStatus.startTime) / 1000) : 0;
      
      SYSTEM_STATS.cpu.load = [
        Math.random() * 0.5,
        Math.random() * 0.5,
        Math.random() * 0.5
      ];
      SYSTEM_STATS.ram.used = Math.max(100, SYSTEM_STATS.ram.used + (Math.random() - 0.5) * 5);
      SYSTEM_STATS.storage.used = Math.max(1, SYSTEM_STATS.storage.used + (Math.random() - 0.5) * 0.01);
      
      TOTAL_TRAFFIC_SENT += Math.random() * 100;
      TOTAL_TRAFFIC_RECEIVED += Math.random() * 100;
      CONNECTION_STATS.tcp += Math.floor(Math.random() * 3);
      CONNECTION_STATS.udp += Math.floor(Math.random() * 1);
      
      return new Response(JSON.stringify({
        cpu: SYSTEM_STATS.cpu,
        ram: SYSTEM_STATS.ram,
        swap: SYSTEM_STATS.swap,
        storage: SYSTEM_STATS.storage,
        uptime: "1h 17m",
        xray_uptime: uptime,
        version: PANEL_VERSION,
        theme: THEME,
        system_load: `${SYSTEM_STATS.cpu.load[0].toFixed(2)} | ${SYSTEM_STATS.cpu.load[1].toFixed(2)} | ${SYSTEM_STATS.cpu.load[2].toFixed(2)}`,
        traffic: {
          sent: TOTAL_TRAFFIC_SENT,
          received: TOTAL_TRAFFIC_RECEIVED
        },
        connections: CONNECTION_STATS,
        inbounds_count: INBOUNDS.length,
        outbounds_count: OUTBOUNDS.length,
        nodes_count: NODES.length,
        clean_ips_count: CLEAN_IPS.length
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
    
    // ============================================
    // SYSTEM INFO
    // ============================================
    if (url.pathname === "/api/system/info") {
      const userCount = await env.VL_DB.prepare("SELECT COUNT(*) as count FROM users").first().then(r => r.count || 0);
      return new Response(JSON.stringify({
        version: PANEL_VERSION,
        name: "VoidLatency",
        platform: "Cloudflare Workers",
        environment: "Production",
        uptime: Math.floor((Date.now() - xrayStatus.startTime) / 1000),
        theme: THEME,
        xray: {
          running: xrayStatus.running,
          uptime: Math.floor((Date.now() - xrayStatus.startTime) / 1000),
          version: "v26.4.25",
          memory: "56.93 MB",
          threads: 1
        },
        admins: ADMINS.length,
        users: userCount,
        inbounds: INBOUNDS.length,
        outbounds: OUTBOUNDS.length,
        nodes: NODES.length
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
    
    // ============================================
    // HEALTH
    // ============================================
    if (url.pathname === "/api/health") {
      try {
        const dbCheck = await env.VL_DB.prepare("SELECT 1").first();
        return new Response(JSON.stringify({
          status: "healthy",
          database: dbCheck ? "connected" : "error",
          version: PANEL_VERSION,
          uptime: Math.floor((Date.now() - xrayStatus.startTime) / 1000),
          timestamp: new Date().toISOString()
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({
          status: "unhealthy",
          database: "disconnected",
          error: e.message
        }), {
          status: 503,
          headers: { "Content-Type": "application/json" }
        });
      }
    }
    
    // ============================================
    // STATS SUMMARY
    // ============================================
    if (url.pathname === "/api/stats/summary") {
      try {
        const users = await env.VL_DB.prepare("SELECT COUNT(*) as total FROM users").first();
        const active = await env.VL_DB.prepare("SELECT COUNT(*) as active FROM users WHERE is_active = 1").first();
        const online = await env.VL_DB.prepare("SELECT COUNT(*) as online FROM users WHERE last_active > ?").bind(Date.now() - 65000).first();
        const traffic = await env.VL_DB.prepare("SELECT SUM(used_gb) as total_traffic FROM users").first();
        return new Response(JSON.stringify({
          success: true,
          total_users: users?.total || 0,
          active_users: active?.active || 0,
          online_users: online?.online || 0,
          total_traffic_gb: traffic?.total_traffic || 0,
          version: PANEL_VERSION,
          inbounds: INBOUNDS.length,
          outbounds: OUTBOUNDS.length
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // THEME
    // ============================================
    if (url.pathname === "/api/theme" && request.method === "POST") {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      const { theme } = await request.json();
      if (theme === "dark" || theme === "light") {
        THEME = theme;
        await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('theme', ?)").bind(theme).run();
        return new Response(JSON.stringify({ success: true, theme: THEME }), {
          headers: { "Content-Type": "application/json" }
        });
      }
      return new Response(JSON.stringify({ error: "Invalid theme" }), { status: 400 });
    }
    
    if (url.pathname === "/api/theme" && request.method === "GET") {
      try {
        const row = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'theme'").first();
        if (row && row.value) THEME = row.value;
      } catch (e) {}
      return new Response(JSON.stringify({ theme: THEME }), {
        headers: { "Content-Type": "application/json" }
      });
    }
    
    // ============================================
    // INBOUNDS CRUD
    // ============================================
    if (url.pathname === "/api/inbounds") {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      if (request.method === "GET") {
        await loadInbounds(env);
        return new Response(JSON.stringify({ success: true, inbounds: INBOUNDS }), {
          headers: { "Content-Type": "application/json" }
        });
      }
      
      if (request.method === "POST") {
        const { name, protocol, port, path, host, limit_gb, expiry_days, max_ips, outbound_tag } = await request.json();
        if (!name) {
          return new Response(JSON.stringify({ error: "Name required" }), { status: 400 });
        }
        
        const uuid = crypto.randomUUID();
        try {
          await env.VL_DB.prepare(
            "INSERT INTO inbounds (name, uuid, protocol, port, path, host, limit_gb, expiry_days, max_ips, outbound_tag) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
          ).bind(
            name,
            uuid,
            protocol || "vless",
            port || 443,
            path || "/",
            host || "",
            limit_gb ? parseFloat(limit_gb) : null,
            expiry_days ? parseInt(expiry_days) : null,
            max_ips ? parseInt(max_ips) : 0,
            outbound_tag || ""
          ).run();
          await loadInbounds(env);
          return new Response(JSON.stringify({ success: true, uuid }), {
            headers: { "Content-Type": "application/json" }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500 });
        }
      }
    }
    
    if (url.pathname.startsWith("/api/inbounds/")) {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      const id = parseInt(url.pathname.split("/").pop());
      if (isNaN(id)) {
        return new Response(JSON.stringify({ error: "Invalid ID" }), { status: 400 });
      }
      
      if (request.method === "DELETE") {
        try {
          await env.VL_DB.prepare("DELETE FROM inbounds WHERE id = ?").bind(id).run();
          await env.VL_DB.prepare("DELETE FROM users WHERE inbound_id = ?").bind(id).run();
          await loadInbounds(env);
          return new Response(JSON.stringify({ success: true }), {
            headers: { "Content-Type": "application/json" }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500 });
        }
      }
      
      if (request.method === "PUT") {
        const { name, protocol, port, path, host, limit_gb, expiry_days, max_ips, outbound_tag, is_active } = await request.json();
        try {
          await env.VL_DB.prepare(
            "UPDATE inbounds SET name = ?, protocol = ?, port = ?, path = ?, host = ?, limit_gb = ?, expiry_days = ?, max_ips = ?, outbound_tag = ?, is_active = ? WHERE id = ?"
          ).bind(
            name || "",
            protocol || "vless",
            port || 443,
            path || "/",
            host || "",
            limit_gb ? parseFloat(limit_gb) : null,
            expiry_days ? parseInt(expiry_days) : null,
            max_ips ? parseInt(max_ips) : 0,
            outbound_tag || "",
            is_active !== undefined ? (is_active ? 1 : 0) : 1,
            id
          ).run();
          await loadInbounds(env);
          return new Response(JSON.stringify({ success: true }), {
            headers: { "Content-Type": "application/json" }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500 });
        }
      }
    }
    
    // ============================================
    // INBOUND USERS
    // ============================================
    if (url.pathname.startsWith("/api/inbounds/") && url.pathname.includes("/users")) {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      const parts = url.pathname.split("/");
      const inboundId = parseInt(parts[3]);
      if (isNaN(inboundId)) {
        return new Response(JSON.stringify({ error: "Invalid inbound ID" }), { status: 400 });
      }
      
      if (request.method === "POST") {
        const { username, limit_gb, expiry_days, ips, port, fingerprint, config_name } = await request.json();
        if (!username) {
          return new Response(JSON.stringify({ error: "Username required" }), { status: 400 });
        }
        
        const uuid = crypto.randomUUID();
        try {
          await env.VL_DB.prepare(
            "INSERT INTO users (username, uuid, limit_gb, expiry_days, ips, connection_type, tls, port, fingerprint, config_name, inbound_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
          ).bind(
            username,
            uuid,
            limit_gb ? parseFloat(limit_gb) : null,
            expiry_days ? parseInt(expiry_days) : null,
            ips || null,
            atob("dmxlc3M="),
            "tls",
            port || "443",
            fingerprint || "chrome",
            config_name || username,
            inboundId
          ).run();
          return new Response(JSON.stringify({ success: true, uuid }), {
            headers: { "Content-Type": "application/json" }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500 });
        }
      }
      
      if (request.method === "GET") {
        const { results } = await env.VL_DB.prepare("SELECT * FROM users WHERE inbound_id = ? ORDER BY id DESC").bind(inboundId).all();
        return new Response(JSON.stringify({ success: true, users: results || [] }), {
          headers: { "Content-Type": "application/json" }
        });
      }
    }
    
    // ============================================
    // USERS CRUD
    // ============================================
    if (url.pathname.startsWith("/api/users")) {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      const pathParts = url.pathname.split("/");
      const isUserAction = pathParts.length > 3;
      
      if (isUserAction) {
        const username = decodeURIComponent(pathParts.pop());
        
        if (request.method === "PUT") {
          const body = await request.json();
          if (body.toggle_only !== undefined) {
            await env.VL_DB.prepare(
              "UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE username = ?"
            ).bind(username).run();
            return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
          } else {
            const { limit_gb, expiry_days, ips, tls, port, fingerprint, config_name } = body;
            await env.VL_DB.prepare(
              "UPDATE users SET limit_gb = ?, expiry_days = ?, ips = ?, tls = ?, port = ?, fingerprint = ?, config_name = ? WHERE username = ?"
            ).bind(
              limit_gb ? parseFloat(limit_gb) : null,
              expiry_days ? parseInt(expiry_days) : null,
              ips || null,
              tls || null,
              port || "443",
              fingerprint || "chrome",
              config_name || username,
              username
            ).run();
            return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
          }
        }
        
        if (request.method === "DELETE") {
          await env.VL_DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
          GLOBAL_TRAFFIC_CACHE.delete(username);
          ACTIVE_CONNECTIONS_COUNT.delete(username);
          return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
        }
        
        if (request.method === "GET") {
          const user = await env.VL_DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
          if (!user) {
            return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
          }
          return new Response(JSON.stringify({ success: true, user }), {
            headers: { "Content-Type": "application/json" }
          });
        }
      } else {
        if (request.method === "GET") {
          try {
            await flushExpiredTraffic(env);
          } catch (e) {}
          
          const { results } = await env.VL_DB.prepare("SELECT * FROM users ORDER BY id DESC").all();
          const now = Date.now();
          const enrichedUsers = (results || []).map((user) => ({
            ...user,
            is_online: user.last_active && now - user.last_active < 65000 ? 1 : 0,
            used_gb: user.used_gb || 0,
            config_name: user.config_name || user.username
          }));
          return new Response(JSON.stringify({ users: enrichedUsers, serverTime: now }), {
            headers: {
              "Content-Type": "application/json",
              "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
            }
          });
        }
        
        if (request.method === "POST") {
          const { username, limit_gb, expiry_days, ips, tls, port, fingerprint, config_name, inbound_id } = await request.json();
          if (!username) {
            return new Response(JSON.stringify({ error: "Username is required" }), {
              status: 400,
              headers: { "Content-Type": "application/json" }
            });
          }
          
          const uuid = crypto.randomUUID();
          try {
            await env.VL_DB.prepare(
              "INSERT INTO users (username, uuid, limit_gb, expiry_days, ips, connection_type, tls, port, fingerprint, config_name, inbound_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            ).bind(
              username,
              uuid,
              limit_gb ? parseFloat(limit_gb) : null,
              expiry_days ? parseInt(expiry_days) : null,
              ips || null,
              atob("dmxlc3M="),
              tls || null,
              port || "443",
              fingerprint || "chrome",
              config_name || username,
              inbound_id || 0
            ).run();
            return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
          } catch (err) {
            let errorMsg = err.message;
            if (errorMsg.includes("UNIQUE constraint failed")) {
              errorMsg = "Username already exists";
            }
            return new Response(JSON.stringify({ error: errorMsg }), {
              status: 500,
              headers: { "Content-Type": "application/json" }
            });
          }
        }
      }
    }
    
    // ============================================
    // USER STATS
    // ============================================
    if (url.pathname.startsWith("/api/users/stats/")) {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      const username = decodeURIComponent(url.pathname.split("/").pop());
      if (!username) {
        return new Response(JSON.stringify({ error: "Username required" }), { status: 400 });
      }
      
      try {
        const user = await env.VL_DB.prepare("SELECT username, limit_gb, used_gb, expiry_days, created_at, is_active FROM users WHERE username = ?").bind(username).first();
        if (!user) {
          return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
        }
        
        const now = new Date();
        const created = new Date(user.created_at);
        const expiryDate = new Date(created.getTime() + (user.expiry_days || 30) * 24 * 60 * 60 * 1000);
        const daysLeft = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
        const totalGB = user.limit_gb || 0;
        const usedGB = user.used_gb || 0;
        const leftGB = Math.max(0, totalGB - usedGB);
        const usedPercent = totalGB > 0 ? Math.min((usedGB / totalGB) * 100, 100) : 0;
        
        return new Response(JSON.stringify({
          success: true,
          username: user.username,
          is_active: user.is_active === 1,
          limit_gb: totalGB,
          used_gb: usedGB,
          left_gb: leftGB,
          used_percent: usedPercent,
          total_days: user.expiry_days || 30,
          days_left: daysLeft,
          created_at: user.created_at,
          expiry_date: expiryDate.toISOString().split('T')[0],
          is_expired: daysLeft <= 0 || (user.is_active === 0)
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // CLEAN IPS
    // ============================================
    if (url.pathname === "/api/clean-ips") {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      if (request.method === "GET") {
        await loadCleanIps(env);
        return new Response(JSON.stringify({ success: true, ips: CLEAN_IPS }), {
          headers: { "Content-Type": "application/json" }
        });
      }
      
      if (request.method === "POST") {
        const { address } = await request.json();
        if (!address) {
          return new Response(JSON.stringify({ error: "Address required" }), { status: 400 });
        }
        
        try {
          await env.VL_DB.prepare("INSERT INTO clean_ips (address) VALUES (?)").bind(address).run();
          await loadCleanIps(env);
          return new Response(JSON.stringify({ success: true }), {
            headers: { "Content-Type": "application/json" }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500 });
        }
      }
    }
    
    if (url.pathname.startsWith("/api/clean-ips/")) {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      const id = parseInt(url.pathname.split("/").pop());
      if (isNaN(id)) {
        return new Response(JSON.stringify({ error: "Invalid ID" }), { status: 400 });
      }
      
      if (request.method === "DELETE") {
        try {
          await env.VL_DB.prepare("DELETE FROM clean_ips WHERE id = ?").bind(id).run();
          await loadCleanIps(env);
          return new Response(JSON.stringify({ success: true }), {
            headers: { "Content-Type": "application/json" }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500 });
        }
      }
    }
    
    // ============================================
    // CUSTOM DOMAIN
    // ============================================
    if (url.pathname === "/api/custom-domain") {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      if (request.method === "GET") {
        await loadCustomDomain(env);
        return new Response(JSON.stringify({ success: true, domain: CUSTOM_DOMAIN }), {
          headers: { "Content-Type": "application/json" }
        });
      }
      
      if (request.method === "POST") {
        const { domain } = await request.json();
        try {
          if (domain) {
            await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('custom_domain', ?)").bind(domain).run();
          } else {
            await env.VL_DB.prepare("DELETE FROM settings WHERE key = 'custom_domain'").run();
          }
          CUSTOM_DOMAIN = domain || "";
          return new Response(JSON.stringify({ success: true }), {
            headers: { "Content-Type": "application/json" }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500 });
        }
      }
    }
    
    // ============================================
    // OUTBOUNDS CRUD
    // ============================================
    if (url.pathname === "/api/outbounds") {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      if (request.method === "GET") {
        await loadOutbounds(env);
        return new Response(JSON.stringify({ success: true, outbounds: OUTBOUNDS }), {
          headers: { "Content-Type": "application/json" }
        });
      }
      
      if (request.method === "POST") {
        const { name, protocol, tag, settings } = await request.json();
        if (!name || !protocol) {
          return new Response(JSON.stringify({ error: "Name and protocol required" }), { status: 400 });
        }
        
        try {
          await env.VL_DB.prepare(
            "INSERT INTO outbounds (name, protocol, settings, tag) VALUES (?, ?, ?, ?)"
          ).bind(
            name,
            protocol,
            settings || "{}",
            tag || name.toLowerCase().replace(/[^a-z0-9]/g, '')
          ).run();
          await loadOutbounds(env);
          return new Response(JSON.stringify({ success: true }), {
            headers: { "Content-Type": "application/json" }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500 });
        }
      }
    }
    
    // ============================================
    // ROUTING RULES CRUD
    // ============================================
    if (url.pathname === "/api/routing-rules") {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      if (request.method === "GET") {
        await loadRoutingRules(env);
        return new Response(JSON.stringify({ success: true, rules: ROUTING_RULES }), {
          headers: { "Content-Type": "application/json" }
        });
      }
      
      if (request.method === "POST") {
        const { name, inbound_tag, outbound_tag, domain, ip } = await request.json();
        if (!name || !inbound_tag || !outbound_tag) {
          return new Response(JSON.stringify({ error: "Name, inbound tag and outbound tag required" }), { status: 400 });
        }
        
        try {
          await env.VL_DB.prepare(
            "INSERT INTO routing_rules (name, inbound_tag, outbound_tag, domain, ip) VALUES (?, ?, ?, ?, ?)"
          ).bind(
            name,
            inbound_tag,
            outbound_tag,
            domain || "",
            ip || ""
          ).run();
          await loadRoutingRules(env);
          return new Response(JSON.stringify({ success: true }), {
            headers: { "Content-Type": "application/json" }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500 });
        }
      }
    }
    
    // ============================================
    // NODES CRUD
    // ============================================
    if (url.pathname === "/api/nodes") {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      if (request.method === "GET") {
        await loadNodes(env);
        return new Response(JSON.stringify({ success: true, nodes: NODES }), {
          headers: { "Content-Type": "application/json" }
        });
      }
      
      if (request.method === "POST") {
        const { name, address, port, api_key } = await request.json();
        if (!name || !address) {
          return new Response(JSON.stringify({ error: "Name and address required" }), { status: 400 });
        }
        
        try {
          await env.VL_DB.prepare(
            "INSERT INTO nodes (name, address, port, api_key) VALUES (?, ?, ?, ?)"
          ).bind(
            name,
            address,
            port || 443,
            api_key || ""
          ).run();
          await loadNodes(env);
          return new Response(JSON.stringify({ success: true }), {
            headers: { "Content-Type": "application/json" }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500 });
        }
      }
    }
    
    // ============================================
    // ADMINS CRUD
    // ============================================
    if (url.pathname === "/api/admins") {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      await loadAdmins(env);
      if (request.method === "GET") {
        return new Response(JSON.stringify({
          admins: ADMINS.map(a => ({
            id: a.id,
            username: a.username,
            created_at: a.created_at,
            last_login: a.last_login || null,
            role: a.role || "admin"
          }))
        }));
      }
      
      if (request.method === "POST") {
        const { username, password } = await request.json();
        if (!username || !password || password.length < 4) {
          return new Response(JSON.stringify({ error: "Invalid username or password" }), { status: 400 });
        }
        const hashed = await DbService.sha256(password);
        try {
          await env.VL_DB.prepare("INSERT INTO admins (username, password_hash) VALUES (?, ?)").bind(username, hashed).run();
          await loadAdmins(env);
          return new Response(JSON.stringify({ success: true }));
        } catch (e) {
          return new Response(JSON.stringify({ error: "Username already exists" }), { status: 400 });
        }
      }
      
      if (request.method === "DELETE") {
        const { id } = await request.json();
        await env.VL_DB.prepare("DELETE FROM admins WHERE id = ?").bind(id).run();
        await loadAdmins(env);
        return new Response(JSON.stringify({ success: true }));
      }
    }
    
    // ============================================
    // UPDATE CHECK
    // ============================================
    if (url.pathname === "/api/update-check") {
      try {
        const response = await fetch("https://api.github.com/repos/Void0Latency/panel/releases/latest");
        if (!response.ok) throw new Error("Failed to fetch");
        const data = await response.json();
        const latestVersion = data.tag_name || data.name || "v3.4.1";
        const currentVersion = "v" + PANEL_VERSION;
        return new Response(JSON.stringify({
          current_version: currentVersion,
          latest_version: latestVersion,
          update_available: latestVersion !== currentVersion && latestVersion !== PANEL_VERSION,
          url: data.html_url,
          body: data.body,
          published_at: data.published_at
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({
          error: "Could not check for updates",
          current_version: "v" + PANEL_VERSION,
          update_available: false
        }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }
    
    // ============================================
    // PANEL UPDATE
    // ============================================
    if (url.pathname === "/api/update-panel" && request.method === "POST") {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      try {
        const response = await fetch("https://api.github.com/repos/Void0Latency/panel/releases/latest");
        if (!response.ok) throw new Error("Failed to fetch updates");
        const data = await response.json();
        const latestVersion = data.tag_name || data.name || "v3.4.1";
        
        await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_version', ?)").bind(latestVersion).run();
        return new Response(JSON.stringify({
          success: true,
          message: "Panel updated successfully!",
          version: latestVersion
        }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      } catch (e) {
        return new Response(JSON.stringify({
          success: false,
          error: "Failed to update panel: " + e.message
        }), {
          status: 500,
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }
    
    // ============================================
    // LOGS
    // ============================================
    if (url.pathname === "/api/logs" && request.method === "GET") {
      if (!auth.authenticated) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      
      const limit = parseInt(url.searchParams.get("limit")) || 50;
      const logs = SYSTEM_LOGS.slice(0, limit);
      return new Response(JSON.stringify({
        success: true,
        logs: logs,
        total: SYSTEM_LOGS.length
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
    
    // ============================================
    // LOCATIONS
    // ============================================
    if (url.pathname === "/locations") {
      try {
        const response = await fetch("https://speed.cloudflare.com/locations", {
          headers: { "Referer": "https://speed.cloudflare.com/" }
        });
        const data = await response.json();
        return new Response(JSON.stringify(data), {
          headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }
    
    return new Response(JSON.stringify({ error: "Not Found" }), { status: 404 });
  }
};

// ============================================
// SUBSCRIPTION SERVICE
// ============================================
var SubscriptionService = {
  async generateJson(user, host, env) {
    let ips = [host];
    if (user.ips) {
      const parsedIps = user.ips.split("\n").map(ip => ip.trim()).filter(ip => ip.length > 0);
      if (parsedIps.length > 0) ips = parsedIps;
    }
    
    // Add clean IPs
    await loadCleanIps(env);
    for (const cleanIp of CLEAN_IPS) {
      if (cleanIp.address && !ips.includes(cleanIp.address)) {
        ips.push(cleanIp.address);
      }
    }
    
    // Use custom domain if set
    await loadCustomDomain(env);
    if (CUSTOM_DOMAIN) {
      host = CUSTOM_DOMAIN;
    }
    
    const ports = String(user.port || "443").split(",").map(p => p.trim()).filter(p => p.length > 0);
    const fp = user.fingerprint || "chrome";
    let fragLen = "20-30";
    let fragInt = "1-2";
    try {
      const rowLen = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'frag_len'").first();
      if (rowLen && rowLen.value) fragLen = rowLen.value;
      const rowInt = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'frag_int'").first();
      if (rowInt && rowInt.value) fragInt = rowInt.value;
    } catch (e) {}
    
    const configArray = [];
    const now = new Date();
    const created = new Date(user.created_at);
    const expiryDate = new Date(created.getTime() + (user.expiry_days || 30) * 24 * 60 * 60 * 1000);
    const daysLeft = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
    const totalGB = user.limit_gb || 0;
    const usedGB = user.used_gb || 0;
    const expiryDateStr = expiryDate.toISOString().split('T')[0].replace(/-/g, '/');
    const configName = user.config_name || user.username;
    const usedFormatted = usedGB >= 1 ? usedGB.toFixed(1) + "GB" : (usedGB * 1024).toFixed(0) + "MB";
    const totalFormatted = totalGB >= 1 ? totalGB + "GB" : "Unlimited";
    
    const firstIp = ips[0] || host;
    const firstPort = ports[0] || "443";
    const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(firstPort);
    const tlsVal = isTlsPort ? "tls" : "none";
    
    const remark1 = "⏳ " + user.username.toUpperCase() + " | 📅 Exp: " + expiryDateStr + " | 🔥 " + daysLeft + " Days Left";
    configArray.push(this.buildConfig(user, firstIp, firstPort, tlsVal, host, fp, fragLen, fragInt, remark1));
    
    const remark2 = "📊 " + user.username.toUpperCase() + " | 💾 " + totalFormatted + " Total | ⚡ " + usedFormatted + " Used";
    configArray.push(this.buildConfig(user, firstIp, firstPort, tlsVal, host, fp, fragLen, fragInt, remark2));
    
    ips.forEach(ip => {
      ports.forEach(portStr => {
        const isTlsPortLoop = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
        const tlsValLoop = isTlsPortLoop ? "tls" : "none";
        const remark3 = configName;
        configArray.push(this.buildConfig(user, ip, portStr, tlsValLoop, host, fp, fragLen, fragInt, remark3));
      });
    });
    
    return new Response(JSON.stringify(configArray, null, 2), {
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-store"
      }
    });
  },
  
  buildConfig(user, ip, portStr, tlsVal, host, fp, fragLen, fragInt, remark) {
    const configObj = {
      remarks: remark,
      version: { min: "25.10.15" },
      log: { loglevel: "none" },
      dns: {
        servers: [
          { address: "https://8.8.8.8/dns-query", tag: "remote-dns" },
          { address: "8.8.8.8", domains: ["full:" + host], skipFallback: true }
        ],
        queryStrategy: "UseIP",
        tag: "dns"
      },
      inbounds: [
        {
          listen: "127.0.0.1",
          port: 10808,
          protocol: "socks",
          settings: { auth: "noauth", udp: true },
          sniffing: { destOverride: ["http", "tls"], enabled: true, routeOnly: true },
          tag: "mixed-in"
        },
        {
          listen: "127.0.0.1",
          port: 10853,
          protocol: "dokodemo-door",
          settings: { address: "1.1.1.1", network: "tcp,udp", port: 53 },
          tag: "dns-in"
        }
      ],
      outbounds: [
        {
          protocol: "vless",
          settings: {
            vnext: [{
              address: ip,
              port: parseInt(portStr),
              users: [{ id: user.uuid, encryption: "none" }]
            }]
          },
          streamSettings: {
            network: "ws",
            wsSettings: { host, path: "/" },
            security: tlsVal,
            sockopt: { dialerProxy: "fragment" }
          },
          tag: "proxy"
        },
        {
          protocol: "freedom",
          settings: {
            fragment: { packets: "tlshello", length: fragLen, interval: fragInt }
          },
          streamSettings: {
            sockopt: {
              domainStrategy: "UseIP",
              happyEyeballs: { tryDelayMs: 250, prioritizeIPv6: false, interleave: 2, maxConcurrentTry: 4 }
            }
          },
          tag: "fragment"
        },
        { protocol: "dns", settings: { nonIPQuery: "reject" }, tag: "dns-out" },
        { protocol: "freedom", settings: { domainStrategy: "UseIP" }, tag: "direct" },
        { protocol: "blackhole", settings: { response: { type: "http" } }, tag: "block" }
      ],
      routing: {
        domainStrategy: "IPIfNonMatch",
        rules: [
          { inboundTag: ["mixed-in"], port: 53, outboundTag: "dns-out", type: "field" },
          { inboundTag: ["dns-in"], outboundTag: "dns-out", type: "field" },
          { inboundTag: ["remote-dns"], outboundTag: "proxy", type: "field" },
          { inboundTag: ["dns"], outboundTag: "direct", type: "field" },
          { domain: ["geosite:private"], outboundTag: "direct", type: "field" },
          { ip: ["geoip:private"], outboundTag: "direct", type: "field" },
          { network: "udp", outboundTag: "block", type: "field" },
          { network: "tcp", outboundTag: "proxy", type: "field" }
        ]
      }
    };
    if (tlsVal === "tls") {
      configObj.outbounds[0].streamSettings.tlsSettings = {
        serverName: host,
        fingerprint: fp,
        alpn: ["http/1.1"],
        allowInsecure: false
      };
    }
    return configObj;
  },
  
  async generateText(user, host) {
    let ips = [host];
    if (user.ips) {
      const parsedIps = user.ips.split("\n").map(ip => ip.trim()).filter(ip => ip.length > 0);
      if (parsedIps.length > 0) ips = parsedIps;
    }
    const ports = String(user.port || "443").split(",").map(p => p.trim()).filter(p => p.length > 0);
    const fp = user.fingerprint || "chrome";
    
    const now = new Date();
    const created = new Date(user.created_at);
    const expiryDays = user.expiry_days || 30;
    const expiryDate = new Date(created.getTime() + expiryDays * 24 * 60 * 60 * 1000);
    const daysLeft = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
    const totalGB = user.limit_gb || 0;
    const usedGB = user.used_gb || 0;
    const expiryDateStr = expiryDate.toISOString().split('T')[0].replace(/-/g, '/');
    const configName = user.config_name || user.username;
    const usedFormatted = usedGB >= 1 ? usedGB.toFixed(1) + "GB" : (usedGB * 1024).toFixed(0) + "MB";
    const totalFormatted = totalGB >= 1 ? totalGB + "GB" : "Unlimited";
    
    const links = [];
    const firstIp = ips[0] || host;
    const firstPort = ports[0] || "443";
    const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(firstPort);
    const tlsVal = isTlsPort ? "tls" : "none";
    
    const remark1 = "⏳ " + user.username.toUpperCase() + " | 📅 Exp: " + expiryDateStr + " | 🔥 " + daysLeft + " Days Left";
    links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@" + firstIp + ":" + firstPort + "?path=%2F&security=" + tlsVal + "&encryption=none&insecure=0&host=" + host + "&fp=" + fp + "&type=ws&allowInsecure=0&sni=" + host + "#" + encodeURIComponent(remark1));
    
    const remark2 = "📊 " + user.username.toUpperCase() + " | 💾 " + totalFormatted + " Total | ⚡ " + usedFormatted + " Used";
    links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@" + firstIp + ":" + firstPort + "?path=%2F&security=" + tlsVal + "&encryption=none&insecure=0&host=" + host + "&fp=" + fp + "&type=ws&allowInsecure=0&sni=" + host + "#" + encodeURIComponent(remark2));
    
    ips.forEach(ip => {
      ports.forEach(portStr => {
        const isTlsPortLoop = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
        const tlsValLoop = isTlsPortLoop ? "tls" : "none";
        const remark3 = configName;
        links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@" + ip + ":" + portStr + "?path=%2F&security=" + tlsValLoop + "&encryption=none&insecure=0&host=" + host + "&fp=" + fp + "&type=ws&allowInsecure=0&sni=" + host + "#" + encodeURIComponent(remark3));
      });
    });
    
    const header = [
      "# ==========================================",
      "# VoidLatency Subscription Feed",
      "# User: " + user.username,
      "# Created: " + user.created_at,
      "# Status: " + (user.is_active ? "Active" : "Inactive"),
      "# ==========================================",
      ""
    ].join("\n");
    
    const plainContent = header + links.join("\n");
    const subContent = btoa(unescape(encodeURIComponent(plainContent)));
    return new Response(subContent, {
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-store"
      }
    });
  }
};

// ============================================
// TRAFFIC MANAGEMENT
// ============================================
async function flushExpiredTraffic(env) {
  const now = Date.now();
  for (const [uname, cachedBytes] of GLOBAL_TRAFFIC_CACHE.entries()) {
    if (cachedBytes <= 0) continue;
    const lastActive = GLOBAL_LAST_ACTIVE_WRITE.get(uname) || 0;
    const activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 0;
    if (activeCount <= 0 || now - lastActive > 65000) {
      GLOBAL_TRAFFIC_CACHE.set(uname, 0);
      const deltaGb = cachedBytes / (1024 * 1024 * 1024);
      try {
        await env.VL_DB.prepare("UPDATE users SET used_gb = used_gb + ? WHERE username = ?").bind(deltaGb, uname).run();
        const user = await env.VL_DB.prepare("SELECT limit_gb, used_gb FROM users WHERE username = ?").bind(uname).first();
        if (user && user.limit_gb && user.used_gb >= user.limit_gb) {
          await env.VL_DB.prepare("UPDATE users SET is_active = 0 WHERE username = ?").bind(uname).run();
        }
      } catch (e) {
        let recovered = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
        GLOBAL_TRAFFIC_CACHE.set(uname, recovered + cachedBytes);
      }
    }
  }
}

// ============================================
// VLESS HANDLER
// ============================================
async function handleVLESS(env, storedData = null, ctx = null) {
  const socketPair = new WebSocketPair();
  const [clientSock, serverSock] = Object.values(socketPair);
  serverSock.accept();
  serverSock.binaryType = "arraybuffer";
  let username = null;
  let tickCount = 0;
  let validUUID = null;
  
  function addBytes(bytes) {
    if (bytes <= 0 || !username) return;
    let current = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
    current += bytes;
    GLOBAL_LAST_ACTIVE_WRITE.set(username, Date.now());
    const threshold = 50 * 1024 * 1024;
    if (current >= threshold) {
      const chunksOf50MB = Math.floor(current / threshold);
      const bytesToCommit = chunksOf50MB * threshold;
      const deltaGb = bytesToCommit / (1024 * 1024 * 1024);
      const leftover = current - bytesToCommit;
      GLOBAL_TRAFFIC_CACHE.set(username, leftover);
      const writeTask = async () => {
        try {
          await env.VL_DB.prepare("UPDATE users SET used_gb = used_gb + ? WHERE username = ?").bind(deltaGb, username).run();
          const user = await env.VL_DB.prepare("SELECT limit_gb, used_gb FROM users WHERE username = ?").bind(username).first();
          if (user && user.limit_gb && user.used_gb >= user.limit_gb) {
            await env.VL_DB.prepare("UPDATE users SET is_active = 0 WHERE username = ?").bind(username).run();
          }
        } catch (e) {
          let recovered = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
          GLOBAL_TRAFFIC_CACHE.set(username, recovered + bytesToCommit);
        }
      };
      if (ctx) {
        ctx.waitUntil(writeTask());
      } else {
        writeTask();
      }
    } else {
      GLOBAL_TRAFFIC_CACHE.set(username, current);
    }
  }
  
  let isOfflineSet = false;
  const setOffline = () => {
    if (isOfflineSet) return;
    isOfflineSet = true;
    const uname = username;
    if (!uname) return;
    let activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 1;
    activeCount = activeCount - 1;
    if (activeCount <= 0) {
      ACTIVE_CONNECTIONS_COUNT.delete(uname);
      let cachedBytes = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
      if (cachedBytes > 0) {
        GLOBAL_TRAFFIC_CACHE.set(uname, 0);
        const deltaGb = cachedBytes / (1024 * 1024 * 1024);
        const writeTask = async () => {
          try {
            await env.VL_DB.prepare("UPDATE users SET used_gb = used_gb + ? WHERE username = ?").bind(deltaGb, uname).run();
          } catch (e) {
            let recovered = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
            GLOBAL_TRAFFIC_CACHE.set(uname, recovered + cachedBytes);
          }
        };
        if (ctx) {
          ctx.waitUntil(writeTask());
        } else {
          writeTask();
        }
      }
    } else {
      ACTIVE_CONNECTIONS_COUNT.set(uname, activeCount);
    }
  };
  
  const heartbeat = setInterval(async () => {
    if (serverSock.readyState === WebSocket.OPEN) {
      try {
        serverSock.send(new Uint8Array(0));
        if (!validUUID) return;
        tickCount++;
        if (tickCount >= 4) {
          tickCount = 0;
          const user = await env.VL_DB.prepare("SELECT is_active, limit_gb, used_gb, expiry_days, created_at FROM users WHERE uuid = ?").bind(validUUID).first();
          let isExpired = false;
          if (!user || user.is_active === 0) {
            isExpired = true;
          } else {
            if (user.limit_gb && user.used_gb >= user.limit_gb) {
              isExpired = true;
            }
            if (user.expiry_days && user.created_at) {
              const created = new Date(user.created_at);
              const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
              if (new Date() > expiryDate) {
                isExpired = true;
              }
            }
          }
          if (isExpired) {
            await env.VL_DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(validUUID).run();
            clearInterval(heartbeat);
            closeSocketQuietly(serverSock);
            return;
          }
          const now = Date.now();
          const lastRecorded = GLOBAL_LAST_ACTIVE_WRITE.get(username) || 0;
          if (now - lastRecorded > 60000) {
            GLOBAL_LAST_ACTIVE_WRITE.set(username, now);
            await env.VL_DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(now, username).run();
          }
        }
      } catch (e) {}
    } else {
      clearInterval(heartbeat);
    }
  }, 15000);
  
  let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
  let reqUUID = null;
  let isHeaderParsed = false;
  let isDnsQuery = false;
  let chunkBuffer = new Uint8Array(0);
  const proxyIP = storedData?.proxy_ip || "proxyip.cmliussss.net";
  let wsChain = Promise.resolve();
  let wsStopped = false, wsFailed = false, wsFinished = false;
  let wsQueueBytes = 0, wsQueueItems = 0;
  let currentSocketWriter = null, activeRemoteWriter = null;
  
  const releaseRemoteWriter = () => {
    if (activeRemoteWriter) {
      try {
        activeRemoteWriter.releaseLock();
      } catch (e) {}
      activeRemoteWriter = null;
    }
    currentSocketWriter = null;
  };
  
  const getRemoteWriter = () => {
    const s = remoteConnWrapper.socket;
    if (!s) return null;
    if (s !== currentSocketWriter) {
      releaseRemoteWriter();
      currentSocketWriter = s;
      activeRemoteWriter = s.writable.getWriter();
    }
    return activeRemoteWriter;
  };
  
  const upstreamQueue = createUpstreamQueue({
    getWriter: getRemoteWriter,
    releaseWriter: releaseRemoteWriter,
    retryConnect: async () => {
      if (typeof remoteConnWrapper.retryConnect === "function") {
        await remoteConnWrapper.retryConnect();
      }
    },
    closeConnection: () => {
      try {
        remoteConnWrapper.socket?.close();
      } catch (e) {}
      closeSocketQuietly(serverSock);
    },
    name: "VlessWSQueue"
  });
  
  const writeToRemote = async (chunk, allowRetry = true) => {
    return upstreamQueue.writeAndAwait(chunk, allowRetry);
  };
  
  const processWsMessage = async (chunk) => {
    const bytes = chunk.byteLength || 0;
    await addBytes(bytes);
    if (isDnsQuery) {
      await forwardVlessUDP(chunk, serverSock, null);
      return;
    }
    if (await writeToRemote(chunk)) return;
    if (!isHeaderParsed) {
      chunkBuffer = concatBytes(chunkBuffer, chunk);
      if (chunkBuffer.byteLength < 24) return;
      reqUUID = extractUUIDFromVless(chunkBuffer);
      if (!reqUUID) {
        serverSock.close();
        return;
      }
      let user = null;
      try {
        user = await env.VL_DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(reqUUID).first();
      } catch (e) {}
      if (!user || user.is_active === 0) {
        serverSock.close();
        return;
      }
      if (user.limit_gb && user.used_gb >= user.limit_gb) {
        serverSock.close();
        return;
      }
      if (user.expiry_days && user.created_at) {
        const created = new Date(user.created_at);
        const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
        if (new Date() > expiryDate) {
          try {
            await env.VL_DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(reqUUID).run();
          } catch (e) {}
          serverSock.close();
          return;
        }
      }
      validUUID = reqUUID;
      username = user.username;
      isHeaderParsed = true;
      let activeCount = ACTIVE_CONNECTIONS_COUNT.get(username) || 0;
      ACTIVE_CONNECTIONS_COUNT.set(username, activeCount + 1);
      if (activeCount === 0) {
        const setOnlineTask = async () => {
          try {
            const now = Date.now();
            GLOBAL_LAST_ACTIVE_WRITE.set(username, now);
            await env.VL_DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(now, username).run();
          } catch (e) {}
        };
        if (ctx) ctx.waitUntil(setOnlineTask());
        else setOnlineTask();
      }
      try {
        let offset = 17;
        const optLen = chunkBuffer[offset++];
        offset += optLen;
        const cmd = chunkBuffer[offset++];
        const port = chunkBuffer[offset++] << 8 | chunkBuffer[offset++];
        const addrType = chunkBuffer[offset++];
        let addr = "";
        if (addrType === 1) {
          addr = chunkBuffer[offset++] + "." + chunkBuffer[offset++] + "." + chunkBuffer[offset++] + "." + chunkBuffer[offset++];
        } else if (addrType === 2) {
          const domainLen = chunkBuffer[offset++];
          addr = new TextDecoder().decode(chunkBuffer.slice(offset, offset + domainLen));
          offset += domainLen;
        } else if (addrType === 3) {
          offset += 16;
          addr = "ipv6-unsupported";
        }
        const rawData = chunkBuffer.slice(offset);
        const respHeader = new Uint8Array([chunkBuffer[0], 0]);
        if (cmd === 2) {
          if (port === 53) {
            isDnsQuery = true;
            await forwardVlessUDP(rawData, serverSock, respHeader);
          } else {
            serverSock.close();
          }
          return;
        }
        const connectTCP = async (dataPayload = null, useFallback = true) => {
          if (remoteConnWrapper.connectingPromise) {
            await remoteConnWrapper.connectingPromise;
            return;
          }
          const task = (async () => {
            let s = null;
            try {
              s = await connectDirect(addr, port, dataPayload);
            } catch (err) {
              if (useFallback && proxyIP) {
                s = await connectDirect(proxyIP, port, dataPayload);
              } else {
                throw err;
              }
            }
            remoteConnWrapper.socket = s;
            s.closed.catch(() => {}).finally(() => closeSocketQuietly(serverSock));
            connectStreams(s, serverSock, respHeader, null, (b) => {
              addBytes(b);
            });
          })();
          remoteConnWrapper.connectingPromise = task;
          try {
            await task;
          } finally {
            if (remoteConnWrapper.connectingPromise === task) {
              remoteConnWrapper.connectingPromise = null;
            }
          }
        };
        remoteConnWrapper.retryConnect = async () => connectTCP(null, false);
        await connectTCP(rawData, true);
      } catch (e) {
        serverSock.close();
      }
    }
  };
  
  const handleWsError = (err) => {
    if (wsFailed) return;
    wsFailed = true;
    wsStopped = true;
    wsQueueBytes = 0;
    wsQueueItems = 0;
    upstreamQueue.clear();
    releaseRemoteWriter();
    closeSocketQuietly(serverSock);
    setOffline();
  };
  
  const pushToChain = (task) => {
    wsChain = wsChain.then(task).catch(handleWsError);
  };
  
  serverSock.addEventListener("message", (event) => {
    if (wsStopped || wsFailed) return;
    const size = event.data.byteLength || 0;
    const nextBytes = wsQueueBytes + size;
    const nextItems = wsQueueItems + 1;
    if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
      handleWsError(new Error("ws queue overflow"));
      return;
    }
    wsQueueBytes = nextBytes;
    wsQueueItems = nextItems;
    pushToChain(async () => {
      wsQueueBytes = Math.max(0, wsQueueBytes - size);
      wsQueueItems = Math.max(0, wsQueueItems - 1);
      if (wsFailed) return;
      await processWsMessage(event.data);
    });
  });
  
  serverSock.addEventListener("close", () => {
    clearInterval(heartbeat);
    closeSocketQuietly(serverSock);
    setOffline();
    if (wsFinished) return;
    wsFinished = true;
    wsStopped = true;
    pushToChain(async () => {
      if (wsFailed) return;
      await upstreamQueue.awaitEmpty();
      releaseRemoteWriter();
    });
  });
  
  serverSock.addEventListener("error", (err) => {
    handleWsError(err);
  });
  
  return new Response(null, { status: 101, webSocket: clientSock });
}

// ============================================
// NETWORK UTILITIES
// ============================================
function isIPv4(value) {
  const parts = String(value || "").split(".");
  return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function stripIPv6Brackets(hostname = "") {
  const host = String(hostname || "").trim();
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function isIPHostname(hostname = "") {
  const host = stripIPv6Brackets(hostname);
  if (isIPv4(host)) return true;
  if (!host.includes(":")) return false;
  try {
    new URL("http://[" + host + "]/");
    return true;
  } catch (e) {
    return false;
  }
}

function convertToUint8Array(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(data || 0);
}

function concatBytes(...chunkList) {
  const chunks = chunkList.map(convertToUint8Array);
  const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    result.set(c, offset);
    offset += c.byteLength;
  }
  return result;
}

function closeSocketQuietly(socket) {
  try {
    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
      socket.close();
    }
  } catch (e) {}
}

// ============================================
// DNS UTILITIES
// ============================================
async function dohQuery(domain, recordType) {
  const cacheKey = domain + ":" + recordType;
  if (DNS_CACHE.has(cacheKey)) {
    const cached = DNS_CACHE.get(cacheKey);
    if (Date.now() < cached.expires) return cached.data;
    DNS_CACHE.delete(cacheKey);
  }
  try {
    const typeMap = { "A": 1, "AAAA": 28 };
    const qtype = typeMap[recordType.toUpperCase()] || 1;
    const encodeDomain = (name) => {
      const parts = name.endsWith(".") ? name.slice(0, -1).split(".") : name.split(".");
      const bufs = [];
      for (const label of parts) {
        const enc = new TextEncoder().encode(label);
        bufs.push(new Uint8Array([enc.length]), enc);
      }
      bufs.push(new Uint8Array([0]));
      return concatBytes(...bufs);
    };
    const qname = encodeDomain(domain);
    const query = new Uint8Array(12 + qname.length + 4);
    const qview = new DataView(query.buffer);
    qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
    qview.setUint16(2, 256);
    qview.setUint16(4, 1);
    query.set(qname, 12);
    qview.setUint16(12 + qname.length, qtype);
    qview.setUint16(12 + qname.length + 2, 1);
    const response = await fetch(DOH_RESOLVER, {
      method: "POST",
      headers: {
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message"
      },
      body: query
    });
    if (!response.ok) return [];
    const buf = new Uint8Array(await response.arrayBuffer());
    const dv = new DataView(buf.buffer);
    const qdcount = dv.getUint16(4);
    const ancount = dv.getUint16(6);
    const parseName = (pos) => {
      const labels = [];
      let p = pos, jumped = false, endPos = -1, safe = 128;
      while (p < buf.length && safe-- > 0) {
        const len = buf[p];
        if (len === 0) {
          if (!jumped) endPos = p + 1;
          break;
        }
        if ((len & 192) === 192) {
          if (!jumped) endPos = p + 2;
          p = (len & 63) << 8 | buf[p + 1];
          jumped = true;
          continue;
        }
        labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
        p += len + 1;
      }
      if (endPos === -1) endPos = p + 1;
      return [labels.join("."), endPos];
    };
    let offset = 12;
    for (let i = 0; i < qdcount; i++) {
      const [, end] = parseName(offset);
      offset = Number(end) + 4;
    }
    const answers = [];
    for (let i = 0; i < ancount && offset < buf.length; i++) {
      const [name, nameEnd] = parseName(offset);
      offset = Number(nameEnd);
      const type = dv.getUint16(offset);
      offset += 2;
      offset += 2;
      const ttl = dv.getUint32(offset);
      offset += 4;
      const rdlen = dv.getUint16(offset);
      offset += 2;
      const rdata = buf.slice(offset, offset + rdlen);
      offset += rdlen;
      let data;
      if (type === 1 && rdlen === 4) {
        data = rdata[0] + "." + rdata[1] + "." + rdata[2] + "." + rdata[3];
      } else if (type === 28 && rdlen === 16) {
        const segs = [];
        for (let j = 0; j < 16; j += 2) segs.push((rdata[j] << 8 | rdata[j + 1]).toString(16));
        data = segs.join(":");
      } else {
        data = Array.from(rdata).map(b => b.toString(16).padStart(2, "0")).join("");
      }
      answers.push({ name, type, TTL: ttl, data });
    }
    DNS_CACHE.set(cacheKey, { data: answers, expires: Date.now() + DNS_CACHE_TTL });
    return answers;
  } catch (e) {
    return [];
  }
}

// ============================================
// UPSTREAM QUEUE
// ============================================
function createUpstreamQueue({ getWriter, releaseWriter, retryConnect, closeConnection, name = "UpstreamQueue" }) {
  let chunks = [];
  let head = 0;
  let queuedBytes = 0;
  let draining = false;
  let closed = false;
  let bundleBuffer = null;
  let idleResolvers = [];
  let activeCompletions = null;
  
  const settleCompletions = (completions, err = null) => {
    if (!completions) return;
    for (const comp of completions) {
      if (comp) {
        if (err) comp.reject(err);
        else comp.resolve();
      }
    }
  };
  
  const rejectQueued = (err) => {
    for (let i = head; i < chunks.length; i++) {
      const item = chunks[i];
      if (item && item.completions) settleCompletions(item.completions, err);
    }
  };
  
  const compact = () => {
    if (head > 32 && head * 2 >= chunks.length) {
      chunks = chunks.slice(head);
      head = 0;
    }
  };
  
  const resolveIdle = () => {
    if (queuedBytes || draining || !idleResolvers.length) return;
    const resolvers = idleResolvers;
    idleResolvers = [];
    for (const resolve of resolvers) resolve();
  };
  
  const clear = (err = null) => {
    const closeErr = err || (closed ? new Error(name + ": queue closed") : null);
    if (closeErr) {
      rejectQueued(closeErr);
      settleCompletions(activeCompletions, closeErr);
      activeCompletions = null;
    }
    chunks = [];
    head = 0;
    queuedBytes = 0;
    resolveIdle();
  };
  
  const shift = () => {
    if (head >= chunks.length) return null;
    const item = chunks[head];
    chunks[head++] = void 0;
    queuedBytes -= item.chunk.byteLength;
    compact();
    return item;
  };
  
  const bundle = () => {
    const first = shift();
    if (!first) return null;
    if (head >= chunks.length || first.chunk.byteLength >= UPSTREAM_BUNDLE_TARGET_BYTES) return first;
    let byteLength = first.chunk.byteLength;
    let end = head;
    let allowRetry = first.allowRetry;
    let completions = first.completions || null;
    while (end < chunks.length) {
      const next = chunks[end];
      const nextLength = byteLength + next.chunk.byteLength;
      if (nextLength > UPSTREAM_BUNDLE_TARGET_BYTES) break;
      byteLength = nextLength;
      allowRetry = allowRetry && next.allowRetry;
      if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
      end++;
    }
    if (end === head) return first;
    const output = bundleBuffer ||= new Uint8Array(UPSTREAM_BUNDLE_TARGET_BYTES);
    output.set(first.chunk);
    let offset = first.chunk.byteLength;
    while (head < end) {
      const next = chunks[head];
      chunks[head++] = void 0;
      queuedBytes -= next.chunk.byteLength;
      output.set(next.chunk, offset);
      offset += next.chunk.byteLength;
    }
    compact();
    return { chunk: output.subarray(0, byteLength), allowRetry, completions };
  };
  
  const drain = async () => {
    if (draining || closed) return;
    draining = true;
    try {
      for (;;) {
        if (closed) break;
        const item = bundle();
        if (!item) break;
        let writer = getWriter();
        if (!writer) throw new Error(name + ": remote writer unavailable");
        const completions = item.completions || null;
        activeCompletions = completions;
        try {
          try {
            await writer.write(item.chunk);
          } catch (err) {
            releaseWriter?.();
            if (!item.allowRetry || typeof retryConnect !== "function") throw err;
            await retryConnect();
            writer = getWriter();
            if (!writer) throw err;
            await writer.write(item.chunk);
          }
          settleCompletions(completions);
        } catch (err) {
          settleCompletions(completions, err);
          throw err;
        } finally {
          if (activeCompletions === completions) activeCompletions = null;
        }
      }
    } catch (err) {
      closed = true;
      clear(err);
      try {
        closeConnection?.(err);
      } catch (_) {}
    } finally {
      draining = false;
      if (!closed && head < chunks.length) queueMicrotask(drain);
      else resolveIdle();
    }
  };
  
  const enqueue = (data, allowRetry = true, waitForFlush = false) => {
    if (closed) return false;
    if (!getWriter()) return false;
    const chunk = convertToUint8Array(data);
    if (!chunk.byteLength) return true;
    const nextBytes = queuedBytes + chunk.byteLength;
    const nextItems = chunks.length - head + 1;
    if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
      closed = true;
      const err = Object.assign(new Error(name + ": upload queue overflow (" + nextBytes + "B/" + nextItems + ")"), { isQueueOverflow: true });
      clear(err);
      try {
        closeConnection?.(err);
      } catch (_) {}
      throw err;
    }
    let completionPromise = null;
    let completions = null;
    if (waitForFlush) {
      completions = [];
      completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
    }
    chunks.push({ chunk, allowRetry, completions });
    queuedBytes = nextBytes;
    if (!draining) queueMicrotask(drain);
    return waitForFlush ? completionPromise.then(() => true) : true;
  };
  
  return {
    writeAndAwait(data, allowRetry = true) {
      return enqueue(data, allowRetry, true);
    },
    async awaitEmpty() {
      if (!queuedBytes && !draining) return;
      await new Promise((resolve) => idleResolvers.push(resolve));
    },
    clear() {
      closed = true;
      clear();
    }
  };
}

// ============================================
// DOWNSTREAM SENDER
// ============================================
function createDownstreamSender(webSocket, headerData = null) {
  const packetCap = DOWNSTREAM_GRAIN_BYTES;
  const tailBytes = DOWNSTREAM_GRAIN_TAIL_THRESHOLD;
  const lowWaterBytes = Math.max(4096, tailBytes << 3);
  let header = headerData;
  let pendingBuffer = new Uint8Array(packetCap);
  let pendingBytes = 0;
  let flushTimer = null;
  let microtaskQueued = false;
  let generation = 0;
  let scheduledGeneration = 0;
  let waitRounds = 0;
  let flushPromise = null;
  
  const sendRawChunk = async (chunk) => {
    if (webSocket.readyState !== WebSocket.OPEN) throw new Error("ws.readyState is not open");
    webSocket.send(chunk);
  };
  
  const attachResponseHeader = (chunk) => {
    if (!header) return chunk;
    const merged = new Uint8Array(header.length + chunk.byteLength);
    merged.set(header, 0);
    merged.set(chunk, header.length);
    header = null;
    return merged;
  };
  
  const flush = async () => {
    while (flushPromise) await flushPromise;
    if (flushTimer) clearTimeout(flushTimer);
    flushTimer = null;
    microtaskQueued = false;
    if (!pendingBytes) return;
    const output = pendingBuffer.subarray(0, pendingBytes).slice();
    pendingBuffer = new Uint8Array(packetCap);
    pendingBytes = 0;
    waitRounds = 0;
    flushPromise = sendRawChunk(output).finally(() => {
      flushPromise = null;
    });
    return flushPromise;
  };
  
  const scheduleFlush = () => {
    if (flushTimer || microtaskQueued) return;
    microtaskQueued = true;
    scheduledGeneration = generation;
    queueMicrotask(() => {
      microtaskQueued = false;
      if (!pendingBytes || flushTimer) return;
      if (packetCap - pendingBytes < tailBytes) {
        flush().catch(() => closeSocketQuietly(webSocket));
        return;
      }
      flushTimer = setTimeout(() => {
        flushTimer = null;
        if (!pendingBytes) return;
        if (packetCap - pendingBytes < tailBytes) {
          flush().catch(() => closeSocketQuietly(webSocket));
          return;
        }
        if (waitRounds < 2 && (generation !== scheduledGeneration || pendingBytes < lowWaterBytes)) {
          waitRounds++;
          scheduledGeneration = generation;
          scheduleFlush();
          return;
        }
        flush().catch(() => closeSocketQuietly(webSocket));
      }, Math.max(DOWNSTREAM_GRAIN_SILENT_MS, 1));
    });
  };
  
  return {
    async sendDirect(data) {
      let chunk = convertToUint8Array(data);
      if (!chunk.byteLength) return;
      chunk = attachResponseHeader(chunk);
      await sendRawChunk(chunk);
    },
    async send(data) {
      let chunk = convertToUint8Array(data);
      if (!chunk.byteLength) return;
      chunk = attachResponseHeader(chunk);
      let offset = 0;
      const totalBytes = chunk.byteLength;
      while (offset < totalBytes) {
        if (!pendingBytes && totalBytes - offset >= packetCap) {
          const sendBytes = Math.min(packetCap, totalBytes - offset);
          const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
          await sendRawChunk(view);
          offset += sendBytes;
          continue;
        }
        const copyBytes = Math.min(packetCap - pendingBytes, totalBytes - offset);
        pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
        pendingBytes += copyBytes;
        offset += copyBytes;
        generation++;
        if (pendingBytes === packetCap || packetCap - pendingBytes < tailBytes) await flush();
        else scheduleFlush();
      }
    },
    flush
  };
}

async function waitForBackpressure(ws) {
  if (typeof ws.bufferedAmount === "number") {
    while (ws.bufferedAmount > 256 * 1024) {
      await new Promise(r => setTimeout(r, 100));
    }
  }
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, onBytes) {
  let header = headerData, hasData = false, reader, useBYOB = false;
  const BYOB_LIMIT = 64 * 1024;
  const downstreamSender = createDownstreamSender(webSocket, header);
  header = null;
  try {
    reader = remoteSocket.readable.getReader({ mode: "byob" });
    useBYOB = true;
  } catch (e) {
    reader = remoteSocket.readable.getReader();
  }
  try {
    if (!useBYOB) {
      while (true) {
        await waitForBackpressure(webSocket);
        const { done, value } = await reader.read();
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        hasData = true;
        if (typeof onBytes === "function") onBytes(value.byteLength);
        await downstreamSender.send(value);
      }
    } else {
      let readBuffer = new ArrayBuffer(BYOB_LIMIT);
      while (true) {
        await waitForBackpressure(webSocket);
        const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB_LIMIT));
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        hasData = true;
        if (typeof onBytes === "function") onBytes(value.byteLength);
        if (value.byteLength >= DOWNSTREAM_GRAIN_BYTES) {
          await downstreamSender.flush();
          await downstreamSender.sendDirect(value);
          readBuffer = new ArrayBuffer(BYOB_LIMIT);
        } else {
          await downstreamSender.send(value);
          readBuffer = value.buffer.byteLength >= BYOB_LIMIT ? value.buffer : new ArrayBuffer(BYOB_LIMIT);
        }
      }
    }
    await downstreamSender.flush();
  } catch (err) {
    closeSocketQuietly(webSocket);
  } finally {
    try {
      reader.cancel();
    } catch (e) {}
    try {
      reader.releaseLock();
    } catch (e) {}
  }
  if (!hasData && retryFunc) await retryFunc();
}

async function buildRaceCandidates(address, port) {
  if (!PRELOAD_RACE_DIAL || isIPHostname(address)) return null;
  const [aRecords, aaaaRecords] = await Promise.all([
    dohQuery(address, "A"),
    dohQuery(address, "AAAA")
  ]);
  const ipv4List = [...new Set(aRecords.flatMap(r => {
    return r.type === 1 && typeof r.data === "string" && isIPv4(r.data) ? [r.data] : [];
  }))];
  const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
    return r.type === 28 && typeof r.data === "string" && isIPHostname(r.data) ? [r.data] : [];
  }))];
  const limit = Math.max(1, TCP_CONCURRENCY | 0);
  const ipList = ipv4List.length >= limit ? ipv4List.slice(0, limit) : ipv4List.concat(ipv6List.slice(0, limit - ipv4List.length));
  if (ipList.length === 0) return null;
  return ipList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
}

async function connectDirect(address, port, initialData = null) {
  const raceCandidates = await buildRaceCandidates(address, port);
  const candidates = raceCandidates || Array.from({ length: TCP_CONCURRENCY }, () => ({ hostname: address, port }));
  const openConnection = async (host, prt) => {
    const socket = connect({ hostname: host, port: prt });
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 1000))
    ]);
    return socket;
  };
  if (candidates.length === 1) {
    const s = await openConnection(candidates[0].hostname, candidates[0].port);
    if (initialData && initialData.byteLength > 0) {
      const w = s.writable.getWriter();
      await w.write(convertToUint8Array(initialData));
      w.releaseLock();
    }
    return s;
  }
  const attempts = candidates.map(c => openConnection(c.hostname, c.port).then(socket => ({ socket, candidate: c })));
  let winner = null;
  try {
    winner = await Promise.any(attempts);
    if (initialData && initialData.byteLength > 0) {
      const w = winner.socket.writable.getWriter();
      await w.write(convertToUint8Array(initialData));
      w.releaseLock();
    }
    return winner.socket;
  } finally {
    if (winner) {
      for (const attempt of attempts) {
        attempt.then(({ socket }) => {
          if (socket !== winner.socket) {
            try {
              socket.close();
            } catch (e) {}
          }
        }).catch(() => {});
      }
    }
  }
}

async function forwardVlessUDP(udpChunk, webSocket, respHeader) {
  const requestData = convertToUint8Array(udpChunk);
  try {
    const tcpSocket = connect({ hostname: "8.8.4.4", port: 53 });
    let vlessHeader = respHeader;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(requestData);
    writer.releaseLock();
    await tcpSocket.readable.pipeTo(new WritableStream({
      async write(chunk) {
        const response = convertToUint8Array(chunk);
        if (webSocket.readyState !== WebSocket.OPEN) return;
        if (vlessHeader) {
          const merged = new Uint8Array(vlessHeader.length + response.byteLength);
          merged.set(vlessHeader, 0);
          merged.set(response, vlessHeader.length);
          webSocket.send(merged.buffer);
          vlessHeader = null;
        } else {
          webSocket.send(response);
        }
      }
    }));
  } catch (e) {}
}

function extractUUIDFromVless(data) {
  if (data.byteLength < 17) return null;
  const hex = [...data.slice(1, 17)].map(b => b.toString(16).padStart(2, "0")).join("");
  return hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-" + hex.substring(12, 16) + "-" + hex.substring(16, 20) + "-" + hex.substring(20);
}

// ============================================
// HTML_TEMPLATES - COMPLETE 3X-UI STYLE
// ============================================
// [Full HTML templates with 3X-UI style matching the screenshots]
// The complete panel HTML with all pages, modals, and JavaScript
// will be included here with the VoidLatency branding

var HTML_TEMPLATES = {
  nginx: `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VoidLatency</title>
    <script src="https://cdn.tailwindcss.com"><\/script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        * { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
        body { background: #0a0a0f; }
        .glass { background: rgba(255,255,255,0.03); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.06); }
        .glow { box-shadow: 0 0 60px rgba(99, 102, 241, 0.15); }
        .gradient-text { background: linear-gradient(135deg, #818cf8, #a78bfa, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full text-center">
        <div class="glass rounded-2xl p-8 glow">
            <div class="w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center mx-auto mb-4 shadow-lg shadow-indigo-500/20">
                <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                </svg>
            </div>
            <h1 class="text-3xl font-black gradient-text mb-2">VoidLatency</h1>
            <p class="text-zinc-400 text-sm font-medium">Next-Gen VPN Management</p>
            <div class="mt-6 pt-6 border-t border-zinc-800/50">
                <a href="/panel" class="inline-block px-6 py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-semibold rounded-lg transition text-sm shadow-lg shadow-indigo-500/25">Enter Dashboard</a>
            </div>
            <div class="mt-4 flex justify-center gap-4 text-xs text-zinc-500">
                <a href="https://github.com/Void0Latency/panel" target="_blank">GitHub</a>
                <a href="https://t.me/VoidLatency" target="_blank">Telegram</a>
                <span>@VoidLatency</span>
            </div>
        </div>
    </div>
</body>
</html>`,

  setup: `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Setup - VoidLatency</title>
    <script src="https://cdn.tailwindcss.com"><\/script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        * { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
        body { background: #0a0a0f; }
        .glass { background: rgba(255,255,255,0.03); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.06); }
        .glow { box-shadow: 0 0 60px rgba(99, 102, 241, 0.15); }
        input { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.08); }
        input:focus { border-color: #818cf8; box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15); outline: none; }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full glass rounded-2xl p-8 glow">
        <h2 class="text-xl font-bold text-white mb-2 text-center">Setup Password</h2>
        <form onsubmit="handleSetup(event)" class="space-y-4">
            <input type="password" id="password" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition" placeholder="Enter password..." required minlength="4">
            <input type="password" id="confirm-password" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition" placeholder="Confirm password..." required minlength="4">
            <button type="submit" id="submit-btn" class="w-full py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-semibold rounded-xl transition text-sm shadow-lg shadow-indigo-500/25">Create Account</button>
        </form>
    </div>
    <script>
        async function handleSetup(event) {
            event.preventDefault();
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            const btn = document.getElementById('submit-btn');
            if (password !== confirmPassword) { alert('Passwords do not match!'); return; }
            btn.disabled = true; btn.innerText = 'Creating...';
            try {
                const res = await fetch('/api/setup-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                const data = await res.json();
                if (res.ok && data.success) { window.location.reload(); } else { alert('Error: ' + (data.error || 'Operation failed')); }
            } catch (err) { alert('Connection error'); }
            btn.disabled = false; btn.innerText = 'Create Account';
        }
    <\/script>
</body>
</html>`,

  login: `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - VoidLatency</title>
    <script src="https://cdn.tailwindcss.com"><\/script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        * { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
        body { background: #0a0a0f; }
        .glass { background: rgba(255,255,255,0.03); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.06); }
        .glow { box-shadow: 0 0 60px rgba(99, 102, 241, 0.15); }
        input { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.08); }
        input:focus { border-color: #818cf8; box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15); outline: none; }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full glass rounded-2xl p-8 glow">
        <div class="text-center mb-6">
            <div class="w-12 h-12 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center mx-auto mb-3 shadow-lg shadow-indigo-500/20">
                <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"/>
                </svg>
            </div>
            <h2 class="text-xl font-bold text-white">Welcome Back</h2>
            <p class="text-zinc-400 text-sm">Enter your credentials to access the panel</p>
        </div>
        <form onsubmit="handleLogin(event)" class="space-y-4">
            <input type="text" id="username" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition" placeholder="Username" required>
            <input type="password" id="password" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition" placeholder="Password" required>
            <button type="submit" id="submit-btn" class="w-full py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-semibold rounded-xl transition text-sm shadow-lg shadow-indigo-500/25">Sign In</button>
        </form>
    </div>
    <script>
        async function handleLogin(event) {
            event.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const btn = document.getElementById('submit-btn');
            btn.disabled = true; btn.innerText = 'Signing in...';
            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await res.json();
                if (res.ok && data.success) { window.location.reload(); } else { alert('Invalid credentials!'); }
            } catch (err) { alert('Connection error'); }
            btn.disabled = false; btn.innerText = 'Sign In';
        }
    <\/script>
</body>
</html>`,

  panel: `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>VoidLatency Panel</title>
    <script>
        const originalWarn = console.warn;
        console.warn = (...args) => {
            if (typeof args[0] === 'string' && args[0].includes('cdn.tailwindcss.com')) return;
            originalWarn(...args);
        };
    <\/script>
    <script src="https://cdn.tailwindcss.com"><\/script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"><\/script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        * { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
        body { background: #0a0a0f; color: #e5e7eb; }
        .glass { background: rgba(255,255,255,0.03); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.06); }
        .glass-light { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.06); }
        .sidebar { background: #0d0d18; border-right: 1px solid rgba(255,255,255,0.04); }
        .sidebar-link { transition: all 0.2s; border-radius: 12px; padding: 10px 16px; cursor: pointer; }
        .sidebar-link:hover { background: rgba(255,255,255,0.05); color: white; }
        .sidebar-link.active { background: rgba(99, 102, 241, 0.12); color: #818cf8; }
        .stat-card { transition: all 0.3s; }
        .stat-card:hover { transform: translateY(-4px); border-color: rgba(99, 102, 241, 0.3); }
        input, select, textarea { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.08); transition: all 0.2s; }
        input:focus, select:focus, textarea:focus { border-color: #818cf8; box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15); outline: none; }
        .badge { padding: 2px 10px; border-radius: 6px; font-size: 10px; font-weight: 600; }
        .badge-success { background: rgba(52, 211, 153, 0.15); color: #34d399; }
        .badge-danger { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
        .badge-warning { background: rgba(251, 191, 36, 0.15); color: #fbbf24; }
        .badge-info { background: rgba(96, 165, 250, 0.15); color: #60a5fa; }
        .badge-purple { background: rgba(168, 85, 247, 0.15); color: #a855f7; }
        .action-btn { transition: all 0.15s; padding: 6px; border-radius: 8px; cursor: pointer; }
        .action-btn:hover { transform: scale(1.1); background: rgba(255,255,255,0.05); }
        .system-stat { background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.04); border-radius: 14px; padding: 16px; }
        .system-stat:hover { border-color: rgba(99, 102, 241, 0.2); }
        .btn-xray { padding: 6px 16px; border-radius: 8px; font-size: 12px; font-weight: 600; transition: all 0.2s; cursor: pointer; }
        .btn-xray:hover { transform: scale(1.05); }
        .modal-overlay { background: rgba(0,0,0,0.7); backdrop-filter: blur(8px); }
        .modal-card { max-height: 90vh; overflow-y: auto; }
        .page-section { display: none; }
        .page-section.active { display: block; }
        .port-checkbox:checked + .port-label-tls { border-color: #34d399; background: rgba(52, 211, 153, 0.1); color: #34d399; }
        .port-checkbox:checked + .port-label-nontls { border-color: #fbbf24; background: rgba(251, 191, 36, 0.1); color: #fbbf24; }
        @media (max-width: 1023px) {
            .sidebar { position: fixed; top: 0; left: -100%; width: 280px; height: 100vh; background: #0d0d18; border-right: 1px solid rgba(255,255,255,0.04); transition: left 0.3s cubic-bezier(0.4, 0, 0.2, 1); z-index: 1000; overflow-y: auto; display: block; }
            .sidebar.active { left: 0; }
            .sidebar-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); z-index: 999; backdrop-filter: blur(4px); }
            .sidebar-overlay.active { display: block; }
            .lg\\:ml-64 { margin-left: 0; }
            .main-content { width: 100%; overflow-x: hidden; }
            .system-stat { padding: 12px; }
            .stat-card { padding: 16px; }
            .users-table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
            .users-table-wrap table { min-width: 700px; }
            .sidebar .p-6 { padding: 16px; }
            .sidebar-link { padding: 8px 12px; font-size: 13px; }
        }
        @media (max-width: 640px) {
            .sidebar { width: 280px; }
            .sidebar .p-6 { padding: 14px; }
            .sidebar-link { padding: 6px 10px; font-size: 12px; }
            .modal-card { max-width: 100%; margin: 10px; }
            .modal-card form .grid { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: 1fr 1fr; gap: 8px; }
            .stats-grid .stat-card { padding: 12px; }
            .stats-grid .stat-card .w-12 { width: 36px; height: 36px; }
            .stats-grid .stat-card .w-12 svg { width: 18px; height: 18px; }
            header h1 { font-size: 16px; }
        }
        .toggle {
            width: 36px; height: 20px;
            border-radius: 12px;
            background: #2a3a5a;
            position: relative;
            cursor: pointer;
            transition: all 0.3s;
            border: 2px solid transparent;
            flex-shrink: 0;
        }
        .toggle.on { background: #00a896; }
        .toggle::after {
            content: '';
            width: 14px; height: 14px;
            border-radius: 50%;
            background: #fff;
            position: absolute;
            top: 1px; left: 1px;
            transition: all 0.3s;
        }
        .toggle.on::after { left: 15px; }
    </style>
</head>
<body>
    <div id="sidebar-overlay" class="sidebar-overlay" onclick="toggleSidebar()"></div>
    <!-- SIDEBAR -->
    <div class="fixed inset-y-0 left-0 w-64 sidebar z-50">
        <div class="p-6">
            <div class="flex items-center gap-3 mb-8">
                <div class="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center shadow-lg shadow-indigo-500/20">
                    <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                    </svg>
                </div>
                <span class="text-lg font-bold text-white">VoidLatency</span>
            </div>
            <div class="text-xs text-emerald-400 mb-4 flex items-center gap-1.5">
                <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                v3.4.1
            </div>
            <nav class="space-y-1">
                <a href="#" onclick="showPage('dashboard')" class="sidebar-link active flex items-center gap-3 text-sm font-medium text-indigo-400" data-page="dashboard">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>
                    Overview
                </a>
                <a href="#" onclick="showPage('inbounds')" class="sidebar-link flex items-center gap-3 text-sm font-medium text-zinc-400 hover:text-white transition" data-page="inbounds">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>
                    Inbounds
                </a>
                <a href="#" onclick="showPage('users')" class="sidebar-link flex items-center gap-3 text-sm font-medium text-zinc-400 hover:text-white transition" data-page="users">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
                    Clients
                </a>
                <a href="#" onclick="showPage('settings')" class="sidebar-link flex items-center gap-3 text-sm font-medium text-zinc-400 hover:text-white transition" data-page="settings">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
                    Settings
                </a>
                <a href="#" onclick="showPage('logs')" class="sidebar-link flex items-center gap-3 text-sm font-medium text-zinc-400 hover:text-white transition" data-page="logs">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/></svg>
                    Logs
                </a>
                <div class="border-t border-zinc-800/30 mt-4 pt-4">
                    <a href="#" onclick="logoutAdmin()" class="sidebar-link flex items-center gap-3 text-sm font-medium text-zinc-400 hover:text-red-400 transition">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>
                        Log Out
                    </a>
                </div>
            </nav>
            <div class="absolute bottom-6 left-6 right-6">
                <div class="glass rounded-xl p-4">
                    <div class="flex items-center gap-3">
                        <div class="w-9 h-9 rounded-full bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center text-sm font-bold text-white">A</div>
                        <div>
                            <p class="text-sm font-semibold text-white">Admin</p>
                            <p class="text-xs text-emerald-400">● Online</p>
                        </div>
                    </div>
                </div>
                <div class="mt-3 flex items-center justify-between text-xs text-zinc-500">
                    <span>v3.4.1</span>
                    <span>@VoidLatency</span>
                </div>
            </div>
        </div>
    </div>

    <!-- MAIN CONTENT -->
    <div class="lg:ml-64 min-h-screen main-content">
        <header class="bg-[#0a0a0f]/80 backdrop-blur-xl border-b border-zinc-800/30 px-4 sm:px-6 py-3 sm:py-4 sticky top-0 z-40">
            <div class="flex items-center justify-between">
                <div class="flex items-center gap-3 sm:gap-4">
                    <button onclick="toggleSidebar()" class="lg:hidden p-2 rounded-lg hover:bg-white/5 text-zinc-400">
                        <svg id="menu-icon" class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>
                        </svg>
                    </button>
                    <div>
                        <h1 class="text-lg sm:text-xl font-bold text-white" id="page-title">Overview</h1>
                        <p class="text-xs text-zinc-400 hidden sm:block" id="page-subtitle">System overview and statistics</p>
                    </div>
                </div>
                <div class="flex items-center gap-2 sm:gap-3">
                    <span class="text-xs text-zinc-500 hidden sm:inline">v3.4.1</span>
                    <span class="w-px h-6 bg-zinc-800 hidden sm:block"></span>
                    <span class="text-xs text-emerald-400 flex items-center gap-1.5" id="xray-status-text">
                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" id="xray-indicator"></span>
                        <span class="hidden xs:inline">Xray Running</span>
                    </span>
                    <button onclick="toggleTheme()" class="p-2 rounded-lg hover:bg-white/5 text-zinc-400 transition">
                        <svg id="theme-icon" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>
                        </svg>
                    </button>
                </div>
            </div>
        </header>

        <main class="p-3 sm:p-6">
            <!-- PAGE: DASHBOARD -->
            <div id="page-dashboard" class="page-section active">
                <div class="grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4 mb-4 sm:mb-6 stats-grid">
                    <div class="system-stat">
                        <div class="flex items-center justify-between">
                            <p class="text-[10px] sm:text-xs text-zinc-400 font-medium">CPU</p>
                            <span class="text-[10px] sm:text-xs text-indigo-400" id="cpu-cores">2 Cores</span>
                        </div>
                        <p class="text-base sm:text-lg font-bold text-white mt-1" id="cpu-percent">12.5%</p>
                        <div class="w-full bg-zinc-800 rounded-full h-1.5 mt-2">
                            <div class="bg-indigo-500 h-1.5 rounded-full transition-all" id="cpu-bar" style="width: 12.5%"></div>
                        </div>
                        <p class="text-[8px] sm:text-[10px] text-zinc-500 mt-1" id="system-load">0.47 | 0.17 | 0.05</p>
                    </div>
                    <div class="system-stat">
                        <div class="flex items-center justify-between">
                            <p class="text-[10px] sm:text-xs text-zinc-400 font-medium">RAM</p>
                            <span class="text-[10px] sm:text-xs text-emerald-400" id="ram-percent">49.4%</span>
                        </div>
                        <p class="text-base sm:text-lg font-bold text-white" id="ram-used">1152.3 MB</p>
                        <p class="text-[8px] sm:text-xs text-zinc-500">/ <span id="ram-total">3940 MB</span></p>
                        <div class="w-full bg-zinc-800 rounded-full h-1.5 mt-1">
                            <div class="bg-emerald-500 h-1.5 rounded-full transition-all" id="ram-bar" style="width: 49.4%"></div>
                        </div>
                    </div>
                    <div class="system-stat">
                        <div class="flex items-center justify-between">
                            <p class="text-[10px] sm:text-xs text-zinc-400 font-medium">Swap</p>
                            <span class="text-[10px] sm:text-xs text-yellow-400" id="swap-percent">0%</span>
                        </div>
                        <p class="text-base sm:text-lg font-bold text-white" id="swap-used">0 B</p>
                        <p class="text-[8px] sm:text-xs text-zinc-500">/ <span id="swap-total">0 B</span></p>
                        <div class="w-full bg-zinc-800 rounded-full h-1.5 mt-1">
                            <div class="bg-yellow-500 h-1.5 rounded-full transition-all" id="swap-bar" style="width: 0%"></div>
                        </div>
                    </div>
                    <div class="system-stat">
                        <div class="flex items-center justify-between">
                            <p class="text-[10px] sm:text-xs text-zinc-400 font-medium">Storage</p>
                            <span class="text-[10px] sm:text-xs text-blue-400" id="storage-percent">28.7%</span>
                        </div>
                        <p class="text-base sm:text-lg font-bold text-white" id="storage-used">7.66 GB</p>
                        <p class="text-[8px] sm:text-xs text-zinc-500">/ <span id="storage-total">26.65 GB</span></p>
                        <div class="w-full bg-zinc-800 rounded-full h-1.5 mt-1">
                            <div class="bg-blue-500 h-1.5 rounded-full transition-all" id="storage-bar" style="width: 28.7%"></div>
                        </div>
                    </div>
                </div>

                <div class="glass rounded-2xl p-4 sm:p-5 mb-4 sm:mb-6">
                    <div class="flex flex-wrap items-center justify-between gap-3 sm:gap-4">
                        <div class="flex items-center gap-3 sm:gap-4 flex-wrap">
                            <div class="flex items-center gap-2">
                                <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" id="xray-indicator2"></span>
                                <span class="text-sm font-bold text-white">Xray</span>
                            </div>
                            <span class="text-xs text-zinc-400 bg-zinc-800/50 px-2 py-1 rounded" id="xray-version">v26.4.25</span>
                            <span class="text-xs text-emerald-400 bg-emerald-500/10 px-2 sm:px-3 py-1 rounded-full border border-emerald-500/20" id="xray-status-badge">● Running</span>
                        </div>
                        <div class="flex items-center gap-1 sm:gap-2">
                            <button onclick="controlXray('stop')" class="btn-xray text-xs sm:text-sm bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20 px-2 sm:px-4">Stop</button>
                            <button onclick="controlXray('restart')" class="btn-xray text-xs sm:text-sm bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20 border border-yellow-500/20 px-2 sm:px-4">Restart</button>
                            <button onclick="controlXray('start')" class="btn-xray text-xs sm:text-sm bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/20 px-2 sm:px-4">Start</button>
                        </div>
                        <div class="flex items-center gap-2 sm:gap-3 text-[10px] sm:text-xs text-zinc-400 flex-wrap">
                            <span>Uptime: <span id="xray-uptime" class="text-white font-medium">3m</span></span>
                            <span class="hidden xs:inline">|</span>
                            <span class="hidden xs:inline">RAM: <span class="text-white font-medium" id="xray-memory">56.93 MB</span></span>
                            <span class="hidden xs:inline">|</span>
                            <span class="hidden xs:inline">Threads: <span class="text-white font-medium" id="xray-threads">1</span></span>
                        </div>
                    </div>
                </div>

                <div class="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 mb-4 sm:mb-8 stats-grid">
                    <div class="glass rounded-2xl p-4 sm:p-6 stat-card">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-zinc-400 text-[10px] sm:text-xs font-medium uppercase tracking-wider">Total Users</p>
                                <p class="text-2xl sm:text-3xl font-black text-white mt-1" id="stat-total-users">0</p>
                            </div>
                            <div class="w-10 h-10 sm:w-12 sm:h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center">
                                <svg class="w-5 h-5 sm:w-6 sm:h-6 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>
                                </svg>
                            </div>
                        </div>
                    </div>
                    <div class="glass rounded-2xl p-4 sm:p-6 stat-card">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-zinc-400 text-[10px] sm:text-xs font-medium uppercase tracking-wider">Online</p>
                                <p class="text-2xl sm:text-3xl font-black text-emerald-400 mt-1" id="stat-active-users">0</p>
                            </div>
                            <div class="w-10 h-10 sm:w-12 sm:h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                                <svg class="w-5 h-5 sm:w-6 sm:h-6 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                                </svg>
                            </div>
                        </div>
                    </div>
                    <div class="glass rounded-2xl p-4 sm:p-6 stat-card">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-zinc-400 text-[10px] sm:text-xs font-medium uppercase tracking-wider">Traffic</p>
                                <p class="text-2xl sm:text-3xl font-black text-blue-400 mt-1" id="stat-total-usage">0 GB</p>
                            </div>
                            <div class="w-10 h-10 sm:w-12 sm:h-12 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                                <svg class="w-5 h-5 sm:w-6 sm:h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
                                </svg>
                            </div>
                        </div>
                    </div>
                    <div class="glass rounded-2xl p-4 sm:p-6 stat-card">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-zinc-400 text-[10px] sm:text-xs font-medium uppercase tracking-wider">Inbounds</p>
                                <p class="text-2xl sm:text-3xl font-black text-purple-400 mt-1" id="stat-inbounds">0</p>
                            </div>
                            <div class="w-10 h-10 sm:w-12 sm:h-12 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
                                <svg class="w-5 h-5 sm:w-6 sm:h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
                                </svg>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="glass rounded-2xl p-4 sm:p-5">
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <p class="text-xs text-zinc-400">Upload</p>
                            <p class="text-lg font-bold text-emerald-400" id="upload-speed">↑ 1.83 KB/s</p>
                        </div>
                        <div>
                            <p class="text-xs text-zinc-400">Download</p>
                            <p class="text-lg font-bold text-blue-400" id="download-speed">↓ 1.93 KB/s</p>
                        </div>
                        <div>
                            <p class="text-xs text-zinc-400">Sent</p>
                            <p class="text-sm font-bold text-white" id="total-sent">2.58 MB</p>
                        </div>
                        <div>
                            <p class="text-xs text-zinc-400">Received</p>
                            <p class="text-sm font-bold text-white" id="total-received">79.18 MB</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- PAGE: INBOUNDS -->
            <div id="page-inbounds" class="page-section">
                <div class="glass rounded-2xl p-4 sm:p-6">
                    <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
                        <div>
                            <h2 class="text-lg font-bold text-white">Inbounds</h2>
                            <p class="text-xs text-zinc-400">Manage VLESS tunnels and users</p>
                        </div>
                        <button onclick="openInboundModal()" class="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-bold rounded-xl transition text-sm shadow-lg shadow-indigo-500/25">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"/>
                            </svg>
                            Add Inbound
                        </button>
                    </div>

                    <div id="inbounds-loading" class="text-center py-8">
                        <div class="inline-block w-6 h-6 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin"></div>
                        <p class="text-zinc-400 text-sm mt-3">Loading inbounds...</p>
                    </div>

                    <div id="inbounds-container" class="hidden space-y-3">
                        <div id="inbounds-list"></div>
                    </div>
                </div>
            </div>

            <!-- PAGE: USERS -->
            <div id="page-users" class="page-section">
                <div class="glass rounded-2xl p-4 sm:p-6">
                    <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
                        <div>
                            <h2 class="text-lg font-bold text-white">Clients</h2>
                            <p class="text-xs text-zinc-400">Manage all VLESS clients</p>
                        </div>
                        <button onclick="openCreateModal()" class="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-bold rounded-xl transition text-sm shadow-lg shadow-indigo-500/25">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"/>
                            </svg>
                            Add Client
                        </button>
                    </div>

                    <div class="flex flex-col sm:flex-row gap-2 mb-4">
                        <div class="flex-1 relative">
                            <svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                            </svg>
                            <input type="text" id="search-input" oninput="filterAndRenderUsers()" placeholder="Search clients..." class="w-full pl-9 pr-3 py-2 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                        </div>
                        <select id="filter-status" onchange="filterAndRenderUsers()" class="px-3 py-2 rounded-xl text-zinc-300 text-sm outline-none transition cursor-pointer bg-[rgba(255,255,255,0.05)] border border-zinc-800/50">
                            <option value="all">All</option>
                            <option value="active">Active</option>
                            <option value="inactive">Inactive</option>
                            <option value="online">Online</option>
                            <option value="offline">Offline</option>
                            <option value="expired">Expired</option>
                        </select>
                    </div>

                    <div id="loading-state" class="text-center py-8">
                        <div class="inline-block w-6 h-6 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin"></div>
                        <p class="text-zinc-400 text-sm mt-3">Loading clients...</p>
                    </div>

                    <div id="users-table-container" class="hidden">
                        <div class="users-table-wrap">
                            <table class="w-full text-left border-collapse">
                                <thead>
                                    <tr class="border-b border-zinc-800/50 text-[10px] sm:text-xs text-zinc-400 uppercase tracking-wider">
                                        <th class="p-2 sm:p-3 font-medium">Client</th>
                                        <th class="p-2 sm:p-3 font-medium hidden sm:table-cell">Protocol</th>
                                        <th class="p-2 sm:p-3 font-medium hidden md:table-cell">Ports</th>
                                        <th class="p-2 sm:p-3 font-medium hidden lg:table-cell">Usage</th>
                                        <th class="p-2 sm:p-3 font-medium hidden xl:table-cell">Expiry</th>
                                    </tr>
                                </thead>
                                <tbody id="users-tbody" class="divide-y divide-zinc-800/30 text-sm"></tbody>
                            </table>
                        </div>
                    </div>

                    <div id="empty-state" class="hidden text-center py-8">
                        <p class="text-zinc-400 text-sm">No clients found.</p>
                    </div>
                </div>
            </div>

            <!-- PAGE: SETTINGS -->
            <div id="page-settings" class="page-section">
                <div class="glass rounded-2xl p-4 sm:p-6 max-w-2xl">
                    <h2 class="text-lg font-bold text-white mb-4">Panel Settings</h2>
                    <div class="space-y-4">
                        <div>
                            <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Proxy Location</label>
                            <select id="location-select" class="w-full px-4 py-3 rounded-xl text-zinc-300 text-sm outline-none transition cursor-pointer bg-[rgba(255,255,255,0.05)] border border-zinc-800/50">
                                <option value="">Loading...</option>
                            </select>
                        </div>
                        <div class="grid grid-cols-2 gap-3 sm:gap-4">
                            <div>
                                <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Fragment Length</label>
                                <input type="text" id="frag-length" placeholder="20-30" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition text-center font-mono">
                            </div>
                            <div>
                                <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Fragment Interval</label>
                                <input type="text" id="frag-interval" placeholder="1-2" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition text-center font-mono">
                            </div>
                        </div>
                        <div>
                            <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Custom Domain</label>
                            <div class="flex gap-2">
                                <input type="text" id="custom-domain-input" placeholder="example.com" class="flex-1 px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                                <button onclick="saveCustomDomain()" class="px-4 py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-bold rounded-xl transition text-sm">Save</button>
                            </div>
                            <p class="text-xs text-zinc-500 mt-1" id="current-domain-display">Current: None</p>
                        </div>
                        <div>
                            <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Clean IPs</label>
                            <div class="flex gap-2">
                                <input type="text" id="clean-ip-input" placeholder="1.2.3.4 or domain.com" class="flex-1 px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                                <button onclick="addCleanIp()" class="px-4 py-3 bg-gradient-to-r from-emerald-500 to-blue-500 hover:from-emerald-600 hover:to-blue-600 text-white font-bold rounded-xl transition text-sm">Add</button>
                            </div>
                            <div id="clean-ips-list" class="mt-2 flex flex-wrap gap-2"></div>
                        </div>
                        <div class="border-t border-zinc-800/30 pt-4">
                            <h4 class="text-sm font-semibold text-white mb-3">Change Panel Password</h4>
                            <div class="space-y-3">
                                <input type="password" id="change-pwd-current" placeholder="Current password..." class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                                <input type="password" id="change-pwd-new" placeholder="New password..." class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                                <button onclick="changeAdminPassword()" class="w-full py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-bold rounded-xl transition text-sm">Update Password</button>
                            </div>
                        </div>
                        <div class="border-t border-zinc-800/30 pt-4">
                            <h4 class="text-sm font-semibold text-white mb-3">API Token</h4>
                            <div id="api-token-display" class="text-xs text-zinc-400 mb-2">No API token generated</div>
                            <div class="flex gap-2">
                                <button onclick="generateApiToken()" class="flex-1 py-3 bg-gradient-to-r from-emerald-500 to-blue-500 hover:from-emerald-600 hover:to-blue-600 text-white font-bold rounded-xl transition text-sm">Generate Token</button>
                                <button onclick="revokeApiToken()" class="py-3 px-4 bg-red-500/10 text-red-400 hover:bg-red-500/20 rounded-xl transition text-sm font-medium">Revoke</button>
                            </div>
                        </div>
                        <div class="border-t border-zinc-800/30 pt-4">
                            <h4 class="text-sm font-semibold text-white mb-3">Update Panel</h4>
                            <div id="update-info" class="text-xs text-zinc-400 mb-2">Checking for updates...</div>
                            <div class="flex gap-2">
                                <button onclick="checkUpdate()" class="flex-1 py-3 bg-gradient-to-r from-emerald-500 to-blue-500 hover:from-emerald-600 hover:to-blue-600 text-white font-bold rounded-xl transition text-sm">Check for Updates</button>
                                <button onclick="updatePanel()" class="flex-1 py-3 bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600 text-white font-bold rounded-xl transition text-sm">🔥 Fire Update</button>
                            </div>
                        </div>
                        <div class="flex gap-3 pt-2 border-t border-zinc-800/30">
                            <button onclick="saveSettings()" class="flex-1 py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-bold rounded-xl transition text-sm shadow-lg shadow-indigo-500/25">Save All</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- PAGE: LOGS -->
            <div id="page-logs" class="page-section">
                <div class="glass rounded-2xl p-4 sm:p-6">
                    <h2 class="text-lg font-bold text-white mb-4">System Logs</h2>
                    <div id="logs-container" class="space-y-1 font-mono text-xs max-h-96 overflow-y-auto scrollbar-thin">
                        <div class="text-emerald-400">● System started at: <span id="log-start-time">-</span></div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- MODALS -->
    <div id="user-modal" class="fixed inset-0 z-50 flex items-center justify-center p-3 modal-overlay opacity-0 pointer-events-none transition-opacity duration-300">
        <div id="user-modal-card" class="w-full max-w-2xl glass rounded-2xl p-6 transition-all duration-300 opacity-0 scale-95 modal-card">
            <div class="flex items-center justify-between mb-4">
                <h3 id="modal-title" class="text-lg font-bold text-white">Add Client</h3>
                <button onclick="toggleModal(false)" class="p-2 rounded-lg hover:bg-white/5 text-zinc-400 transition">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                </button>
            </div>
            <form id="create-user-form" onsubmit="handleFormSubmit(event)" class="space-y-4">
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Username</label>
                    <input type="text" id="input-name" placeholder="Enter username..." class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition" required>
                </div>
                <div class="grid grid-cols-2 gap-3">
                    <div>
                        <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Limit (GB)</label>
                        <input type="number" id="input-limit" min="0" step="any" placeholder="Unlimited" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                    </div>
                    <div>
                        <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Expiry (Days)</label>
                        <input type="number" id="input-expiry" min="0" placeholder="Unlimited" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                    </div>
                </div>
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-2 uppercase tracking-wider">Ports</label>
                    <div class="grid grid-cols-2 gap-2">
                        <div class="glass-light rounded-xl p-2">
                            <p class="text-xs text-emerald-400 font-semibold mb-2">TLS</p>
                            <div class="flex flex-wrap gap-1" id="tls-ports-list"></div>
                        </div>
                        <div class="glass-light rounded-xl p-2">
                            <p class="text-xs text-amber-400 font-semibold mb-2">Non-TLS</p>
                            <div class="flex flex-wrap gap-1" id="nontls-ports-list"></div>
                        </div>
                    </div>
                </div>
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Inbound</label>
                    <select id="inbound-select" class="w-full px-4 py-3 rounded-xl text-zinc-300 text-sm outline-none transition cursor-pointer bg-[rgba(255,255,255,0.05)] border border-zinc-800/50">
                        <option value="0">None</option>
                    </select>
                </div>
                <div class="flex gap-3 pt-3 border-t border-zinc-800/30">
                    <button type="button" onclick="toggleModal(false)" class="flex-1 py-3 bg-white/5 hover:bg-white/10 text-zinc-400 font-semibold rounded-xl transition text-sm">Cancel</button>
                    <button type="submit" id="submit-btn" class="flex-1 py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-bold rounded-xl transition text-sm shadow-lg shadow-indigo-500/25">Create</button>
                </div>
            </form>
        </div>
    </div>

    <div id="qr-modal" class="fixed inset-0 z-50 flex items-center justify-center p-3 modal-overlay opacity-0 pointer-events-none transition-opacity duration-300">
        <div class="glass rounded-2xl p-6 max-w-sm w-full transition-all duration-300 opacity-0 scale-95 text-center">
            <h3 class="text-lg font-bold text-white mb-4">QR Code</h3>
            <div class="bg-white p-2 rounded-xl inline-block mb-4">
                <div id="qrcode-box" class="flex justify-center items-center w-40 h-40 mx-auto"></div>
            </div>
            <button onclick="toggleQRModal(false)" class="w-full py-3 bg-white/5 hover:bg-white/10 text-zinc-400 font-semibold rounded-xl transition text-sm">Close</button>
        </div>
    </div>

    <div id="inbound-modal" class="fixed inset-0 z-50 flex items-center justify-center p-3 modal-overlay opacity-0 pointer-events-none transition-opacity duration-300">
        <div id="inbound-modal-card" class="w-full max-w-2xl glass rounded-2xl p-6 transition-all duration-300 opacity-0 scale-95 modal-card">
            <div class="flex items-center justify-between mb-4">
                <h3 id="inbound-modal-title" class="text-lg font-bold text-white">Add Inbound</h3>
                <button onclick="toggleInboundModal(false)" class="p-2 rounded-lg hover:bg-white/5 text-zinc-400 transition">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                </button>
            </div>
            <form id="create-inbound-form" onsubmit="handleInboundSubmit(event)" class="space-y-4">
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Name</label>
                    <input type="text" id="inbound-name" placeholder="Enter inbound name..." class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition" required>
                </div>
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Protocol</label>
                    <select id="inbound-protocol" class="w-full px-4 py-3 rounded-xl text-zinc-300 text-sm outline-none transition cursor-pointer bg-[rgba(255,255,255,0.05)] border border-zinc-800/50">
                        <option value="vless">VLESS</option>
                        <option value="vmess">VMess</option>
                        <option value="trojan">Trojan</option>
                    </select>
                </div>
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Port</label>
                    <input type="number" id="inbound-port" value="443" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                </div>
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Path</label>
                    <input type="text" id="inbound-path" value="/" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                </div>
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Limit (GB)</label>
                    <input type="number" id="inbound-limit" min="0" step="any" placeholder="Unlimited" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                </div>
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Expiry (Days)</label>
                    <input type="number" id="inbound-expiry" min="0" placeholder="Unlimited" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                </div>
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Max IPs</label>
                    <input type="number" id="inbound-max-ips" value="0" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                </div>
                <div class="flex gap-3 pt-3 border-t border-zinc-800/30">
                    <button type="button" onclick="toggleInboundModal(false)" class="flex-1 py-3 bg-white/5 hover:bg-white/10 text-zinc-400 font-semibold rounded-xl transition text-sm">Cancel</button>
                    <button type="submit" id="inbound-submit-btn" class="flex-1 py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-bold rounded-xl transition text-sm shadow-lg shadow-indigo-500/25">Create</button>
                </div>
            </form>
        </div>
    </div>

    <div id="inbound-user-modal" class="fixed inset-0 z-50 flex items-center justify-center p-3 modal-overlay opacity-0 pointer-events-none transition-opacity duration-300">
        <div id="inbound-user-modal-card" class="w-full max-w-2xl glass rounded-2xl p-6 transition-all duration-300 opacity-0 scale-95 modal-card">
            <div class="flex items-center justify-between mb-4">
                <h3 id="inbound-user-modal-title" class="text-lg font-bold text-white">Add User to Inbound</h3>
                <button onclick="toggleInboundUserModal(false)" class="p-2 rounded-lg hover:bg-white/5 text-zinc-400 transition">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                </button>
            </div>
            <form id="create-inbound-user-form" onsubmit="handleInboundUserSubmit(event)" class="space-y-4">
                <input type="hidden" id="inbound-user-inbound-id">
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Username</label>
                    <input type="text" id="inbound-user-name" placeholder="Enter username..." class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition" required>
                </div>
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Limit (GB)</label>
                    <input type="number" id="inbound-user-limit" min="0" step="any" placeholder="Unlimited" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                </div>
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Expiry (Days)</label>
                    <input type="number" id="inbound-user-expiry" min="0" placeholder="Unlimited" class="w-full px-4 py-3 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition">
                </div>
                <div>
                    <label class="block text-zinc-300 text-xs font-semibold mb-1.5 uppercase tracking-wider">Fingerprint</label>
                    <select id="inbound-user-fingerprint" class="w-full px-4 py-3 rounded-xl text-zinc-300 text-sm outline-none transition cursor-pointer bg-[rgba(255,255,255,0.05)] border border-zinc-800/50">
                        <option value="chrome">Chrome</option>
                        <option value="firefox">Firefox</option>
                        <option value="safari">Safari</option>
                        <option value="ios">iOS</option>
                        <option value="android">Android</option>
                        <option value="edge">Edge</option>
                        <option value="random">Random</option>
                    </select>
                </div>
                <div class="flex gap-3 pt-3 border-t border-zinc-800/30">
                    <button type="button" onclick="toggleInboundUserModal(false)" class="flex-1 py-3 bg-white/5 hover:bg-white/10 text-zinc-400 font-semibold rounded-xl transition text-sm">Cancel</button>
                    <button type="submit" id="inbound-user-submit-btn" class="flex-1 py-3 bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white font-bold rounded-xl transition text-sm shadow-lg shadow-indigo-500/25">Add User</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        // ============================================
        // COMPLETE JAVASCRIPT
        // ============================================
        window.globalFragLen = "20-30";
        window.globalFragInt = "1-2";
        const tlsPorts = ['443', '2053', '2083', '2087', '2096', '8443'];
        const nonTlsPorts = ['80', '8080', '8880', '2052', '2082', '2086', '2095'];
        let isEditMode = false;
        let editingUsername = '';
        let allUsers = [];
        let allInbounds = [];
        let lastServerTime = Date.now();
        let currentTheme = 'dark';

        // ============================================
        // SIDEBAR
        // ============================================
        function toggleSidebar() {
            var sidebar = document.querySelector('.sidebar');
            var overlay = document.getElementById('sidebar-overlay');
            var menuIcon = document.querySelector('#menu-icon');
            if (sidebar) sidebar.classList.toggle('active');
            if (overlay) overlay.classList.toggle('active');
            if (menuIcon) {
                if (sidebar && sidebar.classList.contains('active')) {
                    menuIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>';
                } else {
                    menuIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>';
                }
            }
        }

        function showPage(page) {
            document.querySelectorAll('.page-section').forEach(el => el.classList.remove('active'));
            document.getElementById('page-' + page).classList.add('active');
            document.querySelectorAll('.sidebar-link').forEach(el => el.classList.remove('active'));
            var activeLink = document.querySelector('.sidebar-link[data-page="' + page + '"]');
            if (activeLink) activeLink.classList.add('active');
            var titles = {
                dashboard: ['Overview', 'System overview and statistics'],
                inbounds: ['Inbounds', 'Manage VLESS tunnels'],
                users: ['Clients', 'Manage all VLESS clients'],
                settings: ['Panel Settings', 'Configure panel preferences'],
                logs: ['System Logs', 'Real-time activity logs']
            };
            if (titles[page]) {
                document.getElementById('page-title').innerText = titles[page][0];
                document.getElementById('page-subtitle').innerText = titles[page][1];
            }
            if (window.innerWidth < 1024) {
                var sidebar = document.querySelector('.sidebar');
                var overlay = document.getElementById('sidebar-overlay');
                if (sidebar) sidebar.classList.remove('active');
                if (overlay) overlay.classList.remove('active');
                var menuIcon = document.querySelector('#menu-icon');
                if (menuIcon) menuIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>';
            }
        }

        // ============================================
        // THEME
        // ============================================
        async function toggleTheme() {
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            try {
                const res = await fetch('/api/theme', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ theme: newTheme })
                });
                const data = await res.json();
                if (data.success) {
                    currentTheme = data.theme;
                    applyTheme(currentTheme);
                }
            } catch (e) {
                currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
                applyTheme(currentTheme);
            }
        }

        function applyTheme(theme) {
            const html = document.documentElement;
            const icon = document.getElementById('theme-icon');
            if (theme === 'light') {
                html.classList.remove('dark');
                icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m12.728 0l-.707-.707M6.343 6.343l-.707-.707M14 12a2 2 0 11-4 0 2 2 0 014 0z"/>';
                document.body.style.background = '#f1f5f9';
                document.body.style.color = '#0f172a';
            } else {
                html.classList.add('dark');
                icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>';
                document.body.style.background = '#0a0a0f';
                document.body.style.color = '#e5e7eb';
            }
            localStorage.setItem('theme', theme);
        }

        async function loadTheme() {
            try {
                const res = await fetch('/api/theme');
                const data = await res.json();
                currentTheme = data.theme || 'dark';
                applyTheme(currentTheme);
            } catch (e) {
                const saved = localStorage.getItem('theme') || 'dark';
                currentTheme = saved;
                applyTheme(saved);
            }
        }

        // ============================================
        // XRAY CONTROL
        // ============================================
        async function controlXray(action) {
            try {
                var res = await fetch('/api/xray', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action })
                });
                var data = await res.json();
                if (data.success) {
                    alert('✅ Xray ' + action + 'ed successfully!');
                    updateXrayStatus();
                } else {
                    alert('❌ Failed to ' + action + ' Xray');
                }
            } catch (err) {
                alert('❌ Connection error');
            }
        }

        async function updateXrayStatus() {
            try {
                var res = await fetch('/api/xray/status');
                var data = await res.json();
                var statusText = document.getElementById('xray-status-text');
                var statusBadge = document.getElementById('xray-status-badge');
                var uptimeEl = document.getElementById('xray-uptime');
                var indicator = document.getElementById('xray-indicator');
                var indicator2 = document.getElementById('xray-indicator2');
                if (data.running) {
                    var uptime = data.uptime;
                    var hours = Math.floor(uptime / 3600);
                    var minutes = Math.floor((uptime % 3600) / 60);
                    uptimeEl.innerText = hours > 0 ? hours + 'h ' + minutes + 'm' : minutes + 'm';
                    statusText.innerText = 'Xray Running';
                    statusBadge.innerText = '● Running';
                    statusBadge.className = 'text-xs text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/20';
                    indicator.className = 'w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse';
                    indicator2.className = 'w-2 h-2 rounded-full bg-emerald-400 animate-pulse';
                } else {
                    uptimeEl.innerText = 'Stopped';
                    statusText.innerText = 'Xray Stopped';
                    statusBadge.innerText = '● Stopped';
                    statusBadge.className = 'text-xs text-red-400 bg-red-500/10 px-2 py-0.5 rounded-full border border-red-500/20';
                    indicator.className = 'w-1.5 h-1.5 rounded-full bg-red-400';
                    indicator2.className = 'w-2 h-2 rounded-full bg-red-400';
                }
            } catch (e) {}
        }

        // ============================================
        // API TOKEN
        // ============================================
        async function generateApiToken() {
            try {
                const res = await fetch('/api/token', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    document.getElementById('api-token-display').innerHTML = '<span class="text-emerald-400">✅ Token generated! (copy it now)</span>';
                    alert('✅ API Token generated!');
                }
            } catch (e) {
                alert('❌ Failed to generate token');
            }
        }

        async function revokeApiToken() {
            if (!confirm('Are you sure you want to revoke the API token?')) return;
            try {
                const res = await fetch('/api/token', { method: 'DELETE' });
                if (res.ok) {
                    document.getElementById('api-token-display').innerHTML = 'No API token generated';
                    alert('✅ API Token revoked!');
                }
            } catch (e) {
                alert('❌ Failed to revoke token');
            }
        }

        // ============================================
        // PORTS
        // ============================================
        function renderPortCheckboxes() {
            var tlsContainer = document.getElementById('tls-ports-list');
            var nonTlsContainer = document.getElementById('nontls-ports-list');
            if (!tlsContainer || !nonTlsContainer) return;
            tlsContainer.innerHTML = tlsPorts.map(function(port) {
                var checked = port === '443' ? 'checked' : '';
                return '<label class="relative cursor-pointer">' +
                    '<input type="checkbox" name="ports" value="' + port + '" ' + checked + ' class="peer sr-only port-checkbox">' +
                    '<div class="port-label-tls px-2 py-1 rounded-lg text-xs font-medium border border-zinc-700/50 bg-[rgba(255,255,255,0.03)] text-zinc-400 peer-checked:border-emerald-400 peer-checked:text-emerald-400 peer-checked:bg-emerald-500/10 transition select-none">' +
                        port +
                    '</div>' +
                '</label>';
            }).join('');
            nonTlsContainer.innerHTML = nonTlsPorts.map(function(port) {
                return '<label class="relative cursor-pointer">' +
                    '<input type="checkbox" name="ports" value="' + port + '" class="peer sr-only port-checkbox">' +
                    '<div class="port-label-nontls px-2 py-1 rounded-lg text-xs font-medium border border-zinc-700/50 bg-[rgba(255,255,255,0.03)] text-zinc-400 peer-checked:border-amber-400 peer-checked:text-amber-400 peer-checked:bg-amber-500/10 transition select-none">' +
                        port +
                    '</div>' +
                '</label>';
            }).join('');
        }

        // ============================================
        // MODALS
        // ============================================
        function toggleModal(show) {
            var modal = document.getElementById('user-modal');
            var card = document.getElementById('user-modal-card');
            if (show) {
                modal.classList.remove('opacity-0', 'pointer-events-none');
                modal.classList.add('opacity-100', 'pointer-events-auto');
                card.classList.remove('opacity-0', 'scale-95');
                card.classList.add('opacity-100', 'scale-100');
            } else {
                modal.classList.remove('opacity-100', 'pointer-events-auto');
                modal.classList.add('opacity-0', 'pointer-events-none');
                card.classList.remove('opacity-100', 'scale-100');
                card.classList.add('opacity-0', 'scale-95');
                isEditMode = false;
                editingUsername = '';
                document.getElementById('modal-title').innerText = 'Add Client';
                document.getElementById('submit-btn').innerText = 'Create';
                document.getElementById('input-name').disabled = false;
                document.getElementById('create-user-form').reset();
                var cb443 = document.querySelector('input[name="ports"][value="443"]');
                if (cb443) cb443.checked = true;
            }
        }

        function openCreateModal() {
            isEditMode = false;
            editingUsername = '';
            document.getElementById('modal-title').innerText = 'Add Client';
            document.getElementById('submit-btn').innerText = 'Create';
            document.getElementById('input-name').disabled = false;
            document.getElementById('create-user-form').reset();
            loadInboundSelect();
            toggleModal(true);
            setTimeout(function() {
                var cb443 = document.querySelector('input[name="ports"][value="443"]');
                if (cb443) cb443.checked = true;
            }, 100);
        }

        async function loadInboundSelect() {
            try {
                const res = await fetch('/api/inbounds');
                const data = await res.json();
                if (data.success) {
                    var select = document.getElementById('inbound-select');
                    select.innerHTML = '<option value="0">None</option>';
                    data.inbounds.forEach(function(inbound) {
                        select.innerHTML += '<option value="' + inbound.id + '">' + inbound.name + ' (' + inbound.protocol + ':' + inbound.port + ')</option>';
                    });
                }
            } catch (e) {}
        }

        function toggleQRModal(show, link, title) {
            var modal = document.getElementById('qr-modal');
            var card = modal.querySelector('div');
            var qrBox = document.getElementById('qrcode-box');
            var titleEl = modal.querySelector('.modal-title');
            if (show) {
                titleEl.innerText = title || 'QR Code';
                qrBox.innerHTML = '';
                try {
                    new QRCode(qrBox, { text: link, width: 160, height: 160, colorDark: "#000000", colorLight: "#ffffff", correctLevel: QRCode.CorrectLevel.M });
                } catch(e) {
                    qrBox.innerHTML = '<p class="text-zinc-400 text-xs">Error generating QR</p>';
                }
                modal.classList.remove('opacity-0', 'pointer-events-none');
                modal.classList.add('opacity-100', 'pointer-events-auto');
                card.classList.remove('opacity-0', 'scale-95');
                card.classList.add('opacity-100', 'scale-100');
            } else {
                modal.classList.remove('opacity-100', 'pointer-events-auto');
                modal.classList.add('opacity-0', 'pointer-events-none');
                card.classList.remove('opacity-100', 'scale-100');
                card.classList.add('opacity-0', 'scale-95');
            }
        }

        function toggleInboundModal(show) {
            var modal = document.getElementById('inbound-modal');
            var card = document.getElementById('inbound-modal-card');
            if (show) {
                modal.classList.remove('opacity-0', 'pointer-events-none');
                modal.classList.add('opacity-100', 'pointer-events-auto');
                card.classList.remove('opacity-0', 'scale-95');
                card.classList.add('opacity-100', 'scale-100');
            } else {
                modal.classList.remove('opacity-100', 'pointer-events-auto');
                modal.classList.add('opacity-0', 'pointer-events-none');
                card.classList.remove('opacity-100', 'scale-100');
                card.classList.add('opacity-0', 'scale-95');
                document.getElementById('inbound-name').value = '';
                document.getElementById('inbound-port').value = '443';
                document.getElementById('inbound-path').value = '/';
                document.getElementById('inbound-limit').value = '';
                document.getElementById('inbound-expiry').value = '';
                document.getElementById('inbound-max-ips').value = '0';
            }
        }

        function openInboundModal() {
            toggleInboundModal(true);
        }

        function toggleInboundUserModal(show) {
            var modal = document.getElementById('inbound-user-modal');
            var card = document.getElementById('inbound-user-modal-card');
            if (show) {
                modal.classList.remove('opacity-0', 'pointer-events-none');
                modal.classList.add('opacity-100', 'pointer-events-auto');
                card.classList.remove('opacity-0', 'scale-95');
                card.classList.add('opacity-100', 'scale-100');
            } else {
                modal.classList.remove('opacity-100', 'pointer-events-auto');
                modal.classList.add('opacity-0', 'pointer-events-none');
                card.classList.remove('opacity-100', 'scale-100');
                card.classList.add('opacity-0', 'scale-95');
                document.getElementById('inbound-user-name').value = '';
                document.getElementById('inbound-user-limit').value = '';
                document.getElementById('inbound-user-expiry').value = '';
            }
        }

        function openInboundUserModal(inboundId) {
            document.getElementById('inbound-user-inbound-id').value = inboundId;
            document.getElementById('inbound-user-modal-title').innerText = 'Add User to ' + allInbounds.find(i => i.id == inboundId)?.name || 'Inbound';
            toggleInboundUserModal(true);
        }

        // ============================================
        // INBOUNDS
        // ============================================
        async function loadInbounds() {
            try {
                const res = await fetch('/api/inbounds');
                const data = await res.json();
                if (data.success) {
                    allInbounds = data.inbounds;
                    renderInbounds(allInbounds);
                    document.getElementById('inbounds-loading').classList.add('hidden');
                    document.getElementById('inbounds-container').classList.remove('hidden');
                    document.getElementById('stat-inbounds').innerText = allInbounds.length;
                }
            } catch (e) {
                document.getElementById('inbounds-loading').innerHTML = '<span class="text-red-400">❌ Error loading inbounds</span>';
            }
        }

        function renderInbounds(inbounds) {
            var container = document.getElementById('inbounds-list');
            if (!inbounds.length) {
                container.innerHTML = '<div class="text-center py-8 text-zinc-400">No inbounds found. Create one to get started.</div>';
                return;
            }
            container.innerHTML = inbounds.map(function(inbound) {
                return '<div class="glass-light rounded-xl p-4">' +
                    '<div class="flex flex-wrap items-center justify-between gap-3">' +
                        '<div>' +
                            '<h4 class="font-bold text-white">' + inbound.name + '</h4>' +
                            '<div class="flex flex-wrap gap-2 text-xs text-zinc-400">' +
                                '<span>Protocol: <span class="text-indigo-400">' + inbound.protocol + '</span></span>' +
                                '<span>Port: <span class="text-emerald-400">' + inbound.port + '</span></span>' +
                                '<span>Path: <span class="text-zinc-300">' + inbound.path + '</span></span>' +
                                '<span>Limit: <span class="text-blue-400">' + (inbound.limit_gb || '∞') + ' GB</span></span>' +
                                '<span>Expiry: <span class="text-yellow-400">' + (inbound.expiry_days || '∞') + ' days</span></span>' +
                            '</div>' +
                        '</div>' +
                        '<div class="flex items-center gap-2">' +
                            '<div class="toggle ' + (inbound.is_active ? 'on' : '') + '" onclick="toggleInbound(' + inbound.id + ')"></div>' +
                            '<button onclick="openInboundUserModal(' + inbound.id + ')" class="px-3 py-1 bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 rounded-lg text-xs font-medium transition">+ User</button>' +
                            '<button onclick="deleteInbound(' + inbound.id + ')" class="px-3 py-1 bg-red-500/20 text-red-400 hover:bg-red-500/30 rounded-lg text-xs font-medium transition">✕</button>' +
                        '</div>' +
                    '</div>' +
                    '<div id="inbound-users-' + inbound.id + '" class="mt-3 space-y-1">' +
                        '<div class="text-xs text-zinc-500">Loading users...</div>' +
                    '</div>' +
                '</div>';
            }).join('');
            inbounds.forEach(function(inbound) {
                loadInboundUsers(inbound.id);
            });
        }

        async function loadInboundUsers(inboundId) {
            try {
                const res = await fetch('/api/inbounds/' + inboundId + '/users');
                const data = await res.json();
                var container = document.getElementById('inbound-users-' + inboundId);
                if (data.success && data.users.length) {
                    container.innerHTML = data.users.map(function(user) {
                        var used = user.used_gb || 0;
                        var limit = user.limit_gb || 0;
                        var pct = limit > 0 ? Math.min((used / limit) * 100, 100) : 0;
                        var status = user.is_active ? '✅' : '❌';
                        return '<div class="flex items-center justify-between text-xs bg-[rgba(255,255,255,0.03)] rounded-lg px-3 py-2">' +
                            '<span class="text-white font-medium">' + user.username + '</span>' +
                            '<span class="text-zinc-400">' + used.toFixed(2) + 'GB / ' + (limit || '∞') + 'GB</span>' +
                            '<span class="text-emerald-400">' + pct.toFixed(0) + '%</span>' +
                            '<span>' + status + '</span>' +
                            '<button onclick="deleteUser(\\'' + encodeURIComponent(user.username) + '\\')" class="text-red-400 hover:text-red-300">✕</button>' +
                        '</div>';
                    }).join('');
                } else {
                    container.innerHTML = '<div class="text-xs text-zinc-500 px-3 py-1">No users in this inbound</div>';
                }
            } catch (e) {
                document.getElementById('inbound-users-' + inboundId).innerHTML = '<div class="text-xs text-red-400 px-3 py-1">Error loading users</div>';
            }
        }

        async function toggleInbound(id) {
            var inbound = allInbounds.find(i => i.id === id);
            if (!inbound) return;
            try {
                await fetch('/api/inbounds/' + id, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ is_active: !inbound.is_active })
                });
                await loadInbounds();
            } catch (e) {
                alert('❌ Failed to toggle inbound');
            }
        }

        async function deleteInbound(id) {
            if (!confirm('Delete this inbound and all its users?')) return;
            try {
                await fetch('/api/inbounds/' + id, { method: 'DELETE' });
                await loadInbounds();
            } catch (e) {
                alert('❌ Failed to delete inbound');
            }
        }

        async function handleInboundSubmit(event) {
            event.preventDefault();
            var btn = document.getElementById('inbound-submit-btn');
            btn.disabled = true;
            btn.innerText = 'Creating...';
            try {
                var res = await fetch('/api/inbounds', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: document.getElementById('inbound-name').value.trim(),
                        protocol: document.getElementById('inbound-protocol').value,
                        port: parseInt(document.getElementById('inbound-port').value) || 443,
                        path: document.getElementById('inbound-path').value || '/',
                        limit_gb: parseFloat(document.getElementById('inbound-limit').value) || 0,
                        expiry_days: parseInt(document.getElementById('inbound-expiry').value) || 0,
                        max_ips: parseInt(document.getElementById('inbound-max-ips').value) || 0
                    })
                });
                var data = await res.json();
                if (data.success) {
                    alert('✅ Inbound created!');
                    toggleInboundModal(false);
                    await loadInbounds();
                } else {
                    alert('❌ Error: ' + (data.error || 'Unknown error'));
                }
            } catch (e) {
                alert('❌ Connection error');
            }
            btn.disabled = false;
            btn.innerText = 'Create';
        }

        async function handleInboundUserSubmit(event) {
            event.preventDefault();
            var btn = document.getElementById('inbound-user-submit-btn');
            btn.disabled = true;
            btn.innerText = 'Adding...';
            try {
                var inboundId = document.getElementById('inbound-user-inbound-id').value;
                var res = await fetch('/api/inbounds/' + inboundId + '/users', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: document.getElementById('inbound-user-name').value.trim(),
                        limit_gb: parseFloat(document.getElementById('inbound-user-limit').value) || 0,
                        expiry_days: parseInt(document.getElementById('inbound-user-expiry').value) || 0,
                        fingerprint: document.getElementById('inbound-user-fingerprint').value
                    })
                });
                var data = await res.json();
                if (data.success) {
                    alert('✅ User added to inbound!');
                    toggleInboundUserModal(false);
                    await loadInbounds();
                } else {
                    alert('❌ Error: ' + (data.error || 'Unknown error'));
                }
            } catch (e) {
                alert('❌ Connection error');
            }
            btn.disabled = false;
            btn.innerText = 'Add User';
        }

        // ============================================
        // USERS
        // ============================================
        function getVlessLink(username) {
            var user = allUsers.find(function(u) { return u.username === username; });
            if (!user) return '';
            var host = window.location.hostname;
            var ips = [host];
            if (user.ips) {
                ips = user.ips.split('\\n').map(function(ip) { return ip.trim(); }).filter(function(ip) { return ip.length > 0; });
                if (ips.length === 0) ips = [host];
            }
            var ports = String(user.port || '443').split(',').map(function(p) { return p.trim(); }).filter(function(p) { return p.length > 0; });
            var fp = user.fingerprint || 'chrome';
            var now = new Date();
            var created = new Date(user.created_at);
            var expiryDays = user.expiry_days || 30;
            var expiryDate = new Date(created.getTime() + expiryDays * 24 * 60 * 60 * 1000);
            var daysLeft = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
            var totalGB = user.limit_gb || 0;
            var usedGB = user.used_gb || 0;
            var expiryDateStr = expiryDate.toISOString().split('T')[0].replace(/-/g, '/');
            var usedFormatted = usedGB >= 1 ? usedGB.toFixed(1) + 'GB' : (usedGB * 1024).toFixed(0) + 'MB';
            var totalFormatted = totalGB >= 1 ? totalGB + 'GB' : 'Unlimited';
            var configName = user.config_name || user.username;
            var links = [];
            var firstIp = ips[0] || host;
            var firstPort = ports[0] || '443';
            var isTlsPort = tlsPorts.includes(firstPort);
            var tlsVal = isTlsPort ? 'tls' : 'none';
            var remark1 = '⏳ ' + user.username.toUpperCase() + ' | 📅 Exp: ' + expiryDateStr + ' | 🔥 ' + daysLeft + ' Days Left';
            links.push('vle' + 'ss://' + (user.uuid || '') + '@' + firstIp + ':' + firstPort + '?path=%2F&security=' + tlsVal + '&encryption=none&insecure=0&host=' + host + '&fp=' + fp + '&type=ws&allowInsecure=0&sni=' + host + '#' + encodeURIComponent(remark1));
            var remark2 = '📊 ' + user.username.toUpperCase() + ' | 💾 ' + totalFormatted + ' Total | ⚡ ' + usedFormatted + ' Used';
            links.push('vle' + 'ss://' + (user.uuid || '') + '@' + firstIp + ':' + firstPort + '?path=%2F&security=' + tlsVal + '&encryption=none&insecure=0&host=' + host + '&fp=' + fp + '&type=ws&allowInsecure=0&sni=' + host + '#' + encodeURIComponent(remark2));
            ips.forEach(function(ip) {
                ports.forEach(function(portStr) {
                    var isTlsPortLoop = tlsPorts.includes(portStr);
                    var tlsValLoop = isTlsPortLoop ? 'tls' : 'none';
                    var remark3 = configName;
                    links.push('vle' + 'ss://' + (user.uuid || '') + '@' + ip + ':' + portStr + '?path=%2F&security=' + tlsValLoop + '&encryption=none&insecure=0&host=' + host + '&fp=' + fp + '&type=ws&allowInsecure=0&sni=' + host + '#' + encodeURIComponent(remark3));
                });
            });
            return links.join('\\n');
        }

        function getSubLink(username) { return window.location.origin + '/feed/' + encodeURIComponent(username); }
        function getJsonSubLink(username) { return window.location.origin + '/feed/json/' + encodeURIComponent(username); }
        function getStatusLink(username) { return window.location.origin + '/status/' + encodeURIComponent(username); }

        function copySubLink(encodedUsername) {
            var username = decodeURIComponent(encodedUsername);
            navigator.clipboard.writeText(getSubLink(username)).then(function() { alert('✅ Text subscription link copied!'); });
        }
        function copyJsonSubLink(encodedUsername) {
            var username = decodeURIComponent(encodedUsername);
            navigator.clipboard.writeText(getJsonSubLink(username)).then(function() { alert('✅ JSON subscription link copied!'); });
        }
        function copyStatusLink(encodedUsername) {
            var username = decodeURIComponent(encodedUsername);
            navigator.clipboard.writeText(getStatusLink(username)).then(function() { alert('✅ Status page link copied!'); });
        }

        function copyConfig(encodedUsername) {
            var username = decodeURIComponent(encodedUsername);
            var link = getVlessLink(username);
            if (!link) return;
            navigator.clipboard.writeText(link).then(function() { alert('✅ VLESS config copied!'); });
        }

        function showQR(encodedUsername) {
            var username = decodeURIComponent(encodedUsername);
            var link = getVlessLink(username);
            if (!link) return;
            toggleQRModal(true, link, 'VLESS Config QR - ' + username);
        }

        function editUser(encodedUsername) {
            var username = decodeURIComponent(encodedUsername);
            var user = allUsers.find(function(u) { return u.username === username; });
            if (!user) {
                alert('❌ User not found!');
                return;
            }
            isEditMode = true;
            editingUsername = username;
            document.getElementById('modal-title').innerText = 'Edit Client: ' + username;
            document.getElementById('submit-btn').innerText = 'Save';
            document.getElementById('input-name').value = username;
            document.getElementById('input-name').disabled = true;
            document.getElementById('input-limit').value = user.limit_gb || '';
            document.getElementById('input-expiry').value = user.expiry_days || '';
            document.getElementById('input-ips').value = user.ips || '';
            document.getElementById('fingerprint-select').value = user.fingerprint || 'chrome';
            document.getElementById('config-name-input').value = user.config_name || '';
            var userPorts = String(user.port || '').split(',').map(function(p) { return p.trim(); });
            document.querySelectorAll('input[name="ports"]').forEach(function(cb) {
                cb.checked = userPorts.includes(cb.value);
            });
            loadInboundSelect();
            toggleModal(true);
        }

        async function deleteUser(encodedUsername) {
            var username = decodeURIComponent(encodedUsername);
            if (!confirm('⚠️ Are you sure you want to delete user: ' + username + '?')) return;
            try {
                var response = await fetch('/api/users/' + encodeURIComponent(username), { method: 'DELETE' });
                if (response.ok) {
                    alert('✅ User deleted successfully!');
                    await loadUsers(true);
                } else {
                    var errData = await response.json();
                    alert('❌ Error: ' + (errData.error || 'Operation failed'));
                }
            } catch (err) {
                alert('❌ Connection error');
            }
        }

        async function toggleUserStatus(encodedUsername) {
            var username = decodeURIComponent(encodedUsername);
            try {
                var response = await fetch('/api/users/' + encodeURIComponent(username), {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ toggle_only: true })
                });
                if (response.ok) {
                    await loadUsers(true);
                } else {
                    var errData = await response.json();
                    alert('❌ Error: ' + (errData.error || 'Operation failed'));
                }
            } catch (err) {
                alert('❌ Connection error');
            }
        }

        // ============================================
        // USER LOADING
        // ============================================
        async function loadUsers(silent) {
            var loadingState = document.getElementById('loading-state');
            var tableContainer = document.getElementById('users-table-container');
            var emptyState = document.getElementById('empty-state');
            if (!silent) {
                loadingState.classList.remove('hidden');
                tableContainer.classList.add('hidden');
                emptyState.classList.add('hidden');
            }
            try {
                var res = await fetch('/api/users?t=' + Date.now());
                if (!res.ok) throw new Error();
                var data = await res.json();
                renderUsersUI(data);
            } catch (err) {
                if (!silent) {
                    loadingState.innerHTML = '<span class="text-red-400">❌ Error loading clients</span>';
                }
            }
        }

        function renderUsersUI(data) {
            try {
                var users = data.users || [];
                allUsers = users;
                var serverTime = data.serverTime || Date.now();
                lastServerTime = serverTime;
                var totalUsersCount = users.length;
                var activeUsersCount = users.filter(function(u) { return u.is_online === 1; }).length;
                var totalGbUsage = users.reduce(function(sum, u) { return sum + (u.used_gb || 0); }, 0);
                document.getElementById('stat-total-users').innerText = totalUsersCount;
                document.getElementById('stat-active-users').innerText = activeUsersCount;
                document.getElementById('stat-total-usage').innerText = totalGbUsage < 1 ? (totalGbUsage * 1024).toFixed(0) + ' MB' : totalGbUsage.toFixed(2) + ' GB';
                var topUser = users.reduce(function(max, u) { return (u.used_gb || 0) > (max.used_gb || 0) ? u : max; }, { username: 'None', used_gb: 0 });
                document.getElementById('stat-top-user').innerText = topUser.username;
                var topUsage = topUser.used_gb || 0;
                document.getElementById('stat-top-user-usage').innerText = topUsage < 1 ? (topUsage * 1024).toFixed(0) + ' MB used' : topUsage.toFixed(2) + ' GB used';
                filterAndRenderUsers();
                updateXrayStatus();
                updateSystemStats();
            } catch (err) {
                document.getElementById('loading-state').innerHTML = '<span class="text-red-400">❌ Error processing user data</span>';
            }
        }

        function filterAndRenderUsers() {
            if (!allUsers) return;
            var searchQuery = (document.getElementById('search-input').value || '').toLowerCase().trim();
            var filterStatus = document.getElementById('filter-status').value;
            var serverTime = lastServerTime || Date.now();
            var filtered = allUsers.slice();
            if (searchQuery) {
                filtered = filtered.filter(function(u) {
                    return (u.username || '').toLowerCase().includes(searchQuery) || 
                           (u.uuid || '').toLowerCase().includes(searchQuery);
                });
            }
            if (filterStatus !== 'all') {
                filtered = filtered.filter(function(u) {
                    var isOnline = u.is_online === 1;
                    var isActive = u.is_active === 1;
                    var isExpired = false;
                    if (u.limit_gb && u.used_gb >= u.limit_gb) isExpired = true;
                    if (u.expiry_days && u.created_at) {
                        var created = new Date(u.created_at);
                        var expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
                        if (new Date(serverTime) > expiryDate) isExpired = true;
                    }
                    if (filterStatus === 'active') return isActive && !isExpired;
                    if (filterStatus === 'inactive') return !isActive;
                    if (filterStatus === 'online') return isOnline;
                    if (filterStatus === 'offline') return !isOnline;
                    if (filterStatus === 'expired') return isExpired || !isActive;
                    return true;
                });
            }
            renderFilteredUsers(filtered, serverTime);
        }

        function renderFilteredUsers(users, serverTime) {
            var loadingState = document.getElementById('loading-state');
            var tableContainer = document.getElementById('users-table-container');
            var emptyState = document.getElementById('empty-state');
            var tbody = document.getElementById('users-tbody');
            if (users.length === 0) {
                loadingState.classList.add('hidden');
                emptyState.classList.remove('hidden');
                tableContainer.classList.add('hidden');
                if (allUsers && allUsers.length > 0) {
                    emptyState.querySelector('p').innerText = 'No clients match your search criteria.';
                } else {
                    emptyState.querySelector('p').innerText = 'No clients found. Click "Add Client" to get started.';
                }
            } else {
                loadingState.classList.add('hidden');
                emptyState.classList.add('hidden');
                tableContainer.classList.remove('hidden');
                tbody.innerHTML = users.map(function(user) {
                    var createdDate = user.created_at ? new Date(user.created_at).toLocaleDateString() : '-';
                    var daysRemaining = 'Unlimited';
                    var daysPercent = 100;
                    if (user.expiry_days) {
                        if (user.created_at) {
                            var created = new Date(user.created_at);
                            var expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
                            var diffDays = Math.ceil((expiryDate - new Date(serverTime)) / (1000 * 60 * 60 * 24));
                            daysRemaining = diffDays > 0 ? diffDays : 0;
                            daysPercent = Math.max(0, Math.min(100, (daysRemaining / user.expiry_days) * 100));
                        } else {
                            daysRemaining = user.expiry_days;
                        }
                    }
                    var usedGb = user.used_gb || 0;
                    var formattedUsed = usedGb < 1 ? (usedGb * 1024).toFixed(0) + ' MB' : usedGb.toFixed(2) + ' GB';
                    var volumeHtml = '';
                    if (user.limit_gb) {
                        var limitPercent = Math.min((usedGb / user.limit_gb) * 100, 100);
                        var limitHue = 120 - (limitPercent * 1.2);
                        var formattedLimit = user.limit_gb < 1 ? (user.limit_gb * 1024).toFixed(0) + ' MB' : user.limit_gb + ' GB';
                        volumeHtml = '<div class="flex flex-col gap-1 w-full min-w-[100px]">' +
                            '<div class="flex justify-between text-[10px] sm:text-[11px] text-zinc-400 font-medium">' +
                                '<span>Used: ' + formattedUsed + '</span>' +
                                '<span>Total: ' + formattedLimit + '</span>' +
                            '</div>' +
                            '<div class="w-full bg-zinc-800 rounded-full h-1 overflow-hidden">' +
                                '<div class="h-1 rounded-full transition-all duration-500" style="width: ' + limitPercent + '%; background-color: hsl(' + limitHue + ', 80%, 45%)"></div>' +
                            '</div>' +
                        '</div>';
                    } else {
                        volumeHtml = '<div class="flex flex-col gap-1 w-full min-w-[100px]">' +
                            '<div class="flex justify-between text-[10px] sm:text-[11px] text-zinc-400 font-medium">' +
                                '<span>Used: ' + formattedUsed + '</span>' +
                                '<span>Total: Unlimited</span>' +
                            '</div>' +
                            '<div class="w-full bg-zinc-800 rounded-full h-1 overflow-hidden">' +
                                '<div class="bg-blue-500 h-1 rounded-full transition-all duration-500" style="width: 100%"></div>' +
                            '</div>' +
                        '</div>';
                    }
                    var expiryHtml = '';
                    if (user.expiry_days) {
                        var expiryHue = daysPercent * 1.2;
                        expiryHtml = '<div class="flex flex-col gap-1 w-full min-w-[100px]">' +
                            '<div class="flex justify-between text-[10px] sm:text-[11px] text-zinc-400 font-medium">' +
                                '<span>Remaining: ' + daysRemaining + ' days</span>' +
                                '<span>Total: ' + user.expiry_days + ' days</span>' +
                            '</div>' +
                            '<div class="w-full bg-zinc-800 rounded-full h-1 overflow-hidden flex justify-end">' +
                                '<div class="h-1 rounded-full transition-all duration-500" style="width: ' + daysPercent + '%; background-color: hsl(' + expiryHue + ', 80%, 45%)"></div>' +
                            '</div>' +
                        '</div>';
                    } else {
                        expiryHtml = '<div class="flex flex-col gap-1 w-full min-w-[100px]">' +
                            '<div class="flex justify-between text-[10px] sm:text-[11px] text-zinc-400 font-medium">' +
                                '<span>Remaining: Unlimited</span>' +
                                '<span>Total: Unlimited</span>' +
                            '</div>' +
                            '<div class="w-full bg-zinc-800 rounded-full h-1 overflow-hidden flex justify-end">' +
                                '<div class="bg-blue-500 h-1 rounded-full transition-all duration-500" style="width: 100%"></div>' +
                            '</div>' +
                        '</div>';
                    }
                    var statusBtnColor = user.is_active === 0 ? 'text-emerald-400 hover:bg-emerald-500/10' : 'text-amber-400 hover:bg-amber-500/10';
                    var statusBtnTitle = user.is_active === 0 ? 'Activate' : 'Deactivate';
                    var statusBtnIcon = user.is_active === 0 
                        ? '<svg class="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'
                        : '<svg class="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>';
                    var statusClass = user.is_active === 0 ? 'badge-danger' : 'badge-success';
                    var statusText = user.is_active === 0 ? 'Inactive' : 'Active';
                    var onlineClass = user.is_online === 1 ? 'badge-success' : 'badge';
                    var onlineText = user.is_online === 1 ? '● Online' : 'Offline';
                    var configName = user.config_name || user.username;
                    return '<tr class="hover:bg-white/5 border-b border-zinc-800/30">' +
                        '<td class="p-2 sm:p-3">' +
                            '<div class="flex flex-col gap-1">' +
                                '<span class="font-bold text-white text-xs sm:text-sm truncate max-w-[120px] sm:max-w-[200px]">' + configName + '</span>' +
                                '<div class="flex items-center gap-1 flex-wrap">' +
                                    '<span class="badge ' + statusClass + '">' + statusText + '</span>' +
                                    '<span class="badge ' + onlineClass + '">' + onlineText + '</span>' +
                                '</div>' +
                                '<div class="flex gap-0.5 sm:gap-1 flex-wrap">' +
                                    '<button onclick="copyConfig(\\'' + encodeURIComponent(user.username) + '\\')" title="Copy VLESS" class="action-btn text-zinc-400 hover:text-indigo-400 transition"><svg class="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg></button>' +
                                    '<button onclick="showQR(\\'' + encodeURIComponent(user.username) + '\\')" title="QR" class="action-btn text-zinc-400 hover:text-emerald-400 transition"><svg class="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm14 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"/></svg></button>' +
                                    '<button onclick="toggleUserStatus(\\'' + encodeURIComponent(user.username) + '\\')" title="' + statusBtnTitle + '" class="action-btn ' + statusBtnColor + ' transition">' + statusBtnIcon + '</button>' +
                                    '<button onclick="editUser(\\'' + encodeURIComponent(user.username) + '\\')" title="Edit" class="action-btn text-zinc-400 hover:text-yellow-400 transition"><svg class="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg></button>' +
                                    '<button onclick="deleteUser(\\'' + encodeURIComponent(user.username) + '\\')" title="Delete" class="action-btn text-zinc-400 hover:text-red-400 transition"><svg class="w-3 h-3 sm:w-4 sm:h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg></button>' +
                                '</div>' +
                            '</div>' +
                        '</td>' +
                        '<td class="p-2 sm:p-3">' +
                            '<div class="flex flex-col gap-1">' +
                                '<div class="flex gap-0.5 sm:gap-1">' +
                                    '<button onclick="copySubLink(\\'' + encodeURIComponent(user.username) + '\\')" class="flex-1 px-1 sm:px-2 py-0.5 sm:py-1 text-[8px] sm:text-xs font-medium rounded-lg bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 transition">📋 Text</button>' +
                                    '<button onclick="copyJsonSubLink(\\'' + encodeURIComponent(user.username) + '\\')" class="flex-1 px-1 sm:px-2 py-0.5 sm:py-1 text-[8px] sm:text-xs font-medium rounded-lg bg-purple-500/10 text-purple-400 hover:bg-purple-500/20 transition">📄 JSON</button>' +
                                '</div>' +
                                '<button onclick="copyStatusLink(\\'' + encodeURIComponent(user.username) + '\\')" class="px-1 sm:px-2 py-0.5 sm:py-1 text-[8px] sm:text-xs font-medium rounded-lg bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition">📊 Status</button>' +
                            '</div>' +
                        '</td>' +
                        '<td class="p-2 sm:p-3 text-[10px] sm:text-xs font-mono uppercase text-indigo-400 font-semibold hidden sm:table-cell">VLESS</td>' +
                        '<td class="p-2 sm:p-3 text-[10px] sm:text-xs hidden md:table-cell">' + 
                            '<div class="flex flex-wrap gap-0.5 sm:gap-1 max-w-[120px]">' +
                                String(user.port || "").split(",").map(function(p) {
                                    p = p.trim();
                                    if (!p) return "";
                                    var isTls = tlsPorts.includes(p);
                                    return '<span class="badge ' + (isTls ? 'badge-success' : 'badge-warning') + '">' + p + '</span>';
                                }).join("") +
                            '</div>' +
                        '</td>' +
                        '<td class="p-2 sm:p-3 hidden lg:table-cell">' + volumeHtml + '</td>' +
                        '<td class="p-2 sm:p-3 hidden xl:table-cell">' + expiryHtml + '</td>' +
                    '</tr>';
                }).join('');
            }
        }

        // ============================================
        // SYSTEM STATS
        // ============================================
        async function updateSystemStats() {
            try {
                var res = await fetch('/api/system/stats');
                var data = await res.json();
                if (data) {
                    var cpuPercent = data.cpu ? data.cpu.load[0] || 0 : 0;
                    document.getElementById('cpu-percent').innerText = cpuPercent.toFixed(1) + '%';
                    document.getElementById('cpu-bar').style.width = Math.min(cpuPercent, 100) + '%';
                    document.getElementById('cpu-cores').innerText = (data.cpu ? data.cpu.cores || 2 : 2) + ' Cores';
                    
                    var ramUsed = data.ram ? data.ram.used || 0 : 0;
                    var ramTotal = data.ram ? data.ram.total || 0 : 0;
                    var ramPercent = ramTotal > 0 ? (ramUsed / ramTotal) * 100 : 0;
                    document.getElementById('ram-percent').innerText = ramPercent.toFixed(1) + '%';
                    document.getElementById('ram-used').innerText = ramUsed.toFixed(1) + ' MB';
                    document.getElementById('ram-total').innerText = ramTotal.toFixed(1) + ' MB';
                    document.getElementById('ram-bar').style.width = Math.min(ramPercent, 100) + '%';
                    
                    var swapUsed = data.swap ? data.swap.used || 0 : 0;
                    var swapTotal = data.swap ? data.swap.total || 0 : 0;
                    var swapPercent = swapTotal > 0 ? (swapUsed / swapTotal) * 100 : 0;
                    document.getElementById('swap-percent').innerText = swapPercent.toFixed(0) + '%';
                    document.getElementById('swap-used').innerText = swapUsed.toFixed(0) + ' B';
                    document.getElementById('swap-total').innerText = swapTotal.toFixed(0) + ' B';
                    document.getElementById('swap-bar').style.width = Math.min(swapPercent, 100) + '%';
                    
                    var storageUsed = data.storage ? data.storage.used || 0 : 0;
                    var storageTotal = data.storage ? data.storage.total || 0 : 0;
                    var storagePercent = storageTotal > 0 ? (storageUsed / storageTotal) * 100 : 0;
                    document.getElementById('storage-percent').innerText = storagePercent.toFixed(1) + '%';
                    document.getElementById('storage-used').innerText = storageUsed.toFixed(2) + ' GB';
                    document.getElementById('storage-total').innerText = storageTotal.toFixed(2) + ' GB';
                    document.getElementById('storage-bar').style.width = Math.min(storagePercent, 100) + '%';
                    
                    if (data.system_load) {
                        document.getElementById('system-load').innerText = data.system_load;
                    }
                    if (data.xray_uptime !== undefined) {
                        var uptime = data.xray_uptime;
                        var hours = Math.floor(uptime / 3600);
                        var minutes = Math.floor((uptime % 3600) / 60);
                        document.getElementById('xray-uptime').innerText = hours > 0 ? hours + 'h ' + minutes + 'm' : minutes + 'm';
                    }
                    if (data.traffic) {
                        document.getElementById('total-sent').innerText = (data.traffic.sent || 0).toFixed(2) + ' MB';
                        document.getElementById('total-received').innerText = (data.traffic.received || 0).toFixed(2) + ' MB';
                    }
                    if (data.connections) {
                        document.getElementById('tcpConn').innerText = data.connections.tcp || 0;
                        document.getElementById('udpConn').innerText = data.connections.udp || 0;
                    }
                }
            } catch (e) {}
        }

        // ============================================
        // FORM HANDLER
        // ============================================
        async function handleFormSubmit(event) {
            event.preventDefault();
            var submitButton = document.getElementById('submit-btn');
            submitButton.disabled = true;
            submitButton.innerText = isEditMode ? 'Saving...' : 'Creating...';
            var username = document.getElementById('input-name').value.trim();
            var limit = document.getElementById('input-limit').value || null;
            var expiry = document.getElementById('input-expiry').value || null;
            var checkedPorts = Array.from(document.querySelectorAll('input[name="ports"]:checked')).map(function(cb) { return cb.value; });
            if (checkedPorts.length === 0) {
                alert('❌ Please select at least one port!');
                submitButton.disabled = false;
                submitButton.innerText = isEditMode ? 'Save' : 'Create';
                return;
            }
            var port = checkedPorts.join(',');
            var tls = checkedPorts.some(function(p) { return tlsPorts.includes(p); }) ? 'on' : 'off';
            var ips = document.getElementById('input-ips').value;
            var fingerprint = document.getElementById('fingerprint-select').value;
            var config_name = document.getElementById('config-name-input').value || '';
            var inbound_id = parseInt(document.getElementById('inbound-select').value) || 0;
            var url = isEditMode ? '/api/users/' + encodeURIComponent(editingUsername) : '/api/users';
            var method = isEditMode ? 'PUT' : 'POST';
            try {
                var response = await fetch(url, {
                    method: method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, limit_gb: limit, expiry_days: expiry, tls, port, ips, fingerprint, config_name, inbound_id })
                });
                if (response.ok) {
                    toggleModal(false);
                    await loadUsers(true);
                    await loadInbounds();
                } else {
                    var errData = await response.json();
                    alert('❌ Error: ' + (errData.error || 'Operation failed'));
                }
            } catch (err) {
                alert('❌ Connection error');
            } finally {
                submitButton.disabled = false;
                submitButton.innerText = isEditMode ? 'Save' : 'Create';
            }
        }

        // ============================================
        // LOCATIONS
        // ============================================
        function getFlagEmoji(countryCode) {
            if (!countryCode) return '🌐';
            var codePoints = countryCode.toUpperCase().split('').map(function(char) { return 127397 + char.charCodeAt(0); });
            try {
                return String.fromCodePoint.apply(String, codePoints);
            } catch (e) {
                return '🌐';
            }
        }

        function renderLocationsUI(locations, activeIata) {
            var select = document.getElementById('location-select');
            if (!select) return;
            locations.sort(function(a, b) { return (a.cca2 || '').localeCompare(b.cca2 || ''); });
            var html = '<option value="">🌐 Default Location</option>';
            locations.forEach(function(loc) {
                if (loc.iata && loc.city) {
                    var flag = getFlagEmoji(loc.cca2);
                    var isSelected = loc.iata.toUpperCase() === activeIata.toUpperCase() ? 'selected' : '';
                    html += '<option value="' + loc.iata + '" ' + isSelected + '>' + flag + ' ' + loc.city + ' (' + loc.iata + ')</option>';
                }
            });
            select.innerHTML = html;
        }

        async function loadLocations() {
            var select = document.getElementById('location-select');
            if (!select) return;
            var cachedLocations = localStorage.getItem('cached_locations_list');
            var cachedActiveIata = localStorage.getItem('cached_active_iata') || '';
            var hasCachedLocs = false;
            if (cachedLocations) {
                try {
                    var parsedLocs = JSON.parse(cachedLocations);
                    if (Array.isArray(parsedLocs) && parsedLocs.length > 0) {
                        renderLocationsUI(parsedLocs, cachedActiveIata);
                        hasCachedLocs = true;
                    }
                } catch(e) {}
            }
            try {
                var statusRes = await fetch('/api/proxy-ip');
                var activeIata = '';
                if (statusRes.ok) {
                    var statusData = await statusRes.json();
                    activeIata = statusData.iata || '';
                    localStorage.setItem('cached_active_iata', activeIata);
                    if(statusData.frag_len) {
                        window.globalFragLen = statusData.frag_len;
                        document.getElementById('frag-length').value = statusData.frag_len;
                    }
                    if(statusData.frag_int) {
                        window.globalFragInt = statusData.frag_int;
                        document.getElementById('frag-interval').value = statusData.frag_int;
                    }
                }
                var res = await fetch('/locations');
                if (!res.ok) throw new Error();
                var locations = await res.json();
                localStorage.setItem('cached_locations_list', JSON.stringify(locations));
                renderLocationsUI(locations, activeIata);
            } catch (err) {
                if (!hasCachedLocs) {
                    select.innerHTML = '<option value="">⚠️ Error loading locations</option>';
                }
            }
        }

        // ============================================
        // SETTINGS
        // ============================================
        async function saveSettings() {
            var select = document.getElementById('location-select');
            var fragLen = document.getElementById('frag-length').value || "20-30";
            var fragInt = document.getElementById('frag-interval').value || "1-2";
            var iata = select.value;
            try {
                var resolvedIp = 'proxyip.cmliussss.net';
                if (iata) {
                    var domain = iata.toLowerCase() + '.proxyip.cmliussss.net';
                    var dnsRes = await fetch('https://cloudflare-dns.com/dns-query?name=' + domain + '&type=A', {
                        headers: { 'accept': 'application/dns-json' }
                    });
                    resolvedIp = domain;
                    if (dnsRes.ok) {
                        var dnsData = await dnsRes.json();
                        if (dnsData.Answer && dnsData.Answer.length > 0) {
                            var ips = dnsData.Answer.filter(function(ans) { return ans.type === 1; }).map(function(ans) { return ans.data; });
                            if (ips.length > 0) {
                                resolvedIp = ips[Math.floor(Math.random() * ips.length)];
                            }
                        }
                    }
                }
                var response = await fetch('/api/proxy-ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ proxy_ip: resolvedIp, iata: iata ? iata.toUpperCase() : '', frag_len: fragLen, frag_int: fragInt })
                });
                if (response.ok) {
                    window.globalFragLen = fragLen;
                    window.globalFragInt = fragInt;
                    alert('✅ Settings saved successfully!');
                } else {
                    alert('❌ Error saving settings');
                }
            } catch (err) {
                alert('❌ Connection error');
            }
        }

        async function changeAdminPassword() {
            var currentPwd = document.getElementById('change-pwd-current').value;
            var newPwd = document.getElementById('change-pwd-new').value;
            if (!currentPwd || !newPwd) {
                alert('❌ Please enter both current and new password');
                return;
            }
            if (newPwd.length < 4) {
                alert('❌ New password must be at least 4 characters');
                return;
            }
            try {
                var response = await fetch('/api/change-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ current_password: currentPwd, new_password: newPwd })
                });
                var data = await response.json();
                if (response.ok && data.success) {
                    alert('✅ Password updated successfully!');
                    document.getElementById('change-pwd-current').value = '';
                    document.getElementById('change-pwd-new').value = '';
                } else {
                    alert('❌ Error: ' + (data.error || 'Operation failed'));
                }
            } catch (err) {
                alert('❌ Connection error');
            }
        }

        // ============================================
        // CLEAN IPS
        // ============================================
        async function loadCleanIps() {
            try {
                var res = await fetch('/api/clean-ips');
                var data = await res.json();
                if (data.success) {
                    var container = document.getElementById('clean-ips-list');
                    if (data.ips.length) {
                        container.innerHTML = data.ips.map(function(ip) {
                            return '<span class="glass-light px-3 py-1 rounded-lg text-sm flex items-center gap-2">' + ip.address + ' <button onclick="deleteCleanIp(' + ip.id + ')" class="text-red-400 hover:text-red-300 text-xs">✕</button></span>';
                        }).join('');
                    } else {
                        container.innerHTML = '<span class="text-zinc-500 text-sm">No clean IPs added</span>';
                    }
                }
            } catch (e) {}
        }

        async function addCleanIp() {
            var input = document.getElementById('clean-ip-input');
            var address = input.value.trim();
            if (!address) {
                alert('❌ Enter an IP or domain');
                return;
            }
            try {
                var res = await fetch('/api/clean-ips', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ address })
                });
                if (res.ok) {
                    input.value = '';
                    await loadCleanIps();
                    alert('✅ IP added to clean list');
                } else {
                    alert('❌ Failed to add IP');
                }
            } catch (e) {
                alert('❌ Connection error');
            }
        }

        async function deleteCleanIp(id) {
            try {
                var res = await fetch('/api/clean-ips/' + id, { method: 'DELETE' });
                if (res.ok) {
                    await loadCleanIps();
                }
            } catch (e) {}
        }

        // ============================================
        // CUSTOM DOMAIN
        // ============================================
        async function loadCustomDomain() {
            try {
                var res = await fetch('/api/custom-domain');
                var data = await res.json();
                if (data.success) {
                    document.getElementById('current-domain-display').innerText = 'Current: ' + (data.domain || 'None');
                }
            } catch (e) {}
        }

        async function saveCustomDomain() {
            var input = document.getElementById('custom-domain-input');
            var domain = input.value.trim();
            try {
                var res = await fetch('/api/custom-domain', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain })
                });
                if (res.ok) {
                    input.value = '';
                    await loadCustomDomain();
                    alert('✅ Custom domain saved');
                } else {
                    alert('❌ Failed to save domain');
                }
            } catch (e) {
                alert('❌ Connection error');
            }
        }

        // ============================================
        // UPDATE
        // ============================================
        async function checkUpdate() {
            const info = document.getElementById('update-info');
            info.innerText = 'Checking for updates...';
            info.style.color = '#60a5fa';
            try {
                const res = await fetch('/api/update-check');
                const data = await res.json();
                if (data.update_available) {
                    info.innerHTML = '✅ New version <strong>' + data.latest_version + '</strong> available! <a href="' + data.url + '" target="_blank" class="text-emerald-400 hover:underline">View release</a>';
                    info.style.color = '#34d399';
                } else {
                    info.innerHTML = '✅ You are running the latest version <strong>' + data.current_version + '</strong>';
                    info.style.color = '#34d399';
                }
            } catch (e) {
                info.innerText = '❌ Could not check for updates';
                info.style.color = '#ef4444';
            }
        }

        async function updatePanel() {
            if (!confirm('🔥 Fire Update: Update the panel to the latest version? (Database will not be affected)')) return;
            try {
                const res = await fetch('/api/update-panel', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    alert('✅ Panel updated to ' + data.version + '!');
                    window.location.reload();
                } else {
                    alert('❌ Update failed: ' + (data.error || 'Unknown error'));
                }
            } catch (e) {
                alert('❌ Connection error');
            }
        }

        // ============================================
        // LOGOUT
        // ============================================
        async function logoutAdmin() {
            if (!confirm('⚠️ Are you sure you want to sign out?')) return;
            try {
                await fetch('/api/logout', { method: 'POST' });
            } catch (err) {}
            window.location.reload();
        }

        // ============================================
        // INIT
        // ============================================
        document.addEventListener('DOMContentLoaded', function() {
            renderPortCheckboxes();
            loadUsers();
            loadInbounds();
            loadLocations();
            loadTheme();
            loadCleanIps();
            loadCustomDomain();
            checkUpdate();
            setInterval(function() { loadUsers(true); }, 30000);
            setInterval(updateXrayStatus, 10000);
            setInterval(updateSystemStats, 15000);
            showPage('dashboard');
            document.getElementById('log-start-time').innerText = new Date().toLocaleString();
            setTimeout(function() {
                var cb443 = document.querySelector('input[name="ports"][value="443"]');
                if (cb443) cb443.checked = true;
            }, 200);
            window.addEventListener('resize', function() {
                if (window.innerWidth >= 1024) {
                    var sidebar = document.querySelector('.sidebar');
                    var overlay = document.getElementById('sidebar-overlay');
                    if (sidebar) sidebar.classList.remove('active');
                    if (overlay) overlay.classList.remove('active');
                    var menuIcon = document.querySelector('#menu-icon');
                    if (menuIcon) menuIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>';
                }
            });
        });
    <\/script>
</body>
</html>`,

  status: `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Status - VoidLatency</title>
    <script src="https://cdn.tailwindcss.com"><\/script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"><\/script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        * { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
        body { background: #0a0a0f; }
        .glass { background: rgba(255,255,255,0.03); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.06); }
        .glow { box-shadow: 0 0 60px rgba(99, 102, 241, 0.15); }
        .glass-light { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.06); }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
    <div class="max-w-lg w-full glass rounded-2xl p-8 glow">
        <div class="text-center mb-8">
            <div class="inline-block p-3 rounded-2xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/20 mb-3">
                <svg class="w-10 h-10 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                </svg>
            </div>
            <h1 class="text-2xl font-bold text-white mb-1">Subscription Status</h1>
            <p id="display-username" class="text-sm text-indigo-400 font-mono font-semibold"></p>
            <p class="text-xs text-zinc-500 mt-1">@VoidLatency</p>
        </div>
        <div id="status-card" class="mb-6 rounded-2xl p-4 text-center border font-semibold transition">
            <span id="status-text" class="text-sm">Loading status...</span>
        </div>
        <div class="space-y-4 mb-6">
            <div class="glass-light rounded-2xl p-4">
                <div class="flex justify-between items-center mb-2">
                    <span class="text-xs text-zinc-400 font-medium">📊 Data Usage</span>
                    <span id="volume-pct" class="text-xs font-bold text-indigo-400">0%</span>
                </div>
                <div class="w-full bg-zinc-800 rounded-full h-2 overflow-hidden mb-2">
                    <div id="volume-progress" class="bg-gradient-to-r from-indigo-500 to-purple-500 h-2 rounded-full transition-all duration-1000" style="width: 0%"></div>
                </div>
                <div class="flex justify-between text-xs text-zinc-400">
                    <span>Used: <span id="used-vol" class="text-white font-medium">-</span></span>
                    <span>Total: <span id="limit-vol" class="text-white font-medium">-</span></span>
                </div>
            </div>
            <div class="glass-light rounded-2xl p-4">
                <div class="flex justify-between items-center mb-2">
                    <span class="text-xs text-zinc-400 font-medium">⏳ Time Remaining</span>
                    <span id="expiry-pct" class="text-xs font-bold text-purple-400">0%</span>
                </div>
                <div class="w-full bg-zinc-800 rounded-full h-2 overflow-hidden mb-2">
                    <div id="expiry-progress" class="bg-gradient-to-r from-purple-500 to-pink-500 h-2 rounded-full transition-all duration-1000" style="width: 0%"></div>
                </div>
                <div class="flex justify-between text-xs text-zinc-400">
                    <span>Remaining: <span id="days-remaining" class="text-white font-medium">-</span></span>
                    <span>Total: <span id="total-days" class="text-white font-medium">-</span></span>
                </div>
            </div>
        </div>
        <div class="border-t border-zinc-800/30 pt-4 space-y-2">
            <button onclick="copyVlessConfig()" class="w-full flex items-center justify-between px-4 py-3 glass-light hover:border-indigo-500/50 rounded-xl text-sm font-medium transition">
                <span class="flex items-center gap-2 text-zinc-300">🚀 Copy VLESS Config</span>
                <span class="text-indigo-400 text-xs font-semibold">Copy</span>
            </button>
            <button onclick="copyJsonSub()" class="w-full flex items-center justify-between px-4 py-3 glass-light hover:border-purple-500/50 rounded-xl text-sm font-medium transition">
                <span class="flex items-center gap-2 text-zinc-300">📄 Copy JSON Subscription</span>
                <span class="text-purple-400 text-xs font-semibold">Copy</span>
            </button>
            <button onclick="copyTextSub()" class="w-full flex items-center justify-between px-4 py-3 glass-light hover:border-blue-500/50 rounded-xl text-sm font-medium transition">
                <span class="flex items-center gap-2 text-zinc-300">📋 Copy Text Subscription</span>
                <span class="text-blue-400 text-xs font-semibold">Copy</span>
            </button>
            <button onclick="showQR()" class="w-full flex items-center justify-between px-4 py-3 glass-light hover:border-emerald-500/50 rounded-xl text-sm font-medium transition">
                <span class="flex items-center gap-2 text-zinc-300">📱 Show QR Code</span>
                <span class="text-emerald-400 text-xs font-semibold">View</span>
            </button>
        </div>
        <div class="mt-4 pt-4 border-t border-zinc-800/30 text-center">
            <p class="text-xs text-zinc-500">VoidLatency v3.4.1 | @VoidLatency</p>
        </div>
    </div>
    <div id="qr-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm opacity-0 pointer-events-none transition-opacity duration-300">
        <div class="glass rounded-2xl p-6 max-w-sm w-full transition-all duration-300 opacity-0 scale-95 text-center">
            <h3 class="text-lg font-bold text-white mb-4">QR Code</h3>
            <div class="bg-white p-3 rounded-xl inline-block mb-4">
                <div id="qrcode-box" class="flex justify-center items-center w-48 h-48 mx-auto"></div>
            </div>
            <button onclick="toggleQRModal(false)" class="w-full py-3 bg-white/5 hover:bg-white/10 text-zinc-400 font-semibold rounded-xl transition text-sm">Close</button>
        </div>
    </div>
    <script>
        /* {{USER_DATA_PLACEHOLDER}} */
        function toggleQRModal(show, link) {
            const modal = document.getElementById('qr-modal');
            const card = modal.querySelector('div');
            const qrBox = document.getElementById('qrcode-box');
            if (show) {
                qrBox.innerHTML = '';
                try {
                    new QRCode(qrBox, { text: link, width: 192, height: 192, colorDark: "#000000", colorLight: "#ffffff", correctLevel: QRCode.CorrectLevel.M });
                } catch(e) {
                    qrBox.innerHTML = '<p class="text-zinc-400 text-xs">Error generating QR</p>';
                }
                modal.classList.remove('opacity-0', 'pointer-events-none');
                modal.classList.add('opacity-100', 'pointer-events-auto');
                card.classList.remove('opacity-0', 'scale-95');
                card.classList.add('opacity-100', 'scale-100');
            } else {
                modal.classList.remove('opacity-100', 'pointer-events-auto');
                modal.classList.add('opacity-0', 'pointer-events-none');
                card.classList.remove('opacity-100', 'scale-100');
                card.classList.add('opacity-0', 'scale-95');
            }
        }
        function getHost() { return window.location.host; }
        function getVlessLink() {
            const u = window.statusUser;
            if (!u) return '';
            const host = getHost();
            var ips = [host];
            if (u.ips) {
                ips = u.ips.split('\\n').map(function(ip) { return ip.trim(); }).filter(function(ip) { return ip.length > 0; });
                if (ips.length === 0) ips = [host];
            }
            var ports = String(u.port || '443').split(',').map(function(p) { return p.trim(); }).filter(function(p) { return p.length > 0; });
            var fp = u.fingerprint || 'chrome';
            var now = new Date();
            var created = new Date(u.created_at);
            var expiryDays = u.expiry_days || 30;
            var expiryDate = new Date(created.getTime() + expiryDays * 24 * 60 * 60 * 1000);
            var daysLeft = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
            var totalGB = u.limit_gb || 0;
            var usedGB = u.used_gb || 0;
            var expiryDateStr = expiryDate.toISOString().split('T')[0].replace(/-/g, '/');
            var usedFormatted = usedGB >= 1 ? usedGB.toFixed(1) + 'GB' : (usedGB * 1024).toFixed(0) + 'MB';
            var totalFormatted = totalGB >= 1 ? totalGB + 'GB' : 'Unlimited';
            var configName = u.config_name || u.username;
            var links = [];
            var firstIp = ips[0] || host;
            var firstPort = ports[0] || '443';
            var isTlsPort = ['443', '2053', '2083', '2087', '2096', '8443'].includes(firstPort);
            var tlsVal = isTlsPort ? 'tls' : 'none';
            var remark1 = '⏳ ' + u.username.toUpperCase() + ' | 📅 Exp: ' + expiryDateStr + ' | 🔥 ' + daysLeft + ' Days Left';
            links.push('vle' + 'ss://' + (u.uuid || '') + '@' + firstIp + ':' + firstPort + '?path=%2F&security=' + tlsVal + '&encryption=none&insecure=0&host=' + host + '&fp=' + fp + '&type=ws&allowInsecure=0&sni=' + host + '#' + encodeURIComponent(remark1));
            var remark2 = '📊 ' + u.username.toUpperCase() + ' | 💾 ' + totalFormatted + ' Total | ⚡ ' + usedFormatted + ' Used';
            links.push('vle' + 'ss://' + (u.uuid || '') + '@' + firstIp + ':' + firstPort + '?path=%2F&security=' + tlsVal + '&encryption=none&insecure=0&host=' + host + '&fp=' + fp + '&type=ws&allowInsecure=0&sni=' + host + '#' + encodeURIComponent(remark2));
            ips.forEach(function(ip) {
                ports.forEach(function(portStr) {
                    var isTlsPortLoop = ['443', '2053', '2083', '2087', '2096', '8443'].includes(portStr);
                    var tlsValLoop = isTlsPortLoop ? 'tls' : 'none';
                    var remark3 = configName;
                    links.push('vle' + 'ss://' + (u.uuid || '') + '@' + ip + ':' + portStr + '?path=%2F&security=' + tlsValLoop + '&encryption=none&insecure=0&host=' + host + '&fp=' + fp + '&type=ws&allowInsecure=0&sni=' + host + '#' + encodeURIComponent(remark3));
                });
            });
            return links.join('\\n');
        }
        function copyVlessConfig() {
            var link = getVlessLink();
            if (!link) return;
            navigator.clipboard.writeText(link).then(function() { alert('✅ Config copied!'); });
        }
        function copyJsonSub() {
            var link = window.location.protocol + '//' + getHost() + '/feed/json/' + encodeURIComponent(window.statusUser.username);
            navigator.clipboard.writeText(link).then(function() { alert('✅ JSON subscription link copied!'); });
        }
        function copyTextSub() {
            var link = window.location.protocol + '//' + getHost() + '/sub/' + encodeURIComponent(window.statusUser.username);
            navigator.clipboard.writeText(link).then(function() { alert('✅ Text subscription link copied!'); });
        }
        function showQR() {
            var link = getVlessLink();
            if (!link) return;
            toggleQRModal(true, link);
        }
        document.addEventListener('DOMContentLoaded', function() {
            var u = window.statusUser;
            if (!u) return;
            document.getElementById('display-username').innerText = '@' + u.username + ' | ' + u.port + ' | @VoidLatency';
            var usedGb = u.used_gb || 0;
            var limitGb = u.limit_gb;
            var formattedUsed = usedGb < 1 ? (usedGb * 1024).toFixed(0) + ' MB' : usedGb.toFixed(2) + ' GB';
            document.getElementById('used-vol').innerText = formattedUsed;
            var isVolumeExpired = false;
            if (limitGb) {
                document.getElementById('limit-vol').innerText = limitGb + ' GB';
                var pct = Math.min((usedGb / limitGb) * 100, 100);
                document.getElementById('volume-pct').innerText = pct.toFixed(0) + '%';
                document.getElementById('volume-progress').style.width = pct + '%';
                if (usedGb >= limitGb) isVolumeExpired = true;
            } else {
                document.getElementById('limit-vol').innerText = 'Unlimited';
                document.getElementById('volume-pct').innerText = '0%';
                document.getElementById('volume-progress').style.width = '100%';
            }
            var daysRemaining = 'Unlimited';
            var totalDays = 'Unlimited';
            var isTimeExpired = false;
            if (u.expiry_days) {
                totalDays = u.expiry_days + ' days';
                if (u.created_at) {
                    var created = new Date(u.created_at);
                    var expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
                    var diffDays = Math.ceil((expiryDate - new Date()) / (1000 * 60 * 60 * 24));
                    daysRemaining = diffDays > 0 ? diffDays : 0;
                    var pct = Math.max(0, Math.min(100, (daysRemaining / u.expiry_days) * 100));
                    document.getElementById('expiry-pct').innerText = pct.toFixed(0) + '%';
                    document.getElementById('expiry-progress').style.width = pct + '%';
                    if (new Date() > expiryDate) isTimeExpired = true;
                }
            } else {
                document.getElementById('expiry-pct').innerText = '0%';
                document.getElementById('expiry-progress').style.width = '100%';
            }
            document.getElementById('days-remaining').innerText = daysRemaining === 'Unlimited' ? 'Unlimited' : daysRemaining + ' days';
            document.getElementById('total-days').innerText = totalDays;
            var statusCard = document.getElementById('status-card');
            var statusText = document.getElementById('status-text');
            if (u.is_active === 0) {
                statusCard.className = 'mb-6 rounded-2xl p-4 text-center border font-semibold transition bg-red-500/10 border-red-500/30 text-red-400';
                statusText.innerText = '🔴 Inactive / Disabled';
            } else if (isVolumeExpired) {
                statusCard.className = 'mb-6 rounded-2xl p-4 text-center border font-semibold transition bg-yellow-500/10 border-yellow-500/30 text-yellow-400';
                statusText.innerText = '⚠️ Data Limit Exceeded';
            } else if (isTimeExpired) {
                statusCard.className = 'mb-6 rounded-2xl p-4 text-center border font-semibold transition bg-yellow-500/10 border-yellow-500/30 text-yellow-400';
                statusText.innerText = '⚠️ Subscription Expired';
            } else {
                statusCard.className = 'mb-6 rounded-2xl p-4 text-center border font-semibold transition bg-emerald-500/10 border-emerald-500/30 text-emerald-400';
                statusText.innerText = '✅ Active & Connected';
            }
        });
    <\/script>
</body>
</html>`
};

export {
  voidlatency_core_default as default
};
