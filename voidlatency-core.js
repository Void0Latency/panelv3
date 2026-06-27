var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// ============================================
// fire.js - VoidLatency / Fire Panel v3.0.0
// Full 3X-UI style panel for Cloudflare Workers + D1
// Inbounds, Outbounds, Routing Rules, Nodes, Clients
// ============================================
import { connect } from "cloudflare:sockets";

// ============================================
// CONSTANTS & GLOBAL STATE
// ============================================
var GLOBAL_TRAFFIC_CACHE = /* @__PURE__ */ new Map();   // uuid -> bytes
var ACTIVE_CONNECTIONS_COUNT = /* @__PURE__ */ new Map();
var GLOBAL_LAST_ACTIVE_WRITE = /* @__PURE__ */ new Map();
var DNS_CACHE = /* @__PURE__ */ new Map();
var DNS_CACHE_TTL = 5 * 60 * 1e3;
var DOH_RESOLVER = "https://cloudflare-dns.com/dns-query";
var UPSTREAM_BUNDLE_TARGET_BYTES = 16 * 1024;
var UPSTREAM_QUEUE_MAX_BYTES = 16 * 1024 * 1024;
var UPSTREAM_QUEUE_MAX_ITEMS = 4096;
var DOWNSTREAM_GRAIN_BYTES = 32 * 1024;
var DOWNSTREAM_GRAIN_TAIL_THRESHOLD = 512;
var DOWNSTREAM_GRAIN_SILENT_MS = 1;
var TCP_CONCURRENCY = 2;
var PRELOAD_RACE_DIAL = true;

var PANEL_VERSION = "3.0.0";
var XRAY_VERSION = "v26.4.25";
var xrayStatus = { running: true, startTime: Date.now() };
var ADMINS = [];

// Simulated/seeded system stats (Cloudflare Workers has no host OS access)
var SYS_BASE = {
  cpuCores: 1,
  ramTotal: 961.48 * 1024 * 1024,
  swapTotal: 0,
  diskTotal: 9.32 * 1024 * 1024 * 1024,
  diskUsed: 3.51 * 1024 * 1024 * 1024
};

// ============================================
// MAIN ENTRY
// ============================================
var fire_default = {
  async fetch(request, env, ctx) {
    try {
      await DbService.ensureSchema(env.VL_DB);
      await loadAdmins(env);
    } catch (e) {}
    const url = new URL(request.url);

    // WebSocket upgrade => VLESS proxy (any path)
    const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
    if (upgradeHeader === "websocket") {
      return await handleWebSocket(request, env, ctx);
    }

    if (url.pathname.startsWith("/sub/") || url.pathname.startsWith("/feed/")) {
      return await handleSubscription(url, env);
    }

    if (url.pathname.startsWith("/api/")) {
      return await handleApi(request, url, env, ctx);
    }

    if (url.pathname.startsWith("/status/")) {
      return await handleUserStatus(url, env);
    }

    // Default: serve the panel SPA
    return new Response(HTML_PANEL, {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
};
export default fire_default;

// ============================================
// ADMIN LOADING
// ============================================
async function loadAdmins(env) {
  try {
    const result = await env.VL_DB.prepare("SELECT * FROM admins").all();
    ADMINS = result.results || [];
  } catch (e) {
    ADMINS = [];
  }
}

// ============================================
// WEBSOCKET ROUTING
// ============================================
async function handleWebSocket(request, env, ctx) {
  try {
    let proxyIP = "proxyip.cmliussss.net";
    try {
      const row = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
      if (row && row.value) proxyIP = row.value;
    } catch (e) {}
    return await handleVLESS(env, { proxy_ip: proxyIP }, ctx);
  } catch (e) {
    return new Response("Internal Server Error", { status: 500 });
  }
}

// ============================================
// SUBSCRIPTION
// ============================================
async function handleSubscription(url, env) {
  const isSub = url.pathname.startsWith("/sub/");
  const offset = isSub ? 5 : 6;
  let ident = decodeURIComponent(url.pathname.slice(offset));
  const host = url.hostname;
  const isJson = ident.startsWith("json/");
  if (isJson) ident = ident.slice(5);
  try {
    const client = await env.VL_DB.prepare(
      "SELECT c.*, i.protocol, i.port, i.remark as inbound_remark, i.stream_settings, i.tag FROM clients c JOIN inbounds i ON c.inbound_id = i.id WHERE c.email = ? OR c.uuid = ? OR c.sub_id = ?"
    ).bind(ident, ident, ident).first();
    if (!client) return new Response("Not Found", { status: 404 });
    return await SubscriptionService.generate(client, host, env, isJson);
  } catch (err) {
    return new Response("Error: " + err.message, { status: 500 });
  }
}

async function handleUserStatus(url, env) {
  const ident = decodeURIComponent(url.pathname.slice(8));
  if (!ident) return new Response("Identifier required", { status: 400 });
  try {
    const client = await env.VL_DB.prepare(
      "SELECT c.*, i.remark as inbound_remark, i.protocol, i.port FROM clients c JOIN inbounds i ON c.inbound_id = i.id WHERE c.email = ? OR c.uuid = ?"
    ).bind(ident, ident).first();
    if (!client) return new Response("Not found", { status: 404 });
    const data = JSON.stringify({
      email: client.email, uuid: client.uuid,
      total_gb: client.total_gb, used_gb: client.used_gb,
      expiry_time: client.expiry_time, enable: client.enable,
      protocol: client.protocol, port: client.port
    });
    const html = HTML_STATUS.replace("/*{{DATA}}*/", "window.statusUser=" + data + ";");
    return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  } catch (e) {
    return new Response("Error: " + e.message, { status: 500 });
  }
}

// ============================================
// API HANDLER
// ============================================
function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*", ...extraHeaders }
  });
}

async function handleApi(request, url, env, ctx) {
  const method = request.method;
  const p = url.pathname;
  const authorized = await DbService.verifyAuth(request, env);
  const hasAdmin = ADMINS.length > 0;

  // ---------- SETUP (first run) ----------
  if (p === "/api/setup" && method === "POST") {
    if (hasAdmin) return json({ error: "Already set up" }, 400);
    const { username, password } = await request.json();
    if (!username || !password || password.length < 4) return json({ error: "Invalid username/password" }, 400);
    const hash = await DbService.sha256(password);
    await env.VL_DB.prepare("INSERT INTO admins (username, password_hash) VALUES (?, ?)").bind(username, hash).run();
    await loadAdmins(env);
    return json({ success: true });
  }

  // ---------- LOGIN ----------
  if (p === "/api/login" && method === "POST") {
    const { username, password } = await request.json();
    await loadAdmins(env);
    if (ADMINS.length === 0) return json({ error: "needs_setup", needs_setup: true }, 401);
    const admin = ADMINS.find(a => a.username === username);
    if (admin) {
      const hash = await DbService.sha256(password || "");
      if (admin.password_hash === hash) {
        return json({ success: true, username }, 200, {
          "Set-Cookie": "panel_session=" + admin.id + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400"
        });
      }
    }
    return json({ error: "Invalid credentials" }, 401);
  }

  // ---------- LOGOUT ----------
  if (p === "/api/logout" && method === "POST") {
    return json({ success: true }, 200, {
      "Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax"
    });
  }

  // ---------- AUTH VERIFY ----------
  if (p === "/api/auth/verify" && method === "GET") {
    await loadAdmins(env);
    if (ADMINS.length === 0) return json({ authenticated: false, needs_setup: true });
    if (!authorized) return json({ authenticated: false });
    return json({ authenticated: true, username: authorized.username || "admin" });
  }

  // Everything below requires auth
  if (!authorized) return json({ error: "Unauthorized" }, 401);

  // ---------- SERVER STATUS ----------
  if (p === "/api/server/status" && method === "GET") {
    return json(buildServerStatus(request, env));
  }

  // ---------- XRAY CONTROL ----------
  if (p === "/api/xray/restart" && method === "POST") {
    xrayStatus.running = true; xrayStatus.startTime = Date.now();
    return json({ success: true, status: "restarted" });
  }
  if (p === "/api/xray/stop" && method === "POST") {
    xrayStatus.running = false;
    return json({ success: true, status: "stopped" });
  }
  if (p === "/api/xray/start" && method === "POST") {
    xrayStatus.running = true; xrayStatus.startTime = Date.now();
    return json({ success: true, status: "started" });
  }
  if (p === "/api/panel/restart" && method === "POST") {
    return json({ success: true });
  }

  // ---------- FIRE UPDATE (panel-only update, DB preserved) ----------
  if (p === "/api/fire-update" && method === "POST") {
    // Records that the panel code was updated. DB/users stay intact.
    try {
      await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_version', ?)").bind(PANEL_VERSION).run();
      await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_update', ?)").bind(String(Date.now())).run();
    } catch (e) {}
    return json({ success: true, version: PANEL_VERSION, message: "Panel updated. Your database and users are untouched." });
  }
  if (p === "/api/fire-update/check" && method === "GET") {
    let latest = PANEL_VERSION;
    try {
      const r = await fetch("https://api.github.com/repos/Void0Latency/panel/releases/latest", { headers: { "User-Agent": "fire-panel" } });
      if (r.ok) { const d = await r.json(); latest = (d.tag_name || d.name || PANEL_VERSION).replace(/^v/, ""); }
    } catch (e) {}
    return json({ current: PANEL_VERSION, latest, update_available: latest !== PANEL_VERSION });
  }

  // ---------- ADMIN CREDENTIALS ----------
  if (p === "/api/admin/credentials" && method === "POST") {
    const { current_username, current_password, new_username, new_password } = await request.json();
    await loadAdmins(env);
    const admin = ADMINS.find(a => a.username === current_username) || ADMINS[0];
    if (!admin) return json({ error: "No admin" }, 404);
    const curHash = await DbService.sha256(current_password || "");
    if (admin.password_hash !== curHash) return json({ error: "Current password incorrect" }, 401);
    const newUser = new_username || admin.username;
    const newHash = new_password ? await DbService.sha256(new_password) : admin.password_hash;
    await env.VL_DB.prepare("UPDATE admins SET username = ?, password_hash = ? WHERE id = ?").bind(newUser, newHash, admin.id).run();
    await loadAdmins(env);
    return json({ success: true });
  }

  // ---------- SETTINGS ----------
  if (p === "/api/settings" && method === "GET") {
    const { results } = await env.VL_DB.prepare("SELECT key, value FROM settings").all();
    const obj = {};
    for (const r of (results || [])) obj[r.key] = r.value;
    return json({ settings: obj });
  }
  if (p === "/api/settings" && method === "POST") {
    const body = await request.json();
    for (const [k, v] of Object.entries(body)) {
      await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(k, String(v)).run();
    }
    return json({ success: true });
  }

  // ---------- XRAY CONFIG ----------
  if (p === "/api/xray/config" && method === "GET") {
    const row = await env.VL_DB.prepare("SELECT config FROM xray_config WHERE id = 1").first();
    return json({ config: row ? JSON.parse(row.config || "{}") : DEFAULT_XRAY_CONFIG() });
  }
  if (p === "/api/xray/config" && method === "POST") {
    const body = await request.json();
    const cfg = JSON.stringify(body.config || body);
    await env.VL_DB.prepare("INSERT OR REPLACE INTO xray_config (id, config) VALUES (1, ?)").bind(cfg).run();
    return json({ success: true });
  }

  // ---------- INBOUNDS ----------
  const inboundsRes = await handleInbounds(request, p, method, env, ctx);
  if (inboundsRes) return inboundsRes;

  // ---------- OUTBOUNDS ----------
  const outboundsRes = await handleOutbounds(request, p, method, env);
  if (outboundsRes) return outboundsRes;

  // ---------- ROUTING ----------
  const routingRes = await handleRouting(request, p, method, env);
  if (routingRes) return routingRes;

  // ---------- NODES ----------
  const nodesRes = await handleNodes(request, p, method, env);
  if (nodesRes) return nodesRes;

  return json({ error: "Not Found" }, 404);
}

// ============================================
// INBOUNDS + CLIENTS
// ============================================
async function handleInbounds(request, p, method, env, ctx) {
  if (!p.startsWith("/api/inbounds")) return null;
  const parts = p.split("/").filter(Boolean); // [api, inbounds, :id, ...]

  // GET /api/inbounds  (list)
  if (parts.length === 2 && method === "GET") {
    const { results } = await env.VL_DB.prepare("SELECT * FROM inbounds ORDER BY id ASC").all();
    const inbounds = results || [];
    let totalUp = 0, totalDown = 0, clientsCount = 0;
    for (const ib of inbounds) {
      const cr = await env.VL_DB.prepare("SELECT * FROM clients WHERE inbound_id = ?").bind(ib.id).all();
      ib.clients = cr.results || [];
      ib.clients_count = ib.clients.length;
      clientsCount += ib.clients_count;
      totalUp += ib.up || 0;
      totalDown += ib.down || 0;
      ib.settings_obj = safeParse(ib.settings);
      ib.stream_obj = safeParse(ib.stream_settings);
    }
    return json({ inbounds, total_up: totalUp, total_down: totalDown, clients_count: clientsCount });
  }

  // POST /api/inbounds  (create)
  if (parts.length === 2 && method === "POST") {
    const b = await request.json();
    const tag = b.tag || ("inbound-" + Date.now());
    const r = await env.VL_DB.prepare(
      "INSERT INTO inbounds (remark, enable, listen, port, protocol, settings, stream_settings, sniffing, tag, total, expiry_time) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(
      b.remark || "", b.enable === 0 ? 0 : 1, b.listen || "", parseInt(b.port) || 0,
      b.protocol || "vless", JSON.stringify(b.settings || {}), JSON.stringify(b.stream_settings || {}),
      JSON.stringify(b.sniffing || { enabled: true, destOverride: ["http", "tls"] }), tag,
      b.total ? Math.round(parseFloat(b.total) * 1024 * 1024 * 1024) : 0, parseInt(b.expiry_time) || 0
    ).run();
    const inboundId = r.meta.last_row_id;
    // initial clients
    if (Array.isArray(b.clients)) {
      for (const c of b.clients) await insertClient(env, inboundId, c);
    }
    return json({ success: true, id: inboundId });
  }

  const id = parseInt(parts[2]);
  if (!id) return json({ error: "Invalid id" }, 400);

  // /api/inbounds/:id
  if (parts.length === 3) {
    if (method === "GET") {
      const ib = await env.VL_DB.prepare("SELECT * FROM inbounds WHERE id = ?").bind(id).first();
      if (!ib) return json({ error: "Not found" }, 404);
      const cr = await env.VL_DB.prepare("SELECT * FROM clients WHERE inbound_id = ?").bind(id).all();
      ib.clients = cr.results || [];
      ib.settings_obj = safeParse(ib.settings);
      ib.stream_obj = safeParse(ib.stream_settings);
      return json({ inbound: ib });
    }
    if (method === "PUT") {
      const b = await request.json();
      await env.VL_DB.prepare(
        "UPDATE inbounds SET remark=?, enable=?, listen=?, port=?, protocol=?, settings=?, stream_settings=?, sniffing=?, total=?, expiry_time=? WHERE id=?"
      ).bind(
        b.remark || "", b.enable === 0 ? 0 : 1, b.listen || "", parseInt(b.port) || 0,
        b.protocol || "vless", JSON.stringify(b.settings || {}), JSON.stringify(b.stream_settings || {}),
        JSON.stringify(b.sniffing || { enabled: true }),
        b.total ? Math.round(parseFloat(b.total) * 1024 * 1024 * 1024) : 0, parseInt(b.expiry_time) || 0, id
      ).run();
      return json({ success: true });
    }
    if (method === "DELETE") {
      await env.VL_DB.prepare("DELETE FROM clients WHERE inbound_id = ?").bind(id).run();
      await env.VL_DB.prepare("DELETE FROM inbounds WHERE id = ?").bind(id).run();
      return json({ success: true });
    }
  }

  // /api/inbounds/:id/enable
  if (parts.length === 4 && parts[3] === "enable" && method === "POST") {
    await env.VL_DB.prepare("UPDATE inbounds SET enable = CASE WHEN enable=1 THEN 0 ELSE 1 END WHERE id=?").bind(id).run();
    return json({ success: true });
  }
  // /api/inbounds/:id/reset-traffic
  if (parts.length === 4 && parts[3] === "reset-traffic" && method === "POST") {
    await env.VL_DB.prepare("UPDATE inbounds SET up=0, down=0 WHERE id=?").bind(id).run();
    return json({ success: true });
  }

  // /api/inbounds/:id/clients
  if (parts.length === 4 && parts[3] === "clients") {
    if (method === "GET") {
      const cr = await env.VL_DB.prepare("SELECT * FROM clients WHERE inbound_id = ?").bind(id).all();
      return json({ clients: cr.results || [] });
    }
    if (method === "POST") {
      const c = await request.json();
      const cid = await insertClient(env, id, c);
      return json({ success: true, id: cid });
    }
  }

  // /api/inbounds/:id/clients/:cid
  if (parts.length === 5 && parts[3] === "clients") {
    const cid = parseInt(parts[4]);
    if (method === "PUT") {
      const c = await request.json();
      await env.VL_DB.prepare(
        "UPDATE clients SET email=?, uuid=?, password=?, total_gb=?, expiry_time=?, enable=? WHERE id=? AND inbound_id=?"
      ).bind(
        c.email || "", c.uuid || "", c.password || "", parseFloat(c.total_gb) || 0,
        parseInt(c.expiry_time) || 0, c.enable === 0 ? 0 : 1, cid, id
      ).run();
      return json({ success: true });
    }
    if (method === "DELETE") {
      await env.VL_DB.prepare("DELETE FROM clients WHERE id=? AND inbound_id=?").bind(cid, id).run();
      return json({ success: true });
    }
  }

  // /api/inbounds/:id/clients/:cid/reset-traffic
  if (parts.length === 6 && parts[3] === "clients" && parts[5] === "reset-traffic" && method === "POST") {
    const cid = parseInt(parts[4]);
    await env.VL_DB.prepare("UPDATE clients SET used_gb=0 WHERE id=? AND inbound_id=?").bind(cid, id).run();
    GLOBAL_TRAFFIC_CACHE.clear();
    return json({ success: true });
  }

  return json({ error: "Not Found" }, 404);
}

async function insertClient(env, inboundId, c) {
  const uuid = c.uuid || crypto.randomUUID();
  const subId = c.sub_id || randomStr(12);
  const email = c.email || ("user-" + randomStr(6));
  const r = await env.VL_DB.prepare(
    "INSERT INTO clients (inbound_id, enable, email, uuid, password, total_gb, expiry_time, sub_id) VALUES (?,?,?,?,?,?,?,?)"
  ).bind(
    inboundId, c.enable === 0 ? 0 : 1, email, uuid, c.password || "",
    parseFloat(c.total_gb) || 0, parseInt(c.expiry_time) || 0, subId
  ).run();
  return r.meta.last_row_id;
}

// ============================================
// OUTBOUNDS
// ============================================
async function handleOutbounds(request, p, method, env) {
  if (!p.startsWith("/api/outbounds")) return null;
  const parts = p.split("/").filter(Boolean);
  if (parts.length === 2 && method === "GET") {
    const { results } = await env.VL_DB.prepare("SELECT * FROM outbounds ORDER BY id ASC").all();
    return json({ outbounds: results || [] });
  }
  if (parts.length === 2 && method === "POST") {
    const b = await request.json();
    try {
      const r = await env.VL_DB.prepare(
        "INSERT INTO outbounds (tag, remark, protocol, settings, stream_settings, enable) VALUES (?,?,?,?,?,?)"
      ).bind(b.tag, b.remark || "", b.protocol || "freedom", JSON.stringify(b.settings || {}), JSON.stringify(b.stream_settings || {}), b.enable === 0 ? 0 : 1).run();
      return json({ success: true, id: r.meta.last_row_id });
    } catch (e) { return json({ error: "Tag already exists" }, 400); }
  }
  const id = parseInt(parts[2]);
  if (parts.length === 3 && method === "PUT") {
    const b = await request.json();
    await env.VL_DB.prepare(
      "UPDATE outbounds SET tag=?, remark=?, protocol=?, settings=?, stream_settings=?, enable=? WHERE id=?"
    ).bind(b.tag, b.remark || "", b.protocol || "freedom", JSON.stringify(b.settings || {}), JSON.stringify(b.stream_settings || {}), b.enable === 0 ? 0 : 1, id).run();
    return json({ success: true });
  }
  if (parts.length === 3 && method === "DELETE") {
    await env.VL_DB.prepare("DELETE FROM outbounds WHERE id=?").bind(id).run();
    return json({ success: true });
  }
  return json({ error: "Not Found" }, 404);
}

// ============================================
// ROUTING RULES
// ============================================
async function handleRouting(request, p, method, env) {
  if (!p.startsWith("/api/routing")) return null;
  const parts = p.split("/").filter(Boolean);
  if (parts.length === 2 && method === "GET") {
    const { results } = await env.VL_DB.prepare("SELECT * FROM routing_rules ORDER BY id ASC").all();
    return json({ rules: results || [] });
  }
  if (parts.length === 2 && method === "POST") {
    const b = await request.json();
    const r = await env.VL_DB.prepare(
      "INSERT INTO routing_rules (enable, remark, inbound_tags, outbound_tag, domain, ip, port, protocol, type) VALUES (?,?,?,?,?,?,?,?,?)"
    ).bind(
      b.enable === 0 ? 0 : 1, b.remark || "", JSON.stringify(b.inbound_tags || []),
      b.outbound_tag || "direct", b.domain || "", b.ip || "", b.port || "", b.protocol || "", "field"
    ).run();
    return json({ success: true, id: r.meta.last_row_id });
  }
  const id = parseInt(parts[2]);
  if (parts.length === 3 && method === "PUT") {
    const b = await request.json();
    await env.VL_DB.prepare(
      "UPDATE routing_rules SET enable=?, remark=?, inbound_tags=?, outbound_tag=?, domain=?, ip=?, port=?, protocol=? WHERE id=?"
    ).bind(
      b.enable === 0 ? 0 : 1, b.remark || "", JSON.stringify(b.inbound_tags || []),
      b.outbound_tag || "direct", b.domain || "", b.ip || "", b.port || "", b.protocol || "", id
    ).run();
    return json({ success: true });
  }
  if (parts.length === 3 && method === "DELETE") {
    await env.VL_DB.prepare("DELETE FROM routing_rules WHERE id=?").bind(id).run();
    return json({ success: true });
  }
  return json({ error: "Not Found" }, 404);
}

// ============================================
// NODES
// ============================================
async function handleNodes(request, p, method, env) {
  if (!p.startsWith("/api/nodes")) return null;
  const parts = p.split("/").filter(Boolean);
  if (parts.length === 2 && method === "GET") {
    const { results } = await env.VL_DB.prepare("SELECT * FROM nodes ORDER BY id ASC").all();
    return json({ nodes: results || [] });
  }
  if (parts.length === 2 && method === "POST") {
    const b = await request.json();
    const r = await env.VL_DB.prepare(
      "INSERT INTO nodes (name, address, port, api_port, remark, enable, type) VALUES (?,?,?,?,?,?,?)"
    ).bind(b.name || "", b.address || "", parseInt(b.port) || 0, parseInt(b.api_port) || 62789, b.remark || "", b.enable === 0 ? 0 : 1, b.type || "xray").run();
    return json({ success: true, id: r.meta.last_row_id });
  }
  const id = parseInt(parts[2]);
  if (parts.length === 3 && method === "PUT") {
    const b = await request.json();
    await env.VL_DB.prepare(
      "UPDATE nodes SET name=?, address=?, port=?, api_port=?, remark=?, enable=?, type=? WHERE id=?"
    ).bind(b.name || "", b.address || "", parseInt(b.port) || 0, parseInt(b.api_port) || 62789, b.remark || "", b.enable === 0 ? 0 : 1, b.type || "xray", id).run();
    return json({ success: true });
  }
  if (parts.length === 3 && method === "DELETE") {
    await env.VL_DB.prepare("DELETE FROM nodes WHERE id=?").bind(id).run();
    return json({ success: true });
  }
  return json({ error: "Not Found" }, 404);
}

// ============================================
// HELPERS
// ============================================
function safeParse(s) { try { return JSON.parse(s || "{}"); } catch (e) { return {}; } }
function randomStr(n) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let s = "";
  const arr = crypto.getRandomValues(new Uint8Array(n));
  for (let i = 0; i < n; i++) s += chars[arr[i] % chars.length];
  return s;
}

function buildServerStatus(request, env) {
  const now = Date.now();
  const jitter = (base, range) => Math.max(0, base + (Math.random() - 0.5) * range);
  const xrayUptime = xrayStatus.running ? Math.floor((now - xrayStatus.startTime) / 1000) : 0;
  return {
    cpu: { percent: +jitter(18, 20).toFixed(2), cores: SYS_BASE.cpuCores },
    ram: { used: Math.round(jitter(304 * 1024 * 1024, 40 * 1024 * 1024)), total: SYS_BASE.ramTotal },
    swap: { used: 0, total: SYS_BASE.swapTotal },
    disk: { used: SYS_BASE.diskUsed, total: SYS_BASE.diskTotal },
    xray: { running: xrayStatus.running, version: XRAY_VERSION, mem: (jitter(42, 6)).toFixed(2) + " MB", threads: Math.round(jitter(20, 4)) },
    uptime: { xray: xrayUptime, os: xrayUptime + 600 },
    load: [+jitter(0.05, 0.1).toFixed(2), +jitter(0.12, 0.1).toFixed(2), +jitter(0.09, 0.06).toFixed(2)],
    net: {
      up: Math.round(jitter(2800, 4000)), down: Math.round(jitter(2900, 4000)),
      sent: Math.round(jitter(3.5 * 1024 * 1024, 1024 * 1024)), recv: Math.round(jitter(79 * 1024 * 1024, 2 * 1024 * 1024))
    },
    ip: {
      v4: request.headers.get("CF-Connecting-IP") || "Unknown",
      v6: request.headers.get("CF-Connecting-IPv6") || "Unknown"
    },
    connections: { tcp: Math.round(jitter(184, 20)), udp: Math.round(jitter(5, 4)) },
    panel_version: PANEL_VERSION
  };
}

function DEFAULT_XRAY_CONFIG() {
  return {
    log: { loglevel: "warning", access: "", error: "" },
    stats: {},
    routing: { domainStrategy: "AsIs", rules: [] },
    outbounds: [
      { tag: "direct", protocol: "freedom", settings: {} },
      { tag: "block", protocol: "blackhole", settings: {} }
    ]
  };
}

// ============================================
// DATABASE SERVICE
// ============================================
var schemaEnsured = false;
var DbService = {
  async ensureSchema(db) {
    if (schemaEnsured) return;
    const stmts = [
      `CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`,
      `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`,
      `CREATE TABLE IF NOT EXISTS inbounds (id INTEGER PRIMARY KEY AUTOINCREMENT, remark TEXT, enable INTEGER DEFAULT 1, listen TEXT DEFAULT '', port INTEGER, protocol TEXT DEFAULT 'vless', settings TEXT DEFAULT '{}', stream_settings TEXT DEFAULT '{}', sniffing TEXT DEFAULT '{}', tag TEXT, up INTEGER DEFAULT 0, down INTEGER DEFAULT 0, total INTEGER DEFAULT 0, expiry_time INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`,
      `CREATE TABLE IF NOT EXISTS clients (id INTEGER PRIMARY KEY AUTOINCREMENT, inbound_id INTEGER, enable INTEGER DEFAULT 1, email TEXT, uuid TEXT, password TEXT, total_gb REAL DEFAULT 0, used_gb REAL DEFAULT 0, expiry_time INTEGER DEFAULT 0, sub_id TEXT, last_active INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`,
      `CREATE TABLE IF NOT EXISTS outbounds (id INTEGER PRIMARY KEY AUTOINCREMENT, tag TEXT UNIQUE, remark TEXT, protocol TEXT, settings TEXT DEFAULT '{}', stream_settings TEXT DEFAULT '{}', enable INTEGER DEFAULT 1)`,
      `CREATE TABLE IF NOT EXISTS routing_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, enable INTEGER DEFAULT 1, remark TEXT, inbound_tags TEXT DEFAULT '[]', outbound_tag TEXT DEFAULT 'direct', domain TEXT DEFAULT '', ip TEXT DEFAULT '', port TEXT DEFAULT '', protocol TEXT DEFAULT '', type TEXT DEFAULT 'field')`,
      `CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, address TEXT, port INTEGER, api_port INTEGER DEFAULT 62789, remark TEXT, enable INTEGER DEFAULT 1, type TEXT DEFAULT 'xray')`,
      `CREATE TABLE IF NOT EXISTS xray_config (id INTEGER PRIMARY KEY, config TEXT DEFAULT '{}')`
    ];
    for (const s of stmts) { try { await db.prepare(s).run(); } catch (e) {} }
    // Seed default outbounds
    try {
      const cnt = await db.prepare("SELECT COUNT(*) as c FROM outbounds").first();
      if (!cnt || cnt.c === 0) {
        await db.prepare("INSERT INTO outbounds (tag, remark, protocol, settings) VALUES ('direct','Direct','freedom','{\"domainStrategy\":\"AsIs\"}')").run();
        await db.prepare("INSERT INTO outbounds (tag, remark, protocol, settings) VALUES ('block','Block','blackhole','{\"response\":{\"type\":\"none\"}}')").run();
      }
    } catch (e) {}
    schemaEnsured = true;
  },
  async verifyAuth(request, env) {
    const cookies = request.headers.get("Cookie") || "";
    const sc = cookies.split(";").find((c) => c.trim().startsWith("panel_session="));
    let token = null;
    if (sc) token = sc.split("=")[1].trim();
    if (!token) {
      const auth = request.headers.get("Authorization") || "";
      if (auth.startsWith("Bearer ")) token = auth.slice(7).trim();
    }
    if (!token) return null;
    await loadAdmins(env);
    const admin = ADMINS.find(a => String(a.id) === token);
    if (admin) return { id: admin.id, username: admin.username };
    return null;
  },
  async sha256(message) {
    const buf = new TextEncoder().encode(message);
    const hash = await crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
};

// ============================================
// SUBSCRIPTION SERVICE
// ============================================
var SubscriptionService = {
  async generate(client, host, env, isJson) {
    // Gather IP list from settings or use host
    let ips = [host];
    try {
      const row = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'sub_ips'").first();
      if (row && row.value) {
        const parsed = row.value.split("\n").map(s => s.trim()).filter(Boolean);
        if (parsed.length) ips = parsed;
      }
    } catch (e) {}
    const port = String(client.port || "443");
    const stream = safeParse(client.stream_settings);
    const net = stream.network || "ws";
    const path = (stream.wsSettings && stream.wsSettings.path) || "/";
    const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(port);
    const security = (stream.security && stream.security !== "none") ? stream.security : (isTlsPort ? "tls" : "none");
    const name = client.email || client.inbound_remark || "fire";

    const links = ips.map((ip) => {
      const addrPart = ip.includes(":") && !ip.includes(".") ? "[" + ip + "]" : ip;
      const params = "type=" + net + "&path=" + encodeURIComponent(path) + "&host=" + encodeURIComponent(host) +
        "&security=" + security + "&sni=" + encodeURIComponent(host) + "&fp=chrome&encryption=none";
      return "vless://" + client.uuid + "@" + addrPart + ":" + port + "?" + params + "#" + encodeURIComponent(name + "-" + ip);
    });

    if (isJson) {
      return json({ remarks: name, links, uuid: client.uuid });
    }
    const content = btoa(unescape(encodeURIComponent(links.join("\n"))));
    return new Response(content, {
      headers: { "Content-Type": "text/plain; charset=utf-8", "Access-Control-Allow-Origin": "*", "Cache-Control": "no-store" }
    });
  }
};

// ============================================
// TRAFFIC FLUSH
// ============================================
async function flushTraffic(env, uuid, inboundId, upBytes, downBytes, ctx) {
  upBytes = upBytes || 0; downBytes = downBytes || 0;
  const total = upBytes + downBytes;
  if (!uuid || total <= 0) return;
  const deltaGb = total / (1024 * 1024 * 1024);
  const task = async () => {
    try {
      await env.VL_DB.prepare("UPDATE clients SET used_gb = used_gb + ?, last_active = ? WHERE uuid = ?").bind(deltaGb, Date.now(), uuid).run();
      if (inboundId) {
        await env.VL_DB.prepare("UPDATE inbounds SET up = up + ?, down = down + ? WHERE id = ?").bind(Math.round(upBytes), Math.round(downBytes), inboundId).run();
      }
      const c = await env.VL_DB.prepare("SELECT total_gb, used_gb FROM clients WHERE uuid = ?").bind(uuid).first();
      if (c && c.total_gb && c.used_gb >= c.total_gb) {
        await env.VL_DB.prepare("UPDATE clients SET enable = 0 WHERE uuid = ?").bind(uuid).run();
      }
    } catch (e) {}
  };
  if (ctx) ctx.waitUntil(task()); else await task();
}

// ============================================
// ROUTING RESOLVER
// ============================================
async function resolveOutbound(addr, port, env) {
  try {
    const { results } = await env.VL_DB.prepare("SELECT * FROM routing_rules WHERE enable=1 ORDER BY id ASC").all();
    for (const rule of (results || [])) {
      if (rule.port) {
        const ports = String(rule.port).split(",").map(s => s.trim()).filter(Boolean);
        const match = ports.some(pr => {
          if (pr.includes("-")) { const [lo, hi] = pr.split("-").map(Number); return port >= lo && port <= hi; }
          return Number(pr) === port;
        });
        if (!match) continue;
      }
      if (rule.ip) {
        const ips = rule.ip.split("\n").map(s => s.trim()).filter(Boolean);
        if (ips.length && !ips.some(i => addr === i || addr.includes(i))) continue;
      }
      if (rule.domain) {
        const ds = rule.domain.split("\n").map(s => s.trim()).filter(Boolean);
        if (ds.length && !ds.some(d => addr === d || addr.endsWith("." + d) || addr.endsWith(d))) continue;
      }
      return rule.outbound_tag || "direct";
    }
  } catch (e) {}
  return "direct";
}

async function getOutboundConfig(tag, env) {
  try {
    const ob = await env.VL_DB.prepare("SELECT * FROM outbounds WHERE tag = ?").bind(tag).first();
    return ob || null;
  } catch (e) { return null; }
}

// ============================================
// VLESS HANDLER
// ============================================
async function handleVLESS(env, storedData = null, ctx = null) {
  const socketPair = new WebSocketPair();
  const [clientSock, serverSock] = Object.values(socketPair);
  serverSock.accept();
  serverSock.binaryType = "arraybuffer";
  let clientUUID = null;
  let inboundId = null;
  let upBytes = 0, downBytes = 0;

  // dir: "up" = client->remote, "down" = remote->client
  function addBytes(bytes, dir) {
    if (bytes <= 0 || !clientUUID) return;
    if (dir === "up") upBytes += bytes; else downBytes += bytes;
    GLOBAL_LAST_ACTIVE_WRITE.set(clientUUID, Date.now());
    const threshold = 30 * 1024 * 1024;
    if (upBytes + downBytes >= threshold) {
      const u = upBytes, d = downBytes;
      upBytes = 0; downBytes = 0;
      flushTraffic(env, clientUUID, inboundId, u, d, ctx);
    }
  }

  let isOfflineSet = false;
  const setOffline = () => {
    if (isOfflineSet) return;
    isOfflineSet = true;
    const u = clientUUID;
    if (!u) return;
    let cnt = (ACTIVE_CONNECTIONS_COUNT.get(u) || 1) - 1;
    if (cnt <= 0) ACTIVE_CONNECTIONS_COUNT.delete(u);
    else ACTIVE_CONNECTIONS_COUNT.set(u, cnt);
    // flush any leftover traffic for this connection
    if (upBytes > 0 || downBytes > 0) {
      const up = upBytes, down = downBytes;
      upBytes = 0; downBytes = 0;
      flushTraffic(env, u, inboundId, up, down, ctx);
    }
  };

  const heartbeat = setInterval(() => {
    if (serverSock.readyState === WebSocket.OPEN) {
      try { serverSock.send(new Uint8Array(0)); } catch (e) {}
    } else { clearInterval(heartbeat); }
  }, 15e3);

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
    if (activeRemoteWriter) { try { activeRemoteWriter.releaseLock(); } catch (e) {} activeRemoteWriter = null; }
    currentSocketWriter = null;
  };
  const getRemoteWriter = () => {
    const s = remoteConnWrapper.socket;
    if (!s) return null;
    if (s !== currentSocketWriter) { releaseRemoteWriter(); currentSocketWriter = s; activeRemoteWriter = s.writable.getWriter(); }
    return activeRemoteWriter;
  };

  const upstreamQueue = createUpstreamQueue({
    getWriter: getRemoteWriter,
    releaseWriter: releaseRemoteWriter,
    retryConnect: async () => { if (typeof remoteConnWrapper.retryConnect === "function") await remoteConnWrapper.retryConnect(); },
    closeConnection: () => { try { remoteConnWrapper.socket?.close(); } catch (e) {} closeSocketQuietly(serverSock); },
    name: "FireWSQueue"
  });
  const writeToRemote = async (chunk, allowRetry = true) => upstreamQueue.writeAndAwait(chunk, allowRetry);

  const processWsMessage = async (chunk) => {
    const bytes = chunk.byteLength || 0;
    addBytes(bytes, "up");
    if (isDnsQuery) { await forwardVlessUDP(chunk, serverSock, null); return; }
    if (await writeToRemote(chunk)) return;
    if (!isHeaderParsed) {
      chunkBuffer = concatBytes(chunkBuffer, chunk);
      if (chunkBuffer.byteLength < 24) return;
      reqUUID = extractUUIDFromVless(chunkBuffer);
      if (!reqUUID) { serverSock.close(); return; }
      let client = null;
      try {
        client = await env.VL_DB.prepare(
          "SELECT c.*, i.enable as inbound_enable FROM clients c JOIN inbounds i ON c.inbound_id = i.id WHERE c.uuid = ?"
        ).bind(reqUUID).first();
      } catch (e) {}
      if (!client || client.enable === 0 || client.inbound_enable === 0) { serverSock.close(); return; }
      if (client.total_gb && client.used_gb >= client.total_gb) { serverSock.close(); return; }
      if (client.expiry_time && Date.now() > client.expiry_time) {
        try { await env.VL_DB.prepare("UPDATE clients SET enable=0 WHERE uuid=?").bind(reqUUID).run(); } catch (e) {}
        serverSock.close(); return;
      }
      clientUUID = reqUUID;
      inboundId = client.inbound_id;
      isHeaderParsed = true;
      let cnt = ACTIVE_CONNECTIONS_COUNT.get(clientUUID) || 0;
      ACTIVE_CONNECTIONS_COUNT.set(clientUUID, cnt + 1);
      if (cnt === 0) {
        const t = async () => { try { await env.VL_DB.prepare("UPDATE clients SET last_active=? WHERE uuid=?").bind(Date.now(), clientUUID).run(); } catch (e) {} };
        if (ctx) ctx.waitUntil(t()); else t();
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
          const dl = chunkBuffer[offset++];
          addr = new TextDecoder().decode(chunkBuffer.slice(offset, offset + dl));
          offset += dl;
        } else if (addrType === 3) {
          const segs = [];
          for (let i = 0; i < 16; i += 2) segs.push(((chunkBuffer[offset + i] << 8) | chunkBuffer[offset + i + 1]).toString(16));
          offset += 16;
          addr = segs.join(":");
        }
        const rawData = chunkBuffer.slice(offset);
        const respHeader = new Uint8Array([chunkBuffer[0], 0]);
        if (cmd === 2) {
          if (port === 53) { isDnsQuery = true; await forwardVlessUDP(rawData, serverSock, respHeader); }
          else serverSock.close();
          return;
        }
        // Routing decision
        const outboundTag = await resolveOutbound(addr, port, env);
        if (outboundTag === "block") { serverSock.close(); return; }
        let dialAddr = addr, dialPort = port;
        const obCfg = await getOutboundConfig(outboundTag, env);
        if (obCfg && obCfg.protocol !== "freedom" && obCfg.protocol !== "blackhole") {
          const obs = safeParse(obCfg.settings);
          // relay via outbound server (socks/http/vless server address)
          const srv = obs.servers && obs.servers[0];
          const vnext = obs.vnext && obs.vnext[0];
          if (srv && srv.address) { dialAddr = srv.address; dialPort = srv.port || dialPort; }
          else if (vnext && vnext.address) { dialAddr = vnext.address; dialPort = vnext.port || dialPort; }
        }

        const connectTCP = async (dataPayload = null, useFallback = true) => {
          if (remoteConnWrapper.connectingPromise) { await remoteConnWrapper.connectingPromise; return; }
          const task = (async () => {
            let s = null;
            try { s = await connectDirect(dialAddr, dialPort, dataPayload); }
            catch (err) {
              if (useFallback && proxyIP) s = await connectDirect(proxyIP, dialPort, dataPayload);
              else throw err;
            }
            remoteConnWrapper.socket = s;
            s.closed.catch(() => {}).finally(() => closeSocketQuietly(serverSock));
            connectStreams(s, serverSock, respHeader, null, (b) => addBytes(b, "down"));
          })();
          remoteConnWrapper.connectingPromise = task;
          try { await task; } finally { if (remoteConnWrapper.connectingPromise === task) remoteConnWrapper.connectingPromise = null; }
        };
        remoteConnWrapper.retryConnect = async () => connectTCP(null, false);
        await connectTCP(rawData, true);
      } catch (e) { serverSock.close(); }
    }
  };

  const handleWsError = () => {
    if (wsFailed) return;
    wsFailed = true; wsStopped = true; wsQueueBytes = 0; wsQueueItems = 0;
    upstreamQueue.clear(); releaseRemoteWriter(); closeSocketQuietly(serverSock); setOffline();
  };
  const pushToChain = (task) => { wsChain = wsChain.then(task).catch(handleWsError); };

  serverSock.addEventListener("message", (event) => {
    if (wsStopped || wsFailed) return;
    const size = event.data.byteLength || 0;
    const nextBytes = wsQueueBytes + size, nextItems = wsQueueItems + 1;
    if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) { handleWsError(); return; }
    wsQueueBytes = nextBytes; wsQueueItems = nextItems;
    pushToChain(async () => {
      wsQueueBytes = Math.max(0, wsQueueBytes - size);
      wsQueueItems = Math.max(0, wsQueueItems - 1);
      if (wsFailed) return;
      await processWsMessage(event.data);
    });
  });
  serverSock.addEventListener("close", () => {
    clearInterval(heartbeat); closeSocketQuietly(serverSock); setOffline();
    if (wsFinished) return;
    wsFinished = true; wsStopped = true;
    pushToChain(async () => { if (wsFailed) return; await upstreamQueue.awaitEmpty(); releaseRemoteWriter(); });
  });
  serverSock.addEventListener("error", () => handleWsError());

  return new Response(null, { status: 101, webSocket: clientSock });
}

// ============================================
// NETWORK UTILITIES
// ============================================
function isIPv4(value) {
  const parts = String(value || "").split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
function stripIPv6Brackets(hostname = "") {
  const host = String(hostname || "").trim();
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}
function isIPHostname(hostname = "") {
  const host = stripIPv6Brackets(hostname);
  if (isIPv4(host)) return true;
  if (!host.includes(":")) return false;
  try { new URL("http://[" + host + "]/"); return true; } catch (e) { return false; }
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
  for (const c of chunks) { result.set(c, offset); offset += c.byteLength; }
  return result;
}
function closeSocketQuietly(socket) {
  try { if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) socket.close(); } catch (e) {}
}
function extractUUIDFromVless(data) {
  if (data.byteLength < 17) return null;
  const hex = [...data.slice(1, 17)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-" + hex.substring(12, 16) + "-" + hex.substring(16, 20) + "-" + hex.substring(20);
}

// ============================================
// DNS over HTTPS
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
      for (const label of parts) { const enc = new TextEncoder().encode(label); bufs.push(new Uint8Array([enc.length]), enc); }
      bufs.push(new Uint8Array([0]));
      return concatBytes(...bufs);
    };
    const qname = encodeDomain(domain);
    const query = new Uint8Array(12 + qname.length + 4);
    const qview = new DataView(query.buffer);
    qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
    qview.setUint16(2, 256); qview.setUint16(4, 1);
    query.set(qname, 12);
    qview.setUint16(12 + qname.length, qtype);
    qview.setUint16(12 + qname.length + 2, 1);
    const response = await fetch(DOH_RESOLVER, {
      method: "POST",
      headers: { "Content-Type": "application/dns-message", "Accept": "application/dns-message" },
      body: query
    });
    if (!response.ok) return [];
    const buf = new Uint8Array(await response.arrayBuffer());
    const dv = new DataView(buf.buffer);
    const qdcount = dv.getUint16(4), ancount = dv.getUint16(6);
    const parseName = (pos) => {
      const labels = []; let p = pos, jumped = false, endPos = -1, safe = 128;
      while (p < buf.length && safe-- > 0) {
        const len = buf[p];
        if (len === 0) { if (!jumped) endPos = p + 1; break; }
        if ((len & 192) === 192) { if (!jumped) endPos = p + 2; p = (len & 63) << 8 | buf[p + 1]; jumped = true; continue; }
        labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len))); p += len + 1;
      }
      if (endPos === -1) endPos = p + 1;
      return [labels.join("."), endPos];
    };
    let offset = 12;
    for (let i = 0; i < qdcount; i++) { const [, end] = parseName(offset); offset = Number(end) + 4; }
    const answers = [];
    for (let i = 0; i < ancount && offset < buf.length; i++) {
      const [name, nameEnd] = parseName(offset); offset = Number(nameEnd);
      const type = dv.getUint16(offset); offset += 2; offset += 2;
      const ttl = dv.getUint32(offset); offset += 4;
      const rdlen = dv.getUint16(offset); offset += 2;
      const rdata = buf.slice(offset, offset + rdlen); offset += rdlen;
      let data;
      if (type === 1 && rdlen === 4) data = rdata[0] + "." + rdata[1] + "." + rdata[2] + "." + rdata[3];
      else if (type === 28 && rdlen === 16) { const segs = []; for (let j = 0; j < 16; j += 2) segs.push((rdata[j] << 8 | rdata[j + 1]).toString(16)); data = segs.join(":"); }
      else data = Array.from(rdata).map((b) => b.toString(16).padStart(2, "0")).join("");
      answers.push({ name, type, TTL: ttl, data });
    }
    DNS_CACHE.set(cacheKey, { data: answers, expires: Date.now() + DNS_CACHE_TTL });
    return answers;
  } catch (e) { return []; }
}

// ============================================
// UPSTREAM QUEUE
// ============================================
function createUpstreamQueue({ getWriter, releaseWriter, retryConnect, closeConnection, name = "UpstreamQueue" }) {
  let chunks = [], head = 0, queuedBytes = 0, draining = false, closed = false;
  let bundleBuffer = null, idleResolvers = [], activeCompletions = null;
  const settleCompletions = (completions, err = null) => {
    if (!completions) return;
    for (const comp of completions) { if (comp) { if (err) comp.reject(err); else comp.resolve(); } }
  };
  const rejectQueued = (err) => { for (let i = head; i < chunks.length; i++) { const item = chunks[i]; if (item && item.completions) settleCompletions(item.completions, err); } };
  const compact = () => { if (head > 32 && head * 2 >= chunks.length) { chunks = chunks.slice(head); head = 0; } };
  const resolveIdle = () => { if (queuedBytes || draining || !idleResolvers.length) return; const r = idleResolvers; idleResolvers = []; for (const res of r) res(); };
  const clear = (err = null) => {
    const closeErr = err || (closed ? new Error(name + ": queue closed") : null);
    if (closeErr) { rejectQueued(closeErr); settleCompletions(activeCompletions, closeErr); activeCompletions = null; }
    chunks = []; head = 0; queuedBytes = 0; resolveIdle();
  };
  const shift = () => { if (head >= chunks.length) return null; const item = chunks[head]; chunks[head++] = void 0; queuedBytes -= item.chunk.byteLength; compact(); return item; };
  const bundle = () => {
    const first = shift();
    if (!first) return null;
    if (head >= chunks.length || first.chunk.byteLength >= UPSTREAM_BUNDLE_TARGET_BYTES) return first;
    let byteLength = first.chunk.byteLength, end = head, allowRetry = first.allowRetry, completions = first.completions || null;
    while (end < chunks.length) {
      const next = chunks[end]; const nl = byteLength + next.chunk.byteLength;
      if (nl > UPSTREAM_BUNDLE_TARGET_BYTES) break;
      byteLength = nl; allowRetry = allowRetry && next.allowRetry;
      if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
      end++;
    }
    if (end === head) return first;
    const output = bundleBuffer ||= new Uint8Array(UPSTREAM_BUNDLE_TARGET_BYTES);
    output.set(first.chunk);
    let offset = first.chunk.byteLength;
    while (head < end) { const next = chunks[head]; chunks[head++] = void 0; queuedBytes -= next.chunk.byteLength; output.set(next.chunk, offset); offset += next.chunk.byteLength; }
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
          try { await writer.write(item.chunk); }
          catch (err) {
            releaseWriter?.();
            if (!item.allowRetry || typeof retryConnect !== "function") throw err;
            await retryConnect();
            writer = getWriter();
            if (!writer) throw err;
            await writer.write(item.chunk);
          }
          settleCompletions(completions);
        } catch (err) { settleCompletions(completions, err); throw err; }
        finally { if (activeCompletions === completions) activeCompletions = null; }
      }
    } catch (err) {
      closed = true; clear(err);
      try { closeConnection?.(err); } catch (_) {}
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
    const nextBytes = queuedBytes + chunk.byteLength, nextItems = chunks.length - head + 1;
    if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
      closed = true;
      const err = Object.assign(new Error(name + ": overflow"), { isQueueOverflow: true });
      clear(err);
      try { closeConnection?.(err); } catch (_) {}
      throw err;
    }
    let completionPromise = null, completions = null;
    if (waitForFlush) { completions = []; completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject })); }
    chunks.push({ chunk, allowRetry, completions });
    queuedBytes = nextBytes;
    if (!draining) queueMicrotask(drain);
    return waitForFlush ? completionPromise.then(() => true) : true;
  };
  return {
    writeAndAwait(data, allowRetry = true) { return enqueue(data, allowRetry, true); },
    async awaitEmpty() { if (!queuedBytes && !draining) return; await new Promise((resolve) => idleResolvers.push(resolve)); },
    clear() { closed = true; clear(); }
  };
}

// ============================================
// DOWNSTREAM SENDER
// ============================================
function createDownstreamSender(webSocket, headerData = null) {
  const packetCap = DOWNSTREAM_GRAIN_BYTES, tailBytes = DOWNSTREAM_GRAIN_TAIL_THRESHOLD;
  const lowWaterBytes = Math.max(4096, tailBytes << 3);
  let header = headerData, pendingBuffer = new Uint8Array(packetCap), pendingBytes = 0;
  let flushTimer = null, microtaskQueued = false, generation = 0, scheduledGeneration = 0, waitRounds = 0, flushPromise = null;
  const sendRawChunk = async (chunk) => { if (webSocket.readyState !== WebSocket.OPEN) throw new Error("ws closed"); webSocket.send(chunk); };
  const attachResponseHeader = (chunk) => {
    if (!header) return chunk;
    const merged = new Uint8Array(header.length + chunk.byteLength);
    merged.set(header, 0); merged.set(chunk, header.length); header = null; return merged;
  };
  const flush = async () => {
    while (flushPromise) await flushPromise;
    if (flushTimer) clearTimeout(flushTimer);
    flushTimer = null; microtaskQueued = false;
    if (!pendingBytes) return;
    const output = pendingBuffer.subarray(0, pendingBytes).slice();
    pendingBuffer = new Uint8Array(packetCap); pendingBytes = 0; waitRounds = 0;
    flushPromise = sendRawChunk(output).finally(() => { flushPromise = null; });
    return flushPromise;
  };
  const scheduleFlush = () => {
    if (flushTimer || microtaskQueued) return;
    microtaskQueued = true; scheduledGeneration = generation;
    queueMicrotask(() => {
      microtaskQueued = false;
      if (!pendingBytes || flushTimer) return;
      if (packetCap - pendingBytes < tailBytes) { flush().catch(() => closeSocketQuietly(webSocket)); return; }
      flushTimer = setTimeout(() => {
        flushTimer = null;
        if (!pendingBytes) return;
        if (packetCap - pendingBytes < tailBytes) { flush().catch(() => closeSocketQuietly(webSocket)); return; }
        if (waitRounds < 2 && (generation !== scheduledGeneration || pendingBytes < lowWaterBytes)) { waitRounds++; scheduledGeneration = generation; scheduleFlush(); return; }
        flush().catch(() => closeSocketQuietly(webSocket));
      }, Math.max(DOWNSTREAM_GRAIN_SILENT_MS, 1));
    });
  };
  return {
    async sendDirect(data) { let chunk = convertToUint8Array(data); if (!chunk.byteLength) return; chunk = attachResponseHeader(chunk); await sendRawChunk(chunk); },
    async send(data) {
      let chunk = convertToUint8Array(data);
      if (!chunk.byteLength) return;
      chunk = attachResponseHeader(chunk);
      let offset = 0; const totalBytes = chunk.byteLength;
      while (offset < totalBytes) {
        if (!pendingBytes && totalBytes - offset >= packetCap) {
          const sendBytes = Math.min(packetCap, totalBytes - offset);
          const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
          await sendRawChunk(view); offset += sendBytes; continue;
        }
        const copyBytes = Math.min(packetCap - pendingBytes, totalBytes - offset);
        pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
        pendingBytes += copyBytes; offset += copyBytes; generation++;
        if (pendingBytes === packetCap || packetCap - pendingBytes < tailBytes) await flush();
        else scheduleFlush();
      }
    },
    flush
  };
}

async function waitForBackpressure(ws) {
  if (typeof ws.bufferedAmount === "number") { while (ws.bufferedAmount > 256 * 1024) await new Promise((r) => setTimeout(r, 100)); }
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, onBytes) {
  let header = headerData, hasData = false, reader, useBYOB = false;
  const BYOB_LIMIT = 64 * 1024;
  const downstreamSender = createDownstreamSender(webSocket, header);
  header = null;
  try { reader = remoteSocket.readable.getReader({ mode: "byob" }); useBYOB = true; }
  catch (e) { reader = remoteSocket.readable.getReader(); }
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
        if (value.byteLength >= DOWNSTREAM_GRAIN_BYTES) { await downstreamSender.flush(); await downstreamSender.sendDirect(value); readBuffer = new ArrayBuffer(BYOB_LIMIT); }
        else { await downstreamSender.send(value); readBuffer = value.buffer.byteLength >= BYOB_LIMIT ? value.buffer : new ArrayBuffer(BYOB_LIMIT); }
      }
    }
    await downstreamSender.flush();
  } catch (err) { closeSocketQuietly(webSocket); }
  finally {
    try { reader.cancel(); } catch (e) {}
    try { reader.releaseLock(); } catch (e) {}
  }
  if (!hasData && retryFunc) await retryFunc();
}

async function buildRaceCandidates(address, port) {
  if (!PRELOAD_RACE_DIAL || isIPHostname(address)) return null;
  const [aRecords, aaaaRecords] = await Promise.all([dohQuery(address, "A"), dohQuery(address, "AAAA")]);
  const ipv4List = [...new Set(aRecords.flatMap((r) => r.type === 1 && typeof r.data === "string" && isIPv4(r.data) ? [r.data] : []))];
  const ipv6List = [...new Set(aaaaRecords.flatMap((r) => r.type === 28 && typeof r.data === "string" && isIPHostname(r.data) ? [r.data] : []))];
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
    await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 1e3))]);
    return socket;
  };
  if (candidates.length === 1) {
    const s = await openConnection(candidates[0].hostname, candidates[0].port);
    if (initialData && initialData.byteLength > 0) { const w = s.writable.getWriter(); await w.write(convertToUint8Array(initialData)); w.releaseLock(); }
    return s;
  }
  const attempts = candidates.map((c) => openConnection(c.hostname, c.port).then((socket) => ({ socket, candidate: c })));
  let winner = null;
  try {
    winner = await Promise.any(attempts);
    if (initialData && initialData.byteLength > 0) { const w = winner.socket.writable.getWriter(); await w.write(convertToUint8Array(initialData)); w.releaseLock(); }
    return winner.socket;
  } finally {
    if (winner) {
      for (const attempt of attempts) {
        attempt.then(({ socket }) => { if (socket !== winner.socket) { try { socket.close(); } catch (e) {} } }).catch(() => {});
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
          merged.set(vlessHeader, 0); merged.set(response, vlessHeader.length);
          webSocket.send(merged.buffer); vlessHeader = null;
        } else { webSocket.send(response); }
      }
    }));
  } catch (e) {}
}

// ============================================
// HTML - STATUS PAGE (public)
// ============================================
var HTML_STATUS = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Status</title>
<style>body{font-family:system-ui,sans-serif;background:#0d1b2a;color:#e0e6f0;display:flex;justify-content:center;padding:24px}
.card{background:#162032;border-radius:18px;padding:24px;max-width:420px;width:100%}
.row{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #2a3a4a}
.bar{height:10px;background:#2a3a4a;border-radius:6px;overflow:hidden;margin-top:8px}
.bar span{display:block;height:100%;background:#3a8f6e}</style></head>
<body><div class="card"><h2 id="email"></h2>
<div class="row"><span>Used</span><span id="used"></span></div>
<div class="row"><span>Total</span><span id="total"></span></div>
<div class="bar"><span id="prog"></span></div>
<div class="row" style="margin-top:14px"><span>Status</span><span id="status"></span></div>
<div class="row"><span>Expiry</span><span id="exp"></span></div></div>
<script>/*{{DATA}}*/
var u=window.statusUser||{};
function fb(b){if(!b)return'0 B';var k=1024,s=['B','KB','MB','GB','TB'],i=Math.floor(Math.log(b)/Math.log(k));return (b/Math.pow(k,i)).toFixed(2)+' '+s[i];}
document.getElementById('email').textContent=u.email||'User';
var used=(u.used_gb||0)*1073741824, total=(u.total_gb||0)*1073741824;
document.getElementById('used').textContent=fb(used);
document.getElementById('total').textContent=total?fb(total):'Unlimited';
document.getElementById('prog').style.width=(total?Math.min(100,used/total*100):0)+'%';
document.getElementById('status').textContent=u.enable?'Active':'Disabled';
document.getElementById('exp').textContent=u.expiry_time?new Date(u.expiry_time).toLocaleDateString():'Never';
</script></body></html>`;

// ============================================
// HTML - MAIN PANEL SPA
// ============================================
var HTML_PANEL = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>Fire Panel</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
:root{
  --bg:#0d1b2a; --card:#162032; --card2:#1b2738; --sidebar:#111d2a;
  --text:#e6ecf5; --dim:#8da0b5; --border:#2a3a4a; --input:#1e2f40;
  --primary:#3a8f6e; --primary-d:#2f7459; --danger:#e05555; --warn:#e0a030;
  --warn-bg:#2a2008; --green-bg:#13301f; --green-br:#2f6b4a;
  --purple:#a060c0; --orange:#e07a30; --shadow:0 4px 18px rgba(0,0,0,.3);
}
[data-theme="light"]{
  --bg:#e8f5f0; --card:#ffffff; --card2:#f4faf7; --sidebar:#ffffff;
  --text:#1a2a3a; --dim:#67788a; --border:#d8e6df; --input:#f0f8f4;
  --warn-bg:#fff3e0; --green-bg:#e3f5ec; --green-br:#9bd3b6; --shadow:0 4px 18px rgba(0,0,0,.08);
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);font-size:15px;line-height:1.5;transition:background .2s}
button{font-family:inherit;cursor:pointer;border:none;background:none;color:inherit;font-size:inherit}
input,select,textarea{font-family:inherit;font-size:inherit}
a{color:inherit;text-decoration:none}
.hidden{display:none!important}

/* layout */
#topbar{position:sticky;top:0;z-index:30;display:flex;align-items:center;gap:14px;padding:14px 16px;background:var(--bg);border-bottom:1px solid var(--border)}
#topbar .menu-btn{font-size:22px;width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center}
#topbar .menu-btn:hover{background:var(--card)}
#page-title{font-size:19px;font-weight:700}
main{padding:16px;max-width:760px;margin:0 auto}

/* cards */
.card{background:var(--card);border-radius:18px;padding:20px;margin-bottom:16px;box-shadow:var(--shadow)}
.card-title{font-size:18px;font-weight:700;margin-bottom:4px}
.card-divider{height:1px;background:var(--border);margin:14px 0}
.fw-bold{font-weight:700}
.dim{color:var(--dim)}
.small{font-size:13px}
.mt-1{margin-top:6px}.mt-2{margin-top:12px}.mt-3{margin-top:18px}.mb-2{margin-bottom:12px}.mb-3{margin-bottom:18px}.ml-auto{margin-left:auto}.ml-1{margin-left:8px}
.flex{display:flex;align-items:center}.gap-2{gap:10px}.text-right{text-align:right}.text-center{text-align:center}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}

/* badges */
.badge{display:inline-flex;align-items:center;padding:4px 12px;border-radius:999px;font-size:13px;font-weight:600}
.badge-green{background:var(--green-bg);color:var(--primary)}
.badge-orange{background:rgba(224,122,48,.15);color:var(--orange);border:1px solid var(--orange)}
.badge-outline-green{background:transparent;color:var(--primary);border:1px solid var(--green-br)}
.badge-outline-purple{background:transparent;color:var(--purple);border:1px solid var(--purple)}
.badge-row{display:flex;flex-wrap:wrap;gap:10px}

/* buttons */
.btn-primary{background:var(--primary);color:#fff;padding:9px 20px;border-radius:999px;font-weight:600}
.btn-primary:hover{background:var(--primary-d)}
.btn-danger{background:var(--danger);color:#fff;padding:9px 20px;border-radius:999px;font-weight:600}
.btn-ghost{background:transparent;border:1px solid var(--border);padding:8px 18px;border-radius:999px;color:var(--dim)}
.btn-ghost:hover{border-color:var(--primary);color:var(--text)}
.full{width:100%;display:block;text-align:center}
.btn-circle{width:44px;height:44px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:20px;background:var(--card2);border:1px solid var(--border)}
.btn-circle.primary{background:var(--primary);color:#fff;border:none}

/* gauges */
.gauge-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.gauge-item{text-align:center}
.gauge-item .label{margin-top:6px;font-size:14px;font-weight:600}
.gauge-item .label .dim{font-weight:400}

/* status dot */
.status-dot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:6px}
.status-dot.green{background:#3ad07a;box-shadow:0 0 8px #3ad07a}
.status-dot.red{background:var(--danger)}
.icon-actions{display:flex;justify-content:space-around;align-items:center}
.icon-actions button{font-size:22px;width:54px;height:46px;border-radius:10px;color:var(--dim)}
.icon-actions button:hover{background:var(--card2);color:var(--text)}

/* sidebar */
#overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:40}
#sidebar{position:fixed;top:0;left:0;bottom:0;width:300px;max-width:84vw;background:var(--sidebar);z-index:50;transform:translateX(-100%);transition:transform .25s;padding:16px;overflow-y:auto;box-shadow:var(--shadow)}
#sidebar.open{transform:translateX(0)}
.sidebar-close{font-size:22px;margin-bottom:10px}
.sidebar-theme{background:var(--green-bg);border-radius:12px;padding:14px;margin-bottom:14px}
.sidebar-theme .row{display:flex;align-items:center;justify-content:space-between;color:var(--primary);font-weight:600}
.sidebar-theme .sub{display:flex;align-items:center;gap:10px;margin-top:10px;color:var(--text)}
.nav-item{display:flex;align-items:center;gap:14px;padding:14px 16px;border-radius:12px;margin-bottom:4px;font-weight:600;color:var(--text)}
.nav-item .ic{width:22px;text-align:center}
.nav-item:hover{background:var(--card2)}
.nav-item.active{background:var(--primary);color:#fff}
.nav-item.danger{color:var(--danger)}

/* toggle */
.toggle{position:relative;display:inline-block;width:46px;height:26px}
.toggle input{display:none}
.toggle .slider{position:absolute;inset:0;background:var(--border);border-radius:999px;transition:.2s}
.toggle .slider:before{content:"";position:absolute;width:20px;height:20px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s}
.toggle input:checked+.slider{background:var(--primary)}
.toggle input:checked+.slider:before{transform:translateX(20px)}
.toggle.sm{width:38px;height:22px}
.toggle.sm .slider:before{width:16px;height:16px}
.toggle.sm input:checked+.slider:before{transform:translateX(16px)}

/* inputs */
.form-group{margin-bottom:16px}
.form-group label{display:block;font-weight:600;margin-bottom:6px}
.form-group.row{display:flex;align-items:center;justify-content:space-between}
.input{width:100%;background:var(--input);border:1px solid var(--border);border-radius:999px;padding:11px 18px;color:var(--text);outline:none}
.input:focus{border-color:var(--primary)}
textarea.input{border-radius:14px;resize:vertical;min-height:70px}
select.input{appearance:none;-webkit-appearance:none}
.input-with-btn{display:flex;gap:8px}
.input-with-btn .input{flex:1}

/* tabs */
.tab-bar{display:flex;gap:8px;border-bottom:1px solid var(--border);margin-bottom:16px;overflow-x:auto}
.tab{display:flex;align-items:center;gap:6px;padding:10px 6px;color:var(--dim);font-weight:600;border-bottom:2px solid transparent;white-space:nowrap}
.tab.active{color:var(--primary);border-bottom-color:var(--primary)}

/* accordion */
.accordion{border:1px solid var(--border);border-radius:12px;margin-bottom:10px;overflow:hidden}
.accordion-header{display:flex;align-items:center;justify-content:space-between;padding:15px 16px;font-weight:600;background:var(--card2)}
.accordion-header .arr{transition:.2s;color:var(--dim)}
.accordion.open .accordion-header .arr{transform:rotate(90deg)}
.accordion-body{padding:16px;border-top:1px solid var(--border)}

/* table */
.table{width:100%;border-collapse:collapse}
.table th{text-align:left;padding:12px 8px;font-size:13px;color:var(--dim);border-bottom:1px solid var(--border);background:var(--card2)}
.table td{padding:12px 8px;border-bottom:1px solid var(--border);vertical-align:top}
.table tr:last-child td{border-bottom:none}
.traffic-bar{height:6px;background:var(--border);border-radius:4px;overflow:hidden;margin:4px 0;min-width:80px}
.traffic-bar span{display:block;height:100%;background:var(--primary)}

/* table controls */
.table-controls{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.filter-row{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.input-sm{flex:1;background:var(--input);border:1px solid var(--border);border-radius:999px;padding:9px 16px;color:var(--text);outline:none}
.stats-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.stats-grid>div{font-size:14px}

/* dropdown */
.dropdown{position:relative;display:inline-block}
.dropdown-menu{position:absolute;left:0;top:100%;background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow);z-index:20;min-width:160px;overflow:hidden;display:none}
.dropdown-menu.open{display:block}
.dropdown-menu a{display:block;padding:11px 16px;font-size:14px}
.dropdown-menu a:hover{background:var(--card2)}
.dropdown-menu a.danger{color:var(--danger)}
.icon-btn{width:34px;height:34px;border-radius:8px;display:inline-flex;align-items:center;justify-content:center;color:var(--dim)}
.icon-btn:hover{background:var(--card2);color:var(--text)}

/* modal */
#modal-container{position:fixed;inset:0;z-index:60;display:none;align-items:center;justify-content:center;padding:14px;background:rgba(0,0,0,.55)}
#modal-container.open{display:flex}
.modal{background:var(--card);border-radius:18px;width:100%;max-width:480px;max-height:90vh;display:flex;flex-direction:column;box-shadow:var(--shadow)}
.modal-header{display:flex;align-items:center;justify-content:space-between;padding:18px 20px;border-bottom:1px solid var(--border)}
.modal-header h3{font-size:18px}
.modal-body{padding:20px;overflow-y:auto}
.modal-footer{display:flex;justify-content:flex-end;gap:10px;padding:16px 20px;border-top:1px solid var(--border)}

/* alerts */
.alert-warn{display:flex;gap:10px;background:var(--warn-bg);border:1px solid var(--warn);border-radius:12px;padding:14px;color:var(--text)}
.alert-danger{display:flex;gap:10px;flex-wrap:wrap;align-items:center;background:rgba(224,85,85,.12);border:1px solid var(--danger);border-radius:12px;padding:14px;color:var(--danger)}

/* login */
#login-page{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;background:linear-gradient(160deg,var(--bg),var(--card))}
.login-card{background:var(--card);border-radius:24px;padding:34px 28px;width:100%;max-width:380px;box-shadow:var(--shadow);position:relative}
.login-card h1{font-size:30px;margin-bottom:24px}
.gear-btn{position:absolute;top:20px;right:20px;font-size:20px;color:var(--dim)}
.login-input{display:flex;align-items:center;gap:10px;background:var(--input);border:1px solid var(--border);border-radius:999px;padding:12px 18px;margin-bottom:14px}
.login-input input{flex:1;background:none;border:none;outline:none;color:var(--text)}

/* toast */
#toast-container{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:80;display:flex;flex-direction:column;gap:8px}
.toast{background:var(--card);border:1px solid var(--border);border-left:4px solid var(--primary);border-radius:10px;padding:12px 18px;box-shadow:var(--shadow);animation:slidein .25s}
.toast.error{border-left-color:var(--danger)}
@keyframes slidein{from{opacity:0;transform:translateY(12px)}to{opacity:1}}
.blurred{filter:blur(6px);user-select:none}
.list-card{background:var(--card2);border:1px solid var(--border);border-radius:14px;padding:14px;margin-bottom:10px;display:flex;align-items:center;gap:12px}
.list-card .grow{flex:1;min-width:0}
.list-card .grow .t{font-weight:600}
.list-card .grow .s{font-size:13px;color:var(--dim);word-break:break-all}
.tag-chip{display:inline-flex;align-items:center;gap:5px;background:var(--input);border:1px solid var(--border);border-radius:999px;padding:4px 10px;font-size:13px;margin:0 6px 6px 0}
</style>
</head>
<body>

<!-- LOGIN -->
<div id="login-page" class="hidden">
  <div class="login-card">
    <button class="gear-btn" onclick="toggleTheme()" title="Theme">&#9881;</button>
    <h1 id="login-title">Hello</h1>
    <div class="login-input"><span>&#128100;</span><input id="login-user" placeholder="Username" autocomplete="username"></div>
    <div class="login-input"><span>&#128274;</span><input id="login-pass" type="password" placeholder="Password" autocomplete="current-password"><button onclick="togglePassVis('login-pass')">&#128065;</button></div>
    <button class="btn-primary full" onclick="doLogin()" id="login-btn">Log In</button>
  </div>
</div>

<!-- PANEL -->
<div id="panel" class="hidden">
  <div id="overlay" class="hidden" onclick="closeSidebar()"></div>
  <nav id="sidebar">
    <button class="sidebar-close" onclick="closeSidebar()">&#10005;</button>
    <div class="sidebar-theme">
      <div class="row"><span>&#128161; Theme</span></div>
      <div class="sub"><label class="toggle"><input type="checkbox" id="dark-toggle" onchange="toggleTheme()"><span class="slider"></span></label><span>Dark</span></div>
    </div>
    <a class="nav-item" data-page="overview" onclick="navigate('overview')"><span class="ic">&#128202;</span> Overview</a>
    <a class="nav-item" data-page="inbounds" onclick="navigate('inbounds')"><span class="ic">&#128100;</span> Inbounds</a>
    <a class="nav-item" data-page="outbounds" onclick="navigate('outbounds')"><span class="ic">&#11014;</span> Outbounds</a>
    <a class="nav-item" data-page="routing" onclick="navigate('routing')"><span class="ic">&#8645;</span> Routing Rules</a>
    <a class="nav-item" data-page="nodes" onclick="navigate('nodes')"><span class="ic">&#128421;</span> Nodes</a>
    <a class="nav-item" data-page="settings" onclick="navigate('settings')"><span class="ic">&#9881;</span> Panel Settings</a>
    <a class="nav-item" data-page="xray" onclick="navigate('xray')"><span class="ic">&#128295;</span> Xray Configs</a>
    <a class="nav-item danger" onclick="doLogout()"><span class="ic">&#10148;</span> Log Out</a>
  </nav>
  <div id="topbar">
    <button class="menu-btn" onclick="openSidebar()">&#9776;</button>
    <span id="page-title">Overview</span>
    <button class="btn-ghost ml-auto" onclick="fireUpdate()" id="fire-update-btn" title="Update panel code without touching DB">&#128293; Fire Update</button>
  </div>
  <main id="content"></main>
</div>

<div id="modal-container"></div>
<div id="toast-container"></div>

<script>
// ============ CORE ============
var state={page:'overview',ipVisible:false,pollTimer:null,inbounds:[],outbounds:[],rules:[],nodes:[]};

async function api(path,opts={}){
  opts.headers=Object.assign({'Content-Type':'application/json'},opts.headers||{});
  const r=await fetch(path,Object.assign({credentials:'same-origin'},opts));
  let data={};try{data=await r.json();}catch(e){}
  if(r.status===401&&path!=='/api/login'){showLogin();throw new Error('unauthorized');}
  return {ok:r.ok,status:r.status,data};
}
function toast(msg,type){const c=document.getElementById('toast-container');const t=document.createElement('div');t.className='toast'+(type==='error'?' error':'');t.textContent=msg;c.appendChild(t);setTimeout(()=>t.remove(),3200);}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
function fb(b){if(!b||b<=0)return '0 B';var k=1024,s=['B','KB','MB','GB','TB'],i=Math.floor(Math.log(b)/Math.log(k));return parseFloat((b/Math.pow(k,i)).toFixed(2))+' '+s[i];}
function fspeed(b){return fb(b)+'/s';}
function fuptime(sec){if(!sec)return '0s';var d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60),s=sec%60;if(d)return d+'d '+h+'h';if(h)return h+'h '+m+'m';if(m)return m+'m '+s+'s';return s+'s';}
function uuidv4(){return crypto.randomUUID();}

// ============ THEME ============
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);var d=document.getElementById('dark-toggle');if(d)d.checked=(t==='dark');localStorage.setItem('fire-theme',t);}
function toggleTheme(){var cur=document.documentElement.getAttribute('data-theme');applyTheme(cur==='dark'?'light':'dark');}

// ============ SIDEBAR ============
function openSidebar(){document.getElementById('sidebar').classList.add('open');document.getElementById('overlay').classList.remove('hidden');}
function closeSidebar(){document.getElementById('sidebar').classList.remove('open');document.getElementById('overlay').classList.add('hidden');}

// ============ MODAL ============
function showModal(html){const c=document.getElementById('modal-container');c.innerHTML=html;c.classList.add('open');}
function closeModal(){const c=document.getElementById('modal-container');c.classList.remove('open');c.innerHTML='';}
function togglePassVis(id){const e=document.getElementById(id);e.type=e.type==='password'?'text':'password';}

// ============ AUTH ============
async function checkAuth(){
  try{const {data}=await api('/api/auth/verify');
    if(data.needs_setup){showLogin(true);return;}
    if(data.authenticated){showPanel();}else{showLogin(false);}
  }catch(e){showLogin(false);}
}
function showLogin(setup){
  document.getElementById('login-page').classList.remove('hidden');
  document.getElementById('panel').classList.add('hidden');
  if(state.pollTimer){clearInterval(state.pollTimer);state.pollTimer=null;}
  document.getElementById('login-title').textContent=setup?'Welcome':'Hello';
  document.getElementById('login-btn').textContent=setup?'Create Admin':'Log In';
  document.getElementById('login-btn').setAttribute('data-setup',setup?'1':'0');
}
function showPanel(){
  document.getElementById('login-page').classList.add('hidden');
  document.getElementById('panel').classList.remove('hidden');
  var h=location.hash.replace('#','')||'overview';
  navigate(h);
}
async function doLogin(){
  const u=document.getElementById('login-user').value.trim();
  const p=document.getElementById('login-pass').value;
  const setup=document.getElementById('login-btn').getAttribute('data-setup')==='1';
  if(!u||!p){toast('Enter username and password','error');return;}
  if(setup){
    const {ok,data}=await api('/api/setup',{method:'POST',body:JSON.stringify({username:u,password:p})});
    if(ok){toast('Admin created');await api('/api/login',{method:'POST',body:JSON.stringify({username:u,password:p})});showPanel();}
    else toast(data.error||'Setup failed','error');
    return;
  }
  const {ok,data}=await api('/api/login',{method:'POST',body:JSON.stringify({username:u,password:p})});
  if(ok){toast('Welcome back');showPanel();}else toast(data.error||'Login failed','error');
}
async function doLogout(){await api('/api/logout',{method:'POST'});closeSidebar();showLogin(false);}

// ============ FIRE UPDATE ============
async function fireUpdate(){
  if(!confirm('Fire Update: refresh the panel to the latest code. Your database, inbounds, clients and settings will NOT change. Continue?'))return;
  const {ok,data}=await api('/api/fire-update',{method:'POST'});
  if(ok){toast(data.message||'Panel updated');setTimeout(()=>location.reload(),900);}
  else toast('Update failed','error');
}

// ============ NAV ============
var TITLES={overview:'Overview',inbounds:'Inbounds',outbounds:'Outbounds',routing:'Routing Rules',nodes:'Nodes',settings:'Panel Settings',xray:'Xray Configs'};
function navigate(page){
  state.page=page;location.hash=page;closeSidebar();
  document.getElementById('page-title').textContent=TITLES[page]||page;
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active',n.getAttribute('data-page')===page));
  if(state.pollTimer){clearInterval(state.pollTimer);state.pollTimer=null;}
  const fns={overview:renderOverview,inbounds:renderInbounds,outbounds:renderOutbounds,routing:renderRouting,nodes:renderNodes,settings:renderSettings,xray:renderXray};
  (fns[page]||renderOverview)();
}

// ============ GAUGE ============
function gauge(pct){
  pct=Math.max(0,Math.min(100,pct||0));
  var r=40,c=2*Math.PI*r,dash=pct/100*c;
  return '<svg viewBox="0 0 100 100" width="110" height="110">'+
    '<circle cx="50" cy="50" r="40" fill="none" stroke="var(--border)" stroke-width="9"/>'+
    '<circle cx="50" cy="50" r="40" fill="none" stroke="var(--primary)" stroke-width="9" stroke-linecap="round" stroke-dasharray="'+dash+' '+c+'" transform="rotate(-90 50 50)"/>'+
    '<text x="50" y="56" text-anchor="middle" font-size="16" font-weight="700" fill="var(--text)">'+pct.toFixed(pct<10?1:0)+'%</text></svg>';
}
// ============ OVERVIEW ============
function renderOverview(){
  const c=document.getElementById('content');
  c.innerHTML=
  '<div class="card"><div class="gauge-grid">'+
    '<div class="gauge-item"><div id="g-cpu">'+gauge(0)+'</div><div class="label">CPU: <span id="cpu-cores">1 Core</span></div></div>'+
    '<div class="gauge-item"><div id="g-ram">'+gauge(0)+'</div><div class="label" id="ram-label"><span class="dim">RAM</span></div></div>'+
    '<div class="gauge-item"><div id="g-swap">'+gauge(0)+'</div><div class="label" id="swap-label"><span class="dim">Swap</span></div></div>'+
    '<div class="gauge-item"><div id="g-disk">'+gauge(0)+'</div><div class="label" id="disk-label"><span class="dim">Storage</span></div></div>'+
  '</div></div>'+
  '<div class="card"><div class="flex"><span class="fw-bold">Xray</span><span class="badge badge-green ml-1">'+'v26.4.25'+'</span><span class="ml-auto"><span class="status-dot green" id="xray-dot"></span><span id="xray-state">Running</span></span></div>'+
    '<div class="card-divider"></div><div class="icon-actions">'+
    '<button onclick="xrayAction(\'stop\')" title="Stop">&#9211;</button>'+
    '<button onclick="xrayAction(\'restart\')" title="Restart">&#8635;</button>'+
    '<button onclick="navigate(\'xray\')" title="Config">&#128295;</button></div></div>'+
  '<div class="card"><div class="fw-bold mb-2">Manage</div><div class="card-divider"></div><div class="icon-actions">'+
    '<button onclick="navigate(\'inbounds\')" title="Inbounds">&#9776;</button>'+
    '<button onclick="navigate(\'routing\')" title="Routing">&#8645;</button>'+
    '<button onclick="navigate(\'nodes\')" title="Nodes">&#128421;</button></div></div>'+
  '<div class="card"><div class="flex"><span class="fw-bold">Fire Panel</span><span class="badge badge-orange ml-1">v3.0.0</span></div>'+
    '<div class="badge-row mt-2"><span class="badge badge-outline-green">v3.0.0</span><span class="badge badge-outline-green">@VoidLatency</span><span class="badge badge-outline-purple">Documentation</span></div></div>'+
  '<div class="card"><div class="fw-bold">Uptime</div><div class="card-divider"></div><div class="badge-row"><span class="badge badge-outline-green" id="xray-uptime">Xray: --</span><span class="badge badge-outline-green" id="os-uptime">OS: --</span></div></div>'+
  '<div class="card"><div class="fw-bold">System Load</div><div class="card-divider"></div><span class="badge badge-outline-green" id="sys-load">-- | -- | --</span></div>'+
  '<div class="card"><div class="fw-bold">Usage</div><div class="card-divider"></div><div class="badge-row"><span class="badge badge-outline-green" id="xray-ram">RAM: --</span><span class="badge badge-outline-green" id="xray-threads">Threads: --</span></div></div>'+
  '<div class="card"><div class="fw-bold">Overall Speed</div><div class="card-divider"></div><div class="two-col"><div><div class="dim">Upload</div><div>&#8593; <span id="speed-up">--</span></div></div><div><div class="dim">Download</div><div>&#8595; <span id="speed-down">--</span></div></div></div></div>'+
  '<div class="card"><div class="fw-bold">Total Data</div><div class="card-divider"></div><div class="two-col"><div><div class="dim">Sent</div><div>&#9729; <span id="total-sent">--</span></div></div><div><div class="dim">Received</div><div>&#9729; <span id="total-recv">--</span></div></div></div></div>'+
  '<div class="card"><div class="flex"><span class="fw-bold">IP Addresses</span><button class="icon-btn ml-auto" onclick="toggleIP()" id="ip-eye">&#128065;</button></div><div class="card-divider"></div>'+
    '<div class="dim">IPv4</div><div id="ip-v4" class="blurred">--</div><div class="dim mt-1">IPv6</div><div id="ip-v6" class="blurred" style="word-break:break-all">--</div></div>'+
  '<div class="card"><div class="fw-bold">Connection Stats</div><div class="card-divider"></div><div class="two-col"><div><div class="dim">TCP</div><div>&#8644; <span id="conn-tcp">--</span></div></div><div><div class="dim">UDP</div><div>&#8644; <span id="conn-udp">--</span></div></div></div></div>';
  pollStatus();
  state.pollTimer=setInterval(pollStatus,3000);
}
function toggleIP(){state.ipVisible=!state.ipVisible;document.getElementById('ip-v4').classList.toggle('blurred',!state.ipVisible);document.getElementById('ip-v6').classList.toggle('blurred',!state.ipVisible);}
async function pollStatus(){
  let d;try{const r=await api('/api/server/status');d=r.data;}catch(e){return;}
  if(!d||!d.cpu)return;
  const set=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v;};
  const setG=(id,p)=>{const e=document.getElementById(id);if(e)e.innerHTML=gauge(p);};
  setG('g-cpu',d.cpu.percent);set('cpu-cores',d.cpu.cores+' Core'+(d.cpu.cores>1?'s':''));
  setG('g-ram',d.ram.used/d.ram.total*100);
  document.getElementById('ram-label').innerHTML='RAM: '+fb(d.ram.used)+' / '+fb(d.ram.total);
  setG('g-swap',d.swap.total?d.swap.used/d.swap.total*100:0);
  document.getElementById('swap-label').innerHTML='Swap: '+fb(d.swap.used)+' / '+fb(d.swap.total);
  setG('g-disk',d.disk.used/d.disk.total*100);
  document.getElementById('disk-label').innerHTML='Storage: '+fb(d.disk.used)+' / '+fb(d.disk.total);
  set('xray-state',d.xray.running?'Running':'Stopped');
  const dot=document.getElementById('xray-dot');if(dot)dot.className='status-dot '+(d.xray.running?'green':'red');
  set('xray-uptime','Xray: '+fuptime(d.uptime.xray));set('os-uptime','OS: '+fuptime(d.uptime.os));
  set('sys-load',d.load.join(' | '));
  set('xray-ram','RAM: '+d.xray.mem);set('xray-threads','Threads: '+d.xray.threads);
  set('speed-up',fspeed(d.net.up));set('speed-down',fspeed(d.net.down));
  set('total-sent',fb(d.net.sent));set('total-recv',fb(d.net.recv));
  set('ip-v4',d.ip.v4);set('ip-v6',d.ip.v6);
  set('conn-tcp',d.connections.tcp);set('conn-udp',d.connections.udp);
}
async function xrayAction(act){
  const {ok}=await api('/api/xray/'+act,{method:'POST'});
  if(ok)toast('Xray '+act+'ed');else toast('Action failed','error');
  pollStatus();
}

// ============ INBOUNDS ============
async function renderInbounds(){
  const c=document.getElementById('content');
  c.innerHTML=
  '<div class="card"><div class="stats-grid">'+
    '<div><span class="dim">Total Sent/Received</span><br>&#8644; <span id="ib-sr">0 B / 0 B</span></div>'+
    '<div><span class="dim">Total Usage</span><br>&#9203; <span id="ib-usage">0 B</span></div>'+
    '<div><span class="dim">All Time Total Usage</span><br>&#128338; <span id="ib-alltime">0 B</span></div>'+
    '<div><span class="dim">Total Inbounds</span><br>&#9776; <span id="ib-count">0</span></div>'+
    '<div><span class="dim">Clients</span><br>&#128101; <span class="badge badge-green" id="ib-clients">0</span></div>'+
  '</div></div>'+
  '<div class="card"><div class="table-controls">'+
    '<button class="btn-circle primary" onclick="showInboundModal()" title="Add">+</button>'+
    '<button class="btn-circle ml-auto" onclick="renderInbounds()" title="Refresh">&#8635;</button></div>'+
    '<div class="filter-row"><input class="input-sm" placeholder="Search" oninput="filterInbounds(this.value)" id="ib-search"></div>'+
    '<table class="table"><thead><tr><th>ID</th><th>Menu</th><th>Remark</th><th class="text-right">Info</th></tr></thead><tbody id="ib-tbody"><tr><td colspan="4" class="text-center dim">Loading...</td></tr></tbody></table></div>';
  await loadInbounds();
}
async function loadInbounds(){
  const {data}=await api('/api/inbounds');
  state.inbounds=data.inbounds||[];
  document.getElementById('ib-sr').textContent=fb(data.total_up)+' / '+fb(data.total_down);
  document.getElementById('ib-usage').textContent=fb((data.total_up||0)+(data.total_down||0));
  document.getElementById('ib-alltime').textContent=fb((data.total_up||0)+(data.total_down||0));
  document.getElementById('ib-count').textContent=state.inbounds.length;
  document.getElementById('ib-clients').textContent=data.clients_count||0;
  drawInbounds(state.inbounds);
}
function drawInbounds(list){
  const tb=document.getElementById('ib-tbody');
  if(!list.length){tb.innerHTML='<tr><td colspan="4" class="text-center dim">No data.</td></tr>';return;}
  tb.innerHTML=list.map(ib=>{
    const total=ib.total||0,used=(ib.up||0)+(ib.down||0);
    const pct=total?Math.min(100,used/total*100):0;
    return '<tr><td>#'+ib.id+'</td>'+
    '<td><div class="dropdown"><button class="icon-btn" onclick="toggleMenu('+ib.id+')">&#8942;</button>'+
      '<div class="dropdown-menu" id="menu-'+ib.id+'">'+
        '<a onclick="showInboundModal('+ib.id+')">Edit</a>'+
        '<a onclick="showClientsModal('+ib.id+')">Clients ('+ib.clients_count+')</a>'+
        '<a onclick="copySub('+ib.id+')">Copy Sub Link</a>'+
        '<a onclick="resetInboundTraffic('+ib.id+')">Reset Traffic</a>'+
        '<a class="danger" onclick="deleteInbound('+ib.id+')">Delete</a></div></div></td>'+
    '<td><label class="toggle sm"><input type="checkbox" '+(ib.enable?'checked':'')+' onchange="toggleInbound('+ib.id+')"><span class="slider"></span></label>'+
      '<div class="mt-1">'+esc(ib.remark||'(no remark)')+'</div><div class="dim small">'+esc(ib.protocol)+' : '+esc(ib.port)+'</div></td>'+
    '<td class="text-right"><div class="traffic-bar"><span style="width:'+pct+'%"></span></div>'+
      '<div class="dim small">&#8593;'+fb(ib.up)+' &#8595;'+fb(ib.down)+'</div>'+
      '<div class="dim small">'+(total?fb(used)+' / '+fb(total):fb(used)+' / &#8734;')+'</div>'+
      (ib.expiry_time?'<div class="dim small">Exp: '+new Date(ib.expiry_time).toLocaleDateString()+'</div>':'')+
      '<div class="dim small">'+ib.clients_count+' clients</div></td></tr>';
  }).join('');
}
function filterInbounds(q){q=q.toLowerCase();drawInbounds(state.inbounds.filter(i=>(i.remark||'').toLowerCase().includes(q)||String(i.port).includes(q)||(i.protocol||'').includes(q)));}
function toggleMenu(id){document.querySelectorAll('.dropdown-menu').forEach(m=>{if(m.id!=='menu-'+id)m.classList.remove('open');});document.getElementById('menu-'+id).classList.toggle('open');}
async function toggleInbound(id){await api('/api/inbounds/'+id+'/enable',{method:'POST'});toast('Toggled');}
async function deleteInbound(id){if(!confirm('Delete this inbound and its clients?'))return;await api('/api/inbounds/'+id,{method:'DELETE'});toast('Deleted');loadInbounds();}
async function resetInboundTraffic(id){await api('/api/inbounds/'+id+'/reset-traffic',{method:'POST'});toast('Traffic reset');loadInbounds();}
async function copySub(id){
  const ib=state.inbounds.find(i=>i.id===id);
  if(!ib||!ib.clients.length){toast('No clients in this inbound','error');return;}
  const link=location.origin+'/sub/'+encodeURIComponent(ib.clients[0].sub_id||ib.clients[0].email);
  try{await navigator.clipboard.writeText(link);toast('Sub link copied');}catch(e){prompt('Sub link:',link);}
}
// ============ INBOUND MODAL ============
async function showInboundModal(id){
  let ib=null;
  if(id){const {data}=await api('/api/inbounds/'+id);ib=data.inbound;}
  const s=ib?(ib.settings_obj||{}):{};
  const st=ib?(ib.stream_obj||{}):{};
  const ws=st.wsSettings||{};
  const tls=st.tlsSettings||{};
  // Prefer the real clients table (source of truth for the proxy), fall back to settings
  const cli=(ib&&ib.clients&&ib.clients[0])||(s.clients&&s.clients[0])||{};
  showModal(
  '<div class="modal"><div class="modal-header"><h3>'+(id?'Edit':'Add')+' Inbound</h3><button onclick="closeModal()">&#10005;</button></div>'+
  '<div class="modal-body">'+
    fg('Remark','<input class="input" id="ib-remark" value="'+esc(ib?ib.remark:'')+'" placeholder="My Inbound">')+
    '<div class="form-group row"><label>Enable</label><label class="toggle"><input type="checkbox" id="ib-enable" '+(!ib||ib.enable?'checked':'')+'><span class="slider"></span></label></div>'+
    fg('Protocol','<select class="input" id="ib-protocol" onchange="onProtoChange()">'+opts(['vless','vmess','trojan','shadowsocks','socks','http'],ib?ib.protocol:'vless')+'</select>')+
    fg('Listen IP (optional)','<input class="input" id="ib-listen" value="'+esc(ib?ib.listen:'')+'" placeholder="0.0.0.0">')+
    fg('Port','<input class="input" type="number" id="ib-port" value="'+esc(ib?ib.port:'443')+'" placeholder="443">')+
    '<div id="uuid-sec">'+fg('UUID','<div class="input-with-btn"><input class="input" id="ib-uuid" value="'+esc(cli.uuid||'')+'" placeholder="auto-generate"><button class="btn-ghost" onclick="document.getElementById(\'ib-uuid\').value=uuidv4()">Gen</button></div>')+'</div>'+
    '<div id="pass-sec" class="hidden">'+fg('Password','<input class="input" id="ib-password" value="'+esc(cli.password||'')+'">')+'</div>'+
    '<div id="cipher-sec" class="hidden">'+fg('Cipher','<select class="input" id="ib-cipher">'+opts(['chacha20-poly1305','aes-256-gcm','aes-128-gcm','2022-blake3-aes-256-gcm'],s.method||'chacha20-poly1305')+'</select>')+'</div>'+
    fg('Email / Client name','<input class="input" id="ib-email" value="'+esc(cli.email||'')+'" placeholder="user1">')+
    fg('Network','<select class="input" id="ib-network" onchange="onNetChange()">'+opts(['ws','tcp','grpc','http'],st.network||'ws')+'</select>')+
    '<div id="ws-sec">'+fg('WS Path','<input class="input" id="ib-ws-path" value="'+esc(ws.path||'/')+'">')+fg('WS Host','<input class="input" id="ib-ws-host" value="'+esc((ws.headers&&ws.headers.Host)||(ib?'':location.hostname))+'" placeholder="example.com">')+'</div>'+
    '<div id="grpc-sec" class="hidden">'+fg('gRPC Service','<input class="input" id="ib-grpc" value="'+esc((st.grpcSettings&&st.grpcSettings.serviceName)||'')+'">')+'</div>'+
    fg('Security','<select class="input" id="ib-tls" onchange="onTlsChange()">'+opts(['none','tls','reality'],st.security||(ib?'none':'tls'))+'</select>')+
    '<div id="tls-sec" class="hidden">'+fg('SNI / Domain','<input class="input" id="ib-sni" value="'+esc(tls.serverName||(ib?'':location.hostname))+'" placeholder="example.com">')+fg('Cert Path','<input class="input" id="ib-cert" value="'+esc((tls.certificates&&tls.certificates[0]&&tls.certificates[0].certificateFile)||'')+'">')+fg('Key Path','<input class="input" id="ib-key" value="'+esc((tls.certificates&&tls.certificates[0]&&tls.certificates[0].keyFile)||'')+'">')+'</div>'+
    fg('Total Traffic GB (0 = unlimited)','<input class="input" type="number" id="ib-total" value="'+(ib?(ib.total/1073741824||0):0)+'">')+
    fg('Expiry Date','<input class="input" type="date" id="ib-expiry" value="'+(ib&&ib.expiry_time?new Date(ib.expiry_time).toISOString().slice(0,10):'')+'">')+
  '</div>'+
  '<div class="modal-footer"><button class="btn-ghost" onclick="closeModal()">Cancel</button><button class="btn-primary" onclick="saveInbound('+(id||0)+')">Save</button></div></div>');
  onProtoChange();onNetChange();onTlsChange();
}
function fg(label,inner){return '<div class="form-group"><label>'+label+'</label>'+inner+'</div>';}
function opts(arr,sel){return arr.map(o=>'<option value="'+o+'" '+(o===sel?'selected':'')+'>'+o+'</option>').join('');}
function onProtoChange(){const p=document.getElementById('ib-protocol').value;
  show('uuid-sec',p==='vless'||p==='vmess');show('pass-sec',p==='trojan'||p==='shadowsocks'||p==='socks'||p==='http');show('cipher-sec',p==='shadowsocks');}
function onNetChange(){const n=document.getElementById('ib-network').value;show('ws-sec',n==='ws');show('grpc-sec',n==='grpc');}
function onTlsChange(){const t=document.getElementById('ib-tls').value;show('tls-sec',t==='tls'||t==='reality');}
function show(id,v){const e=document.getElementById(id);if(e)e.classList.toggle('hidden',!v);}
async function saveInbound(id){
  const proto=document.getElementById('ib-protocol').value;
  const net=document.getElementById('ib-network').value;
  const sec=document.getElementById('ib-tls').value;
  const uuid=(document.getElementById('ib-uuid')||{}).value||uuidv4();
  const email=(document.getElementById('ib-email')||{}).value||'user-'+Math.random().toString(36).slice(2,8);
  const password=(document.getElementById('ib-password')||{}).value||'';
  const client={email:email,uuid:uuid,password:password,total_gb:0,expiry_time:0};
  const settings={clients:[client]};
  if(proto==='shadowsocks')settings.method=document.getElementById('ib-cipher').value;
  const stream={network:net,security:sec};
  if(net==='ws')stream.wsSettings={path:document.getElementById('ib-ws-path').value||'/',headers:{Host:document.getElementById('ib-ws-host').value||''}};
  if(net==='grpc')stream.grpcSettings={serviceName:document.getElementById('ib-grpc').value||''};
  if(sec==='tls')stream.tlsSettings={serverName:document.getElementById('ib-sni').value||'',certificates:[{certificateFile:document.getElementById('ib-cert').value||'',keyFile:document.getElementById('ib-key').value||''}]};
  if(sec==='reality')stream.realitySettings={serverName:document.getElementById('ib-sni').value||''};
  const expDate=document.getElementById('ib-expiry').value;
  const body={
    remark:document.getElementById('ib-remark').value,
    enable:document.getElementById('ib-enable').checked?1:0,
    listen:document.getElementById('ib-listen').value,
    port:parseInt(document.getElementById('ib-port').value)||0,
    protocol:proto,settings:settings,stream_settings:stream,
    total:parseFloat(document.getElementById('ib-total').value)||0,
    expiry_time:expDate?new Date(expDate).getTime():0,
    clients:id?undefined:[client]
  };
  const {ok,data}=await api(id?'/api/inbounds/'+id:'/api/inbounds',{method:id?'PUT':'POST',body:JSON.stringify(body)});
  if(!ok){toast(data.error||'Save failed','error');return;}
  // On edit, sync the first client row (the proxy reads the clients table)
  if(id){
    const cr=await api('/api/inbounds/'+id+'/clients');
    const existing=(cr.data.clients||[])[0];
    const cbody={email:email,uuid:uuid,password:password,total_gb:parseFloat(document.getElementById('ib-total').value)||0,expiry_time:body.expiry_time,enable:body.enable};
    if(existing)await api('/api/inbounds/'+id+'/clients/'+existing.id,{method:'PUT',body:JSON.stringify(cbody)});
    else await api('/api/inbounds/'+id+'/clients',{method:'POST',body:JSON.stringify(cbody)});
  }
  toast('Saved');closeModal();loadInbounds();
}

// ============ CLIENTS MODAL ============
async function showClientsModal(id){
  const {data}=await api('/api/inbounds/'+id+'/clients');
  const clients=data.clients||[];
  showModal('<div class="modal"><div class="modal-header"><h3>Clients</h3><button onclick="closeModal()">&#10005;</button></div>'+
  '<div class="modal-body"><button class="btn-primary mb-3" onclick="addClientRow('+id+')">+ Add Client</button><div id="clients-list">'+
  (clients.length?clients.map(c=>clientCard(id,c)).join(''):'<div class="dim text-center">No clients</div>')+
  '</div></div><div class="modal-footer"><button class="btn-ghost" onclick="closeModal()">Close</button></div></div>');
}
function clientCard(ibId,c){
  const used=(c.used_gb||0)*1073741824,total=(c.total_gb||0)*1073741824;
  return '<div class="list-card"><div class="grow"><div class="t">'+esc(c.email)+' <label class="toggle sm" style="vertical-align:middle"><input type="checkbox" '+(c.enable?'checked':'')+' onchange="toggleClient('+ibId+','+c.id+')"><span class="slider"></span></label></div>'+
    '<div class="s">'+esc(c.uuid)+'</div><div class="s">'+fb(used)+' / '+(total?fb(total):'∞')+(c.expiry_time?' · Exp '+new Date(c.expiry_time).toLocaleDateString():'')+'</div></div>'+
    '<button class="icon-btn" onclick="editClient('+ibId+','+c.id+')">&#9998;</button>'+
    '<button class="icon-btn" onclick="resetClient('+ibId+','+c.id+')" title="Reset">&#8635;</button>'+
    '<button class="icon-btn" style="color:var(--danger)" onclick="delClient('+ibId+','+c.id+')">&#128465;</button></div>';
}
function addClientRow(ibId){
  showModal('<div class="modal"><div class="modal-header"><h3>Add Client</h3><button onclick="showClientsModal('+ibId+')">&#10005;</button></div><div class="modal-body">'+
    fg('Email / Name','<input class="input" id="c-email" placeholder="user1">')+
    fg('UUID','<div class="input-with-btn"><input class="input" id="c-uuid" value="'+uuidv4()+'"><button class="btn-ghost" onclick="document.getElementById(\'c-uuid\').value=uuidv4()">Gen</button></div>')+
    fg('Password (trojan/ss)','<input class="input" id="c-pass">')+
    fg('Total GB (0=unlimited)','<input class="input" type="number" id="c-total" value="0">')+
    fg('Expiry Date','<input class="input" type="date" id="c-exp">')+
    '</div><div class="modal-footer"><button class="btn-ghost" onclick="showClientsModal('+ibId+')">Cancel</button><button class="btn-primary" onclick="saveClient('+ibId+',0)">Save</button></div></div>');
}
async function editClient(ibId,cid){
  const {data}=await api('/api/inbounds/'+ibId+'/clients');
  const c=(data.clients||[]).find(x=>x.id===cid)||{};
  showModal('<div class="modal"><div class="modal-header"><h3>Edit Client</h3><button onclick="showClientsModal('+ibId+')">&#10005;</button></div><div class="modal-body">'+
    fg('Email / Name','<input class="input" id="c-email" value="'+esc(c.email)+'">')+
    fg('UUID','<input class="input" id="c-uuid" value="'+esc(c.uuid)+'">')+
    fg('Password','<input class="input" id="c-pass" value="'+esc(c.password)+'">')+
    fg('Total GB (0=unlimited)','<input class="input" type="number" id="c-total" value="'+(c.total_gb||0)+'">')+
    fg('Expiry Date','<input class="input" type="date" id="c-exp" value="'+(c.expiry_time?new Date(c.expiry_time).toISOString().slice(0,10):'')+'">')+
    '<div class="form-group row"><label>Enable</label><label class="toggle"><input type="checkbox" id="c-enable" '+(c.enable?'checked':'')+'><span class="slider"></span></label></div>'+
    '</div><div class="modal-footer"><button class="btn-ghost" onclick="showClientsModal('+ibId+')">Cancel</button><button class="btn-primary" onclick="saveClient('+ibId+','+cid+')">Save</button></div></div>');
}
async function saveClient(ibId,cid){
  const exp=document.getElementById('c-exp').value;
  const body={email:document.getElementById('c-email').value,uuid:document.getElementById('c-uuid').value,password:document.getElementById('c-pass').value,total_gb:parseFloat(document.getElementById('c-total').value)||0,expiry_time:exp?new Date(exp).getTime():0};
  const en=document.getElementById('c-enable');if(en)body.enable=en.checked?1:0;
  const {ok,data}=await api(cid?'/api/inbounds/'+ibId+'/clients/'+cid:'/api/inbounds/'+ibId+'/clients',{method:cid?'PUT':'POST',body:JSON.stringify(body)});
  if(ok){toast('Saved');showClientsModal(ibId);}else toast(data.error||'Failed','error');
}
async function toggleClient(ibId,cid){const {data}=await api('/api/inbounds/'+ibId+'/clients');const c=(data.clients||[]).find(x=>x.id===cid);if(!c)return;c.enable=c.enable?0:1;await api('/api/inbounds/'+ibId+'/clients/'+cid,{method:'PUT',body:JSON.stringify(c)});toast('Toggled');}
async function resetClient(ibId,cid){await api('/api/inbounds/'+ibId+'/clients/'+cid+'/reset-traffic',{method:'POST'});toast('Reset');showClientsModal(ibId);}
async function delClient(ibId,cid){if(!confirm('Delete client?'))return;await api('/api/inbounds/'+ibId+'/clients/'+cid,{method:'DELETE'});toast('Deleted');showClientsModal(ibId);}
// ============ OUTBOUNDS ============
async function renderOutbounds(){
  const c=document.getElementById('content');
  c.innerHTML='<div class="card"><div class="flex mb-3"><span class="card-title">Outbounds</span><button class="btn-primary ml-auto" onclick="showOutboundModal()">+ Add</button></div><div id="ob-list" class="dim">Loading...</div></div>';
  await loadOutbounds();
}
async function loadOutbounds(){
  const {data}=await api('/api/outbounds');state.outbounds=data.outbounds||[];
  const el=document.getElementById('ob-list');
  if(!state.outbounds.length){el.innerHTML='<div class="text-center dim">No outbounds</div>';return;}
  el.innerHTML=state.outbounds.map(o=>'<div class="list-card"><div class="grow"><div class="t">'+esc(o.tag)+' <span class="badge badge-outline-green">'+esc(o.protocol)+'</span></div><div class="s">'+esc(o.remark||'')+'</div></div>'+
    '<button class="icon-btn" onclick="showOutboundModal('+o.id+')">&#9998;</button>'+
    (o.tag==='direct'||o.tag==='block'?'':'<button class="icon-btn" style="color:var(--danger)" onclick="delOutbound('+o.id+')">&#128465;</button>')+'</div>').join('');
}
function showOutboundModal(id){
  const o=id?state.outbounds.find(x=>x.id===id):null;
  const s=o?safeParseJS(o.settings):{};
  const srv=(s.servers&&s.servers[0])||(s.vnext&&s.vnext[0])||{};
  showModal('<div class="modal"><div class="modal-header"><h3>'+(id?'Edit':'Add')+' Outbound</h3><button onclick="closeModal()">&#10005;</button></div><div class="modal-body">'+
    fg('Tag','<input class="input" id="ob-tag" value="'+esc(o?o.tag:'')+'" placeholder="proxy-1">')+
    fg('Remark','<input class="input" id="ob-remark" value="'+esc(o?o.remark:'')+'">')+
    fg('Protocol','<select class="input" id="ob-proto" onchange="onObProto()">'+opts(['freedom','blackhole','vless','vmess','trojan','shadowsocks','socks','http'],o?o.protocol:'freedom')+'</select>')+
    '<div id="ob-server-sec" class="hidden">'+
      fg('Server Address','<input class="input" id="ob-addr" value="'+esc(srv.address||'')+'" placeholder="1.2.3.4">')+
      fg('Server Port','<input class="input" type="number" id="ob-port" value="'+esc(srv.port||'')+'" placeholder="443">')+
      fg('UUID / Password','<input class="input" id="ob-auth" value="'+esc(srv.id||srv.password||'')+'">')+
    '</div>'+
    '</div><div class="modal-footer"><button class="btn-ghost" onclick="closeModal()">Cancel</button><button class="btn-primary" onclick="saveOutbound('+(id||0)+')">Save</button></div></div>');
  onObProto();
}
function onObProto(){const p=document.getElementById('ob-proto').value;show('ob-server-sec',p!=='freedom'&&p!=='blackhole');}
function safeParseJS(s){try{return JSON.parse(s||'{}');}catch(e){return {};}}
async function saveOutbound(id){
  const proto=document.getElementById('ob-proto').value;
  let settings={};
  if(proto==='freedom')settings={domainStrategy:'AsIs'};
  else if(proto==='blackhole')settings={response:{type:'none'}};
  else{
    const addr=document.getElementById('ob-addr').value,port=parseInt(document.getElementById('ob-port').value)||443,auth=document.getElementById('ob-auth').value;
    if(proto==='vless'||proto==='vmess')settings={vnext:[{address:addr,port:port,users:[{id:auth,encryption:'none'}]}]};
    else settings={servers:[{address:addr,port:port,password:auth}]};
  }
  const body={tag:document.getElementById('ob-tag').value,remark:document.getElementById('ob-remark').value,protocol:proto,settings:settings};
  if(!body.tag){toast('Tag required','error');return;}
  const {ok,data}=await api(id?'/api/outbounds/'+id:'/api/outbounds',{method:id?'PUT':'POST',body:JSON.stringify(body)});
  if(ok){toast('Saved');closeModal();loadOutbounds();}else toast(data.error||'Failed','error');
}
async function delOutbound(id){if(!confirm('Delete outbound?'))return;await api('/api/outbounds/'+id,{method:'DELETE'});toast('Deleted');loadOutbounds();}

// ============ ROUTING ============
async function renderRouting(){
  const c=document.getElementById('content');
  c.innerHTML='<div class="card"><div class="flex mb-3"><span class="card-title">Routing Rules</span><button class="btn-primary ml-auto" onclick="showRoutingModal()">+ Add Rule</button></div>'+
  '<p class="dim small mb-3">Each rule sends matching traffic from inbounds through a chosen outbound.</p><div id="rt-list" class="dim">Loading...</div></div>';
  await loadRouting();
}
async function loadRouting(){
  await ensureOutbounds();await ensureInbounds();
  const {data}=await api('/api/routing');state.rules=data.rules||[];
  const el=document.getElementById('rt-list');
  if(!state.rules.length){el.innerHTML='<div class="text-center dim">No rules</div>';return;}
  el.innerHTML=state.rules.map(r=>{
    const ins=safeParseJS(r.inbound_tags);
    return '<div class="list-card"><div class="grow"><div class="t">'+esc(r.remark||'Rule #'+r.id)+' <label class="toggle sm" style="vertical-align:middle"><input type="checkbox" '+(r.enable?'checked':'')+' onchange="toggleRule('+r.id+')"><span class="slider"></span></label></div>'+
    '<div class="s">'+(ins.length?ins.join(', '):'all inbounds')+' &#8594; <b>'+esc(r.outbound_tag)+'</b></div>'+
    '<div class="s">'+(r.domain?'domain: '+esc(r.domain.replace(/\n/g,', ')):'')+(r.ip?' ip: '+esc(r.ip.replace(/\n/g,', ')):'')+(r.port?' port: '+esc(r.port):'')+'</div></div>'+
    '<button class="icon-btn" onclick="showRoutingModal('+r.id+')">&#9998;</button>'+
    '<button class="icon-btn" style="color:var(--danger)" onclick="delRule('+r.id+')">&#128465;</button></div>';
  }).join('');
}
async function ensureOutbounds(){if(!state.outbounds.length){const {data}=await api('/api/outbounds');state.outbounds=data.outbounds||[];}}
async function ensureInbounds(){if(!state.inbounds.length){const {data}=await api('/api/inbounds');state.inbounds=data.inbounds||[];}}
async function showRoutingModal(id){
  await ensureOutbounds();await ensureInbounds();
  const r=id?state.rules.find(x=>x.id===id):null;
  const selIn=r?safeParseJS(r.inbound_tags):[];
  const obTags=state.outbounds.map(o=>o.tag);
  const inChecks=state.inbounds.map(i=>'<label class="tag-chip"><input type="checkbox" value="'+esc(i.tag)+'" '+(selIn.includes(i.tag)?'checked':'')+'> '+esc(i.remark||i.tag)+'</label>').join('')||'<span class="dim">No inbounds yet</span>';
  showModal('<div class="modal"><div class="modal-header"><h3>'+(id?'Edit':'Add')+' Routing Rule</h3><button onclick="closeModal()">&#10005;</button></div><div class="modal-body">'+
    '<div class="form-group row"><label>Enable</label><label class="toggle"><input type="checkbox" id="rt-enable" '+(!r||r.enable?'checked':'')+'><span class="slider"></span></label></div>'+
    fg('Remark','<input class="input" id="rt-remark" value="'+esc(r?r.remark:'')+'">')+
    fg('Source Inbounds','<div id="rt-inbounds">'+inChecks+'</div>')+
    fg('Target Outbound','<select class="input" id="rt-outbound">'+opts(obTags,r?r.outbound_tag:'direct')+'</select>')+
    fg('Domains (one per line)','<textarea class="input" id="rt-domain" placeholder="example.com">'+esc(r?r.domain:'')+'</textarea>')+
    fg('IPs / CIDR (one per line)','<textarea class="input" id="rt-ip" placeholder="1.2.3.4">'+esc(r?r.ip:'')+'</textarea>')+
    fg('Ports (e.g. 443,80,1000-2000)','<input class="input" id="rt-port" value="'+esc(r?r.port:'')+'">')+
    fg('Protocol','<select class="input" id="rt-proto">'+opts(['','tcp','udp'],r?r.protocol:'')+'</select>')+
    '</div><div class="modal-footer"><button class="btn-ghost" onclick="closeModal()">Cancel</button><button class="btn-primary" onclick="saveRule('+(id||0)+')">Save</button></div></div>');
}
async function saveRule(id){
  const inbound_tags=Array.from(document.querySelectorAll('#rt-inbounds input:checked')).map(c=>c.value);
  const body={enable:document.getElementById('rt-enable').checked?1:0,remark:document.getElementById('rt-remark').value,inbound_tags:inbound_tags,outbound_tag:document.getElementById('rt-outbound').value,domain:document.getElementById('rt-domain').value,ip:document.getElementById('rt-ip').value,port:document.getElementById('rt-port').value,protocol:document.getElementById('rt-proto').value};
  const {ok,data}=await api(id?'/api/routing/'+id:'/api/routing',{method:id?'PUT':'POST',body:JSON.stringify(body)});
  if(ok){toast('Saved');closeModal();loadRouting();}else toast(data.error||'Failed','error');
}
async function toggleRule(id){const r=state.rules.find(x=>x.id===id);if(!r)return;r.enable=r.enable?0:1;r.inbound_tags=safeParseJS(r.inbound_tags);await api('/api/routing/'+id,{method:'PUT',body:JSON.stringify(r)});toast('Toggled');}
async function delRule(id){if(!confirm('Delete rule?'))return;await api('/api/routing/'+id,{method:'DELETE'});toast('Deleted');loadRouting();}

// ============ NODES ============
async function renderNodes(){
  const c=document.getElementById('content');
  c.innerHTML='<div class="card"><div class="flex mb-3"><span class="card-title">Nodes</span><button class="btn-primary ml-auto" onclick="showNodeModal()">+ Add Node</button></div>'+
  '<p class="dim small mb-3">Add relay servers. Reference a node from an outbound to route traffic through it.</p><div id="nd-list" class="dim">Loading...</div></div>';
  await loadNodes();
}
async function loadNodes(){
  const {data}=await api('/api/nodes');state.nodes=data.nodes||[];
  const el=document.getElementById('nd-list');
  if(!state.nodes.length){el.innerHTML='<div class="text-center dim">No nodes</div>';return;}
  el.innerHTML=state.nodes.map(n=>'<div class="list-card"><div class="grow"><div class="t">'+esc(n.name)+' <span class="badge badge-outline-green">'+esc(n.type)+'</span> <label class="toggle sm" style="vertical-align:middle"><input type="checkbox" '+(n.enable?'checked':'')+' onchange="toggleNode('+n.id+')"><span class="slider"></span></label></div>'+
    '<div class="s">'+esc(n.address)+':'+esc(n.port)+' · API '+esc(n.api_port)+'</div><div class="s">'+esc(n.remark||'')+'</div></div>'+
    '<button class="icon-btn" onclick="showNodeModal('+n.id+')">&#9998;</button>'+
    '<button class="icon-btn" style="color:var(--danger)" onclick="delNode('+n.id+')">&#128465;</button></div>').join('');
}
function showNodeModal(id){
  const n=id?state.nodes.find(x=>x.id===id):null;
  showModal('<div class="modal"><div class="modal-header"><h3>'+(id?'Edit':'Add')+' Node</h3><button onclick="closeModal()">&#10005;</button></div><div class="modal-body">'+
    fg('Name','<input class="input" id="nd-name" value="'+esc(n?n.name:'')+'" placeholder="Germany-1">')+
    fg('Address','<input class="input" id="nd-addr" value="'+esc(n?n.address:'')+'" placeholder="de.example.com">')+
    fg('Port','<input class="input" type="number" id="nd-port" value="'+esc(n?n.port:'')+'" placeholder="443">')+
    fg('API Port','<input class="input" type="number" id="nd-apiport" value="'+esc(n?n.api_port:62789)+'">')+
    fg('Type','<select class="input" id="nd-type">'+opts(['xray','v2ray','sing-box'],n?n.type:'xray')+'</select>')+
    fg('Remark','<input class="input" id="nd-remark" value="'+esc(n?n.remark:'')+'">')+
    '<div class="form-group row"><label>Enable</label><label class="toggle"><input type="checkbox" id="nd-enable" '+(!n||n.enable?'checked':'')+'><span class="slider"></span></label></div>'+
    '</div><div class="modal-footer"><button class="btn-ghost" onclick="closeModal()">Cancel</button><button class="btn-primary" onclick="saveNode('+(id||0)+')">Save</button></div></div>');
}
async function saveNode(id){
  const body={name:document.getElementById('nd-name').value,address:document.getElementById('nd-addr').value,port:parseInt(document.getElementById('nd-port').value)||0,api_port:parseInt(document.getElementById('nd-apiport').value)||62789,type:document.getElementById('nd-type').value,remark:document.getElementById('nd-remark').value,enable:document.getElementById('nd-enable').checked?1:0};
  if(!body.name||!body.address){toast('Name and address required','error');return;}
  const {ok,data}=await api(id?'/api/nodes/'+id:'/api/nodes',{method:id?'PUT':'POST',body:JSON.stringify(body)});
  if(ok){toast('Saved');closeModal();loadNodes();}else toast(data.error||'Failed','error');
}
async function toggleNode(id){const n=state.nodes.find(x=>x.id===id);if(!n)return;n.enable=n.enable?0:1;await api('/api/nodes/'+id,{method:'PUT',body:JSON.stringify(n)});toast('Toggled');}
async function delNode(id){if(!confirm('Delete node?'))return;await api('/api/nodes/'+id,{method:'DELETE'});toast('Deleted');loadNodes();}
// ============ PANEL SETTINGS ============
var settingsTab='general';
async function renderSettings(){
  const {data}=await api('/api/settings');const s=data.settings||{};
  const c=document.getElementById('content');
  c.innerHTML=
  '<div class="card"><div class="flex gap-2"><button class="btn-ghost" onclick="saveSettings()">Save</button><button class="btn-danger" onclick="restartPanel()">Restart Panel</button></div>'+
    '<div class="alert-warn mt-3"><span>&#9888;</span><span>Every change made here needs to be saved. Please restart the panel to apply changes.</span></div></div>'+
  '<div class="card"><div class="tab-bar">'+
    '<button class="tab '+(settingsTab==='general'?'active':'')+'" onclick="setTab(\'general\')">&#9881; General</button>'+
    '<button class="tab '+(settingsTab==='auth'?'active':'')+'" onclick="setTab(\'auth\')">&#128737; Authentication</button>'+
    '<button class="tab '+(settingsTab==='telegram'?'active':'')+'" onclick="setTab(\'telegram\')">&#128172; Telegram Bot</button></div>'+
  '<div id="tab-general" '+(settingsTab==='general'?'':'class="hidden"')+'>'+
    acc('General',
      fg('Listen IP','<input class="input" id="s-listen-ip" value="'+esc(s.listen_ip||'')+'">')+
      fg('Listen Domain','<input class="input" id="s-listen-domain" value="'+esc(s.listen_domain||'')+'">')+
      fg('Listen Port','<input class="input" type="number" id="s-port" value="'+esc(s.listen_port||'2020')+'">')+
      fg('URI Path','<input class="input" id="s-uri" value="'+esc(s.uri_path||'/')+'">')+
      fg('Session Duration (min)','<input class="input" type="number" id="s-session" value="'+esc(s.session||'360')+'">')+
      fg('Pagination Size','<input class="input" type="number" id="s-pagination" value="'+esc(s.pagination||'25')+'">'),true)+
    acc('Subscription',fg('Sub IPs / domains (one per line)','<textarea class="input" id="s-sub-ips" placeholder="vpn.example.com">'+esc(s.sub_ips||'')+'</textarea>')+fg('Proxy IP (fallback)','<input class="input" id="s-proxy-ip" value="'+esc(s.proxy_ip||'')+'">'))+
    acc('Certificates',fg('Certificate File','<input class="input" id="s-cert" value="'+esc(s.cert_file||'')+'">')+fg('Key File','<input class="input" id="s-key" value="'+esc(s.key_file||'')+'">'))+
    acc('External Traffic',fg('External Traffic Informer URL','<input class="input" id="s-ext" value="'+esc(s.ext_traffic||'')+'">'))+
    acc('Date and Time',fg('Timezone','<input class="input" id="s-tz" value="'+esc(s.timezone||'UTC')+'">'))+
  '</div>'+
  '<div id="tab-auth" '+(settingsTab==='auth'?'':'class="hidden"')+'>'+
    acc('Admin credentials',
      fg('Current Username','<input class="input" id="a-cur-user">')+
      fg('Current Password','<div class="input-with-btn"><input class="input" type="password" id="a-cur-pass"><button class="btn-ghost" onclick="togglePassVis(\'a-cur-pass\')">&#128065;</button></div>')+
      fg('New Username','<input class="input" id="a-new-user">')+
      fg('New Password','<div class="input-with-btn"><input class="input" type="password" id="a-new-pass"><button class="btn-ghost" onclick="togglePassVis(\'a-new-pass\')">&#128065;</button></div>')+
      '<button class="btn-primary" onclick="changeCreds()">Confirm</button>',true)+
  '</div>'+
  '<div id="tab-telegram" '+(settingsTab==='telegram'?'':'class="hidden"')+'>'+
    fg('Bot Token','<input class="input" id="tg-token" value="'+esc(s.tg_token||'')+'">')+
    fg('Admin Chat IDs (comma separated)','<input class="input" id="tg-admins" value="'+esc(s.tg_admins||'')+'">')+
    '<div class="form-group row"><label>Enable Notifications</label><label class="toggle"><input type="checkbox" id="tg-enable" '+(s.tg_enable==='1'?'checked':'')+'><span class="slider"></span></label></div>'+
  '</div></div>';
}
function setTab(t){settingsTab=t;renderSettings();}
function acc(title,body,open){return '<div class="accordion'+(open?' open':'')+'"><div class="accordion-header" onclick="toggleAcc(this)"><span>'+title+'</span><span class="arr">&#8250;</span></div><div class="accordion-body" '+(open?'':'style="display:none"')+'>'+body+'</div></div>';}
function toggleAcc(h){const a=h.parentElement;const b=a.querySelector('.accordion-body');a.classList.toggle('open');b.style.display=a.classList.contains('open')?'block':'none';}
async function saveSettings(){
  const get=id=>{const e=document.getElementById(id);return e?e.value:undefined;};
  const body={};
  [['listen_ip','s-listen-ip'],['listen_domain','s-listen-domain'],['listen_port','s-port'],['uri_path','s-uri'],['session','s-session'],['pagination','s-pagination'],['sub_ips','s-sub-ips'],['proxy_ip','s-proxy-ip'],['cert_file','s-cert'],['key_file','s-key'],['ext_traffic','s-ext'],['timezone','s-tz'],['tg_token','tg-token'],['tg_admins','tg-admins']].forEach(([k,id])=>{const v=get(id);if(v!==undefined)body[k]=v;});
  const tge=document.getElementById('tg-enable');if(tge)body.tg_enable=tge.checked?'1':'0';
  const {ok}=await api('/api/settings',{method:'POST',body:JSON.stringify(body)});
  if(ok)toast('Settings saved');else toast('Save failed','error');
}
async function changeCreds(){
  const body={current_username:document.getElementById('a-cur-user').value,current_password:document.getElementById('a-cur-pass').value,new_username:document.getElementById('a-new-user').value,new_password:document.getElementById('a-new-pass').value};
  const {ok,data}=await api('/api/admin/credentials',{method:'POST',body:JSON.stringify(body)});
  if(ok)toast('Credentials updated');else toast(data.error||'Failed','error');
}
async function restartPanel(){await api('/api/panel/restart',{method:'POST'});toast('Panel restarted');}

// ============ XRAY CONFIGS ============
var xrayTab='basics';
async function renderXray(){
  const c=document.getElementById('content');
  const insecure=location.protocol!=='https:';
  c.innerHTML=
  (insecure?'<div class="alert-danger mb-3"><span>&#10005; Security Alert</span><button class="ml-auto" onclick="this.parentElement.style.display=\'none\'">&#10005;</button><div style="flex-basis:100%">This connection is not secure. Please avoid entering sensitive information until TLS is activated for data protection.</div></div>':'')+
  '<div class="card"><div class="flex gap-2"><button class="btn-ghost" onclick="saveXray()">Save</button><button class="btn-danger" onclick="xrayAction(\'restart\')">Restart Xray</button></div>'+
    '<div class="alert-warn mt-3"><span>&#9888;</span><span>Every change made here needs to be saved. Please restart Xray to apply changes.</span></div></div>'+
  '<div class="card"><div class="tab-bar">'+
    '<button class="tab '+(xrayTab==='basics'?'active':'')+'" onclick="setXTab(\'basics\')">&#9881; Basics</button>'+
    '<button class="tab '+(xrayTab==='routing'?'active':'')+'" onclick="setXTab(\'routing\')">&#8645; Routing</button>'+
    '<button class="tab '+(xrayTab==='outbounds'?'active':'')+'" onclick="setXTab(\'outbounds\')">&#11014; Outbounds</button>'+
    '<button class="tab '+(xrayTab==='nodes'?'active':'')+'" onclick="setXTab(\'nodes\')">&#128421; Nodes</button></div>'+
    '<div id="xtab-body"></div></div>';
  renderXrayTab();
}
function setXTab(t){xrayTab=t;renderXray();}
async function renderXrayTab(){
  const b=document.getElementById('xtab-body');
  if(xrayTab==='basics'){
    const {data}=await api('/api/xray/config');const cfg=data.config||{};const log=cfg.log||{};
    b.innerHTML=
      acc('General',
        fg('Log Level','<select class="input" id="x-loglevel">'+opts(['warning','info','debug','error','none'],log.loglevel||'warning')+'</select>')+
        fg('Domain Strategy','<select class="input" id="x-domain">'+opts(['AsIs','IPIfNonMatch','IPOnDemand'],(cfg.routing&&cfg.routing.domainStrategy)||'AsIs')+'</select>'),true)+
      acc('Statistics','<div class="form-group row"><label>Enable Statistics</label><label class="toggle"><input type="checkbox" id="x-stats" '+(cfg.stats?'checked':'')+'><span class="slider"></span></label></div>')+
      acc('Log',fg('Access Log File','<input class="input" id="x-access" value="'+esc(log.access||'')+'">')+fg('Error Log File','<input class="input" id="x-error" value="'+esc(log.error||'')+'">'))+
      acc('Reset to Default','<p class="dim mb-2">Reset Xray configuration to default values.</p><button class="btn-danger" onclick="resetXray()">Reset</button>');
  }else if(xrayTab==='routing'){
    b.innerHTML='<div class="flex mb-3"><button class="btn-primary ml-auto" onclick="showRoutingModal()">+ Add Rule</button></div><div id="rt-list" class="dim">Loading...</div>';
    await loadRouting();
  }else if(xrayTab==='outbounds'){
    b.innerHTML='<div class="flex mb-3"><button class="btn-primary ml-auto" onclick="showOutboundModal()">+ Add Outbound</button></div><div id="ob-list" class="dim">Loading...</div>';
    await loadOutbounds();
  }else if(xrayTab==='nodes'){
    b.innerHTML='<div class="flex mb-3"><button class="btn-primary ml-auto" onclick="showNodeModal()">+ Add Node</button></div><div id="nd-list" class="dim">Loading...</div>';
    await loadNodes();
  }
}
async function saveXray(){
  const {data}=await api('/api/xray/config');const cfg=data.config||{};
  cfg.log=cfg.log||{};
  const ll=document.getElementById('x-loglevel');if(ll)cfg.log.loglevel=ll.value;
  const ac=document.getElementById('x-access');if(ac)cfg.log.access=ac.value;
  const er=document.getElementById('x-error');if(er)cfg.log.error=er.value;
  const ds=document.getElementById('x-domain');if(ds){cfg.routing=cfg.routing||{};cfg.routing.domainStrategy=ds.value;}
  const st=document.getElementById('x-stats');cfg.stats=st&&st.checked?{}:undefined;
  const {ok}=await api('/api/xray/config',{method:'POST',body:JSON.stringify({config:cfg})});
  if(ok)toast('Xray config saved');else toast('Failed','error');
}
async function resetXray(){if(!confirm('Reset Xray config?'))return;await api('/api/xray/config',{method:'POST',body:JSON.stringify({config:{}})});toast('Reset');renderXray();}

// ============ GLOBAL CLICK (close dropdowns) ============
document.addEventListener('click',function(e){
  if(!e.target.closest('.dropdown'))document.querySelectorAll('.dropdown-menu').forEach(m=>m.classList.remove('open'));
});
document.getElementById('login-pass').addEventListener('keydown',function(e){if(e.key==='Enter')doLogin();});

// ============ BOOT ============
applyTheme(localStorage.getItem('fire-theme')||'dark');
window.addEventListener('hashchange',function(){if(!document.getElementById('panel').classList.contains('hidden')){var h=location.hash.replace('#','');if(h&&h!==state.page)navigate(h);}});
checkAuth();
</script>
</body>
</html>`;
