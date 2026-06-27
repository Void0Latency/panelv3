// voidlatency-core.js - entry (router + subscription + fetch)
import { GLOBAL_TRAFFIC_CACHE, ACTIVE_CONNECTIONS_COUNT, SYSTEM_STATS, xrayStatus, PANEL_VERSION } from "./config.js";
import { ADMINS, loadAdmins, DbService } from "./db.js";
import { handleVLESS, flushExpiredTraffic } from "./proxy.js";
import { HTML_TEMPLATES } from "./html.js";
var THEME = "dark";
var voidlatency_core_default = {
  async fetch(request, env, ctx) {
    await DbService.ensureSchema(env.VL_DB);
    await loadAdmins(env);
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
    
    if (url.pathname === "/panel" || url.pathname === "/login") {
      return await Router.handlePanel(request, env);
    }
    
    if (url.pathname.startsWith("/status/")) {
      return await Router.handleUserStatus(url, env);
    }
    
    return new Response(HTML_TEMPLATES.nginx, {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
};

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
        if (proxyRow && proxyRow.value) {
          proxyIP = proxyRow.value;
        }
      } catch (e) {}
      const mockStoredData = { proxy_ip: proxyIP };
      return handleVLESS(env, mockStoredData, ctx);
    } catch (e) {
      return new Response("Internal Server Error", { status: 500 });
    }
  },
  async handleSubscription(url, env) {
    const isSubPath = url.pathname.startsWith("/sub/");
    const offset = isSubPath ? 5 : 6;
    let subUser = decodeURIComponent(url.pathname.slice(offset));
    const host = url.hostname;
    const isJson = !isSubPath && subUser.startsWith("json/");
    if (isJson) {
      subUser = subUser.slice(5);
    }
    try {
      const user = await env.VL_DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(subUser, subUser).first();
      if (!user || user.connection_type !== atob("dmxlc3M=")) {
        return new Response("Not Found", { status: 404 });
      }
      if (isJson) {
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
    const authorized = await DbService.verifyApiAuth(request, env);
    if (!authorized) {
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
    const hasPassword = await DbService.getPanelPassword(env.VL_DB);
    const authorized = await DbService.verifyApiAuth(request, env);
    
    // ============================================
    // SETUP PASSWORD - First time setup
    // ============================================
    if (url.pathname === "/api/setup-password" && request.method === "POST") {
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
    // LOGIN - Admin login with username + password
    // ============================================
    if (url.pathname === "/api/login" && request.method === "POST") {
      const { username, password } = await request.json();
      
      // First check: Is this a panel admin with username?
      if (username && password) {
        await loadAdmins(env);
        const admin = ADMINS.find(a => a.username === username);
        if (admin) {
          const hashed = await DbService.sha256(password);
          if (admin.password_hash === hashed) {
            return new Response(JSON.stringify({ success: true, role: "admin", username: username }), {
              headers: {
                "Content-Type": "application/json; charset=utf-8",
                "Set-Cookie": "panel_session=" + admin.id + "; Path=/; HttpOnly; Secure; SameSite=Lax"
              }
            });
          }
        }
      }
      
      // Second check: Is this the panel password (backward compatibility)
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
    // ADMIN CREATE - Create first admin
    // ============================================
    if (url.pathname === "/api/admin/create" && request.method === "POST") {
      // Only allow if no admin exists or if panel password is set
      await loadAdmins(env);
      if (ADMINS.length > 0 && !authorized) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      }
      const { username, password } = await request.json();
      if (!username || !password || password.length < 4) {
        return new Response(JSON.stringify({ error: "Invalid username or password" }), { status: 400 });
      }
      const hashed = await DbService.sha256(password);
      try {
        await env.VL_DB.prepare("INSERT INTO admins (username, password_hash) VALUES (?, ?)").bind(username, hashed).run();
        await loadAdmins(env);
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: "Username already exists" }), { status: 400 });
      }
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
    // AUTH VERIFICATION - Check if user is logged in
    // ============================================
    if (url.pathname === "/api/auth/verify" && request.method === "GET") {
      const cookies = request.headers.get("Cookie") || "";
      const sessionCookie = cookies.split(";").find((c) => c.trim().startsWith("panel_session="));
      if (!sessionCookie) {
        return new Response(JSON.stringify({ authenticated: false }), {
          headers: { "Content-Type": "application/json" }
        });
      }
      const sessionToken = sessionCookie.split("=")[1].trim();
      
      // Check if it's an admin ID
      await loadAdmins(env);
      const admin = ADMINS.find(a => String(a.id) === sessionToken);
      if (admin) {
        return new Response(JSON.stringify({ authenticated: true, role: "admin", username: admin.username }), {
          headers: { "Content-Type": "application/json" }
        });
      }
      
      // Check if it's the panel password
      const storedHash = await DbService.getPanelPassword(env.VL_DB);
      if (storedHash && sessionToken === storedHash) {
        return new Response(JSON.stringify({ authenticated: true, role: "admin" }), {
          headers: { "Content-Type": "application/json" }
        });
      }
      
      return new Response(JSON.stringify({ authenticated: false }), {
        headers: { "Content-Type": "application/json" }
      });
    }
    
    // ============================================
    // CHANGE PASSWORD - Panel password
    // ============================================
    if (url.pathname === "/api/change-password" && request.method === "POST") {
      if (!authorized) {
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
    // CHANGE ADMIN PASSWORD - Admin user password
    // ============================================
    if (url.pathname === "/api/admin/change-password" && request.method === "POST") {
      if (!authorized) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      }
      const { username, current_password, new_password } = await request.json();
      if (!username || !current_password || !new_password) {
        return new Response(JSON.stringify({ error: "Username, current and new password required" }), {
          status: 400,
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
      await loadAdmins(env);
      const admin = ADMINS.find(a => a.username === username);
      if (!admin) {
        return new Response(JSON.stringify({ error: "Admin not found" }), { status: 404 });
      }
      const currentHash = await DbService.sha256(current_password);
      if (admin.password_hash !== currentHash) {
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
      await env.VL_DB.prepare("UPDATE admins SET password_hash = ? WHERE username = ?").bind(newHash, username).run();
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          "Content-Type": "application/json; charset=utf-8"
        }
      });
    }
    
    // ============================================
    // XRAY CONTROL
    // ============================================
    if (url.pathname === "/api/xray" && request.method === "POST") {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
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
        memory: "50.98 MB",
        threads: 14
      }));
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
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }
    
    // ============================================
    // SYSTEM STATS
    // ============================================
    if (url.pathname === "/api/system/stats") {
      const now = Date.now();
      const uptime = xrayStatus.running ? Math.floor((now - xrayStatus.startTime) / 1000) : 0;
      return new Response(JSON.stringify({
        cpu: SYSTEM_STATS.cpu,
        ram: SYSTEM_STATS.ram,
        swap: SYSTEM_STATS.swap,
        storage: SYSTEM_STATS.storage,
        uptime: "26d 3h",
        xray_uptime: uptime,
        version: PANEL_VERSION,
        theme: THEME
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
    
    // ============================================
    // THEME SETTINGS
    // ============================================
    if (url.pathname === "/api/theme" && request.method === "POST") {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
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
        if (row && row.value) {
          THEME = row.value;
        }
      } catch (e) {}
      return new Response(JSON.stringify({ theme: THEME }), {
        headers: { "Content-Type": "application/json" }
      });
    }
    
    // ============================================
    // PROXY IP SETTINGS
    // ============================================
    if (url.pathname === "/api/proxy-ip") {
      if (request.method === "POST") {
        if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
        const { proxy_ip, iata, frag_len, frag_int } = await request.json();
        if (proxy_ip) await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_ip', ?)").bind(proxy_ip).run();
        if (iata !== void 0) await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_location_iata', ?)").bind(iata).run();
        if (frag_len !== void 0) await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('frag_len', ?)").bind(frag_len).run();
        if (frag_int !== void 0) await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('frag_int', ?)").bind(frag_int).run();
        return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
      }
      if (request.method === "GET") {
        const rowIp = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
        const rowIata = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'proxy_location_iata'").first();
        const rowLen = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'frag_len'").first();
        const rowInt = await env.VL_DB.prepare("SELECT value FROM settings WHERE key = 'frag_int'").first();
        return new Response(JSON.stringify({
          proxy_ip: rowIp ? rowIp.value : "proxyip.cmliussss.net",
          iata: rowIata ? rowIata.value : "",
          frag_len: rowLen ? rowLen.value : "20-30",
          frag_int: rowInt ? rowInt.value : "1-2"
        }), { headers: { "Content-Type": "application/json" } });
      }
    }
    
    // ============================================
    // ADMINS - CRUD (Requires authentication)
    // ============================================
    if (url.pathname === "/api/admins") {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      await loadAdmins(env);
      if (request.method === "GET") {
        return new Response(JSON.stringify({ admins: ADMINS.map(a => ({ id: a.id, username: a.username, created_at: a.created_at })) }));
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
    // USERS - CRUD (Requires authentication)
    // ============================================
    if (url.pathname.startsWith("/api/users")) {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      const pathParts = url.pathname.split("/");
      const isUserAction = pathParts.length > 3;
      
      if (isUserAction) {
        const username = decodeURIComponent(pathParts.pop());
        
        if (request.method === "PUT") {
          const body = await request.json();
          if (body.toggle_only !== void 0) {
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
              tls,
              port,
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
            is_online: user.last_active && now - user.last_active < 65e3 ? 1 : 0,
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
          const { username, limit_gb, expiry_days, ips, tls, port, fingerprint, config_name } = await request.json();
          if (!username) {
            return new Response(JSON.stringify({ error: "Username is required" }), { status: 400, headers: { "Content-Type": "application/json" } });
          }
          const uuid = crypto.randomUUID();
          try {
            await env.VL_DB.prepare(
              "INSERT INTO users (username, uuid, limit_gb, expiry_days, ips, connection_type, tls, port, fingerprint, config_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            ).bind(
              username,
              uuid,
              limit_gb ? parseFloat(limit_gb) : null,
              expiry_days ? parseInt(expiry_days) : null,
              ips || null,
              atob("dmxlc3M="),
              tls,
              port,
              fingerprint || "chrome",
              config_name || username
            ).run();
            return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
          } catch (err) {
            let errorMsg = err.message;
            if (errorMsg.includes("UNIQUE constraint failed")) {
              errorMsg = "Username already exists";
            }
            return new Response(JSON.stringify({ error: errorMsg }), { status: 500, headers: { "Content-Type": "application/json" } });
          }
        }
      }
    }
    
    // ============================================
    // USER STATS - Get real traffic usage
    // ============================================
    if (url.pathname.startsWith("/api/users/stats/")) {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
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
    // USER TRAFFIC - Get traffic data
    // ============================================
    if (url.pathname.startsWith("/api/users/traffic/")) {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      const username = decodeURIComponent(url.pathname.split("/").pop());
      if (!username) {
        return new Response(JSON.stringify({ error: "Username required" }), { status: 400 });
      }
      try {
        const user = await env.VL_DB.prepare("SELECT username, used_gb, limit_gb FROM users WHERE username = ?").bind(username).first();
        if (!user) {
          return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
        }
        const usedBytes = user.used_gb * 1024 * 1024 * 1024;
        const limitBytes = user.limit_gb ? user.limit_gb * 1024 * 1024 * 1024 : null;
        const percent = limitBytes ? Math.min((usedBytes / limitBytes) * 100, 100) : 0;
        return new Response(JSON.stringify({
          success: true,
          username: user.username,
          used_gb: user.used_gb,
          used_bytes: usedBytes,
          limit_gb: user.limit_gb,
          limit_bytes: limitBytes,
          percent: percent,
          remaining_gb: user.limit_gb ? Math.max(0, user.limit_gb - user.used_gb) : null
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // USER CHECK - Check if user exists and is active
    // ============================================
    if (url.pathname.startsWith("/api/users/check/")) {
      const username = decodeURIComponent(url.pathname.split("/").pop());
      if (!username) {
        return new Response(JSON.stringify({ error: "Username required" }), { status: 400 });
      }
      try {
        const user = await env.VL_DB.prepare("SELECT username, is_active, limit_gb, used_gb, expiry_days, created_at FROM users WHERE username = ?").bind(username).first();
        if (!user) {
          return new Response(JSON.stringify({ exists: false }), {
            headers: { "Content-Type": "application/json" }
          });
        }
        const now = new Date();
        const created = new Date(user.created_at);
        const expiryDate = new Date(created.getTime() + (user.expiry_days || 30) * 24 * 60 * 60 * 1000);
        const isExpired = now > expiryDate || (user.limit_gb && user.used_gb >= user.limit_gb);
        return new Response(JSON.stringify({
          exists: true,
          username: user.username,
          is_active: user.is_active === 1 && !isExpired,
          is_expired: isExpired,
          limit_gb: user.limit_gb,
          used_gb: user.used_gb
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // USER CONFIG - Get single user's config
    // ============================================
    if (url.pathname.startsWith("/api/users/config/")) {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      const username = decodeURIComponent(url.pathname.split("/").pop());
      if (!username) {
        return new Response(JSON.stringify({ error: "Username required" }), { status: 400 });
      }
      try {
        const user = await env.VL_DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
        if (!user) {
          return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
        }
        const host = url.hostname;
        const config = await SubscriptionService.generateText(user, host);
        return new Response(JSON.stringify({
          success: true,
          username: user.username,
          config: config,
          links: {
            text: `${url.origin}/feed/${encodeURIComponent(username)}`,
            json: `${url.origin}/feed/json/${encodeURIComponent(username)}`,
            status: `${url.origin}/status/${encodeURIComponent(username)}`
          }
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // USER RESET - Reset user traffic
    // ============================================
    if (url.pathname.startsWith("/api/users/reset/")) {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      const username = decodeURIComponent(url.pathname.split("/").pop());
      if (!username) {
        return new Response(JSON.stringify({ error: "Username required" }), { status: 400 });
      }
      try {
        await env.VL_DB.prepare("UPDATE users SET used_gb = 0 WHERE username = ?").bind(username).run();
        GLOBAL_TRAFFIC_CACHE.delete(username);
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // USER RESET ALL - Reset all users traffic
    // ============================================
    if (url.pathname === "/api/users/reset-all" && request.method === "POST") {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      try {
        await env.VL_DB.prepare("UPDATE users SET used_gb = 0").run();
        GLOBAL_TRAFFIC_CACHE.clear();
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // BULK USER OPERATIONS
    // ============================================
    if (url.pathname === "/api/users/bulk" && request.method === "POST") {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      const { users } = await request.json();
      if (!users || !Array.isArray(users)) {
        return new Response(JSON.stringify({ error: "Invalid users array" }), { status: 400 });
      }
      const results = [];
      for (const userData of users) {
        try {
          const { username, limit_gb, expiry_days, ips, tls, port, fingerprint } = userData;
          if (!username) continue;
          const uuid = crypto.randomUUID();
          await env.VL_DB.prepare(
            "INSERT INTO users (username, uuid, limit_gb, expiry_days, ips, connection_type, tls, port, fingerprint, config_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
          ).bind(
            username,
            uuid,
            limit_gb ? parseFloat(limit_gb) : null,
            expiry_days ? parseInt(expiry_days) : null,
            ips || null,
            atob("dmxlc3M="),
            tls,
            port,
            fingerprint || "chrome",
            username
          ).run();
          results.push({ username, success: true });
        } catch (e) {
          results.push({ username: userData.username, success: false, error: e.message });
        }
      }
      return new Response(JSON.stringify({ success: true, results }), {
        headers: { "Content-Type": "application/json" }
      });
    }
    
    // ============================================
    // UPDATE CHECK
    // ============================================
    if (url.pathname === "/api/update-check") {
      try {
        const response = await fetch("https://api.github.com/repos/Void0Latency/panel/releases/latest");
        if (!response.ok) throw new Error("Failed to fetch");
        const data = await response.json();
        const latestVersion = data.tag_name || data.name || "v2.9.4";
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
    // SYSTEM INFO
    // ============================================
    if (url.pathname === "/api/system/info") {
      return new Response(JSON.stringify({
        version: PANEL_VERSION,
        platform: "Cloudflare Workers",
        environment: "Production",
        uptime: Math.floor((Date.now() - xrayStatus.startTime) / 1000),
        theme: THEME,
        xray: {
          running: xrayStatus.running,
          uptime: Math.floor((Date.now() - xrayStatus.startTime) / 1000),
          version: "v26.4.25",
          memory: "50.98 MB",
          threads: 14
        }
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
    
    // ============================================
    // SYSTEM HEALTH CHECK
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
          version: PANEL_VERSION
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // USER ONLINE CHECK
    // ============================================
    if (url.pathname.startsWith("/api/users/online/")) {
      const username = decodeURIComponent(url.pathname.split("/").pop());
      if (!username) {
        return new Response(JSON.stringify({ error: "Username required" }), { status: 400 });
      }
      try {
        const user = await env.VL_DB.prepare("SELECT last_active FROM users WHERE username = ?").bind(username).first();
        if (!user) {
          return new Response(JSON.stringify({ online: false, exists: false }), {
            headers: { "Content-Type": "application/json" }
          });
        }
        const isOnline = user.last_active && (Date.now() - user.last_active < 65000);
        return new Response(JSON.stringify({
          online: isOnline,
          exists: true,
          username: username
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // USER EXTEND - Extend expiry date
    // ============================================
    if (url.pathname.startsWith("/api/users/extend/")) {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      const username = decodeURIComponent(url.pathname.split("/").pop());
      if (!username) {
        return new Response(JSON.stringify({ error: "Username required" }), { status: 400 });
      }
      const { days } = await request.json();
      if (!days || days <= 0) {
        return new Response(JSON.stringify({ error: "Invalid days" }), { status: 400 });
      }
      try {
        const user = await env.VL_DB.prepare("SELECT expiry_days, created_at FROM users WHERE username = ?").bind(username).first();
        if (!user) {
          return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
        }
        const newExpiry = (user.expiry_days || 30) + days;
        await env.VL_DB.prepare("UPDATE users SET expiry_days = ? WHERE username = ?").bind(newExpiry, username).run();
        return new Response(JSON.stringify({
          success: true,
          username: username,
          new_expiry_days: newExpiry
        }), {
          headers: { "Content-Type": "application/json" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // USER ADD TRAFFIC - Add traffic to user
    // ============================================
    if (url.pathname.startsWith("/api/users/add-traffic/")) {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      const username = decodeURIComponent(url.pathname.split("/").pop());
      if (!username) {
        return new Response(JSON.stringify({ error: "Username required" }), { status: 400 });
      }
      const { gb } = await request.json();
      if (!gb || gb <= 0) {
        return new Response(JSON.stringify({ error: "Invalid GB amount" }), { status: 400 });
      }
      try {
        const user = await env.VL_DB.prepare("SELECT limit_gb FROM users WHERE username = ?").bind(username).first();
        if (!user) {
          return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
        }
        const newLimit = (user.limit_gb || 0) + gb;
        await env.VL_DB.prepare("UPDATE users SET limit_gb = ? WHERE username = ?").bind(newLimit, username).run();
        return new Response(JSON.stringify({
          success: true,
          username: username,
          new_limit_gb: newLimit
        }), {
          headers: { "Content-Type": "application/json" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // USER RENAME - Rename user
    // ============================================
    if (url.pathname === "/api/users/rename" && request.method === "POST") {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      const { old_username, new_username } = await request.json();
      if (!old_username || !new_username) {
        return new Response(JSON.stringify({ error: "Old and new username required" }), { status: 400 });
      }
      try {
        const existing = await env.VL_DB.prepare("SELECT username FROM users WHERE username = ?").bind(new_username).first();
        if (existing) {
          return new Response(JSON.stringify({ error: "New username already exists" }), { status: 400 });
        }
        await env.VL_DB.prepare("UPDATE users SET username = ? WHERE username = ?").bind(new_username, old_username).run();
        if (GLOBAL_TRAFFIC_CACHE.has(old_username)) {
          const traffic = GLOBAL_TRAFFIC_CACHE.get(old_username);
          GLOBAL_TRAFFIC_CACHE.delete(old_username);
          GLOBAL_TRAFFIC_CACHE.set(new_username, traffic);
        }
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // SUBSCRIPTION LINKS GET
    // ============================================
    if (url.pathname.startsWith("/api/subscription/")) {
      const username = decodeURIComponent(url.pathname.split("/").pop());
      if (!username) {
        return new Response(JSON.stringify({ error: "Username required" }), { status: 400 });
      }
      try {
        const user = await env.VL_DB.prepare("SELECT username FROM users WHERE username = ?").bind(username).first();
        if (!user) {
          return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
        }
        const origin = url.origin;
        return new Response(JSON.stringify({
          success: true,
          username: username,
          links: {
            text: `${origin}/feed/${encodeURIComponent(username)}`,
            json: `${origin}/feed/json/${encodeURIComponent(username)}`,
            status: `${origin}/status/${encodeURIComponent(username)}`,
            panel: `${origin}/panel`
          }
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // LOGS - Get system logs
    // ============================================
    if (url.pathname === "/api/logs" && request.method === "GET") {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      const limit = parseInt(url.searchParams.get("limit")) || 50;
      const logs = [
        { timestamp: new Date().toISOString(), level: "info", message: "System started" },
        { timestamp: new Date().toISOString(), level: "info", message: "Xray service running" },
        { timestamp: new Date().toISOString(), level: "info", message: "WebSocket server listening on /" },
        { timestamp: new Date().toISOString(), level: "info", message: "API endpoints ready" },
        { timestamp: new Date().toISOString(), level: "info", message: "Database connected" },
        { timestamp: new Date().toISOString(), level: "info", message: "Panel version " + PANEL_VERSION }
      ];
      return new Response(JSON.stringify({
        success: true,
        logs: logs.slice(0, limit),
        total: logs.length
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
    
    // ============================================
    // PANEL CONFIG - Get panel configuration
    // ============================================
    if (url.pathname === "/api/panel/config" && request.method === "GET") {
      return new Response(JSON.stringify({
        version: PANEL_VERSION,
        theme: THEME,
        xray: {
          running: xrayStatus.running,
          version: "v26.4.25"
        },
        admin_count: ADMINS.length,
        user_count: await env.VL_DB.prepare("SELECT COUNT(*) as count FROM users").first().then(r => r.count || 0)
      }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
    
    // ============================================
    // EXPORT USERS - Export users data
    // ============================================
    if (url.pathname === "/api/users/export" && request.method === "GET") {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      try {
        const { results } = await env.VL_DB.prepare("SELECT username, uuid, limit_gb, used_gb, expiry_days, is_active, created_at FROM users ORDER BY id DESC").all();
        return new Response(JSON.stringify({
          success: true,
          users: results,
          export_date: new Date().toISOString(),
          total: results.length
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // USER STATUS PUBLIC - Public status page data (no auth needed)
    // ============================================
    if (url.pathname.startsWith("/api/status/")) {
      const username = decodeURIComponent(url.pathname.split("/").pop());
      if (!username) {
        return new Response(JSON.stringify({ error: "Username required" }), { status: 400 });
      }
      try {
        const user = await env.VL_DB.prepare("SELECT username, uuid, limit_gb, used_gb, expiry_days, created_at, is_active, port FROM users WHERE username = ?").bind(username).first();
        if (!user) {
          return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
        }
        const now = new Date();
        const created = new Date(user.created_at);
        const expiryDate = new Date(created.getTime() + (user.expiry_days || 30) * 24 * 60 * 60 * 1000);
        const daysLeft = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
        return new Response(JSON.stringify({
          success: true,
          username: user.username,
          is_active: user.is_active === 1,
          limit_gb: user.limit_gb || 0,
          used_gb: user.used_gb || 0,
          expiry_days: user.expiry_days || 30,
          days_left: daysLeft > 0 ? daysLeft : 0,
          created_at: user.created_at,
          expiry_date: expiryDate.toISOString().split('T')[0],
          is_expired: daysLeft <= 0 || user.is_active === 0,
          port: user.port || "443"
        }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500 });
      }
    }
    
    // ============================================
    // FIRE: FIRE UPDATE (panel-only, DB preserved)
    // ============================================
    if (url.pathname === "/api/fire-update" && request.method === "POST") {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      try { await env.VL_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_update', ?)").bind(String(Date.now())).run(); } catch (e) {}
      return new Response(JSON.stringify({ success: true, message: "Panel updated. Database & users untouched." }), { headers: { "Content-Type": "application/json" } });
    }

    // ============================================
    // FIRE: INBOUNDS CRUD
    // ============================================
    if (url.pathname === "/api/inbounds") {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      if (request.method === "GET") {
        const { results } = await env.VL_DB.prepare("SELECT * FROM inbounds ORDER BY id DESC").all();
        let up = 0, down = 0;
        for (const i of (results || [])) { up += i.up || 0; down += i.down || 0; }
        return new Response(JSON.stringify({ inbounds: results || [], total_up: up, total_down: down, count: (results || []).length }), { headers: { "Content-Type": "application/json" } });
      }
      if (request.method === "POST") {
        const b = await request.json();
        const uuid = b.uuid || crypto.randomUUID();
        const r = await env.VL_DB.prepare("INSERT INTO inbounds (remark, enable, protocol, listen, port, network, security, path, host, uuid, total, expiry_time) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)").bind(
          b.remark || "", b.enable === 0 ? 0 : 1, b.protocol || "vless", b.listen || "", parseInt(b.port) || 443,
          b.network || "ws", b.security || "tls", b.path || "/", b.host || "", uuid,
          b.total ? Math.round(parseFloat(b.total) * 1073741824) : 0, parseInt(b.expiry_time) || 0
        ).run();
        return new Response(JSON.stringify({ success: true, id: r.meta.last_row_id, uuid }), { headers: { "Content-Type": "application/json" } });
      }
    }
    if (url.pathname.startsWith("/api/inbounds/")) {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      const id = parseInt(url.pathname.split("/").pop());
      if (request.method === "PUT") {
        const b = await request.json();
        await env.VL_DB.prepare("UPDATE inbounds SET remark=?, enable=?, protocol=?, listen=?, port=?, network=?, security=?, path=?, host=?, uuid=?, total=?, expiry_time=? WHERE id=?").bind(
          b.remark || "", b.enable === 0 ? 0 : 1, b.protocol || "vless", b.listen || "", parseInt(b.port) || 443,
          b.network || "ws", b.security || "tls", b.path || "/", b.host || "", b.uuid || crypto.randomUUID(),
          b.total ? Math.round(parseFloat(b.total) * 1073741824) : 0, parseInt(b.expiry_time) || 0, id
        ).run();
        return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
      }
      if (request.method === "DELETE") {
        await env.VL_DB.prepare("DELETE FROM inbounds WHERE id=?").bind(id).run();
        return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
      }
    }

    // ============================================
    // FIRE: OUTBOUNDS CRUD
    // ============================================
    if (url.pathname === "/api/outbounds") {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      if (request.method === "GET") {
        const { results } = await env.VL_DB.prepare("SELECT * FROM outbounds ORDER BY id ASC").all();
        return new Response(JSON.stringify({ outbounds: results || [] }), { headers: { "Content-Type": "application/json" } });
      }
      if (request.method === "POST") {
        const b = await request.json();
        try {
          const r = await env.VL_DB.prepare("INSERT INTO outbounds (tag, remark, protocol, address, port, auth, enable) VALUES (?,?,?,?,?,?,?)").bind(
            b.tag, b.remark || "", b.protocol || "freedom", b.address || "", parseInt(b.port) || 0, b.auth || "", b.enable === 0 ? 0 : 1
          ).run();
          return new Response(JSON.stringify({ success: true, id: r.meta.last_row_id }), { headers: { "Content-Type": "application/json" } });
        } catch (e) { return new Response(JSON.stringify({ error: "Tag already exists" }), { status: 400 }); }
      }
    }
    if (url.pathname.startsWith("/api/outbounds/")) {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      const id = parseInt(url.pathname.split("/").pop());
      if (request.method === "PUT") {
        const b = await request.json();
        await env.VL_DB.prepare("UPDATE outbounds SET tag=?, remark=?, protocol=?, address=?, port=?, auth=?, enable=? WHERE id=?").bind(
          b.tag, b.remark || "", b.protocol || "freedom", b.address || "", parseInt(b.port) || 0, b.auth || "", b.enable === 0 ? 0 : 1, id
        ).run();
        return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
      }
      if (request.method === "DELETE") {
        await env.VL_DB.prepare("DELETE FROM outbounds WHERE id=?").bind(id).run();
        return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
      }
    }

    // ============================================
    // FIRE: ROUTING RULES CRUD
    // ============================================
    if (url.pathname === "/api/routing") {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      if (request.method === "GET") {
        const { results } = await env.VL_DB.prepare("SELECT * FROM routing_rules ORDER BY id ASC").all();
        return new Response(JSON.stringify({ rules: results || [] }), { headers: { "Content-Type": "application/json" } });
      }
      if (request.method === "POST") {
        const b = await request.json();
        const r = await env.VL_DB.prepare("INSERT INTO routing_rules (enable, remark, inbound_tag, outbound_tag, domain, ip, port) VALUES (?,?,?,?,?,?,?)").bind(
          b.enable === 0 ? 0 : 1, b.remark || "", b.inbound_tag || "", b.outbound_tag || "direct", b.domain || "", b.ip || "", b.port || ""
        ).run();
        return new Response(JSON.stringify({ success: true, id: r.meta.last_row_id }), { headers: { "Content-Type": "application/json" } });
      }
    }
    if (url.pathname.startsWith("/api/routing/")) {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      const id = parseInt(url.pathname.split("/").pop());
      if (request.method === "PUT") {
        const b = await request.json();
        await env.VL_DB.prepare("UPDATE routing_rules SET enable=?, remark=?, inbound_tag=?, outbound_tag=?, domain=?, ip=?, port=? WHERE id=?").bind(
          b.enable === 0 ? 0 : 1, b.remark || "", b.inbound_tag || "", b.outbound_tag || "direct", b.domain || "", b.ip || "", b.port || "", id
        ).run();
        return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
      }
      if (request.method === "DELETE") {
        await env.VL_DB.prepare("DELETE FROM routing_rules WHERE id=?").bind(id).run();
        return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
      }
    }

    // ============================================
    // FIRE: NODES CRUD
    // ============================================
    if (url.pathname === "/api/nodes") {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      if (request.method === "GET") {
        const { results } = await env.VL_DB.prepare("SELECT * FROM nodes ORDER BY id ASC").all();
        return new Response(JSON.stringify({ nodes: results || [] }), { headers: { "Content-Type": "application/json" } });
      }
      if (request.method === "POST") {
        const b = await request.json();
        const r = await env.VL_DB.prepare("INSERT INTO nodes (name, address, port, api_port, remark, type, enable) VALUES (?,?,?,?,?,?,?)").bind(
          b.name || "", b.address || "", parseInt(b.port) || 0, parseInt(b.api_port) || 62789, b.remark || "", b.type || "xray", b.enable === 0 ? 0 : 1
        ).run();
        return new Response(JSON.stringify({ success: true, id: r.meta.last_row_id }), { headers: { "Content-Type": "application/json" } });
      }
    }
    if (url.pathname.startsWith("/api/nodes/")) {
      if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
      const id = parseInt(url.pathname.split("/").pop());
      if (request.method === "PUT") {
        const b = await request.json();
        await env.VL_DB.prepare("UPDATE nodes SET name=?, address=?, port=?, api_port=?, remark=?, type=?, enable=? WHERE id=?").bind(
          b.name || "", b.address || "", parseInt(b.port) || 0, parseInt(b.api_port) || 62789, b.remark || "", b.type || "xray", b.enable === 0 ? 0 : 1, id
        ).run();
        return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
      }
      if (request.method === "DELETE") {
        await env.VL_DB.prepare("DELETE FROM nodes WHERE id=?").bind(id).run();
        return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
      }
    }

    return new Response(JSON.stringify({ error: "Not Found" }), { status: 404 });
  }
};

var SubscriptionService = {
  async generateJson(user, host, env) {
    let ips = [host];
    if (user.ips) {
      const parsedIps = user.ips.split("\n").map((ip) => ip.trim()).filter((ip) => ip.length > 0);
      if (parsedIps.length > 0) ips = parsedIps;
    }
    const ports = String(user.port || "443").split(",").map((p) => p.trim()).filter((p) => p.length > 0);
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
    const leftGB = Math.max(0, totalGB - usedGB);
    const expiryDateStr = expiryDate.toISOString().split('T')[0].replace(/-/g, '/');
    const configName = user.config_name || user.username;
    const usedFormatted = usedGB >= 1 ? usedGB.toFixed(1) + "GB" : (usedGB * 1024).toFixed(0) + "MB";
    const totalFormatted = totalGB >= 1 ? totalGB + "GB" : "Unlimited";
    
    // فقط دو کانفیگ اطلاعاتی برای اولین IP و پورت
    const firstIp = ips[0] || host;
    const firstPort = ports[0] || "443";
    const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(firstPort);
    const tlsVal = isTlsPort ? "tls" : "none";
    
    // کانفیگ اطلاعات 1: تاریخ انقضا
    const remark1 = "⏳ " + user.username.toUpperCase() + " | 📅 Exp: " + expiryDateStr + " | 🔥 " + daysLeft + " Days Left";
    const configObj1 = this.buildConfig(user, firstIp, firstPort, tlsVal, host, fp, fragLen, fragInt, remark1);
    configArray.push(configObj1);
    
    // کانفیگ اطلاعات 2: حجم مصرفی
    const remark2 = "📊 " + user.username.toUpperCase() + " | 💾 " + totalFormatted + " Total | ⚡ " + usedFormatted + " Used";
    const configObj2 = this.buildConfig(user, firstIp, firstPort, tlsVal, host, fp, fragLen, fragInt, remark2);
    configArray.push(configObj2);
    
    // کانفیگ‌های باقی‌مده برای تمام آیپی‌ها و پورت‌ها با اسم کاربر
    ips.forEach((ip) => {
      ports.forEach((portStr) => {
        const isTlsPortLoop = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
        const tlsValLoop = isTlsPortLoop ? "tls" : "none";
        const remark3 = configName;
        const configObj3 = this.buildConfig(user, ip, portStr, tlsValLoop, host, fp, fragLen, fragInt, remark3);
        configArray.push(configObj3);
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
            ["vnext"]: [{
              address: ip,
              port: parseInt(portStr),
              users: [{ id: user.uuid, encryption: "none" }]
            }]
          },
          ["streamSettings"]: {
            network: "ws",
            ["wsSettings"]: { host, path: "/" },
            security: tlsVal,
            sockopt: { ["dialerProxy"]: "fragment" }
          },
          tag: "proxy"
        },
        {
          protocol: "freedom",
          settings: {
            fragment: { packets: "tlshello", length: fragLen, interval: fragInt }
          },
          ["streamSettings"]: {
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
      configObj.outbounds[0]["streamSettings"]["tlsSettings"] = {
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
      const parsedIps = user.ips.split("\n").map((ip) => ip.trim()).filter((ip) => ip.length > 0);
      if (parsedIps.length > 0) ips = parsedIps;
    }
    const ports = String(user.port || "443").split(",").map((p) => p.trim()).filter((p) => p.length > 0);
    const fp = user.fingerprint || "chrome";
    
    const now = new Date();
    const created = new Date(user.created_at);
    const expiryDays = user.expiry_days || 30;
    const expiryDate = new Date(created.getTime() + expiryDays * 24 * 60 * 60 * 1000);
    const daysLeft = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
    const totalGB = user.limit_gb || 0;
    const usedGB = user.used_gb || 0;
    const leftGB = Math.max(0, totalGB - usedGB);
    const expiryDateStr = expiryDate.toISOString().split('T')[0].replace(/-/g, '/');
    const configName = user.config_name || user.username;
    const usedFormatted = usedGB >= 1 ? usedGB.toFixed(1) + "GB" : (usedGB * 1024).toFixed(0) + "MB";
    const totalFormatted = totalGB >= 1 ? totalGB + "GB" : "Unlimited";
    
    const links = [];
    
    // فقط دو کانفیگ اطلاعاتی برای اولین IP و پورت
    const firstIp = ips[0] || host;
    const firstPort = ports[0] || "443";
    const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(firstPort);
    const tlsVal = isTlsPort ? "tls" : "none";
    
    // کانفیگ اطلاعات 1: تاریخ انقضا
    const remark1 = "⏳ " + user.username.toUpperCase() + " | 📅 Exp: " + expiryDateStr + " | 🔥 " + daysLeft + " Days Left";
    links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@" + firstIp + ":" + firstPort + "?path=%2F&security=" + tlsVal + "&encryption=none&insecure=0&host=" + host + "&fp=" + fp + "&type=ws&allowInsecure=0&sni=" + host + "#" + encodeURIComponent(remark1));
    
    // کانفیگ اطلاعات 2: حجم مصرفی
    const remark2 = "📊 " + user.username.toUpperCase() + " | 💾 " + totalFormatted + " Total | ⚡ " + usedFormatted + " Used";
    links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@" + firstIp + ":" + firstPort + "?path=%2F&security=" + tlsVal + "&encryption=none&insecure=0&host=" + host + "&fp=" + fp + "&type=ws&allowInsecure=0&sni=" + host + "#" + encodeURIComponent(remark2));
    
    // کانفیگ‌های باقی‌مده برای تمام آیپی‌ها و پورت‌ها با اسم کاربر
    ips.forEach((ip) => {
      ports.forEach((portStr) => {
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

export { voidlatency_core_default as default };
