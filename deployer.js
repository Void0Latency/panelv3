// deployer.js - VoidLatency / Fire Panel v3 Deployer
// Pulls voidlatency-core.js + schema.sql from GitHub, creates D1, deploys the worker,
// runs the schema, enables the workers.dev subdomain, and SETS the admin password
// so the password shown to the user actually works.
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        if (request.method === 'GET' && url.pathname === '/') {
            return new Response(getHtmlContent(), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' },
            });
        }

        if (request.method === 'POST' && url.pathname === '/api/deploy') {
            try {
                const { token } = await request.json();
                if (!token) throw new Error("❌ لطفاً توکن کلودفلر خود را وارد کنید.");

                const headers = {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json"
                };

                // 1. Account ID
                const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", { headers });
                const accData = await accRes.json();
                if (!accData.success || accData.result.length === 0) {
                    throw new Error("❌ توکن نامعتبر. اکانت کلودفلر یافت نشد.");
                }
                const accountId = accData.result[0].id;

                // 2. Subdomain
                let devSub = null;
                const subRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/subdomain`, { headers });
                const subData = await subRes.json();
                if (subData.success && subData.result.subdomain) {
                    devSub = subData.result.subdomain;
                } else {
                    const newSub = `void-${Math.random().toString(36).substring(2, 8)}`;
                    const createSub = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/subdomain`, {
                        method: 'PUT',
                        headers,
                        body: JSON.stringify({ subdomain: newSub })
                    });
                    const createSubData = await createSub.json();
                    if (!createSubData.success) throw new Error("❌ ایجاد ساب‌دامن ناموفق.");
                    devSub = newSub;
                }

                // 3. D1 Database
                const uniqueSuffix = Math.random().toString(36).substring(2, 8);
                const workerName = `fire-panel-${uniqueSuffix}`;
                const dbName = `fire-db-${uniqueSuffix}`;

                const dbRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database`, {
                    method: 'POST',
                    headers,
                    body: JSON.stringify({ name: dbName })
                });
                const dbData = await dbRes.json();
                if (!dbData.success) {
                    const cfError = dbData.errors && dbData.errors.length > 0 ? dbData.errors[0].message : "Unknown";
                    throw new Error(`❌ ایجاد دیتابیس ناموفق: ${cfError}`);
                }
                const dbUuid = dbData.result.uuid;
                await new Promise(resolve => setTimeout(resolve, 1000));

                // 4. Fetch code + schema from GitHub (panelv3) - single-file worker
                const baseUrl = "https://raw.githubusercontent.com/Void0Latency/panelv3/main/";
                const coreRes = await fetch(baseUrl + "voidlatency-core.js?t=" + Date.now());
                if (!coreRes.ok) throw new Error("❌ دریافت کد پنل از GitHub ناموفق (" + coreRes.status + ").");
                const coreCode = await coreRes.text();
                const schemaRes = await fetch(baseUrl + "schema.sql?t=" + Date.now());
                const schemaCode = schemaRes.ok ? await schemaRes.text() : "";

                // 5. Deploy Worker
                const metadata = {
                    main_module: "voidlatency-core.js",
                    compatibility_date: "2024-12-18",
                    bindings: [{ type: "d1", name: "VL_DB", id: dbUuid }]
                };
                const formData = new FormData();
                formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
                formData.append("voidlatency-core.js", new Blob([coreCode], { type: "application/javascript+module" }), "voidlatency-core.js");

                const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}`, {
                    method: 'PUT',
                    headers: { "Authorization": `Bearer ${token}` },
                    body: formData
                });
                const deployData = await deployRes.json();
                if (!deployData.success) {
                    const cfError = deployData.errors && deployData.errors.length > 0 ? deployData.errors[0].message : "Unknown";
                    throw new Error(`❌ دیپلوی ناموفق: ${cfError}`);
                }

                // 6. Run migration (schema.sql)
                const sqlRes = await fetch(
                    `https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database/${dbUuid}/query`,
                    {
                        method: 'POST',
                        headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
                        body: JSON.stringify({ sql: schemaCode })
                    }
                );
                if (!sqlRes.ok) console.warn("Migration warning:", await sqlRes.text());

                // 7. Enable subdomain route
                const routeRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}/subdomain`, {
                    method: 'POST',
                    headers,
                    body: JSON.stringify({ enabled: true })
                });
                if (!routeRes.ok) throw new Error("❌ فعال‌سازی ساب‌دامن ناموفق.");

                // 8. Generate admin credentials and ACTUALLY set them on the panel
                const adminUsername = "admin";
                const adminPassword = generatePassword();
                const finalUrl = `https://${workerName}.${devSub}.workers.dev`;

                // The new worker takes a few seconds to go live; retry.
                // This panel uses /api/setup-password (panel password) + /api/admin/create.
                let setupOk = false;
                for (let i = 0; i < 10; i++) {
                    await new Promise(r => setTimeout(r, 2500));
                    try {
                        // 1) set the panel password (used as login fallback)
                        const su = await fetch(finalUrl + "/api/setup-password", {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ password: adminPassword })
                        });
                        const sd = await su.json().catch(() => ({}));
                        if (su.ok && sd.success) { setupOk = true; }
                        else if (sd.error && /already/i.test(sd.error)) { setupOk = true; }
                        // 2) also create a named admin user "admin" (best-effort)
                        if (setupOk) {
                            try {
                                await fetch(finalUrl + "/api/admin/create", {
                                    method: "POST",
                                    headers: { "Content-Type": "application/json" },
                                    body: JSON.stringify({ username: adminUsername, password: adminPassword })
                                });
                            } catch (e) {}
                            break;
                        }
                    } catch (e) { /* not live yet, retry */ }
                }

                return new Response(JSON.stringify({
                    success: true,
                    url: finalUrl,
                    username: adminUsername,
                    password: adminPassword,
                    credentials_set: setupOk,
                    workerName,
                    dbName
                }), { headers: { 'Content-Type': 'application/json' } });

            } catch (error) {
                return new Response(JSON.stringify({ success: false, error: error.message }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }

        return new Response("Not Found", { status: 404 });
    }
};

function generatePassword(length = 12) {
    // Avoid ambiguous/url-unsafe chars so the shown password is easy to copy & type
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
    let password = '';
    const arr = crypto.getRandomValues(new Uint8Array(length));
    for (let i = 0; i < length; i++) password += chars.charAt(arr[i] % chars.length);
    return password;
}

function getHtmlContent() {
    return `
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fire Panel Deployer</title>
    <script src="https://cdn.tailwindcss.com"><\/script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        * { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
        body { background: #0d1b2a; direction: ltr; }
        .glass { background: rgba(255,255,255,0.03); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.06); }
        .glow { box-shadow: 0 0 60px rgba(16, 185, 129, 0.15); }
        .gradient-text { background: linear-gradient(135deg, #34d399, #06b6d4); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .btn-green { background: linear-gradient(135deg, #10b981, #059669); }
        .btn-green:hover { background: linear-gradient(135deg, #059669, #047857); transform: scale(1.02); }
        .animate-float { animation: float 6s ease-in-out infinite; }
        @keyframes float { 0%, 100% { transform: translateY(0px); } 50% { transform: translateY(-10px); } }
        .dark-blue-card { background: rgba(13, 27, 42, 0.8); border: 1px solid rgba(255,255,255,0.06); }
        .dark-blue-input { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.08); }
        .dark-blue-input:focus { border-color: #10b981; box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.15); }
        .badge-fire { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.2); }
    </style>
</head>
<body class="min-h-screen flex flex-col justify-center items-center p-4 bg-[#0d1b2a]">

    <div class="max-w-md w-full glass rounded-3xl p-8 glow dark-blue-card relative z-10">
        <div class="text-center mb-8">
            <div class="animate-float inline-block p-4 rounded-2xl bg-[#1a2744] border border-emerald-500/20 mb-4">
                <svg class="w-14 h-14 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                </svg>
            </div>
            <h1 class="text-4xl font-black gradient-text mb-1">Fire Panel</h1>
            <p class="text-zinc-400 text-sm font-medium">Deploy your panel in seconds</p>
            <span class="inline-block mt-2 px-3 py-1 text-xs font-semibold badge-fire rounded-full">v3.0.0</span>
        </div>

        <a href="https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_subdomain%22%2C%22type%22%3A%22edit%22%7D%5D&accountId=*&zoneId=all&name=Fire-Panel-Deployer"
           target="_blank" class="block text-center w-full py-3.5 bg-[#1a2744] hover:bg-[#243b5a] text-emerald-400 font-semibold rounded-xl transition border border-emerald-500/20 mb-4 text-sm">
            🔑 دریافت توکن کلودفلر
        </a>

        <input type="password" id="apiToken" placeholder="توکن کلودفلر خود را وارد کنید..."
               class="w-full px-4 py-3.5 rounded-xl text-white placeholder-zinc-500 text-sm outline-none transition dark-blue-input mb-4"
               autocomplete="off" spellcheck="false">

        <button id="deployBtn" onclick="startDeploy()"
                class="w-full py-3.5 btn-green text-white font-bold rounded-xl transition text-sm shadow-lg shadow-emerald-500/25">
            🚀 نصب پنل
        </button>

        <div id="status-container" class="mt-4 hidden">
            <div id="status-text" class="text-sm text-zinc-400 text-center mb-2">در حال نصب...</div>
            <div class="w-full bg-zinc-800 rounded-full h-1 overflow-hidden">
                <div id="progressBar" class="bg-emerald-500 h-1 rounded-full transition-all duration-300" style="width: 0%"></div>
            </div>
        </div>

        <div id="error-box" class="mt-4 p-3 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl text-sm text-center hidden"></div>

        <div id="success-box" class="mt-4 hidden">
            <div class="bg-emerald-500/10 border border-emerald-500/20 rounded-xl p-4 text-center">
                <p class="text-emerald-400 font-bold text-sm mb-2">✅ نصب با موفقیت انجام شد!</p>
                <p class="text-zinc-400 text-xs mb-1">🔗 آدرس پنل:</p>
                <code id="panel-url" class="block bg-[#0d1b2a] p-2 rounded text-emerald-400 text-xs font-mono break-all mb-2">-</code>
                <p class="text-zinc-400 text-xs mb-1">👤 نام کاربری:</p>
                <code id="admin-username" class="block bg-[#0d1b2a] p-2 rounded text-emerald-400 text-xs font-mono break-all mb-2">admin</code>
                <p class="text-zinc-400 text-xs mb-1">🔑 رمز عبور ادمین:</p>
                <code id="admin-password" class="block bg-[#0d1b2a] p-2 rounded text-emerald-400 text-xs font-mono break-all mb-3">-</code>
                <div id="cred-note" class="hidden text-amber-400 text-xs mb-3"></div>
                <div class="flex flex-col gap-2">
                    <a href="#" id="panel-link" target="_blank" class="w-full py-2.5 btn-green text-white font-bold rounded-xl transition text-sm">🌐 ورود به پنل</a>
                    <button onclick="copyText('panel-url')" class="w-full py-2 bg-[#1a2744] hover:bg-[#243b5a] text-zinc-300 font-medium rounded-xl transition text-sm border border-zinc-700/50">📋 کپی آدرس</button>
                    <button onclick="copyText('admin-password')" class="w-full py-2 bg-[#1a2744] hover:bg-[#243b5a] text-zinc-300 font-medium rounded-xl transition text-sm border border-zinc-700/50">🔑 کپی رمز</button>
                </div>
                <div class="mt-3 text-xs text-zinc-500">
                    <span class="badge-fire px-2 py-0.5 rounded">Fire Panel v3.0.0</span>
                </div>
            </div>
        </div>
    </div>

    <div class="mt-6 flex gap-4 text-xs text-zinc-500">
        <a href="https://github.com/Void0Latency/panelv3" target="_blank" class="hover:text-zinc-300 transition">GitHub</a>
        <span>•</span>
        <a href="https://t.me/VoidLatency" target="_blank" class="hover:text-zinc-300 transition">Telegram</a>
        <span>•</span>
        <span>@VoidLatency</span>
        <span>•</span>
        <span class="text-emerald-400">v3.0.0</span>
    </div>

    <script>
        function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
        function copyText(elementId) {
            const el = document.getElementById(elementId);
            const text = el.innerText;
            navigator.clipboard.writeText(text).then(() => {
                const btn = event.target;
                const original = btn.innerText;
                btn.innerText = '✅ کپی شد!';
                setTimeout(() => btn.innerText = original, 2000);
            }).catch(() => { alert('📋 کپی دستی: ' + text); });
        }
        async function startDeploy() {
            const token = document.getElementById('apiToken').value.trim();
            const btn = document.getElementById('deployBtn');
            const statusContainer = document.getElementById('status-container');
            const statusText = document.getElementById('status-text');
            const progressBar = document.getElementById('progressBar');
            const errorBox = document.getElementById('error-box');
            const successBox = document.getElementById('success-box');
            successBox.style.display = 'none';
            errorBox.style.display = 'none';
            if(!token) { errorBox.style.display = 'block'; errorBox.innerText = '❌ لطفاً توکن کلودفلر خود را وارد کنید.'; return; }
            btn.disabled = true; btn.innerText = '⏳ در حال نصب...'; statusContainer.style.display = 'block';
            const steps = [
                { text: '🔍 اعتبارسنجی توکن...', pct: 10 },
                { text: '🔗 اتصال به کلودفلر...', pct: 22 },
                { text: '📦 ایجاد دیتابیس...', pct: 38 },
                { text: '📤 دریافت کد از GitHub...', pct: 52 },
                { text: '🌐 دیپلوی Worker...', pct: 66 },
                { text: '⚡ اجرای Migration...', pct: 78 },
                { text: '🔐 تنظیم رمز ادمین...', pct: 90 }
            ];
            for (const step of steps) { statusText.innerText = step.text; progressBar.style.width = step.pct + '%'; await sleep(400); }
            try {
                const response = await fetch('/api/deploy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
                const result = await response.json();
                if (result.success) {
                    progressBar.style.width = '100%';
                    statusText.innerText = '✅ نصب کامل! 100%';
                    await sleep(400);
                    statusContainer.style.display = 'none';
                    document.getElementById('panel-url').innerText = result.url;
                    document.getElementById('admin-username').innerText = result.username || 'admin';
                    document.getElementById('admin-password').innerText = result.password;
                    document.getElementById('panel-link').href = result.url;
                    const note = document.getElementById('cred-note');
                    if (!result.credentials_set) {
                        note.style.display = 'block';
                        note.innerText = '⚠ رمز به‌صورت خودکار تنظیم نشد. در اولین ورود، صفحه نصب باز می‌شود؛ همین نام کاربری و رمز را وارد کنید.';
                    }
                    successBox.style.display = 'block';
                    successBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
                } else { throw new Error(result.error); }
            } catch(e) {
                statusContainer.style.display = 'none';
                errorBox.style.display = 'block';
                errorBox.innerText = '❌ ' + e.message;
            } finally { btn.disabled = false; btn.innerText = '🚀 نصب پنل'; }
        }
        document.getElementById('apiToken').addEventListener('keypress', function(e) { if (e.key === 'Enter') startDeploy(); });
    <\/script>
</body>
</html>
    `;
}
