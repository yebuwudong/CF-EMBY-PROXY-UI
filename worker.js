// EMBY-PROXY-PRO V13.9 (ES Modules Edition)
// 适配 ES Modules 标准格式
// 强制北京时间 UI + JWT 鉴权 + KV 缓存优化
// 恢复到原先节点KV单独储存的方式

// ============================================================================
// 1. CONFIG MODULE
// ============================================================================
const Config = {
    Regex: {
        Static: /\.(?:jpg|jpeg|gif|png|svg|ico|webp|js|css|woff2?|ttf|otf|map|webmanifest|json)$/i,
        Streaming: /\.(?:mp4|m4v|m4s|m4a|ogv|webm|mkv|mov|avi|wmv|flv|ts|m3u8|mpd)$/i
    },
    Defaults: {
        JwtExpiry: 60 * 60 * 24 * 7,
        LoginLockDuration: 900,
        MaxLoginAttempts: 5
    }
};

// ============================================================================
// 2. AUTH MODULE
// ============================================================================
const Auth = {
    async handleLogin(request, env) {
        const ip = request.headers.get("cf-connecting-ip") || "unknown";
        try {
            const formData = await request.formData();
            const password = (formData.get("password") || "").trim();

            // 优先使用 JWT_SECRET，如果没有则回退到 ADMIN_PASS
            const secret = env.JWT_SECRET || env.ADMIN_PASS; 

            if (password === env.ADMIN_PASS) {
                if(env.ENI_KV) await env.ENI_KV.delete(`fail:${ip}`);
                const jwt = await this.generateJwt(secret, Config.Defaults.JwtExpiry);
                return new Response("Login Success", {
                    status: 302,
                    headers: {
                        "Location": "/admin", 
                        "Set-Cookie": `auth_token=${jwt}; Path=/; Max-Age=${Config.Defaults.JwtExpiry}; HttpOnly; Secure; SameSite=Strict`
                    }
                });
            }

            let count = 0;
            if(env.ENI_KV) {
                count = await env.ENI_KV.get(`fail:${ip}`);
                count = count ? parseInt(count) + 1 : 1;
                await env.ENI_KV.put(`fail:${ip}`, count, { expirationTtl: Config.Defaults.LoginLockDuration });
            }

            if (count >= Config.Defaults.MaxLoginAttempts) return UI.renderLockedPage(ip, Config.Defaults.LoginLockDuration);
            return UI.renderLoginPage(`密码错误 (剩余次数: ${Config.Defaults.MaxLoginAttempts - count})`);
        } catch (e) { return UI.renderLoginPage("请求无效"); }
    },

    async verifyRequest(request, env) {
        const cookie = request.headers.get("Cookie");
        const token = this.parseCookie(cookie, "auth_token");
        if (!token) return false;
        const secret = env.JWT_SECRET || env.ADMIN_PASS;
        return await this.verifyJwt(token, secret);
    },

    async generateJwt(secret, expiresIn) {
        const header = { alg: "HS256", typ: "JWT" };
        const payload = { sub: "admin", exp: Math.floor(Date.now() / 1000) + expiresIn };
        const encHeader = this.base64UrlEncode(JSON.stringify(header));
        const encPayload = this.base64UrlEncode(JSON.stringify(payload));
        const signature = await this.sign(secret, `${encHeader}.${encPayload}`);
        return `${encHeader}.${encPayload}.${signature}`;
    },

    async verifyJwt(token, secret) {
        if (!token) return false;
        const [encHeader, encPayload, signature] = token.split('.');
        if (!encHeader || !encPayload || !signature) return false;
        const expectedSignature = await this.sign(secret, `${encHeader}.${encPayload}`);
        if (signature !== expectedSignature) return false;
        try {
            const payload = JSON.parse(this.base64UrlDecode(encPayload));
            return payload.exp > Math.floor(Date.now() / 1000);
        } catch (e) { return false; }
    },

    base64UrlEncode(str) { return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
    base64UrlDecode(str) { 
        str = str.replace(/-/g, '+').replace(/_/g, '/'); 
        while (str.length % 4) str += '='; 
        return atob(str); 
    },
    async sign(secret, data) {
        const enc = new TextEncoder();
        const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const signature = await crypto.subtle.sign("HMAC", key, enc.encode(data));
        return this.base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
    },
    parseCookie(cookieString, key) {
        if (!cookieString) return null;
        const match = cookieString.match(new RegExp('(^| )' + key + '=([^;]+)'));
        return match ? match[2] : null;
    }
};

// ============================================================================
// 3. DATABASE MODULE
// ============================================================================
const Database = {
    PREFIX: "node:",

    async getNode(nodeName, env, ctx) {
        if (!env.ENI_KV) return null; // 防止未绑定 KV 报错

        const cache = caches.default;
        const cacheUrl = new URL(`https://internal-config-cache/node/${nodeName}`);
        
        let response = await cache.match(cacheUrl);
        if (response) return await response.json();

        try {
            const nodeData = await env.ENI_KV.get(`${this.PREFIX}${nodeName}`, { type: "json" });
            if (nodeData) {
                const jsonStr = JSON.stringify(nodeData);
                const cacheResp = new Response(jsonStr, { 
                    headers: { "Cache-Control": "public, max-age=60, stale-while-revalidate=600" } 
                });
                // ES Modules 中 ctx 直接包含 waitUntil
                ctx.waitUntil(cache.put(cacheUrl, cacheResp));
                return nodeData;
            }
        } catch (err) { console.error(`KV Get Error for ${nodeName}:`, err); }
        return null;
    },

    async handleApi(request, env) {
        if (!env.ENI_KV) return new Response(JSON.stringify({ error: "KV Namespace Not Bound (ENI_KV)" }), { status: 500 });

        const data = await request.json();
        const cache = caches.default;

        switch (data.action) {
            case "save": 
            case "import":
                const nodesToSave = data.action === "save" ? [data] : data.nodes;
                for (const n of nodesToSave) {
                    if (n.name && n.target) {
                        const val = { secret: n.secret || n.path || "", target: n.target };
                        await env.ENI_KV.put(`${this.PREFIX}${n.name}`, JSON.stringify(val));
                        await cache.delete(`https://internal-config-cache/node/${n.name}`);
                    }
                }
                return new Response(JSON.stringify({ success: true }));

            case "delete":
                if (data.name) {
                    await env.ENI_KV.delete(`${this.PREFIX}${data.name}`);
                    await cache.delete(`https://internal-config-cache/node/${data.name}`);
                }
                return new Response(JSON.stringify({ success: true }));

            case "list":
                const list = await env.ENI_KV.list({ prefix: this.PREFIX });
                const nodesList = await Promise.all(list.keys.map(async (key) => {
                    try {
                        const nodeVal = await env.ENI_KV.get(key.name, { type: "json" });
                        return { name: key.name.replace(this.PREFIX, ""), ...nodeVal };
                    } catch(e) { return null; }
                }));
                const validNodes = nodesList.filter(n => n !== null);
                return new Response(JSON.stringify({ nodes: validNodes }));
                
            default: return new Response("Invalid Action", { status: 400 });
        }
    }
};

// ============================================================================
// 4. PROXY MODULE
// ============================================================================
const Proxy = {
    async handle(request, node, path, name, key) {
        const targetBase = new URL(node.target);
        const finalUrl = new URL(path, targetBase);
        finalUrl.search = new URL(request.url).search;

        const isWS = request.headers.get("Upgrade") === "websocket";
        const isStreaming = Config.Regex.Streaming.test(path);
        const isStatic = Config.Regex.Static.test(path);

        if (request.method === "OPTIONS") return this.renderCors();

        if (isWS) return this.handleWebSocket(finalUrl, request);

        const newHeaders = new Headers(request.headers);
        newHeaders.set("Host", targetBase.host);
        // ES Modules 模式下，cf-connecting-ip 依然可用
        newHeaders.set("X-Real-IP", request.headers.get("cf-connecting-ip"));
        newHeaders.set("X-Forwarded-For", request.headers.get("cf-connecting-ip"));
        
        ["cf-connecting-ip", "cf-ipcountry", "cf-ray", "cf-visitor"].forEach(h => newHeaders.delete(h));

        if (isStreaming) {
            newHeaders.delete("Referer"); 
        }

        let cfOptions = { cacheTtl: 0 };
        if (isStreaming) {
            cfOptions = { cacheEverything: false, cacheTtl: 0 }; 
        } else if (isStatic) {
            cfOptions = { cacheEverything: true, cacheTtlByStatus: { "200-299": 86400 } };
        }

        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 30000); 
            
            const response = await fetch(new Request(finalUrl, {
                method: request.method,
                headers: newHeaders,
                body: request.body,
                redirect: "manual",
                signal: controller.signal
            }), { cf: cfOptions });
            
            clearTimeout(timeout);

            const modifiedHeaders = new Headers(response.headers);
            modifiedHeaders.set("Access-Control-Allow-Origin", "*");
            if (isStreaming) modifiedHeaders.set("Cache-Control", "no-store");

            this.rewriteLocation(modifiedHeaders, response.status, name, key, targetBase);

            return new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers: modifiedHeaders
            });

        } catch (err) {
            return UI.renderSmartError(request, err.message, name);
        }
    },

    handleWebSocket(url, request) {
        try {
            const protocols = request.headers.get("Sec-WebSocket-Protocol") || "emby-websocket";
            const wsTarget = new URL(url);
            wsTarget.protocol = wsTarget.protocol === 'https:' ? 'wss:' : 'ws:';
            
            // WebSocketPair 是全局对象
            const [client, server] = Object.values(new WebSocketPair());
            const ws = new WebSocket(wsTarget.toString(), protocols);

            server.accept();

            let isClosed = false;
            const closeBoth = (code, reason) => {
                if (isClosed) return;
                isClosed = true;
                try { server.close(code || 1000, reason || "Normal Closure"); } catch(e){}
                try { ws.close(code || 1000, reason || "Normal Closure"); } catch(e){}
            };

            ws.addEventListener('message', e => {
                try { server.send(e.data); } catch(error) { closeBoth(1001, "Client Send Error"); }
            });
            server.addEventListener('message', e => {
                try { ws.send(e.data); } catch(error) { closeBoth(1001, "Server Send Error"); }
            });

            ws.addEventListener('close', e => closeBoth(e.code, e.reason));
            server.addEventListener('close', e => closeBoth(e.code, e.reason));
            ws.addEventListener('error', () => closeBoth(1006, "Upstream Error"));
            server.addEventListener('error', () => closeBoth(1006, "Client Error"));

            return new Response(null, { 
                status: 101, 
                webSocket: client,
                headers: { "Sec-WebSocket-Protocol": protocols }
            });
        } catch (e) {
            return new Response("WS Error: " + e.message, { status: 502 });
        }
    },

    rewriteLocation(headers, status, name, key, targetBase) {
        const location = headers.get("Location");
        if (!location || status < 300 || status >= 400) return;
        const prefix = key ? `/${name}/${key}` : `/${name}`;
        if (location.startsWith("/")) { headers.set("Location", `${prefix}${location}`); return; }
        try {
            const locUrl = new URL(location);
            if (locUrl.host === targetBase.host) { headers.set("Location", `${prefix}${locUrl.pathname}${locUrl.search}`); }
        } catch (e) { }
    },

    renderCors() {
        return new Response(null, {
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": "*"
            }
        });
    }
};

// ============================================================================
// 5. UI MODULE (CN Edition + Beijing Timezone Forced)
// ============================================================================
const UI = {
    commonHead: `
    <script>
        (function(){
            try {
                // 强制北京时间 (Asia/Shanghai) 判断昼夜
                const beijingHour = parseInt(new Intl.DateTimeFormat('en-US', {
                    timeZone: 'Asia/Shanghai',
                    hour: 'numeric',
                    hour12: false
                }).format(new Date()));
                if(beijingHour >= 6 && beijingHour < 18) {
                    document.documentElement.classList.add('light');
                }
            } catch(e){}
        })();
    </script>
    <style>
        :root {
            --bg: #111; --panel: #222; --border: #333; --text: #eee; --text-sub: #888;
            --input-bg: #333; --btn-bg: #333; --btn-hover: #444;
            --accent: #22c55e; --accent-hover: #16a34a; --error: #ef4444; --link-bg: #1a1a1a;
        }
        html.light {
            --bg: #f5f5f5; --panel: #ffffff; --border: #e0e0e0; --text: #333; --text-sub: #666;
            --input-bg: #fff; --btn-bg: #f0f0f0; --btn-hover: #e5e5e5;
            --accent: #16a34a; --accent-hover: #15803d; --link-bg: #f3f4f6;
        }
        body { background:var(--bg); color:var(--text); font-family:-apple-system, "Microsoft YaHei", sans-serif; transition:background 0.3s, color 0.3s; }
        input, button, .panel, .link, table, th, td { transition: background 0.3s, border-color 0.3s, color 0.3s; }
    </style>`,

    escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') return unsafe;
        return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    },

    renderSmartError(request, msg, nodeName) {
        const accept = request.headers.get("Accept") || "";
        const safeNodeName = this.escapeHtml(nodeName);
        const safeMsg = this.escapeHtml(msg);
        if (accept.includes("text/html")) {
            return new Response(`<html><head><meta charset="UTF-8">${this.commonHead}</head><body style="display:flex;justify-content:center;align-items:center;height:100vh;margin:0"><div style="text-align:center;background:var(--panel);padding:40px;border-radius:8px;border:1px solid var(--border);box-shadow:0 4px 12px rgba(0,0,0,0.1)"><h2>连接失败</h2><p>节点: <strong>${safeNodeName}</strong></p><p style="color:var(--error);font-family:monospace;margin:20px 0;background:var(--bg);padding:10px;border:1px solid var(--border)">${safeMsg}</p><button onclick="location.reload()" style="padding:10px 24px;cursor:pointer;background:var(--accent);color:#fff;border:none;border-radius:4px;font-weight:bold">重试</button></div></body></html>`, { headers: { "Content-Type": "text/html;charset=utf-8" }, status: 502 });
        }
        return new Response(JSON.stringify({ error: msg, node: nodeName }), { status: 502, headers: { "Content-Type": "application/json" } });
    },

    renderLoginPage(error = "") {
        const safeError = this.escapeHtml(error);
        return new Response(`
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>管理员登录</title>
            ${this.commonHead}
            <style>
                body { display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }
                .box { background:var(--panel); padding:30px; border-radius:8px; width:300px; border:1px solid var(--border); box-shadow:0 4px 12px rgba(0,0,0,0.1); }
                input { width:100%; padding:10px; margin-bottom:15px; background:var(--input-bg); border:1px solid var(--border); color:var(--text); box-sizing:border-box; border-radius:4px; }
                button { width:100%; padding:10px; background:var(--accent); border:none; color:#fff; font-weight:bold; cursor:pointer; border-radius:4px; }
                button:hover { background:var(--accent-hover); }
                .error { color:var(--error); font-size:12px; margin-bottom:10px; text-align:center; }
                h3 { color:var(--text); margin-top:0; text-align:center; }
            </style>
        </head>
        <body>
            <div class="box">
                <h3>Emby 代理管理</h3>
                <form method="POST">
                    <input type="password" name="password" placeholder="请输入管理员密码" required />
                    ${safeError ? `<div class="error">${safeError}</div>` : ''}
                    <button>登 录</button>
                </form>
            </div>
        </body>
        </html>`, { headers: { "Content-Type": "text/html" } });
    },

    renderLockedPage(ip, duration) {
        return new Response(`<html><head><meta charset="UTF-8">${this.commonHead}</head><body style="display:flex;justify-content:center;align-items:center;height:100vh"><div><h1 style="color:var(--error)">IP 已锁定</h1><p>IP: ${this.escapeHtml(ip)}</p><p>尝试次数过多，请 15 分钟后再试。</p></div></body></html>`, { status: 429, headers: { "Content-Type": "text/html" } });
    },

    renderAdminUI() {
        return new Response(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>代理管理后台</title>
    ${this.commonHead}
    <style>
        body { margin:0; padding:20px; max-width:1000px; margin:0 auto; }
        .header { display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border); padding-bottom:15px; margin-bottom:20px; }
        .grid { display:grid; grid-template-columns: 1fr 2fr; gap:20px; }
        @media(max-width:700px) { .grid { grid-template-columns: 1fr; } }
        .panel { background:var(--panel); padding:20px; border-radius:8px; border:1px solid var(--border); box-shadow:0 2px 8px rgba(0,0,0,0.05); }
        input { width:100%; padding:8px; margin:5px 0 15px; background:var(--input-bg); border:1px solid var(--border); color:var(--text); box-sizing:border-box; border-radius:4px; }
        input:focus { outline:none; border-color:var(--accent); }
        label { font-size:12px; color:var(--text-sub); }
        button { padding:8px 15px; background:var(--btn-bg); color:var(--text); border:1px solid var(--border); cursor:pointer; border-radius:4px; font-size:13px; }
        button:hover { background:var(--btn-hover); }
        .btn-green { background:var(--accent); color:#fff; border:none; font-weight:bold; }
        .btn-green:hover { background:var(--accent-hover); }
        .btn-del { color:var(--error); border-color:transparent; background:transparent; }
        .btn-del:hover { background:rgba(239, 68, 68, 0.1); }
        table { width:100%; border-collapse:collapse; font-size:13px; }
        th { text-align:left; color:var(--text-sub); padding:10px 5px; border-bottom:1px solid var(--border); font-weight:normal; }
        td { padding:10px 5px; border-bottom:1px solid var(--border); }
        .tag { padding:2px 6px; border-radius:4px; font-size:10px; }
        .tag-sec { background:rgba(251, 191, 36, 0.2); color:#d97706; }
        .tag-pub { background:rgba(34, 197, 94, 0.2); color:#16a34a; }
        .link { font-family:monospace; color:var(--text-sub); background:var(--link-bg); padding:4px; border-radius:4px; cursor:pointer; }
    </style>
</head>
<body>
    <div class="header">
        <h2 style="margin:0">Emby 代理管理 <span style="font-size:12px;color:var(--text-sub)">V13.9</span></h2>
        <div style="font-size:12px;color:var(--text-sub);font-family:monospace" id="clock">加载中...</div>
    </div>

    <div class="grid">
        <div class="panel">
            <h3 style="margin-top:0">添加新节点</h3>
            <label>节点名称 (英文/数字)</label>
            <input id="inName" placeholder="例如: HK-Node" />
            <label>Emby 服务器地址</label>
            <input id="inTarget" placeholder="http://1.2.3.4:8096" />
            <label>私密路径 (可选, 留空则公开)</label>
            <input id="inSecret" placeholder="例如: mysecret" />
            <button class="btn-green" onclick="App.save()" style="width:100%">部署节点</button>
        </div>

        <div class="panel">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px">
                <h3 style="margin:0">活跃节点列表</h3>
                <div>
                    <button onclick="App.export()">导出配置</button>
                    <button onclick="document.getElementById('fileIn').click()">导入配置</button>
                    <input type="file" id="fileIn" hidden accept=".json" onchange="App.import(this)" />
                </div>
            </div>
            <table>
                <thead><tr><th>名称</th><th>连接地址 (点击复制)</th><th style="text-align:right">操作</th></tr></thead>
                <tbody id="nodeTable"></tbody>
            </table>
        </div>
    </div>

    <script>
        const API = { async req(d) { const r=await fetch('/admin',{method:'POST',body:JSON.stringify(d)}); if(r.status===401)location.reload(); return r.json(); } };
        const App = {
            nodes: [],
            async refresh() {
                const d = await API.req({action:'list'});
                this.nodes = d.nodes;
                const html = d.nodes.map(n => {
                    const link = location.origin + '/' + n.name + (n.secret ? '/' + n.secret : '');
                    const isSec = !!n.secret;
                    return \`<tr>
                        <td>\${n.name} \${isSec?'<span class="tag tag-sec">私密</span>':'<span class="tag tag-pub">公开</span>'}</td>
                        <td><span class="link" onclick="App.copy('\${link}',this)">\${link}</span></td>
                        <td style="text-align:right"><button class="btn-del" onclick="App.del('\${n.name}')">删除</button></td>
                    </tr>\`;
                }).join('');
                document.getElementById('nodeTable').innerHTML = html || '<tr><td colspan="3" style="text-align:center;color:var(--text-sub);padding:20px">暂无节点，请在左侧添加</td></tr>';
            },
            async save() {
                const name = document.getElementById('inName').value.trim();
                const target = document.getElementById('inTarget').value.trim();
                const secret = document.getElementById('inSecret').value.trim();
                if(!name || !target) return alert('名称和地址不能为空');
                await API.req({action:'save', name, target, path:secret});
                document.getElementById('inName').value=''; document.getElementById('inTarget').value=''; document.getElementById('inSecret').value='';
                this.refresh();
            },
            async del(n) { if(confirm('确认删除节点 ['+n+'] 吗?')) { await API.req({action:'delete',name:n}); this.refresh(); } },
            async export() {
                const b = new Blob([JSON.stringify(this.nodes)],{type:'application/json'});
                const a = document.createElement('a'); a.href=URL.createObjectURL(b); a.download='emby_nodes.json'; a.click();
            },
            async import(el) {
                const f = el.files[0]; if(!f)return;
                const r = new FileReader();
                r.onload = async e => { try { await API.req({action:'import',nodes:JSON.parse(e.target.result)}); this.refresh(); } catch(e){alert('文件格式错误');} };
                r.readAsText(f); el.value='';
            },
            copy(t,el) { navigator.clipboard.writeText(t); const o=el.innerText; el.innerText='已复制!'; setTimeout(()=>el.innerText=o,1000); }
        };
        
        function updateClock() {
            const now = new Date();
            document.getElementById('clock').innerText = now.toLocaleTimeString('zh-CN', {timeZone:'Asia/Shanghai'}) + " 北京时间";
        }
        setInterval(updateClock, 1000);
        updateClock(); 
        App.refresh();
    </script>
</body>
</html>`, { headers: { "Content-Type": "text/html" } });
    }
};

// ============================================================================
// 6. MAIN WORKER LOGIC
// ============================================================================
const MainWorker = {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const segments = path.split('/').filter(p => p).map(p => decodeURIComponent(p));

        if (segments[0] === "admin") {
            const contentType = request.headers.get("content-type") || "";
            if (request.method === "POST" && (contentType.includes("form") || contentType.includes("urlencoded"))) {
                return Auth.handleLogin(request, env);
            }
            const isAuth = await Auth.verifyRequest(request, env);
            if (!isAuth) {
                if (request.method === "POST") return new Response("Unauthorized", { status: 401 });
                return UI.renderLoginPage();
            }
            if (request.method === "POST") return Database.handleApi(request, env);
            return UI.renderAdminUI();
        }

        if (segments.length >= 1) {
            const nodeName = segments[0];
            const nodeData = await Database.getNode(nodeName, env, ctx);

            if (nodeData) {
                let authorized = false;
                let subIndex = 1;
                if (nodeData.secret) {
                    if (segments[1] === nodeData.secret) { authorized = true; subIndex = 2; }
                } else { authorized = true; }

                if (authorized) {
                    const remainingPath = "/" + segments.slice(subIndex).join('/');
                    if (remainingPath === "/" || remainingPath === "") {
                        const prefix = nodeData.secret ? `/${nodeName}/${nodeData.secret}` : `/${nodeName}`;
                        return Response.redirect(url.origin + prefix + "/web/index.html", 302);
                    }
                    return Proxy.handle(request, nodeData, remainingPath, nodeName, nodeData.secret);
                }
            }
        }
        return new Response("403 Forbidden / Access Denied", { status: 403 });
    }
};

// ============================================================================
// 0. ENTRY POINT (ES Modules Standard)
// ============================================================================
export default {
    async fetch(request, env, ctx) {
        // 直接调用逻辑核心
        return MainWorker.fetch(request, env, ctx);
    }
};
