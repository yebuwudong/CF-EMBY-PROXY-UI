/**
 * EMBY-PROXY-UI V9.3 (CN Terminology Update)
 * 术语修正：节点->代理，回源->服务器
 * 核心特性：真实IP穿透、北京时间、思源黑体 UI
 */

const STATIC_REGEX = /\.(?:jpg|jpeg|gif|png|svg|ico|webp|js|css|woff2?|ttf|otf|map|webmanifest|json)$/i;
const STREAMING_REGEX = /\.(?:mp4|m4v|m4s|m4a|ogv|webm|mkv|mov|avi|wmv|flv|ts|m3u8)$/i;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const segments = url.pathname.split('/').filter(p => p).map(p => decodeURIComponent(p));

    // 1. [管理后台入口]
    if (segments[0] === env.ADMIN_PASS) {
      if (request.method === "POST") return await handleApi(request, env);
      return renderAdminUI(env);
    }

    // 2. [代理转发逻辑]
    if (segments.length >= 1) {
      const nodeName = segments[0];
      const nodeData = await env.ENI_KV.get(`node:${nodeName}`, { type: "json" });

      if (nodeData) {
        let authorized = false;
        let subIndex = 1;
        const secretRequired = nodeData.secret && nodeData.secret !== "";

        if (secretRequired) {
          if (segments[1] === nodeData.secret) {
            authorized = true;
            subIndex = 2;
          }
        } else {
          authorized = true;
        }

        if (authorized) {
          const remainingPath = "/" + segments.slice(subIndex).join('/');
          
          // 路径自动补全
          if (remainingPath === "/" || remainingPath === "") {
             const redirectPrefix = secretRequired ? `/${nodeName}/${nodeData.secret}` : `/${nodeName}`;
             return Response.redirect(url.origin + redirectPrefix + "/web/index.html", 302);
          }

          // 记录日志 (仅记录 HTML 页面访问)
          if (remainingPath.includes(".html") || remainingPath === "/web/index.html") {
            ctx.waitUntil(addLog(env, request, nodeName, nodeData.target));
          }
          return await handleProxy(request, nodeData, remainingPath, nodeName, nodeData.secret);
        }
      }
    }
    return new Response("ACCESS DENIED // 403 Forbidden", { status: 403 });
  }
};

/**
 * 核心代理处理：确保传递真实 IP
 */
async function handleProxy(request, node, path, name, key) {
  const targetBase = new URL(node.target);
  const url = new URL(request.url);
  const finalUrl = new URL(path, targetBase);
  finalUrl.search = url.search;

  const upgradeHeader = request.headers.get("Upgrade");
  const isWS = upgradeHeader && upgradeHeader.toLowerCase() === "websocket";
  const isStatic = STATIC_REGEX.test(finalUrl.pathname);
  const isStreaming = STREAMING_REGEX.test(finalUrl.pathname);
  
  // 缓存策略
  let cfOptions = { polish: isStatic ? "lossless" : "off" };
  if (isStatic) {
    cfOptions.cacheEverything = true;
    cfOptions.cacheTtlByStatus = { "200-299": 31536000, "404": 1 };
  } else if (!isStreaming && !isWS) {
    cfOptions.cacheEverything = true;
    cfOptions.cacheTtl = 10;
  }

  // --- [真实 IP 透传] ---
  const newHeaders = new Headers(request.headers);
  newHeaders.set("Host", targetBase.host);
  
  const realIp = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "0.0.0.0";
  newHeaders.set("X-Real-IP", realIp);
  newHeaders.set("X-Forwarded-For", realIp);

  if (isWS) return fetch(new Request(finalUrl, { headers: newHeaders }));

  let response = await fetch(new Request(finalUrl.toString(), {
    method: request.method, headers: newHeaders, body: request.body, redirect: "manual"
  }), { cf: cfOptions });

  // 修正 Location 跳转
  let modifiedHeaders = new Headers(response.headers);
  const location = modifiedHeaders.get("Location");
  if (location && response.status >= 300 && response.status < 400) {
    const prefix = key ? `/${name}/${key}` : `/${name}`;
    if (location.startsWith("/")) {
      modifiedHeaders.set("Location", `${prefix}${location}`);
    } else {
      try {
        const locURL = new URL(location);
        if (locURL.host === url.host) modifiedHeaders.set("Location", `${prefix}${locURL.pathname}${locURL.search}`);
      } catch (e) {}
    }
  }
  return new Response(response.body, { status: response.status, headers: modifiedHeaders });
}

/**
 * 日志系统：北京时间 + 真实 IP
 */
async function addLog(env, request, name, target) {
  const ip = request.headers.get("cf-connecting-ip") || "Unknown";
  const geo = request.cf ? `${request.cf.city || '未知'} [${request.cf.country || 'CN'}]` : "内网/未知";
  
  const timeStr = new Date().toLocaleString('zh-CN', { 
    timeZone: 'Asia/Shanghai', 
    hour12: false,
    hour: '2-digit', 
    minute: '2-digit', 
    second: '2-digit' 
  });

  const newLog = {
    time: timeStr,
    ip: ip, 
    geo: geo, 
    node: name, 
    target: target
  };
  
  let logs = await env.ENI_KV.get("system:logs", { type: "json" }) || [];
  logs.unshift(newLog);
  if (logs.length > 50) logs = logs.slice(0, 50);
  await env.ENI_KV.put("system:logs", JSON.stringify(logs));
}

async function handleApi(request, env) {
  const data = await request.json();
  if (data.action === "save") {
    await env.ENI_KV.put(`node:${data.name}`, JSON.stringify({ secret: data.path || "", target: data.target }));
    return new Response(JSON.stringify({ success: true }));
  }
  if (data.action === "delete") {
    await env.ENI_KV.delete(`node:${data.name}`);
    return new Response(JSON.stringify({ success: true }));
  }
  if (data.action === "list") {
    const list = await env.ENI_KV.list({ prefix: "node:" });
    const nodes = await Promise.all(list.keys.map(async (k) => ({
      name: k.name.replace("node:", ""),
      ...(await env.ENI_KV.get(k.name, { type: "json" }))
    })));
    const logs = await env.ENI_KV.get("system:logs", { type: "json" }) || [];
    return new Response(JSON.stringify({ nodes, logs }));
  }
}

function renderAdminUI(env) {
  const cstDate = new Date().toLocaleString("en-US", {timeZone: "Asia/Shanghai"});
  const hour = new Date(cstDate).getHours();
  const theme = (hour >= 6 && hour < 18) ? "lofi" : "black"; 
  const isDark = theme === "black";

  return new Response(`
<!DOCTYPE html>
<html data-theme="${theme}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EMBY-PROXY-UI</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@3.9.4/dist/full.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@300;400;700;900&family=JetBrains+Mono:wght@400;700&display=swap');
        
        body { 
            font-family: 'Noto Sans SC', system-ui, -apple-system, sans-serif; 
            background-color: ${isDark ? '#050505' : '#f8fafc'};
            background-image: ${isDark ? 'radial-gradient(#ffffff08 1px, transparent 1px)' : 'radial-gradient(#00000008 1px, transparent 1px)'};
            background-size: 20px 20px;
        }
        .mono { font-family: 'JetBrains Mono', monospace; }
        
        .glass-panel {
            background: ${isDark ? 'rgba(20, 20, 20, 0.7)' : 'rgba(255, 255, 255, 0.8)'};
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid ${isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.05)'};
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }
        
        .status-dot {
            width: 6px; height: 6px; border-radius: 50%;
            background-color: #00d26a;
            box-shadow: 0 0 12px #00d26a;
            animation: pulse 3s infinite ease-in-out;
        }
        @keyframes pulse { 0% { opacity: 0.3; transform: scale(0.8); } 50% { opacity: 1; transform: scale(1.2); } 100% { opacity: 0.3; transform: scale(0.8); } }
        
        .terminal-box {
            background-color: #0d1117;
            border: 1px solid #30363d;
            color: #c9d1d9;
        }
        .scrollbar-hide::-webkit-scrollbar { display: none; }
    </style>
</head>
<body class="min-h-screen p-4 lg:p-10 transition-colors duration-500 flex flex-col items-center">
    <div class="max-w-[1500px] w-full space-y-6">
        
        <header class="navbar glass-panel rounded-2xl px-8 py-5 flex justify-between items-center">
            <div class="flex items-center gap-4">
                <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-400 to-cyan-500 flex items-center justify-center text-white shadow-lg shadow-emerald-500/20">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.384-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" /></svg>
                </div>
                <div>
                    <h1 class="text-2xl font-black tracking-tight ${isDark ? 'text-white' : 'text-slate-800'}">EMBY-PROXY-UI</h1>
                    <div class="flex items-center gap-2 mt-1">
                        <div class="status-dot"></div>
                        <span class="text-xs font-medium opacity-50 tracking-wider">系统运行正常 · 北京时间</span>
                    </div>
                </div>
            </div>
            <div class="hidden md:block">
                <div class="font-mono text-xs opacity-40 bg-base-content/5 px-3 py-1.5 rounded-md" id="clock">正在连接时钟服务器...</div>
            </div>
        </header>

        <main class="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            
            <aside class="lg:col-span-4 xl:col-span-3 flex flex-col gap-6">
                <div class="card glass-panel shadow-xl">
                    <div class="card-body p-6 space-y-4">
                        <div class="flex items-center justify-between border-b border-base-content/10 pb-3 mb-2">
                            <h2 class="text-sm font-bold opacity-60">新增代理</h2>
                            <span class="text-[10px] font-mono opacity-40">DEPLOY</span>
                        </div>
                        
                        <div class="form-control w-full space-y-1">
                            <label class="label p-0 mb-1"><span class="label-text text-xs font-bold opacity-70">代理名称 (英文)</span></label>
                            <input id="inName" type="text" placeholder="例如: HK-Emby" class="input input-bordered input-sm w-full bg-base-100/50 focus:border-emerald-500 font-medium" />
                        </div>
                        
                        <div class="form-control w-full space-y-1">
                            <label class="label p-0 mb-1"><span class="label-text text-xs font-bold opacity-70">访问密钥 (可选)</span></label>
                            <input id="inPath" type="password" placeholder="留空则公开访问" class="input input-bordered input-sm w-full bg-base-100/50 focus:border-emerald-500 font-medium" />
                        </div>
                        
                        <div class="form-control w-full space-y-1">
                            <label class="label p-0 mb-1"><span class="label-text text-xs font-bold opacity-70">服务器地址 (Target)</span></label>
                            <input id="inTarget" type="text" placeholder="http://1.2.3.4:8096" class="input input-bordered input-sm w-full bg-base-100/50 focus:border-emerald-500 font-mono text-xs" />
                        </div>

                        <button onclick="saveNode()" class="btn btn-neutral w-full mt-4 bg-gradient-to-r from-slate-800 to-slate-900 text-white border-0 shadow-lg hover:shadow-xl hover:scale-[1.02] transition-all duration-300">
                            立即部署
                        </button>
                    </div>
                </div>
            </aside>

            <section class="lg:col-span-8 xl:col-span-9 flex flex-col gap-6 h-full">
                
                <div class="card glass-panel shadow-xl overflow-hidden min-h-[280px]">
                    <div class="px-6 py-4 border-b border-base-content/5 flex justify-between items-center bg-base-content/5">
                        <h2 class="text-sm font-bold opacity-70">活跃代理列表</h2>
                        <div id="nodes-label" class="badge badge-success gap-1 badge-sm text-white border-0">
                            <span class="animate-pulse w-1.5 h-1.5 rounded-full bg-white"></span> 连接中
                        </div>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="table w-full">
                            <thead>
                                <tr class="text-xs uppercase opacity-50 bg-base-200/30 font-medium">
                                    <th class="pl-6 py-4">代理 ID</th>
                                    <th>入口地址 (点击复制)</th>
                                    <th class="text-right pr-6">操作</th>
                                </tr>
                            </thead>
                            <tbody id="nodeTable" class="text-sm font-medium opacity-90">
                                </tbody>
                        </table>
                    </div>
                </div>

                <div class="card terminal-box shadow-2xl overflow-hidden rounded-xl flex flex-col h-[320px]">
                    <div class="px-4 py-2 border-b border-white/10 flex justify-between items-center bg-[#161b22]">
                        <div class="flex gap-2">
                            <div class="w-3 h-3 rounded-full bg-[#ff5f56]"></div>
                            <div class="w-3 h-3 rounded-full bg-[#ffbd2e]"></div>
                            <div class="w-3 h-3 rounded-full bg-[#27c93f]"></div>
                        </div>
                        <div class="flex items-center gap-2 text-[10px] font-mono text-slate-500">
                            <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                            access.log (Real-IP)
                        </div>
                    </div>
                    <div id="logViewer" class="p-4 overflow-y-auto font-mono text-[11px] space-y-2 scrollbar-hide flex-1">
                        </div>
                </div>
            </section>
        </main>
    </div>

    <script>
        async function refresh() {
            try {
                const res = await fetch(window.location.href, { method: 'POST', body: JSON.stringify({ action: 'list' }) });
                const data = await res.json();
                
                // 渲染代理表格
                const nodeHtml = data.nodes.map(n => {
                    const fullLink = window.location.origin + '/' + n.name + (n.secret ? '/' + n.secret : '');
                    const isSecured = !!n.secret;
                    return \`
                        <tr class="hover:bg-base-content/5 transition-colors border-b border-base-content/5 last:border-0 group">
                            <td class="pl-6 py-3">
                                <div class="flex items-center gap-3">
                                    <div class="w-2 h-2 rounded-full \${isSecured ? 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.5)]' : 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]'}"></div>
                                    <span class="font-bold tracking-wide">\${n.name}</span>
                                    \${isSecured ? '<span class="px-1.5 py-0.5 rounded text-[9px] bg-amber-500/10 text-amber-500 font-bold border border-amber-500/20">密</span>' : ''}
                                </div>
                            </td>
                            <td>
                                <button onclick="copy('\${fullLink}')" class="text-left font-mono text-xs opacity-60 hover:opacity-100 hover:text-emerald-500 transition-colors select-all truncate max-w-[200px] md:max-w-xs bg-base-content/5 px-2 py-1 rounded">
                                    \${fullLink}
                                </button>
                            </td>
                            <td class="text-right pr-6">
                                <button onclick="deleteNode('\${n.name}')" class="btn btn-ghost btn-xs text-rose-500 opacity-60 hover:opacity-100 hover:bg-rose-500/10">
                                    删除
                                </button>
                            </td>
                        </tr>
                    \`;
                }).join('');
                
                document.getElementById('nodeTable').innerHTML = nodeHtml || '<tr><td colspan="3" class="text-center py-12 opacity-30 text-xs">暂无活跃代理，请在左侧添加</td></tr>';
                document.getElementById('nodes-label').innerHTML = \`<span class="w-1.5 h-1.5 rounded-full bg-white"></span> \${data.nodes.length} 个运行中\`;

                // 渲染日志
                const logHtml = data.logs.map(l => \`
                    <div class="flex gap-3 hover:bg-white/5 p-1 rounded cursor-default items-center">
                        <span class="text-emerald-500 w-[60px] shrink-0 opacity-80">\${l.time}</span>
                        <span class="text-cyan-400 w-[110px] shrink-0 font-bold bg-cyan-400/10 px-1 rounded text-center">\${l.ip}</span>
                        <span class="text-slate-500 w-[120px] shrink-0 truncate text-[10px]">\${l.geo}</span>
                        <span class="text-amber-400 w-[80px] shrink-0 font-bold">\${l.node}</span>
                        <span class="text-slate-600 shrink-0 select-none">→</span>
                        <span class="text-slate-400 truncate flex-1 italic opacity-60">\${l.target}</span>
                    </div>
                \`).join('');
                document.getElementById('logViewer').innerHTML = logHtml || '<div class="opacity-30 text-center mt-12 text-slate-600">// 等待流量接入...</div>';
                
            } catch(e) { console.error(e); }
        }

        async function saveNode() {
            const btn = document.querySelector('button[onclick="saveNode()"]');
            const originalText = btn.innerText;
            btn.innerText = "部署中...";
            btn.disabled = true;

            const name = document.getElementById('inName').value.trim();
            const path = document.getElementById('inPath').value.trim();
            const target = document.getElementById('inTarget').value.trim();
            
            if(name && target) {
                await fetch(window.location.href, { method: 'POST', body: JSON.stringify({ action: 'save', name, path, target }) });
                document.getElementById('inName').value = '';
                document.getElementById('inPath').value = '';
                document.getElementById('inTarget').value = '';
                await refresh();
            }
            
            btn.innerText = originalText;
            btn.disabled = false;
        }

        async function deleteNode(name) {
            if(!confirm('确定要删除代理 [' + name + '] 吗？')) return;
            await fetch(window.location.href, { method: 'POST', body: JSON.stringify({ action: 'delete', name }) });
            refresh();
        }

        function copy(text) { 
            navigator.clipboard.writeText(text);
            const el = document.activeElement;
            const original = el.innerText;
            el.innerText = "已复制 ✓";
            setTimeout(() => el.innerText = original, 1000);
        }

        function updateClock() {
            const now = new Date();
            const timeString = now.toLocaleTimeString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });
            document.getElementById('clock').innerText = timeString + " CST";
        }

        refresh();
        setInterval(refresh, 5000);
        setInterval(updateClock, 1000);
    </script>
</body>
</html>
  `, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
}
