/**
 * OpenAI API Key Pool — Deno Deploy
 * Admin: /admin  |  Proxy: /v1/
 * 
 * 环境变量:
 *   ADMIN_PASSWORD   管理员密码 (默认 admin123)
 *   KV_PATH          SQLite 数据库路径 (Deno Deploy 用 Deno KV，本地用文件路径)
 * 
 * Deno Deploy 部署:
 *   1. 上传本文件到 GitHub
 *   2. 在 Deno Deploy 新建项目，连接 GitHub repo
 *   3. 设置环境变量 ADMIN_PASSWORD
 */

// ═══ Deno KV Storage ═══
const kv = await Deno.openKv();

async function kvListEmails(): Promise<string[]> {
  try {
    const res = await kv.get<string[]>(["a", "list"]);
    return res.value ?? [];
  } catch { return []; }
}

async function kvGetAcc(email: string): Promise<Record<string, unknown> | null> {
  try {
    const res = await kv.get<Record<string, unknown>>(["a", "d", email]);
    return res.value ?? null;
  } catch { return null; }
}

async function kvSaveAcc(data: Record<string, unknown>) {
  const email = data.email as string;
  await kv.set(["a", "d", email], data);
  const list = await kvListEmails();
  if (!list.includes(email)) {
    list.push(email);
    await kv.set(["a", "list"], list);
  }
}

async function kvDelAcc(email: string) {
  await kv.delete(["a", "d", email]);
  const list = (await kvListEmails()).filter(e => e !== email);
  await kv.set(["a", "list"], list);
}

async function kvIncrStat(key: string) {
  try {
    const res = await kv.get<number>(["stats", key]);
    await kv.set(["stats", key], (res.value ?? 0) + 1);
  } catch { /**/ }
}

async function kvGetStat(key: string): Promise<number> {
  const res = await kv.get<number>(["stats", key]);
  return res.value ?? 0;
}

async function kvGetCF(): Promise<{ cfClearance: string; sessionToken: string } | null> {
  const res = await kv.get<{ cfClearance: string; sessionToken: string }>(["cf", "config"]);
  return res.value ?? null;
}

async function kvSetCF(cfg: { cfClearance: string; sessionToken: string }) {
  await kv.set(["cf", "config"], cfg);
}

// ═══ Helpers ═══
function jsonResp(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store",
    },
  });
}

function corsResp(): Response {
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,Authorization",
      "Access-Control-Max-Age": "86400",
    },
  });
}

// ═══ Auth ═══
async function makeToken(): Promise<string> {
  const pw = Deno.env.get("ADMIN_PASSWORD") ?? "admin123";
  const day = Math.floor(Date.now() / 86400000);
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(pw),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(pw + ":" + day));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function getCookie(req: Request, name: string): string | null {
  const cookie = req.headers.get("Cookie") ?? "";
  const m = cookie.match(new RegExp(`${name}=([^;]+)`));
  return m ? m[1] : null;
}

async function isAuthed(req: Request): Promise<boolean> {
  const tok = getCookie(req, "adm");
  if (!tok) return false;
  return tok === await makeToken();
}

// ═══ Token utils ═══
function getToken(acc: Record<string, unknown>): string {
  return (acc.access_token as string) || (acc.id_token as string) || "";
}

function isExpired(acc: Record<string, unknown>): boolean {
  if (!acc.expired) return false;
  return Date.now() > new Date(acc.expired as string).getTime() - 60000;
}

function getPlan(acc: Record<string, unknown>): string {
  try {
    const parts = (acc.id_token as string).split(".");
    const pay = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    return pay["https://api.openai.com/auth"]?.chatgpt_plan_type ?? "unknown";
  } catch { return "unknown"; }
}

async function setStatus(email: string, status: string) {
  try {
    const acc = await kvGetAcc(email);
    if (!acc) return;
    acc._status = status;
    acc._lastUsed = new Date().toISOString();
    await kv.set(["a", "d", email], acc);
  } catch { /**/ }
}

// ═══ ChatGPT Headers ═══
function buildChatGPTHeaders(token: string, cfClearance: string, sessionToken: string): Headers {
  const h = new Headers();
  h.set("Authorization", "Bearer " + token);
  h.set("Content-Type", "application/json");
  h.set("Accept", "text/event-stream, */*");
  h.set("Origin", "https://chatgpt.com");
  h.set("Referer", "https://chatgpt.com/");
  h.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36");
  h.set("sec-ch-ua", '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"');
  h.set("sec-ch-ua-mobile", "?0");
  h.set("sec-ch-ua-platform", '"Windows"');
  h.set("sec-fetch-dest", "empty");
  h.set("sec-fetch-mode", "cors");
  h.set("sec-fetch-site", "same-origin");
  h.set("OAI-Device-Id", crypto.randomUUID());
  h.set("OAI-Language", "zh-CN");

  const cookieParts: string[] = [];
  if (cfClearance) cookieParts.push("cf-clearance=" + cfClearance);
  if (sessionToken) cookieParts.push("__Secure-next-auth.session-token.0=" + sessionToken);
  if (cookieParts.length) h.set("Cookie", cookieParts.join("; "));

  return h;
}

function buildChatGPTTarget(path: string, search: string): string {
  const p = path.replace(/^\/v1/, "");
  const map: Record<string, string> = {
    "/chat/completions": "/backend-api/conversation",
    "/models": "/backend-api/models",
    "/completions": "/backend-api/completions",
  };
  return "https://chatgpt.com" + (map[p] ?? "/backend-api" + p) + search;
}

function transformRequestBody(raw: ArrayBuffer): string | null {
  try {
    const b = JSON.parse(new TextDecoder().decode(raw));
    return JSON.stringify({
      action: "next",
      messages: (b.messages ?? []).map((m: { role: string; content: unknown }) => ({
        id: crypto.randomUUID(),
        author: { role: m.role },
        content: {
          content_type: "text",
          parts: [typeof m.content === "string" ? m.content : JSON.stringify(m.content)],
        },
        metadata: {},
      })),
      model: b.model ?? "gpt-4o",
      timezone_offset_min: -480,
      suggestions: [],
      history_and_training_disabled: true,
      conversation_mode: { kind: "primary_assistant" },
      websocket_request_id: crypto.randomUUID(),
      parent_message_id: crypto.randomUUID(),
      stream: true,
    });
  } catch { return null; }
}

function transformSSEStream(body: ReadableStream, model: string): ReadableStream {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  let buf = "", full = "";
  const created = Math.floor(Date.now() / 1000);
  const id = "chatcmpl-" + crypto.randomUUID().replace(/-/g, "").slice(0, 24);

  (async () => {
    try {
      const reader = body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split("\n"); buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const raw = line.slice(6).trim();
          if (!raw || raw === "[DONE]") continue;
          let ev: Record<string, unknown>;
          try { ev = JSON.parse(raw); } catch { continue; }
          const parts = (ev?.message as Record<string, unknown>)?.content as Record<string, unknown>;
          const textParts = parts?.parts as string[];
          if (!textParts) continue;
          const newFull = textParts.join("");
          const delta = newFull.slice(full.length);
          full = newFull;
          const stop = (ev?.message as Record<string, unknown>)?.status === "finished_successfully";
          if (!delta && !stop) continue;
          const chunk = JSON.stringify({
            id, object: "chat.completion.chunk", created, model,
            choices: [{ index: 0, delta: delta ? { content: delta } : {}, finish_reason: stop ? "stop" : null }],
          });
          await writer.write(enc.encode("data: " + chunk + "\n\n"));
        }
      }
      await writer.write(enc.encode("data: [DONE]\n\n"));
    } catch { /**/ } finally { writer.close().catch(() => {}); }
  })();

  return readable;
}

// Round-robin index stored in KV
async function nextAccIndex(total: number): Promise<number> {
  const res = await kv.get<number>(["rr", "i"]);
  const idx = (res.value ?? 0) % total;
  await kv.set(["rr", "i"], (idx + 1) % total);
  return idx;
}

// ═══ Proxy Handler ═══
async function handleProxy(req: Request, path: string, url: URL): Promise<Response> {
  const list = await kvListEmails();
  if (!list.length) {
    return jsonResp({ error: { message: "No accounts. Import at /admin", type: "proxy_error" } }, 503);
  }

  const cf = await kvGetCF();
  const cfClearance = cf?.cfClearance ?? "";
  const sessionToken = cf?.sessionToken ?? "";

  let raw: ArrayBuffer | null = null;
  if (req.method !== "GET" && req.method !== "HEAD") {
    raw = await req.arrayBuffer().catch(() => null);
  }

  const isChat = path.includes("/chat/completions");
  let chatBody: string | null = null;
  let chatModel = "gpt-4o";
  if (isChat && raw) {
    chatBody = transformRequestBody(raw);
    try { chatModel = JSON.parse(new TextDecoder().decode(raw)).model ?? "gpt-4o"; } catch { /**/ }
  }

  let lastStatus = 0, lastMsg = "";

  for (let attempt = 0; attempt < Math.min(3, list.length); attempt++) {
    const cur = await kvListEmails();
    if (!cur.length) break;

    const idx = await nextAccIndex(cur.length);
    const acc = await kvGetAcc(cur[idx]);
    if (!acc || isExpired(acc)) {
      if (acc) await setStatus(acc.email as string, "expired");
      continue;
    }

    const token = getToken(acc);
    if (!token) continue;

    const targetUrl = buildChatGPTTarget(path, url.search);
    const headers = buildChatGPTHeaders(token, cfClearance, sessionToken);

    try {
      const resp = await fetch(targetUrl, {
        method: req.method,
        headers,
        body: isChat ? chatBody : (raw ? new TextDecoder().decode(raw) : null),
      });

      lastStatus = resp.status;
      await kvIncrStat("calls");

      if (resp.status === 401 || resp.status === 403) {
        lastMsg = await resp.text().catch(() => "");
        await setStatus(acc.email as string, "invalid");
        await kvIncrStat("errors");
        continue;
      }

      await setStatus(acc.email as string, "active");

      const outH = new Headers({
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-store",
      });
      const ct = resp.headers.get("Content-Type") ?? "";

      if (isChat && ct.includes("event-stream") && resp.body) {
        outH.set("Content-Type", "text/event-stream; charset=utf-8");
        outH.set("Cache-Control", "no-cache");
        outH.set("Connection", "keep-alive");
        return new Response(transformSSEStream(resp.body, chatModel), { status: 200, headers: outH });
      }

      outH.set("Content-Type", ct || "application/json");
      return new Response(resp.body, { status: resp.status, headers: outH });

    } catch (e) {
      lastMsg = (e as Error).message;
      await kvIncrStat("errors");
    }
  }

  return jsonResp({
    error: { message: "All failed. HTTP:" + lastStatus + " " + lastMsg.slice(0, 300), type: "proxy_error" }
  }, 503);
}

// ═══ Admin API Handlers ═══
async function handleApiStats(): Promise<Response> {
  const list = await kvListEmails();
  let active = 0, expired = 0, invalid = 0, unknown = 0;
  for (const email of list) {
    const a = await kvGetAcc(email);
    if (!a) { unknown++; continue; }
    const s = a._status as string;
    if (s === "active") active++;
    else if (s === "expired" || isExpired(a)) expired++;
    else if (s === "invalid") invalid++;
    else unknown++;
  }
  return jsonResp({
    total: list.length, active, expired, invalid, unknown,
    calls: await kvGetStat("calls"),
    errors: await kvGetStat("errors"),
  });
}

async function handleApiList(): Promise<Response> {
  const list = await kvListEmails();
  const out = [];
  for (const email of list) {
    const a = await kvGetAcc(email);
    if (a) out.push({
      email: a.email,
      status: (a._status as string) || (isExpired(a) ? "expired" : "unknown"),
      expired: a.expired ?? null,
      lastUsed: a._lastUsed ?? null,
      plan: getPlan(a),
    });
  }
  return jsonResp({ accounts: out, total: out.length });
}

async function handleApiImport(req: Request): Promise<Response> {
  const data = await req.json().catch(() => null) as Record<string, unknown> | null;
  if (!data?.email) return jsonResp({ error: "Missing email" }, 400);
  await kvSaveAcc(data);
  return jsonResp({ ok: true, email: data.email });
}

async function handleApiBatch(req: Request): Promise<Response> {
  const body = await req.json().catch(() => ({})) as { files?: Record<string, unknown>[] };
  const files = body.files ?? [];
  let success = 0, failed = 0;
  const errors: unknown[] = [];
  for (let i = 0; i < files.length; i++) {
    const d = files[i];
    try {
      if (!d?.email) throw new Error("missing email");
      await kvSaveAcc(d); success++;
    } catch (e) {
      failed++;
      errors.push({ index: i, email: d?.email ?? "?", error: (e as Error).message });
    }
  }
  return jsonResp({ success, failed, errors: errors.slice(0, 20) });
}

async function handleApiDelete(req: Request): Promise<Response> {
  const body = await req.json().catch(() => ({})) as { email?: string };
  if (!body.email) return jsonResp({ error: "missing email" }, 400);
  await kvDelAcc(body.email);
  return jsonResp({ ok: true });
}

async function handleApiWipe(): Promise<Response> {
  const list = await kvListEmails();
  for (const email of list) await kv.delete(["a", "d", email]);
  await kv.set(["a", "list"], []);
  return jsonResp({ ok: true, deleted: list.length });
}

async function handleApiProbe(req: Request): Promise<Response> {
  const list = await kvListEmails();
  if (!list.length) return jsonResp({ error: "No accounts" }, 400);

  const body = await req.json().catch(() => ({})) as { email?: string };
  const email = body.email ?? list[0];
  const acc = await kvGetAcc(email);
  if (!acc) return jsonResp({ error: "Not found" }, 404);

  const token = getToken(acc);
  if (!token) return jsonResp({ error: "No token" }, 400);

  const cf = await kvGetCF();
  const cfClearance = cf?.cfClearance ?? "";
  const sessionToken = cf?.sessionToken ?? "";

  const results = [];

  // Test 1: chatgpt.com/backend-api/models
  try {
    const r = await fetch("https://chatgpt.com/backend-api/models", {
      headers: buildChatGPTHeaders(token, cfClearance, sessionToken),
    });
    const t = await r.text();
    results.push({ url: "chatgpt.com/backend-api/models", status: r.status, ok: r.ok, body: t.slice(0, 400) });
  } catch (e) { results.push({ url: "chatgpt.com/backend-api/models", error: (e as Error).message }); }

  // Test 2: chatgpt.com/backend-api/me
  try {
    const r = await fetch("https://chatgpt.com/backend-api/me", {
      headers: buildChatGPTHeaders(token, cfClearance, sessionToken),
    });
    const t = await r.text();
    results.push({ url: "chatgpt.com/backend-api/me", status: r.status, ok: r.ok, body: t.slice(0, 400) });
  } catch (e) { results.push({ url: "chatgpt.com/backend-api/me", error: (e as Error).message }); }

  // CF status
  results.push({
    url: "CF Cookie Status",
    ok: !!cfClearance,
    status: cfClearance ? 200 : 0,
    body: cfClearance
      ? `cf-clearance: ${cfClearance.slice(0, 30)}... (${cfClearance.length}chars)\nsession-token: ${sessionToken ? sessionToken.slice(0, 20) + "... (" + sessionToken.length + "chars)" : "NOT SET"}`
      : "NO cf-clearance. Call POST /admin/api/setcf",
  });

  return jsonResp({ email, tokenLen: token.length, hasRefresh: !!acc.refresh_token, expired: isExpired(acc), results });
}

async function handleApiSetCF(req: Request): Promise<Response> {
  const body = await req.json().catch(() => ({})) as { cfClearance?: string; sessionToken?: string };
  if (!body.cfClearance) return jsonResp({ error: "cfClearance required" }, 400);
  await kvSetCF({ cfClearance: body.cfClearance.trim(), sessionToken: (body.sessionToken ?? "").trim() });
  return jsonResp({ ok: true, cfLen: body.cfClearance.length, stLen: (body.sessionToken ?? "").length });
}

async function handleApiGetCF(): Promise<Response> {
  const cf = await kvGetCF();
  if (!cf) return jsonResp({ set: false });
  return jsonResp({ set: true, cfLen: cf.cfClearance.length, stLen: cf.sessionToken.length });
}

async function handleApiCheck(): Promise<Response> {
  try {
    await kv.set(["_check"], "ok");
    const v = await kv.get<string>(["_check"]);
    const list = await kvListEmails();
    return jsonResp({ kvBinding: true, kvWritable: true, kvReadable: v.value === "ok", listLen: list.length });
  } catch (e) {
    return jsonResp({ kvBinding: false, kvWritable: false, kvReadable: false, error: (e as Error).message }, 500);
  }
}

// ═══ Main Router ═══
Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const p = url.pathname;

  if (req.method === "OPTIONS") return corsResp();

  // Proxy
  if (p.startsWith("/v1/")) return handleProxy(req, p, url);

  // Admin page
  if (p === "/admin" || p === "/admin/") {
    const ok = await isAuthed(req);
    return new Response(ok ? buildPanel() : buildLogin(), {
      headers: { "Content-Type": "text/html;charset=utf-8", "Cache-Control": "no-store" },
    });
  }

  // Login / Logout
  if (p === "/admin/login" && req.method === "POST") {
    const body = await req.json().catch(() => ({})) as { password?: string };
    const pw = Deno.env.get("ADMIN_PASSWORD") ?? "admin123";
    if (body.password !== pw) return jsonResp({ error: "Wrong password" }, 401);
    const tok = await makeToken();
    const h = new Headers({ "Content-Type": "application/json", "Cache-Control": "no-store" });
    h.append("Set-Cookie", `adm=${tok}; HttpOnly; Secure; SameSite=Strict; Max-Age=86400; Path=/`);
    return new Response('{"ok":true}', { headers: h });
  }

  if (p === "/admin/logout" && req.method === "POST") {
    const h = new Headers({ Location: "/admin" });
    h.append("Set-Cookie", "adm=; HttpOnly; Secure; Max-Age=0; Path=/");
    return new Response(null, { status: 302, headers: h });
  }

  // Admin APIs (auth required)
  if (p.startsWith("/admin/api/")) {
    if (!await isAuthed(req)) return jsonResp({ error: "Unauthorized" }, 401);

    if (p === "/admin/api/stats"  && req.method === "GET")    return handleApiStats();
    if (p === "/admin/api/list"   && req.method === "GET")    return handleApiList();
    if (p === "/admin/api/import" && req.method === "POST")   return handleApiImport(req);
    if (p === "/admin/api/batch"  && req.method === "POST")   return handleApiBatch(req);
    if (p === "/admin/api/delete" && req.method === "DELETE") return handleApiDelete(req);
    if (p === "/admin/api/wipe"   && req.method === "DELETE") return handleApiWipe();
    if (p === "/admin/api/probe"  && req.method === "POST")   return handleApiProbe(req);
    if (p === "/admin/api/setcf"  && req.method === "POST")   return handleApiSetCF(req);
    if (p === "/admin/api/getcf"  && req.method === "GET")    return handleApiGetCF();
    if (p === "/admin/api/check"  && req.method === "GET")    return handleApiCheck();

    return jsonResp({ error: "Not found" }, 404);
  }

  return new Response("OpenAI Proxy OK\nAdmin: /admin\nProxy: /v1/", {
    headers: { "Content-Type": "text/plain" },
  });
});

// ═══ HTML (same as Workers version) ═══
function buildLogin(): string {
  return '<!DOCTYPE html><html lang="zh-CN"><head>'
    + '<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>Login</title>'
    + '<style>'
    + '*{box-sizing:border-box;margin:0;padding:0}'
    + 'body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#07080d;color:#e6edf3;font-family:system-ui,sans-serif}'
    + '.box{background:#0d1117;border:1px solid #30363d;border-radius:14px;padding:36px;width:320px}'
    + 'h1{font-size:15px;font-weight:800;color:#58a6ff;font-family:monospace;letter-spacing:1px;margin-bottom:3px}'
    + 'p{font-size:12px;color:#7d8590;margin-bottom:22px}'
    + 'label{display:block;font-size:11px;font-weight:700;color:#7d8590;text-transform:uppercase;margin-bottom:5px}'
    + 'input{width:100%;background:#07080d;border:1px solid #30363d;border-radius:7px;padding:9px 12px;color:#e6edf3;font-size:14px;outline:none;margin-bottom:13px}'
    + 'input:focus{border-color:#58a6ff}'
    + 'button{width:100%;padding:10px;background:#58a6ff;border:none;border-radius:7px;color:#000;font-size:14px;font-weight:700;cursor:pointer}'
    + '.err{padding:9px;background:rgba(248,81,73,.1);border-left:3px solid #f85149;color:#f85149;border-radius:7px;font-size:12px;margin-bottom:12px;display:none}'
    + '</style></head><body>'
    + '<div class="box"><h1>API KEY POOL</h1><p>Deno Deploy &middot; OpenAI Proxy</p>'
    + '<div class="err" id="err"></div><label>管理员密码</label>'
    + '<input type="password" id="pw" placeholder="请输入密码" autofocus>'
    + '<button onclick="go()">登 录</button></div>'
    + '<script>document.getElementById("pw").onkeydown=function(e){if(e.key==="Enter")go();};'
    + 'function go(){'
    + 'var pw=document.getElementById("pw").value;if(!pw)return;'
    + 'var btn=document.querySelector("button");btn.disabled=true;btn.textContent="验证中...";'
    + 'fetch("/admin/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:pw})})'
    + '.then(function(r){if(r.ok){location.reload();}else{var e=document.getElementById("err");e.textContent="密码错误";e.style.display="block";btn.disabled=false;btn.textContent="登 录";}})'
    + '.catch(function(e){var el=document.getElementById("err");el.textContent=e.message;el.style.display="block";btn.disabled=false;btn.textContent="登 录";});}'
    + '<\/script></body></html>';
}

function buildPanel(): string {
  return buildPanelHead() + buildPanelBody() + buildPanelJS() + '</body></html>';
}

function buildPanelHead(): string {
  return '<!DOCTYPE html><html lang="zh-CN"><head>'
    + '<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>API Key Pool</title><style>' + PANEL_CSS + '</style></head>';
}

const PANEL_CSS = [
  '*{box-sizing:border-box;margin:0;padding:0}',
  ':root{--bg:#07080d;--s1:#0d1117;--s2:#161b22;--bd:#30363d;--blue:#58a6ff;--green:#3fb950;--red:#f85149;--orange:#d29922;--purple:#bc8cff;--text:#e6edf3;--dim:#7d8590}',
  'body{height:100vh;display:flex;background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;font-size:14px;overflow:hidden}',
  '::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:var(--s1)}::-webkit-scrollbar-thumb{background:#444c56;border-radius:3px}',
  '.sb{width:215px;flex-shrink:0;background:var(--s1);border-right:1px solid var(--bd);display:flex;flex-direction:column;height:100vh}',
  '.logo{padding:18px 15px 14px;border-bottom:1px solid var(--bd)}',
  '.logo-t{font-size:13px;font-weight:800;color:var(--blue);letter-spacing:.5px;font-family:monospace}',
  '.logo-s{font-size:10px;color:var(--dim);margin-top:2px;font-family:monospace}',
  '.nav{padding:10px 7px;flex:1}',
  '.ni{display:flex;align-items:center;gap:8px;padding:9px 11px;border-radius:7px;color:var(--dim);cursor:pointer;border:none;background:none;width:100%;font-size:13px;font-weight:600;transition:all .15s;text-align:left;font-family:system-ui,sans-serif}',
  '.ni:hover{background:var(--s2);color:var(--text)}.ni.on{background:var(--s2);color:var(--blue)}',
  '.sbf{padding:10px;border-top:1px solid var(--bd)}',
  '.lg-btn{width:100%;padding:8px;background:none;border:1px solid var(--bd);border-radius:7px;color:var(--dim);cursor:pointer;font-size:12px;font-family:system-ui,sans-serif}',
  '.lg-btn:hover{border-color:var(--red);color:var(--red)}',
  '.main{flex:1;overflow-y:auto}',
  '.pg{display:none;padding:24px 26px;max-width:1020px}.pg.on{display:block}',
  '.pt{font-size:20px;font-weight:800;margin-bottom:3px}.ps{font-size:12px;color:var(--dim);margin-bottom:18px}',
  '.sg{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:14px}',
  '.sc{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:14px;position:relative;overflow:hidden}',
  '.sc::after{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:var(--c)}',
  '.sl{font-size:10px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-bottom:5px}',
  '.sv{font-size:24px;font-weight:700;font-family:monospace;color:var(--c)}',
  '.card{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:15px;margin-bottom:12px}',
  '.ct{font-size:10px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:1.2px;margin-bottom:11px}',
  '.btn{display:inline-flex;align-items:center;gap:5px;padding:7px 13px;border-radius:7px;font-size:12px;font-weight:600;cursor:pointer;transition:all .15s;border:none;font-family:system-ui,sans-serif}',
  '.bp{background:var(--blue);color:#000}.bp:hover{opacity:.85}',
  '.br{background:var(--red);color:#fff}.br:hover{opacity:.85}',
  '.bg_{background:none;border:1px solid var(--bd);color:var(--text)}.bg_:hover{border-color:var(--blue);color:var(--blue)}',
  '.sm{padding:4px 9px;font-size:11px}.btn:disabled{opacity:.35;cursor:not-allowed}',
  '.brow{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}',
  '.fg{margin-bottom:11px}',
  '.fl{display:block;font-size:11px;font-weight:700;color:var(--dim);text-transform:uppercase;margin-bottom:5px}',
  '.fi,.ft{width:100%;background:var(--bg);border:1px solid var(--bd);border-radius:7px;padding:8px 11px;color:var(--text);font-family:monospace;font-size:12px;outline:none}',
  '.fi:focus,.ft:focus{border-color:var(--blue)}.ft{min-height:150px;resize:vertical;line-height:1.7}',
  '.uz{border:2px dashed #444c56;border-radius:10px;padding:30px 16px;text-align:center;cursor:pointer;transition:all .2s;margin-bottom:10px}',
  '.uz:hover,.uz.ov{border-color:var(--blue);background:rgba(88,166,255,.04)}',
  '.tw{overflow-x:auto;border:1px solid var(--bd);border-radius:10px}',
  'table{width:100%;border-collapse:collapse;font-size:12px}',
  'th{padding:9px 11px;background:var(--s2);color:var(--dim);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;text-align:left;white-space:nowrap}',
  'td{padding:9px 11px;border-top:1px solid var(--bd)}tr:hover td{background:var(--s2)}',
  '.ec{font-family:monospace;font-size:11px;max-width:185px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
  '.badge{display:inline-flex;align-items:center;gap:3px;padding:2px 7px;border-radius:20px;font-size:10px;font-weight:700}',
  '.badge::before{content:"";width:5px;height:5px;border-radius:50%;background:currentColor}',
  '.bac{background:rgba(63,185,80,.15);color:var(--green)}.bex{background:rgba(210,153,34,.15);color:var(--orange)}',
  '.bin{background:rgba(248,81,73,.15);color:var(--red)}.bun{background:rgba(125,133,144,.1);color:var(--dim)}',
  '.bpl{background:rgba(188,140,255,.15);color:var(--purple)}',
  '.prog{height:5px;background:#21262d;border-radius:3px;overflow:hidden;margin:6px 0}',
  '.pb{height:100%;background:linear-gradient(90deg,var(--blue),var(--purple));transition:width .4s;border-radius:3px}',
  '.logbox{background:var(--bg);border:1px solid var(--bd);border-radius:7px;padding:11px;font-family:monospace;font-size:11px;max-height:220px;overflow-y:auto;line-height:1.9}',
  '.ll{display:block}.lok{color:var(--green)}.ler{color:var(--red)}.lin{color:var(--dim)}.lwn{color:var(--orange)}',
  '.al{padding:9px 12px;border-radius:7px;font-size:12px;margin-bottom:10px;border-left:3px solid}',
  '.aok{background:rgba(63,185,80,.1);border-color:var(--green);color:var(--green)}',
  '.aer{background:rgba(248,81,73,.1);border-color:var(--red);color:var(--red)}',
  '.awk{background:rgba(210,153,34,.1);border-color:var(--orange);color:var(--orange)}',
  '.sp{width:12px;height:12px;border:2px solid rgba(255,255,255,.15);border-top-color:currentColor;border-radius:50%;animation:sp .5s linear infinite;flex-shrink:0}',
  '@keyframes sp{to{transform:rotate(360deg)}}',
  '.abox{background:var(--bg);border:1px solid var(--bd);border-radius:7px;padding:12px;font-family:monospace;font-size:12px;line-height:2;position:relative}',
  '.cpb{position:absolute;top:7px;right:7px;background:var(--s2);border:1px solid var(--bd);border-radius:4px;padding:2px 7px;color:var(--dim);cursor:pointer;font-size:11px;font-family:system-ui,sans-serif}',
  '.cpb:hover{color:var(--blue)}',
  '.probe-res{margin-top:12px;font-size:12px;display:none}',
  '.probe-ep{margin-bottom:9px;padding:10px;border:1px solid var(--bd);border-radius:7px}',
  '.pre{white-space:pre-wrap;word-break:break-all;font-family:monospace;font-size:11px;color:var(--dim);margin-top:6px;max-height:140px;overflow-y:auto}',
].join('');

function buildPanelBody(): string {
  return '<body>'
    + '<aside class="sb">'
    + '<div class="logo"><div class="logo-t">API KEY POOL</div><div class="logo-s">DENO DEPLOY</div></div>'
    + '<nav class="nav">'
    + '<button class="ni on" id="n-dash">&#128202; 仪表盘</button>'
    + '<button class="ni" id="n-import">&#11014; 导入账号</button>'
    + '<button class="ni" id="n-accs">&#128101; 账号列表</button>'
    + '<button class="ni" id="n-cf">&#128273; CF Cookie</button>'
    + '<button class="ni" id="n-api">&#128279; 接口信息</button>'
    + '</nav>'
    + '<div class="sbf"><button class="lg-btn" id="btn-logout">退出登录</button></div>'
    + '</aside>'
    + '<div class="main">'
    + buildDashPage()
    + buildImportPage()
    + buildAccsPage()
    + buildCFPage()
    + buildApiPage()
    + '</div>';
}

function buildDashPage(): string {
  return '<div id="pg-dash" class="pg on">'
    + '<div class="pt">仪表盘</div><div class="ps">账号池实时状态</div>'
    + '<div class="sg">'
    + '<div class="sc" style="--c:var(--blue)"><div class="sl">总账号</div><div class="sv" id="s-total">—</div></div>'
    + '<div class="sc" style="--c:var(--green)"><div class="sl">有效</div><div class="sv" id="s-active">—</div></div>'
    + '<div class="sc" style="--c:var(--orange)"><div class="sl">过期</div><div class="sv" id="s-expired">—</div></div>'
    + '<div class="sc" style="--c:var(--red)"><div class="sl">失效</div><div class="sv" id="s-invalid">—</div></div>'
    + '<div class="sc" style="--c:var(--purple)"><div class="sl">总调用</div><div class="sv" id="s-calls">—</div></div>'
    + '<div class="sc" style="--c:var(--dim)"><div class="sl">错误数</div><div class="sv" id="s-errors">—</div></div>'
    + '</div>'
    + '<div class="card"><div class="ct">有效率</div>'
    + '<div class="prog"><div class="pb" id="hbar" style="width:0%"></div></div>'
    + '<div style="font-size:11px;color:var(--dim);margin-top:4px" id="hlabel">加载中...</div></div>'
    + '<div class="card"><div class="ct">快速操作</div>'
    + '<div class="brow">'
    + '<button class="btn bg_" id="btn-refresh">刷新状态</button>'
    + '<button class="btn bg_" id="btn-probe">&#128269; 后端诊断</button>'
    + '<button class="btn br sm" id="btn-wipe">清空账号池</button>'
    + '</div>'
    + '<div class="probe-res" id="probe-res"></div>'
    + '</div></div>';
}

function buildImportPage(): string {
  return '<div id="pg-import" class="pg">'
    + '<div class="pt">导入账号</div><div class="ps">支持 codex-json 格式，最多 600 个</div>'
    + '<div id="ial"></div>'
    + '<div class="card"><div class="ct">&#128193; 批量上传 JSON 文件</div>'
    + '<div id="uz" class="uz"><div style="font-size:26px;margin-bottom:7px;opacity:.4">&#11014;</div>'
    + '<div style="font-weight:700;margin-bottom:4px">拖放 .json 文件到这里，或点击选择</div>'
    + '<div style="font-size:12px;color:var(--dim)">每个文件 = 一个 codex-json 账号 · 支持多选</div></div>'
    + '<input type="file" id="fi" accept=".json" multiple style="display:none">'
    + '<div id="finfo" style="display:none;margin-bottom:10px">'
    + '<div style="font-size:12px;color:var(--dim);margin-bottom:5px">已选 <span id="fcnt">0</span> 个文件</div>'
    + '<div class="prog"><div class="pb" id="uprog" style="width:0%"></div></div>'
    + '<div style="font-size:11px;color:var(--dim);margin-top:3px" id="ust">就绪</div></div>'
    + '<button class="btn bp" id="ubtn" disabled>开始上传导入</button></div>'
    + '<div class="card"><div class="ct">&#128203; 粘贴 JSON 数组（批量）</div>'
    + '<div class="fg"><label class="fl">将多个 codex-json 放入数组</label><textarea id="parr" class="ft"></textarea></div>'
    + '<button class="btn bp" id="btn-arr">批量导入</button></div>'
    + '<div class="card"><div class="ct">&#128203; 粘贴单个 JSON</div>'
    + '<div class="fg"><label class="fl">单个 codex-json 内容</label><textarea id="pone" class="ft" style="min-height:110px"></textarea></div>'
    + '<button class="btn bp" id="btn-one">导入单个</button></div>'
    + '<div id="logcard" class="card" style="display:none"><div class="ct">导入日志</div>'
    + '<div class="logbox" id="lbox"></div></div></div>';
}

function buildAccsPage(): string {
  return '<div id="pg-accs" class="pg">'
    + '<div class="pt">账号列表</div><div class="ps">所有已导入账号</div>'
    + '<div class="brow"><button class="btn bg_" id="btn-reload">刷新列表</button>'
    + '<button class="btn br sm" id="btn-wipe2">清空所有</button></div>'
    + '<div id="accscon"><div style="color:var(--dim);padding:20px">切换到账号列表自动加载</div></div>'
    + '</div>';
}

function buildCFPage(): string {
  return '<div id="pg-cf" class="pg">'
    + '<div class="pt">CF Cookie 管理</div>'
    + '<div class="ps">cf-clearance 有效期约 1 小时，过期后需要重新获取并更新</div>'
    + '<div id="cf-status" class="card" style="margin-bottom:12px"></div>'
    + '<div class="card"><div class="ct">更新 CF Cookie</div>'
    + '<div class="fg"><label class="fl">cf-clearance（从浏览器 DevTools → Application → Cookies → chatgpt.com 获取）</label>'
    + '<textarea id="cf-input" class="ft" style="min-height:80px;font-size:11px" placeholder="Fi3kFiK..."></textarea></div>'
    + '<div class="fg"><label class="fl">__Secure-next-auth.session-token.0（可选，有助于绕过验证）</label>'
    + '<textarea id="st-input" class="ft" style="min-height:80px;font-size:11px" placeholder="eyJhbGci..."></textarea></div>'
    + '<button class="btn bp" id="btn-setcf">保存 CF Cookie</button>'
    + '<div id="cf-al" style="margin-top:10px"></div>'
    + '</div>'
    + '<div class="card"><div class="ct">获取步骤</div>'
    + '<div style="font-size:12px;color:var(--dim);line-height:2">'
    + '1. 用浏览器登录 <b style="color:var(--text)">chatgpt.com</b><br>'
    + '2. 按 F12 → Application → Cookies → https://chatgpt.com<br>'
    + '3. 找到 <b style="color:var(--blue)">cf-clearance</b> 复制 Value<br>'
    + '4. 找到 <b style="color:var(--blue)">__Secure-next-auth.session-token.0</b> 复制 Value<br>'
    + '5. 粘贴到上方，点保存<br>'
    + '<span style="color:var(--orange)">⚠ cf-clearance 绑定浏览器 IP，约 1 小时后失效，需重新获取</span>'
    + '</div></div></div>';
}

function buildApiPage(): string {
  return '<div id="pg-api" class="pg">'
    + '<div class="pt">接口信息</div><div class="ps">将本服务作为 OpenAI API 代理</div>'
    + '<div class="card"><div class="ct">代理地址</div>'
    + '<div class="abox"><button class="cpb" id="cp-base">复制</button>'
    + '<span style="color:var(--dim)">Base URL: </span><span style="color:var(--green)" id="abase"></span><br>'
    + '<span style="color:var(--dim)">API Key:  </span><span style="color:var(--blue)">sk-any（任意字符串）</span>'
    + '</div></div>'
    + '<div class="card"><div class="ct">Python 示例</div>'
    + '<div class="abox"><button class="cpb" id="cp-pyc">复制</button><pre id="pyc" style="font-size:11px;white-space:pre-wrap"></pre></div></div>'
    + '</div>';
}

function buildPanelJS(): string {
  const lines: string[] = [];
  lines.push('<script>');
  lines.push('(function(){');
  lines.push('function on(id,ev,fn){var el=document.getElementById(id);if(el)el.addEventListener(ev,fn);}');

  lines.push('function SP(btn,id){');
  lines.push('  document.querySelectorAll(".pg").forEach(function(p){p.classList.remove("on");});');
  lines.push('  document.querySelectorAll(".ni").forEach(function(b){b.classList.remove("on");});');
  lines.push('  document.getElementById("pg-"+id).classList.add("on");');
  lines.push('  btn.classList.add("on");');
  lines.push('  if(id==="dash")loadStats();');
  lines.push('  if(id==="accs")loadAccs();');
  lines.push('  if(id==="api")fillApi();');
  lines.push('  if(id==="cf")loadCFStatus();');
  lines.push('}');
  lines.push('on("n-dash","click",function(){SP(this,"dash");});');
  lines.push('on("n-import","click",function(){SP(this,"import");});');
  lines.push('on("n-accs","click",function(){SP(this,"accs");});');
  lines.push('on("n-cf","click",function(){SP(this,"cf");});');
  lines.push('on("n-api","click",function(){SP(this,"api");});');

  lines.push('function setAl(id,cls,msg){document.getElementById(id).innerHTML=msg?"<div class=\\"al "+cls+"\\">"+msg+"</div>":""}');
  lines.push('function cp(t){navigator.clipboard.writeText(t).catch(function(){});}');
  lines.push('function lg(msg,t){document.getElementById("logcard").style.display="block";var b=document.getElementById("lbox"),s=document.createElement("span");s.className="ll l"+(t||"in");s.textContent="["+new Date().toLocaleTimeString()+"] "+msg;b.appendChild(s);b.scrollTop=b.scrollHeight;}');
  lines.push('function sBadge(s){var m={active:"bac",expired:"bex",invalid:"bin",unknown:"bun"};var el=document.createElement("span");el.className="badge "+(m[s]||"bun");el.textContent=s||"unknown";return el;}');
  lines.push('function pBadge(p){var el=document.createElement("span");el.className="badge "+(p==="plus"||p==="pro"?"bpl":"bun");el.textContent=p||"free";return el;}');

  lines.push('function loadStats(){');
  lines.push('  fetch("/admin/api/stats").then(function(r){return r.json();}).then(function(d){');
  lines.push('    ["total","active","expired","invalid","calls","errors"].forEach(function(k){var el=document.getElementById("s-"+k);if(el)el.textContent=d[k]||0;});');
  lines.push('    var pct=d.total>0?Math.round(d.active/d.total*100):0;');
  lines.push('    document.getElementById("hbar").style.width=pct+"%";');
  lines.push('    document.getElementById("hlabel").textContent="有效率 "+pct+"% ("+d.active+"/"+d.total+" 个账号可用)";');
  lines.push('  }).catch(function(e){document.getElementById("hlabel").textContent="加载失败: "+e.message;});');
  lines.push('}');

  lines.push('function runProbe(){');
  lines.push('  var box=document.getElementById("probe-res");box.style.display="block";box.innerHTML="";');
  lines.push('  var ld=document.createElement("div");ld.style.color="var(--dim)";ld.textContent="🔍 诊断中...";box.appendChild(ld);');
  lines.push('  fetch("/admin/api/probe",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"})');
  lines.push('  .then(function(r){return r.json();}).then(function(d){');
  lines.push('    box.innerHTML="";');
  lines.push('    var info=document.createElement("div");info.style.cssText="font-size:12px;margin-bottom:10px;color:var(--dim)";');
  lines.push('    info.textContent="Email: "+(d.email||"?")+" | Token: "+(d.tokenLen||0)+"chars | 过期: "+(d.expired?"是":"否");');
  lines.push('    box.appendChild(info);');
  lines.push('    (d.results||[]).forEach(function(r){');
  lines.push('      var col=r.ok?"var(--green)":r.error?"var(--red)":"var(--orange)";');
  lines.push('      var ep=document.createElement("div");ep.className="probe-ep";');
  lines.push('      var title=document.createElement("div");title.style.fontWeight="700";title.style.color=col;');
  lines.push('      title.textContent=(r.ok?"✓ ":"✗ ")+r.url+" HTTP "+(r.status||"ERR");');
  lines.push('      ep.appendChild(title);');
  lines.push('      if(r.error){var err=document.createElement("div");err.style.color="var(--red)";err.textContent=r.error;ep.appendChild(err);}');
  lines.push('      if(r.body){var pre=document.createElement("div");pre.className="pre";pre.textContent=r.body;ep.appendChild(pre);}');
  lines.push('      box.appendChild(ep);');
  lines.push('    });');
  lines.push('  }).catch(function(e){box.innerHTML="";var err=document.createElement("span");err.style.color="var(--red)";err.textContent="诊断失败: "+e.message;box.appendChild(err);});');
  lines.push('}');

  lines.push('function loadCFStatus(){');
  lines.push('  var box=document.getElementById("cf-status");if(!box)return;');
  lines.push('  fetch("/admin/api/getcf").then(function(r){return r.json();}).then(function(d){');
  lines.push('    if(d.set){');
  lines.push('      box.innerHTML="<div class=\\"al aok\\">✓ CF Cookie 已设置 | cf-clearance: "+d.cfLen+"chars | session-token: "+d.stLen+"chars</div>";');
  lines.push('    } else {');
  lines.push('      box.innerHTML="<div class=\\"al awk\\">⚠ 未设置 CF Cookie，代理请求会被 Cloudflare 拦截 (403)</div>";');
  lines.push('    }');
  lines.push('  }).catch(function(){box.innerHTML="<div class=\\"al aer\\">加载失败</div>";});');
  lines.push('}');

  lines.push('function saveCF(){');
  lines.push('  var cf=document.getElementById("cf-input").value.trim();');
  lines.push('  var st=document.getElementById("st-input").value.trim();');
  lines.push('  if(!cf)return setAl("cf-al","awk","请填写 cf-clearance");');
  lines.push('  fetch("/admin/api/setcf",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({cfClearance:cf,sessionToken:st})})');
  lines.push('  .then(function(r){return r.json();}).then(function(d){');
  lines.push('    if(d.ok){setAl("cf-al","aok","✓ 保存成功！cf-clearance: "+d.cfLen+"chars");loadCFStatus();}');
  lines.push('    else setAl("cf-al","aer",d.error||"保存失败");');
  lines.push('  }).catch(function(e){setAl("cf-al","aer",e.message);});');
  lines.push('}');

  lines.push('function loadAccs(){');
  lines.push('  var con=document.getElementById("accscon");con.innerHTML="";');
  lines.push('  var ld=document.createElement("div");ld.style.cssText="color:var(--dim);padding:20px";ld.textContent="加载中...";con.appendChild(ld);');
  lines.push('  fetch("/admin/api/list").then(function(r){return r.json();}).then(function(d){');
  lines.push('    var accs=d.accounts||[];con.innerHTML="";');
  lines.push('    if(!accs.length){var em=document.createElement("div");em.style.cssText="color:var(--dim);padding:28px;text-align:center";em.textContent="暂无账号";con.appendChild(em);return;}');
  lines.push('    var wrap=document.createElement("div");wrap.className="tw";');
  lines.push('    var table=document.createElement("table");');
  lines.push('    table.innerHTML="<thead><tr><th>Email</th><th>状态</th><th>套餐</th><th>到期</th><th>操作</th></tr></thead>";');
  lines.push('    var tbody=document.createElement("tbody");');
  lines.push('    accs.forEach(function(a){');
  lines.push('      var tr=document.createElement("tr");');
  lines.push('      var tdE=document.createElement("td");tdE.className="ec";tdE.title=a.email;tdE.textContent=a.email;');
  lines.push('      var tdS=document.createElement("td");tdS.appendChild(sBadge(a.status));');
  lines.push('      var tdP=document.createElement("td");tdP.appendChild(pBadge(a.plan));');
  lines.push('      var tdX=document.createElement("td");tdX.style.cssText="font-size:11px;color:var(--dim)";tdX.textContent=a.expired?new Date(a.expired).toLocaleDateString("zh-CN"):"—";');
  lines.push('      var tdA=document.createElement("td");tdA.style.whiteSpace="nowrap";');
  lines.push('      var del=document.createElement("button");del.className="btn br sm";del.textContent="删除";');
  lines.push('      (function(email){del.addEventListener("click",function(){if(!confirm("删除: "+email))return;fetch("/admin/api/delete",{method:"DELETE",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:email})}).then(function(){loadAccs();loadStats();});});})(a.email);');
  lines.push('      tdA.appendChild(del);');
  lines.push('      tr.appendChild(tdE);tr.appendChild(tdS);tr.appendChild(tdP);tr.appendChild(tdX);tr.appendChild(tdA);');
  lines.push('      tbody.appendChild(tr);');
  lines.push('    });');
  lines.push('    table.appendChild(tbody);wrap.appendChild(table);con.appendChild(wrap);');
  lines.push('  }).catch(function(e){con.innerHTML="";var err=document.createElement("div");err.className="al aer";err.textContent=e.message;con.appendChild(err);});');
  lines.push('}');

  lines.push('function wipeAll(){if(!confirm("确认清空所有账号？"))return;fetch("/admin/api/wipe",{method:"DELETE"}).then(function(){loadAccs();loadStats();});}');

  lines.push('var SF=[];var uz=document.getElementById("uz");');
  lines.push('if(uz){uz.addEventListener("click",function(){document.getElementById("fi").click();});uz.addEventListener("dragover",function(e){e.preventDefault();uz.classList.add("ov");});uz.addEventListener("dragleave",function(){uz.classList.remove("ov");});uz.addEventListener("drop",function(e){e.preventDefault();uz.classList.remove("ov");setFiles(e.dataTransfer.files);});}');
  lines.push('on("fi","change",function(e){setFiles(e.target.files);});');
  lines.push('function setFiles(list){SF=Array.from(list).filter(function(f){return f.name.endsWith(".json");});var n=SF.length;var c=document.getElementById("fcnt");if(c)c.textContent=n;var fi=document.getElementById("finfo");if(fi)fi.style.display=n?"block":"none";var ub=document.getElementById("ubtn");if(ub)ub.disabled=!n;var us=document.getElementById("ust");if(us)us.textContent="已选 "+n+" 个";}');

  lines.push('function doUpload(){if(!SF.length)return;var btn=document.getElementById("ubtn");btn.disabled=true;btn.innerHTML="<div class=\\"sp\\"></div> 读取中...";var all=[],total=SF.length,idx=0;lg("读取 "+total+" 个文件...","in");function next(){if(idx>=total){btn.innerHTML="<div class=\\"sp\\"></div> 上传中...";fetch("/admin/api/batch",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({files:all})}).then(function(r){return r.json();}).then(function(res){lg("完成：成功 "+res.success+"，失败 "+res.failed,res.failed===0?"ok":"wn");setAl("ial",res.failed===0?"aok":res.success>0?"awk":"aer","成功 "+res.success+"，失败 "+res.failed);btn.disabled=false;btn.textContent="开始上传导入";loadStats();}).catch(function(e){lg("失败: "+e.message,"er");btn.disabled=false;btn.textContent="开始上传导入";});return;}var rd=new FileReader();rd.onload=function(ev){try{all.push(JSON.parse(ev.target.result));}catch(err){lg("解析失败: "+SF[idx].name,"er");}idx++;document.getElementById("uprog").style.width=Math.round(idx/total*100)+"%";next();};rd.onerror=function(){idx++;next();};rd.readAsText(SF[idx]);}next();}');

  lines.push('function importArr(){var text=document.getElementById("parr").value.trim();if(!text)return setAl("ial","awk","请粘贴 JSON 数组");var arr;try{arr=JSON.parse(text);}catch(e){return setAl("ial","aer","JSON解析失败: "+e.message);}if(!Array.isArray(arr))return setAl("ial","aer","需要数组格式");lg("批量导入 "+arr.length+" 个...","in");fetch("/admin/api/batch",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({files:arr})}).then(function(r){return r.json();}).then(function(res){lg("完成: 成功"+res.success+" 失败"+res.failed,res.failed===0?"ok":"wn");setAl("ial",res.failed===0?"aok":res.success>0?"awk":"aer","成功 "+res.success+"，失败 "+res.failed);loadStats();}).catch(function(e){setAl("ial","aer",e.message);});}');

  lines.push('function importOne(){var text=document.getElementById("pone").value.trim();if(!text)return setAl("ial","awk","请粘贴 JSON");var json;try{json=JSON.parse(text);}catch(e){return setAl("ial","aer","格式错误: "+e.message);}fetch("/admin/api/import",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(json)}).then(function(r){return r.json();}).then(function(d){if(d.ok){lg("✓ "+d.email,"ok");setAl("ial","aok","导入成功: "+d.email);}else{setAl("ial","aer",d.error||"失败");}loadStats();}).catch(function(e){setAl("ial","aer",e.message);});}');

  lines.push('function fillApi(){var base=location.origin+"/v1";document.getElementById("abase").textContent=base;document.getElementById("pyc").textContent="from openai import OpenAI\\nclient = OpenAI(base_url=\\""+base+"\\", api_key=\\"sk-any\\")\\nresp = client.chat.completions.create(model=\\"gpt-4o\\", messages=[{\\"role\\":\\"user\\",\\"content\\":\\"Hi!\\"}])\\nprint(resp.choices[0].message.content)";on("cp-base","click",function(){cp(base);});on("cp-pyc","click",function(){cp(document.getElementById("pyc").textContent);});}');

  lines.push('on("btn-logout","click",function(){fetch("/admin/logout",{method:"POST"}).then(function(){location.reload();});});');
  lines.push('on("btn-refresh","click",loadStats);');
  lines.push('on("btn-probe","click",runProbe);');
  lines.push('on("btn-wipe","click",wipeAll);');
  lines.push('on("btn-wipe2","click",wipeAll);');
  lines.push('on("btn-reload","click",loadAccs);');
  lines.push('on("ubtn","click",doUpload);');
  lines.push('on("btn-arr","click",importArr);');
  lines.push('on("btn-one","click",importOne);');
  lines.push('on("btn-setcf","click",saveCF);');

  lines.push('loadStats();');
  lines.push('})();');
  lines.push('<\/script>');
  return lines.join('\n');
}
