#!/usr/bin/env node
// raycast-bridge — OpenAI-совместимый прокси к Raycast AI (backend.raycast.com)
// Один файл, ноль зависимостей. Запуск: node server.mjs (или npm start)
// При первом запуске сам проводит OAuth-логин Raycast и сохраняет токен.
//
// Реверс-основания (Raycast 2.6.1.0, MS Store):
//   backend/index.mjs: Pb/base URL, $Kt (OpenAI-подобное тело), Kqt/Jqt (подпись и заголовки),
//   Wfn/Gfn (deviceTag), zUt (OAuth client), /api/v1/ai/models (каталог, без авторизации).
//   Raycast.dll: Secrets.get_SignatureSecret (статический 64-байтовый ключ).

import http from "node:http";
import { createHash, createHmac, randomUUID } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, appendFileSync, unlinkSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const PORT = +(process.env.RAYCAST_BRIDGE_PORT || 8787);
const API = process.env.RAYCAST_API || "https://backend.raycast.com";
const AUTH_HOST = process.env.RAYCAST_AUTH_HOST || "https://www.raycast.com";
const CLIENT_ID = "FRsHICIAlyPB_v2m4tfVqHtVUS40Ieco_da0Y6zBwgA";
const REDIRECT_URI = `${AUTH_HOST}/oauth-redirect?scheme=com.raycast`;
const SIG_SECRET = "6bc455473576ce2cd6f70426caff867aabbe3f7291c1a79681af5e8ce0ca1408";
const DEVICE_SALT = "xK7mQ2vLpN8wY4jR6tBfHsAeDc";
const SCHEME = "com.raycast";
const TOKEN_FILE = path.join(DIR, "token.json");
const DEVICE_FILE = path.join(DIR, "device.json");
const CODE_FILE = path.join(DIR, "login-code.txt");
const CATALOG_CACHE = path.join(DIR, "catalog-cache.json");
const UA = "Raycast/2.6.1.0 (x-Windows Version 10.0.26100)";

const log = (...a) => console.log(new Date().toISOString(), ...a);
const die = (msg) => { console.error(msg); process.exit(1); };
const run = (cmd, args) => new Promise((res) => execFile(cmd, args, { windowsHide: true }, (err, stdout) => res({ err, stdout: String(stdout ?? "") })));

// ── подпись X-Raycast-Signature-v2 ────────────────────────────────────────────
// rot13 для букв, +5 mod 10 для цифр (функция Uqt из index.mjs)
function rot13shift(str) {
  let out = "";
  for (const ch of str) {
    const c = ch.charCodeAt(0);
    if (c >= 65 && c <= 90) out += String.fromCharCode((c - 65 + 13) % 26 + 65);
    else if (c >= 97 && c <= 122) out += String.fromCharCode((c - 97 + 13) % 26 + 97);
    else if (c >= 48 && c <= 57) out += String.fromCharCode((c - 48 + 5) % 10 + 48);
    else out += ch;
  }
  return out;
}
const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");

function signedHeaders(bodyStr, deviceId, accessToken) {
  const ts = Math.floor(Date.now() / 1e3).toString();
  const payload = [ts, deviceId, sha256hex(bodyStr)].map(rot13shift).join(".");
  const sig = createHmac("sha256", SIG_SECRET).update(payload, "utf8").digest("hex");
  return {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": UA,
    "X-Raycast-Timestamp": ts,
    "X-Raycast-DeviceId": deviceId,
    "X-Raycast-Signature-v2": sig,
    "X-Raycast-Experimental": "autoModels",
    ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
  };
}

// ── deviceTag: sha256(uuid + serial + salt + "Production") ────────────────────
async function getDeviceTag() {
  if (process.env.RAYCAST_DEVICE_TAG) return process.env.RAYCAST_DEVICE_TAG;
  if (existsSync(DEVICE_FILE)) return JSON.parse(readFileSync(DEVICE_FILE, "utf8")).deviceTag;
  let uuid = process.env.RAYCAST_DEVICE_UUID, serial = process.env.RAYCAST_DEVICE_SERIAL;
  if (!uuid || !serial) {
    const q = await run("powershell", ["-NoProfile", "-Command",
      "$p = Get-CimInstance Win32_ComputerSystemProduct | Select-Object -First 1; Write-Output ($p.UUID + '|' + $p.IdentifyingNumber)"]);
    const line = (q.stdout || "").trim().split("\n")[0]?.trim();
    if (line && line.includes("|")) [uuid, serial] = line.split("|");
  }
  let tag;
  if (uuid && serial) {
    tag = sha256hex(`${uuid}${serial}${DEVICE_SALT}Production`); // Wfn из index.mjs
  } else {
    tag = sha256hex(`fallback:${randomUUID()}:${DEVICE_SALT}:Production`);
    log("WARN: SMBIOS uuid/serial недоступны, использую стабильный случайный deviceTag");
  }
  writeFileSync(DEVICE_FILE, JSON.stringify({ deviceTag: tag, uuid: uuid ?? null }, null, 1));
  return tag;
}

// ── токен ─────────────────────────────────────────────────────────────────────
const readToken = () => (existsSync(TOKEN_FILE) ? JSON.parse(readFileSync(TOKEN_FILE, "utf8")) : null);
const writeToken = (t) => writeFileSync(TOKEN_FILE, JSON.stringify(t, null, 1));
const tokenFresh = (t) => t?.access_token && (!t.expires_at || t.expires_at - 60_000 > Date.now());

async function oauthToken(form) {
  const r = await fetch(`${API}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "User-Agent": UA },
    body: new URLSearchParams(form).toString(),
  });
  const body = await r.text();
  if (!r.ok) throw new Error(`oauth/token ${r.status}: ${body.slice(0, 300)}`);
  const j = JSON.parse(body);
  if (!j.access_token) throw new Error(`нет access_token: ${body.slice(0, 300)}`);
  return { access_token: j.access_token, refresh_token: j.refresh_token ?? null,
           expires_at: Number.isFinite(j.expires_in) ? Date.now() + j.expires_in * 1000 : null,
           token_type: j.token_type ?? "Bearer" };
}

async function refreshToken(t) {
  if (!t?.refresh_token) return null;
  try {
    const n = await oauthToken({ client_id: CLIENT_ID, grant_type: "refresh_token", refresh_token: t.refresh_token });
    writeToken(n); log("токен обновлён (refresh_token)"); return n;
  } catch (e) { log("refresh не удался:", e.message); return null; }
}

// ── OAuth логин: перехват com.raycast:// через HKCU ───────────────────────────
async function doLogin() {
  const verifier = randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, ""); // 64 chars
  const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
  const state = randomUUID();

  // 1. HKCU-оверрайд схемы com.raycast:// → наш кэтчер (приоритетнее HKCR/HKLM)
  const regKey = `HKCU\\Software\\Classes\\${SCHEME}`;
  const had = await run("reg", ["query", regKey]);
  const nodePath = process.execPath, scriptPath = fileURLToPath(import.meta.url);
  await run("reg", ["add", regKey, "/ve", "/d", `URL:com.raycast`, "/f"]);
  await run("reg", ["add", regKey, "/v", "URL Protocol", "/d", "", "/f"]);
  await run("reg", ["add", `${regKey}\\shell\\open\\command`, "/ve", "/d",
    `"${nodePath}" "${scriptPath}" --catch "%1"`, "/f"]);
  if (existsSync(CODE_FILE)) unlinkSync(CODE_FILE);

  const url = `${AUTH_HOST}/oauth/authorize?` + new URLSearchParams({
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: "read write",
    code_challenge: challenge, code_challenge_method: "S256", response_type: "code", state,
  });
  log("Открываю браузер для входа в Raycast…");
  spawn("cmd", ["/c", "start", "", url], { detached: true, stdio: "ignore" }).unref();

  // 2. ждём код из кэтчера
  const deadline = Date.now() + 300_000;
  let code = null;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 500));
    if (existsSync(CODE_FILE)) {
      const m = readFileSync(CODE_FILE, "utf8").match(/code=([^&\s"']+)/);
      if (m) { code = m[1]; break; }
    }
  }
  if (!had.err?.code) { /* ключ существовал — оставляем как было не трогая содержимое */ }
  else await run("reg", ["delete", regKey, "/f"]); // удаляем только созданное нами
  if (!code) throw new Error("код авторизации не получен за 5 минут (Raycast перехватил ссылку? закрой приложение и запусти снова)");
  try { unlinkSync(CODE_FILE); } catch {}

  // 3. обмен
  const tok = await oauthToken({ client_id: CLIENT_ID, grant_type: "authorization_code",
    code, redirect_uri: REDIRECT_URI, code_verifier: verifier });
  writeToken(tok);
  log("✓ вход выполнен, токен сохранён в token.json");
  return tok;
}

let tokenPromise = null;
async function ensureToken(forceLogin = false) {
  let t = readToken();
  if (!forceLogin && tokenFresh(t)) return t;
  if (t?.refresh_token) { const n = await refreshToken(t); if (n) return n; }
  if (forceLogin || !t?.refresh_token) {
    if (!tokenPromise) tokenPromise = doLogin().finally(() => { tokenPromise = null; });
    return tokenPromise;
  }
  return t;
}

// ── каталог моделей (GET /api/v1/ai/models — публичный) ───────────────────────
let catalog = { map: new Map(), list: [], fetchedAt: 0 };
async function getCatalog(force = false) {
  if (!force && catalog.list.length && Date.now() - catalog.fetchedAt < 600_000) return catalog;
  try {
    const r = await fetch(`${API}/api/v1/ai/models`, { headers: { "Accept": "application/json", "User-Agent": UA, "X-Raycast-Experimental": "autoModels" } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    catalog = { map: new Map(j.models.map((m) => [m.id, m])), list: j.models, fetchedAt: Date.now() };
    writeFileSync(CATALOG_CACHE, JSON.stringify(j, null, 1));
  } catch (e) {
    if (!catalog.list.length && existsSync(CATALOG_CACHE)) {
      const j = JSON.parse(readFileSync(CATALOG_CACHE, "utf8"));
      catalog = { map: new Map(j.models.map((m) => [m.id, m])), list: j.models, fetchedAt: 0 };
    } else throw e;
  }
  return catalog;
}

// ── трансляция OpenAI → формат Raycast ────────────────────────────────────────
function normContent(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return content == null ? "" : String(content);
  const parts = [];
  for (const p of content) {
    if (p?.type === "text") parts.push({ type: "text", text: p.text ?? "" });
    else if (p?.type === "image_url") parts.push(p); // best effort: сервер может не принять
  }
  return parts.length ? parts : "";
}

function buildUpstreamBody(oai, entry) {
  const messages = (oai.messages ?? []).map((m) => {
    const out = { role: m.role === "developer" ? "system" : m.role ?? "user", content: normContent(m.content) };
    if (m.name) out.name = m.name;
    if (m.tool_call_id) out.tool_call_id = m.tool_call_id;
    if (m.tool_calls) out.tool_calls = m.tool_calls;
    return out;
  });
  const body = { model: entry.model, provider: entry.provider, messages, buffer_id: randomUUID() };
  if (oai.temperature != null) body.temperature = oai.temperature;
  if (oai.reasoning_effort && (entry.abilities?.reasoning_effort?.supported ?? true))
    body.reasoning_effort = oai.reasoning_effort;
  if (Array.isArray(oai.tools)) {
    body.tools = oai.tools
      .filter((t) => t?.type === "function" && t.function)
      .map((t) => ({ type: "function", function: { name: t.function.name, description: t.function.description ?? "", parameters: t.function.parameters ?? { type: "object", properties: {} } } }));
  }
  return body;
}

// ── upstream стрим → события ─────────────────────────────────────────────────
async function* upstreamEvents(resp) {
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf("\n")) !== -1) {
      let line = buf.slice(0, idx); buf = buf.slice(idx + 1);
      if (line.endsWith("\r")) line = line.slice(0, -1);
      if (!line || line.startsWith(":")) continue;
      if (line.startsWith("event:")) continue;
      if (line.startsWith("id:")) continue;
      if (line.startsWith("data:")) {
        const data = line.slice(5).trim();
        if (!data || data === "[DONE]") continue;
        try { yield JSON.parse(data); } catch { /* не-JSON — пропускаем */ }
      } else {
        try { yield JSON.parse(line); } catch { /* NDJSON/мусор — пропускаем */ }
      }
    }
  }
}

function mapUsage(u) {
  if (!u || typeof u !== "object") return undefined;
  const pt = u.prompt_tokens ?? u.input_tokens, ct = u.completion_tokens ?? u.output_tokens;
  if (pt == null && ct == null) return undefined;
  return { prompt_tokens: pt ?? 0, completion_tokens: ct ?? 0, total_tokens: u.total_tokens ?? (pt ?? 0) + (ct ?? 0) };
}

// нормализация их tool_call → OpenAI delta tool_call
function mapToolCall(tc, i) {
  const name = tc.name ?? tc.toolName ?? tc.function?.name ?? "";
  let args = tc.input ?? tc.args ?? tc.arguments ?? "";
  if (typeof args !== "string") { try { args = JSON.stringify(args); } catch { args = "{}"; } }
  if (!args) args = "";
  return { index: i, id: tc.id ?? tc.toolCallId ?? `call_${randomUUID().slice(0, 8)}`, type: "function", function: { name, arguments: args } };
}

// ── HTTP сервер ───────────────────────────────────────────────────────────────
function json(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(b) });
  res.end(b);
}

async function readBody(req, limit = 64 * 1024 * 1024) {
  const chunks = []; let size = 0;
  for await (const c of req) { size += c.length; if (size > limit) throw new Error("body too large"); chunks.push(c); }
  return Buffer.concat(chunks).toString("utf8");
}

async function handleChat(req, res) {
  const oai = JSON.parse(await readBody(req));
  const cat = await getCatalog();
  const id = oai.model;
  const entry = cat.map.get(id);
  if (!entry) return json(res, 400, { error: { message: `unknown model '${id}'. Список: GET /v1/models`, type: "invalid_request_error" } });

  const wantStream = oai.stream === true;
  const deviceTag = await getDeviceTag();

  const attempt = async () => {
    const tok = await ensureToken();
    const bodyStr = JSON.stringify(buildUpstreamBody(oai, entry));
    const r = await fetch(`${API}/api/v1/ai/chat_completions`, {
      method: "POST", headers: signedHeaders(bodyStr, deviceTag, tok?.access_token), body: bodyStr,
    });
    if ((r.status === 401 || r.status === 403)) {
      const n = await ensureToken(true); // форс-логин не нужен — пробуем refresh/re-login
      if (n?.access_token && n !== tok) {
        const r2 = await fetch(`${API}/api/v1/ai/chat_completions`, {
          method: "POST", headers: signedHeaders(bodyStr, deviceTag, n.access_token), body: bodyStr });
        return r2;
      }
    }
    return r;
  };

  let up;
  try { up = await attempt(); }
  catch (e) { return json(res, 502, { error: { message: `upstream: ${e.message}`, type: "api_error" } }); }

  if (!up.ok && !(up.headers.get("content-type") ?? "").includes("event-stream")) {
    const t = await up.text();
    return json(res, up.status === 401 || up.status === 403 ? 401 : 502,
      { error: { message: `raycast ${up.status}: ${t.slice(0, 400)}`, type: "api_error" } });
  }

  const id7 = `chatcmpl-${randomUUID().replace(/-/g, "").slice(0, 24)}`;
  const created = Math.floor(Date.now() / 1000);
  const mk = (delta, finish_reason = null, usage = undefined) =>
    `data: ${JSON.stringify({ id: id7, object: "chat.completion.chunk", created, model: id, choices: [{ index: 0, delta, finish_reason }], ...(usage ? { usage } : {}) })}\n\n`;

  if (wantStream) {
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
    res.write(mk({ role: "assistant", content: "" }));
  }

  let content = "", reasoning = "", toolCalls = [], usage, sawTools = false, errMsg = null;
  const ac = new AbortController();
  req.on("close", () => ac.abort());

  try {
    for await (const ev of upstreamEvents(up)) {
      if (ev == null || typeof ev !== "object") continue;
      if (ev.error) { errMsg = ev.error.message ?? ev.error.userMessage ?? JSON.stringify(ev.error).slice(0, 300); break; }
      let delta = null;
      if (typeof ev.text === "string" && ev.text) { content += ev.text; delta = { ...(delta ?? {}), content: ev.text }; }
      if (typeof ev.reasoning === "string" && ev.reasoning) { reasoning += ev.reasoning; delta = { ...(delta ?? {}), reasoning_content: ev.reasoning }; }
      if (Array.isArray(ev.tool_calls) && ev.tool_calls.length) {
        sawTools = true;
        for (const tc of ev.tool_calls) { const mapped = mapToolCall(tc, toolCalls.length); toolCalls.push(mapped); }
        delta = { ...(delta ?? {}), tool_calls: ev.tool_calls.map((tc) => mapToolCall(tc, 0)) };
      }
      const u = mapUsage(ev.usage); if (u) usage = u;
      if (delta && wantStream) res.write(mk(delta));
      const fin = ev.finish_reason ?? ev.finish ?? ev.done;
      if (fin) break;
    }
  } catch (e) {
    if (!wantStream) return json(res, 502, { error: { message: `stream: ${e.message}`, type: "api_error" } });
  }

  const finish_reason = errMsg ? "error" : sawTools ? "tool_calls" : "stop";
  if (wantStream) {
    if (errMsg) res.write(mk({ content: `\n[raycast-bridge error: ${errMsg}]` }));
    res.write(mk({}, finish_reason, usage));
    res.write("data: [DONE]\n\n");
    res.end();
  } else {
    if (errMsg) return json(res, 502, { error: { message: errMsg, type: "api_error" } });
    const message = { role: "assistant", content };
    if (reasoning) message.reasoning_content = reasoning;
    if (toolCalls.length) message.tool_calls = toolCalls.map(({ index, ...t }) => t);
    json(res, 200, { id: id7, object: "chat.completion", created, model: id,
      choices: [{ index: 0, message, finish_reason }], ...(usage ? { usage } : {}) });
  }
}

// ── gen models.yml ────────────────────────────────────────────────────────────
function genModelsYml() {
  const lines = ["providers:", "  raycast:", "    baseUrl: http://127.0.0.1:" + PORT + "/v1", "    auth: none", "    api: openai-completions", "    models:"];
  for (const m of catalog.list) {
    const ab = m.abilities ?? {};
    const vision = !!ab.vision;
    const ctx = Math.max(32000, (Number(m.context) || 200) * 1000);
    const reason = ab.reasoning_effort?.supported === true;
    const name = String(m.name ?? m.id).replace(/"/g, "'");
    lines.push(`      - id: ${m.id}`);
    lines.push(`        name: "${name}"`);
    lines.push(`        reasoning: ${reason}`);
    lines.push(`        input: [text${vision ? ", image" : ""}]`);
    lines.push(`        contextWindow: ${ctx}`);
    lines.push(`        maxTokens: ${Math.min(32768, ctx)}`);
    lines.push(`        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }`);
  }
  return lines.join("\n");
}

// ── main ──────────────────────────────────────────────────────────────────────
const [arg1] = process.argv.slice(2);

if (arg1 === "--catch") {
  // кэтчер deeplink: browser → HKCU handler → сюда
  const url = process.argv[3] ?? "";
  if (url) { try { appendFileSync(CODE_FILE, url + "\n"); } catch {} }
  process.exit(0);
}

if (arg1 === "--gen-models") {
  getCatalog(true).then((c) => { console.log(genModelsYml()); process.exit(0); },
    (e) => die(`каталог недоступен: ${e.message}`));
} else if (arg1 === "--refresh") {
  refreshToken(readToken()).then((t) => { t ? log("ok") : die("refresh failed"); process.exit(0); });
} else if (arg1 === "--logout") {
  try { unlinkSync(TOKEN_FILE); log("токен удалён"); } catch {}
  process.exit(0);
} else {
  const srv = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://x");
    try {
      if (req.method === "GET" && (url.pathname === "/v1/models" || url.pathname === "/models")) {
        const cat = await getCatalog();
        return json(res, 200, { object: "list", data: cat.list.map((m) => ({ id: m.id, object: "model", created: 0, owned_by: m.provider ?? "raycast", display_name: m.name })) });
      }
      if (req.method === "GET" && url.pathname === "/healthz") return json(res, 200, { ok: true });
      if (req.method === "POST" && (url.pathname === "/v1/chat/completions" || url.pathname === "/chat/completions")) return await handleChat(req, res);
      json(res, 404, { error: { message: `no route ${req.method} ${url.pathname}` } });
    } catch (e) {
      try { json(res, 500, { error: { message: e.message } }); } catch {}
    }
  });
  srv.listen(PORT, "127.0.0.1", () => {
    log(`raycast-bridge: http://127.0.0.1:${PORT}/v1  (OpenAI-совместимый)`);
    log(`модели: ${catalog.list.length ? "кэш" : "GET /v1/models"} · вход: ${existsSync(TOKEN_FILE) ? "token.json есть" : "требуется логин"}`);
    // логин в фоне: сервер уже отвечает на /v1/models без токена
    if (!tokenFresh(readToken())) {
      ensureToken().catch((e) => log("логин не завершён:", e.message, "— повтори запуск (токен не получен)"));
    }
  });
}
