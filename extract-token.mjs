#!/usr/bin/env node
// extract-token.mjs — достаёт OAuth-токен Raycast из базы залогиненного приложения.
// Использует их же нативный аддон (vendor/data.win32-x64-msvc.node) + ключ из Windows Credential Manager.
// Работает на КОПИИ баз (не трогает живые файлы приложения).
// Запуск: node extract-token.mjs [--write]   (--write — сохранить в token.json)

import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, existsSync, readFileSync, writeFileSync, rmSync, readdirSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const SUPPORT_DIR = process.env.RAYCAST_SUPPORT_DIR || path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local"), "Raycast");
const CRED_TARGET = process.env.RAYCAST_CRED_TARGET || "Raycast-Production/BackendDBKey";
const die = (m) => { console.error(m); process.exit(1); };

function readBackendKey() {
  if (process.env.RAYCAST_BACKEND_DB_KEY) return process.env.RAYCAST_BACKEND_DB_KEY;
  const ps = `
Add-Type -TypeDefinition '
using System;
using System.Runtime.InteropServices;
public class CredMan {
  [DllImport("advapi32", CharSet=CharSet.Unicode)]
  public static extern bool CredRead(string target, int type, int flags, out IntPtr credPtr);
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct CREDENTIAL {
    public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public int CredentialBlobSize; public IntPtr CredentialBlob; public int Persist;
    public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;
  }
}';
$ptr = [IntPtr]::Zero;
if (-not [CredMan]::CredRead('${CRED_TARGET}', 1, 0, [ref]$ptr)) { Write-Error 'CredRead failed'; exit 3 }
$c = [Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][CredMan+CREDENTIAL]);
$bytes = New-Object byte[] $c.CredentialBlobSize;
[Runtime.InteropServices.Marshal]::Copy($c.CredentialBlob, $bytes, 0, $c.CredentialBlobSize);
[Console]::Write([Text.Encoding]::UTF8.GetString($bytes));
`;
  try {
    return execFileSync("powershell", ["-NoProfile", "-Command", ps], { windowsHide: true }).toString().trim();
  } catch (e) {
    return null;
  }
}

// ── main ──────────────────────────────────────────────────────────────────────
const writeMode = process.argv.includes("--write");

if (!existsSync(SUPPORT_DIR)) die(`нет папки данных Raycast: ${SUPPORT_DIR} (приложение установлено?)`);

// 1. ключ базы из Credential Manager
const key = readBackendKey();
if (!key) die(`не найден ${CRED_TARGET} в Windows Credential Manager — приложение залогинено/запускалось?`);

// 2. копируем базы во временный каталог (не трогаем живые)
const tmp = path.join(os.tmpdir(), `raycast-bridge-db-${Date.now()}`);
mkdirSync(tmp, { recursive: true });
let copied = 0;
for (const f of readdirSync(SUPPORT_DIR)) {
  if (/^[\w-]+\.db(-wal|-shm)?$/.test(f)) {
    try { cpSync(path.join(SUPPORT_DIR, f), path.join(tmp, f)); copied++; } catch {}
  }
}
if (!copied) { rmSync(tmp, { recursive: true, force: true }); die(`в ${SUPPORT_DIR} нет .db файлов`); }

// 3. открываем их же аддоном
let tokenRaw = null, errDetail = "", client = null;
try {
  const require2 = createRequire(import.meta.url);
  const addon = require2("./vendor/data.win32-x64-msvc.node");
  const logcb = () => {}; // r_t() из бандла возвращает (message, meta) => void
  client = new addon.DatabaseClient(tmp, key, logcb);
  const ud = client.userDefaults;
  if (!ud) throw new Error("нет userDefaults в DatabaseClient");
  tokenRaw = await ud.get("OAuthTokenResponse");
} catch (e) { errDetail = e.message; }
finally {
  try { const r = client?.shutdown?.(); if (r && typeof r.then === "function") await r; } catch {}
}

// 4. уборка (аддон мог держать хэндлы — даём секунду и не падаем)
for (const delay of [0, 500, 1500]) {
  await new Promise((r) => setTimeout(r, delay));
  try { rmSync(tmp, { recursive: true, force: true }); break; } catch {}
}
if (!tokenRaw) die(`OAuthTokenResponse не найден (${errDetail || "пусто"}) — приложение залогинено?`);

const parsed = JSON.parse(tokenRaw);
if (!parsed.access_token) die("в OAuthTokenResponse нет access_token");

const out = {
  access_token: parsed.access_token,
  refresh_token: parsed.refresh_token ?? null,
  expires_at: Number.isFinite(parsed.expires_at) ? parsed.expires_at * (parsed.expires_at > 1e12 ? 1 : 1000) : null,
  token_type: parsed.token_type ?? "Bearer",
  extracted_at: new Date().toISOString(),
};
if (writeMode) {
  writeFileSync(path.join(DIR, "token.json"), JSON.stringify(out, null, 1));
  console.log(`✓ токен сохранён в token.json (access_token ${parsed.access_token.slice(0, 12)}…, expires_at ${out.expires_at ?? "?"})`);
} else {
  console.log(JSON.stringify(out, null, 1));
}
