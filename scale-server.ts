// ============================================================================
// SmartCaptcha — 100% Standalone Hetzner Backend Server (Bun + Postgres + Redis)
// Zero Supabase Dependency! Handles Auth, Device Lock, Captcha (Redis RAM),
// Compounding Plans, Team Tree, Withdrawals, Tickets & Full Admin Control.
//
// Capacity:
//   - Stage 1 (1 Hetzner CX23 ₹560/mo): 3 Lakh+ Active Users, 5,000+ req/s
//   - Stage 2+ (Auto-Scale Replicas + PgBouncer): 10 Lakh - 50 Lakh+ Users
// ============================================================================

import postgres from "postgres";
import Redis from "ioredis";
import { SignJWT, jwtVerify } from "jose";
import { gzipSync } from "node:zlib";
import { readFileSync } from "node:fs";
import { randomBytes, createHash, createHmac } from "node:crypto";

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL || "";
const REDIS_URL = process.env.REDIS_URL || "redis://127.0.0.1:6379";
const EPHEMERAL_SECRET = randomBytes(32).toString("hex");
const ENV_JWT = (process.env.JWT_SECRET || "").trim();
const JWT_SECRET = ENV_JWT.length >= 24 && !ENV_JWT.includes("change-this") ? ENV_JWT : EPHEMERAL_SECRET;
const CAPTCHA_HMAC_SECRET = (process.env.CAPTCHA_HMAC_SECRET || "").trim() || createHash("sha256").update("cap:" + JWT_SECRET).digest("hex");
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || "";
const ADMIN_EMAILS = new Set(
  (process.env.ADMIN_EMAILS || process.env.ADMIN_EMAIL || "ak84839100@gmail.com")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
);
const BOOTSTRAP_ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const BOOTSTRAP_ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || "").trim();
const USDT_INR_RATE = 100;
const FLUSH_INTERVAL_MS = Number(process.env.FLUSH_INTERVAL_MS || 60000);

const EXTRA_ORIGINS = new Set(
  (process.env.ALLOWED_ORIGINS || "https://smartcaptcha-site.pages.dev,https://13-206-72-86.sslip.io")
    .split(",")
    .map((s) => s.trim().replace(/\/+$/, "").toLowerCase())
    .filter(Boolean)
);

if (!DATABASE_URL) throw new Error("DATABASE_URL is required");

const sql = postgres(DATABASE_URL, {
  max: Number(process.env.PG_POOL_MAX || 15),
  idle_timeout: 10,
  max_lifetime: 1800,
  connect_timeout: 10,
  prepare: false,
});

const redis = new Redis(REDIS_URL, {
  maxRetriesPerRequest: 2,
  enableReadyCheck: true,
});

function isAllowedOrigin(origin: string): boolean {
  const o = origin.trim().replace(/\/+$/, "").toLowerCase();
  if (!o) return false;
  if (EXTRA_ORIGINS.has(o)) return true;
  if (/^https:\/\/[a-z0-9-]+\.smartcaptcha-site\.pages\.dev$/i.test(o)) return true;
  if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(o)) return true;
  return false;
}

const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Cache-Control": "no-store, no-cache, must-revalidate",
};

function buildCorsHeaders(req?: Request): Record<string, string> {
  const origin = req?.headers.get("origin") || "";
  const allowOrigin = origin && isAllowedOrigin(origin) ? origin : "https://smartcaptcha-site.pages.dev";
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-device-token",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Vary": "Origin",
    ...SECURITY_HEADERS,
  };
}

function jsonRes(data: unknown, status = 200, req?: Request): Response {
  const body = JSON.stringify(data);
  return new Response(body, {
    status,
    headers: {
      ...buildCorsHeaders(req),
      "Content-Type": "application/json",
      "Content-Length": String(Buffer.byteLength(body)),
    },
  });
}

function sha256Hex(v: string): string {
  return createHash("sha256").update(v).digest("hex");
}

function maskIp(ip: string): string {
  if (!ip || ip === "unknown") return "unknown";
  if (ip.includes(".")) {
    const p = ip.split(".");
    if (p.length === 4) return `${p[0]}.${p[1]}.xxx.xxx`;
  }
  if (ip.includes(":")) return ip.split(":").slice(0, 3).join(":") + ":xxxx";
  return "masked";
}

function deviceFingerprint(rawToken: string): string {
  const t = String(rawToken || "").trim();
  if (t.length < 12) return "";
  return sha256Hex("dfp:" + t).slice(0, 32);
}

const enc = new TextEncoder();
let cachedHmacKey: CryptoKey | null = null;
async function getHmacKey(): Promise<CryptoKey> {
  if (cachedHmacKey) return cachedHmacKey;
  cachedHmacKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(CAPTCHA_HMAC_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  return cachedHmacKey;
}

// PBKDF2-SHA256 Password & PIN Hashing
async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  const toHex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
  return `pbkdf2$${toHex(salt)}$${toHex(new Uint8Array(bits))}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = String(stored || "").split("$");
  if (parts.length !== 3 || parts[0] !== "pbkdf2") return false;
  const fromHex = (h: string) => new Uint8Array(h.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
  const salt = fromHex(parts[1]);
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  const actualHex = Array.from(new Uint8Array(bits)).map((x) => x.toString(16).padStart(2, "0")).join("");
  return constantTimeEqual(actualHex, parts[2]);
}

// RFC 6238 TOTP (Google Authenticator / Authy compatible)
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function generateBase32Secret(len = 20): string {
  const rnd = randomBytes(len);
  let out = "";
  for (let i = 0; i < rnd.length; i++) out += BASE32_ALPHABET[rnd[i] % 32];
  return out;
}
function base32ToBuffer(b32: string): Buffer {
  const clean = b32.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0, value = 0;
  const bytes: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}
function totpForStep(secret: string, step: number): string {
  const key = base32ToBuffer(secret);
  const msg = Buffer.alloc(8);
  msg.writeUInt32BE(Math.floor(step / 0x100000000), 0);
  msg.writeUInt32BE(step >>> 0, 4);
  const hmac = createHmac("sha1", key).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, "0");
}
function verifyTotpCode(secret: string, inputCode: string): { ok: boolean; step: number } {
  const clean = String(inputCode || "").trim();
  if (!/^\d{6}$/.test(clean) || !secret) return { ok: false, step: 0 };
  const nowStep = Math.floor(Date.now() / 30000);
  for (const delta of [-1, 0, 1]) {
    if (constantTimeEqual(totpForStep(secret, nowStep + delta), clean)) {
      return { ok: true, step: nowStep + delta };
    }
  }
  return { ok: false, step: 0 };
}

async function getTokenVersion(userId: string): Promise<number> {
  const key = `tv:${userId}`;
  const cached = await redis.get(key);
  if (cached !== null && Number.isFinite(Number(cached))) return Number(cached);
  const [u] = await sql`select coalesce(token_version, 1)::integer as tv from public.users where id = ${userId} limit 1`;
  const tv = Number(u?.tv || 1);
  await redis.set(key, String(tv), "EX", 300);
  return tv;
}

async function bumpTokenVersion(userId: string): Promise<number> {
  const [u] = await sql`
    update public.users
    set token_version = coalesce(token_version, 1) + 1
    where id = ${userId}
    returning token_version
  `;
  const tv = Number(u?.token_version || 2);
  await redis.set(`tv:${userId}`, String(tv), "EX", 300);
  return tv;
}

async function issueJwt(user: { id: string; email: string; role: string }, dfp = "", tv = 1): Promise<string> {
  return await new SignJWT({ email: user.email, role: user.role, dfp, tv })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(user.id)
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(enc.encode(JWT_SECRET));
}

async function authenticateRequest(req: Request): Promise<{ id: string; email: string; role: string } | null> {
  const auth = req.headers.get("authorization") || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, enc.encode(JWT_SECRET));
    if (!payload.sub || !payload.tv) return null;
    const uid = String(payload.sub);
    if (payload.dfp) {
      const hdrFp = deviceFingerprint(req.headers.get("x-device-token") || "");
      if (!hdrFp || !constantTimeEqual(String(payload.dfp), hdrFp)) {
        return null;
      }
    }
    const currentTv = await getTokenVersion(uid);
    if (Number(payload.tv) !== currentTv) return null;
    return {
      id: uid,
      email: String(payload.email || ""),
      role: String(payload.role || "user"),
    };
  } catch {
    return null;
  }
}

async function verifyTurnstile(token?: string): Promise<boolean> {
  if (!TURNSTILE_SECRET_KEY) return true;
  if (!token) return false;
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret: TURNSTILE_SECRET_KEY, response: token }),
    });
    const j: any = await res.json();
    return Boolean(j?.success);
  } catch {
    return false;
  }
}

function toBase64Url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(str: string): Uint8Array {
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function signCaptchaToken(payload: Record<string, unknown>): Promise<string> {
  const body = toBase64Url(enc.encode(JSON.stringify(payload)));
  const sigBuf = await crypto.subtle.sign("HMAC", await getHmacKey(), enc.encode(body));
  return `${body}.${toBase64Url(sigBuf)}`;
}

async function verifyCaptchaToken(token: string): Promise<Record<string, any> | null> {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  try {
    const ok = await crypto.subtle.verify("HMAC", await getHmacKey(), fromBase64Url(parts[1]), enc.encode(parts[0]));
    if (!ok) return null;
    const decoded = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[0])));
    if (Date.now() > Number(decoded.exp || 0)) return null;
    return decoded;
  } catch {
    return null;
  }
}

function randomCode(len = 6): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const rnd = new Uint8Array(len);
  crypto.getRandomValues(rnd);
  return Array.from(rnd).map((b) => chars[b % chars.length]).join("");
}

function renderCaptchaSvg(code: string): string {
  const letters = code
    .split("")
    .map((ch, idx) => {
      const x = 22 + idx * 28;
      const y = 38 + (idx % 2 === 0 ? -1 : 1) * ((ch.charCodeAt(0) % 7) + 2);
      const rot = (ch.charCodeAt(0) % 24) - 12;
      return `<text x="${x}" y="${y}" font-family="monospace" font-size="28" font-weight="800" fill="#e2e8f0" transform="rotate(${rot} ${x} ${y})">${ch}</text>`;
    })
    .join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="58" viewBox="0 0 200 58"><rect width="200" height="58" rx="10" fill="#0f172a"/><path d="M8 18 Q 95 45, 192 14" stroke="#38bdf8" stroke-opacity="0.35" stroke-width="2" fill="none"/><path d="M12 44 Q 110 8, 188 42" stroke="#f472b6" stroke-opacity="0.35" stroke-width="2" fill="none"/>${letters}</svg>`;
}

function calcProjectedBalance(principalInr: number, dailyRatePct: number, days: number): number {
  return Math.round(principalInr * Math.pow(1 + dailyRatePct / 100, days) * 100) / 100;
}

function todayIst(): string {
  return new Date(Date.now() + 5.5 * 3600 * 1000).toISOString().slice(0, 10);
}

// ----------------------------------------------------------------------------
// Redis -> PostgreSQL Batch Flush Worker (with Orphan Recovery & Mutex Wait)
// ----------------------------------------------------------------------------
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
let flushing = false;
let activeFlushPromise: Promise<{ users: number; captchas: number }> | null = null;

async function processFlushHashKey(processingKey: string): Promise<{ users: number; captchas: number }> {
  const rawMap = await redis.hgetall(processingKey);
  const payload: Array<{ user_id: string; solved: number; reward_usdt: number }> = [];
  for (const [userId, val] of Object.entries(rawMap)) {
    if (!UUID_RE.test(userId)) continue;
    const [cntStr, usdtStr] = String(val).split(":");
    const solved = Number(cntStr || 0);
    const rewardUsdt = Number(usdtStr || 0);
    if (solved > 0) payload.push({ user_id: userId, solved, reward_usdt: Math.round(rewardUsdt * 10000) / 10000 });
  }
  let totalUsers = 0, totalCaptchas = 0;
  for (let i = 0; i < payload.length; i += 1000) {
    const chunk = payload.slice(i, i + 1000);
    const res = await sql`select public.batch_credit_captchas(${JSON.stringify(chunk)}::jsonb) as res`;
    totalUsers += Number(res[0]?.res?.users || 0);
    totalCaptchas += Number(res[0]?.res?.captchas || 0);
  }
  await redis.del(processingKey);
  return { users: totalUsers, captchas: totalCaptchas };
}

async function flushPendingCaptchas(): Promise<{ users: number; captchas: number }> {
  if (flushing && activeFlushPromise) return await activeFlushPromise;
  flushing = true;
  activeFlushPromise = (async () => {
    try {
      // Recover any orphaned flush keys older than current run
      const orphans = await redis.keys("pending:captchas:flush:*").catch(() => []);
      for (const k of orphans.slice(0, 5)) {
        try { await processFlushHashKey(k); } catch (e) { console.error("[orphan flush retry]", e); }
      }

      const exists = await redis.exists("pending:captchas");
      if (!exists) return { users: 0, captchas: 0 };
      const processingKey = `pending:captchas:flush:${Date.now()}:${Math.random().toString(36).slice(2, 7)}`;
      try { await redis.rename("pending:captchas", processingKey); } catch { return { users: 0, captchas: 0 }; }

      return await processFlushHashKey(processingKey);
    } catch (err) {
      console.error("[flushPendingCaptchas error]", err);
      return { users: 0, captchas: 0 };
    } finally {
      flushing = false;
      activeFlushPromise = null;
    }
  })();
  return await activeFlushPromise;
}

setInterval(() => { flushPendingCaptchas().catch(() => {}); }, FLUSH_INTERVAL_MS);

// Built-in IST Daily Compounding Scheduler (runs once per day after 00:05 IST)
setInterval(async () => {
  try {
    const istNow = new Date(Date.now() + 5.5 * 3600 * 1000);
    if (istNow.getUTCHours() === 0 && istNow.getUTCMinutes() >= 5) {
      const day = istNow.toISOString().slice(0, 10);
      const lock = await redis.set(`cron:compounding:${day}`, "1", "EX", 86400, "NX");
      if (lock) {
        let more = true;
        while (more) {
          const [r] = await sql`select public.run_daily_compounding_batch(${day}::date, 5000) as res`;
          more = Boolean(r?.res?.has_more);
        }
      }
    }
  } catch (e) {
    console.error("[daily compounding cron]", e);
  }
}, 60_000);

const LUA_ADD_PENDING = `
local cur = redis.call("HGET", KEYS[1], ARGV[1])
local c, u = 0, 0.0
if cur then
  local sep = string.find(cur, ":")
  if sep then
    c = tonumber(string.sub(cur, 1, sep - 1)) or 0
    u = tonumber(string.sub(cur, sep + 1)) or 0.0
  end
end
c = c + tonumber(ARGV[2])
u = u + tonumber(ARGV[3])
redis.call("HSET", KEYS[1], ARGV[1], tostring(c) .. ":" .. string.format("%.4f", u))
return tostring(c) .. ":" .. string.format("%.4f", u)
`;

async function checkRateLimit(key: string, maxHits: number, windowSec: number): Promise<boolean> {
  const n = await redis.incr(key);
  if (n === 1) await redis.expire(key, windowSec);
  return n <= maxHits;
}

function clientIp(req: Request): string {
  return (
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown"
  );
}

async function getCachedConfigRow(cacheKey: string, queryFn: () => Promise<any[]>, fallback: Record<string, any> | null = null) {
  const cached = await redis.get(cacheKey);
  if (cached) return JSON.parse(cached);
  const rows = await queryFn();
  const row = rows[0] || fallback;
  if (row) await redis.set(cacheKey, JSON.stringify(row), "EX", 60);
  return row;
}

const DEFAULT_INCOME_CONFIG = {
  income_enabled: true,
  captcha_daily_limit: 50,
  captcha_reward_usdt: 0.01,
  captcha_reward_inr: 1,
  signup_bonus_usdt: 0,
  signup_bonus_inr: 0,
  fast_start_bonus_usdt: 0,
  fast_start_bonus_inr: 0,
  fast_start_directs: 5,
  streak_bonus_usdt: 0,
  streak_bonus_inr: 0,
  streak_days: 7,
  daily_company_cap_inr: 50000,
  level_once_inr: [100, 50, 25, 15, 10, 5, 5, 5],
  level_daily_inr: [10, 5, 3, 2, 2, 1, 1, 1],
  level_daily_directs: [1, 2, 3, 4, 5, 6, 7, 8],
};

function normalizeIncomeSettings(row: Record<string, any> | null | undefined) {
  const extra = row?.extra_config && typeof row.extra_config === "object" ? row.extra_config : {};
  const capUsdt = Number(row?.captcha_reward_usdt ?? extra.captcha_reward_usdt ?? 0.01);
  const signUsdt = Number(row?.signup_bonus_usdt ?? extra.signup_bonus_usdt ?? 0);
  const fastUsdt = Number(row?.fast_start_bonus_usdt ?? extra.fast_start_bonus_usdt ?? 0);
  const streakUsdt = Number(row?.streak_bonus_usdt ?? extra.streak_bonus_usdt ?? 0);
  return {
    ...DEFAULT_INCOME_CONFIG,
    ...extra,
    income_enabled: extra.income_enabled !== undefined ? Boolean(extra.income_enabled) : true,
    captcha_daily_limit: Math.max(0, Number(row?.captcha_daily_limit ?? extra.captcha_daily_limit ?? 50)),
    captcha_reward_usdt: capUsdt,
    captcha_reward_inr: Number(extra.captcha_reward_inr ?? Math.round(capUsdt * USDT_INR_RATE * 100) / 100),
    signup_bonus_usdt: signUsdt,
    signup_bonus_inr: Number(extra.signup_bonus_inr ?? Math.round(signUsdt * USDT_INR_RATE * 100) / 100),
    fast_start_bonus_usdt: fastUsdt,
    fast_start_bonus_inr: Number(extra.fast_start_bonus_inr ?? Math.round(fastUsdt * USDT_INR_RATE * 100) / 100),
    streak_bonus_usdt: streakUsdt,
    streak_bonus_inr: Number(extra.streak_bonus_inr ?? Math.round(streakUsdt * USDT_INR_RATE * 100) / 100),
  };
}

function parseCaptchaMode(raw: unknown): { random_enabled: boolean; length: number } {
  const s = String(raw || "").trim();
  if (s.startsWith("{")) {
    try {
      const p = JSON.parse(s);
      return {
        random_enabled: p.random_enabled !== false,
        length: Math.min(8, Math.max(4, Math.round(Number(p.length || 5)))),
      };
    } catch {}
  }
  if (s === "off" || s === "disabled") return { random_enabled: false, length: 5 };
  return { random_enabled: true, length: 5 };
}

async function getCachedIncomeSettings() {
  const cached = await redis.get("cache:income_settings");
  if (cached) return JSON.parse(cached);
  const rows = await sql`select * from public.income_settings where id = 1`.catch(() => []);
  const norm = normalizeIncomeSettings(rows[0] || {});
  await redis.set("cache:income_settings", JSON.stringify(norm), "EX", 60);
  return norm;
}

async function getCachedCompoundingSettings() {
  return await getCachedConfigRow(
    "cache:compounding_settings",
    () => sql`select * from public.compounding_settings where id = 1`,
    null
  );
}

async function getCachedWithdrawConfig() {
  return await getCachedConfigRow(
    "cache:public_withdraw_config",
    () => sql`select * from public.public_withdraw_config where id = 1`,
    null
  );
}

async function getCachedAppSettings() {
  return await getCachedConfigRow(
    "cache:app_settings",
    () => sql`select * from public.app_settings where id = 1`,
    { registration_open: true, max_registered: 1000000, device_lock_enabled: true, captcha_mode: "standard" }
  );
}

// Fast O(1) count for large tables (uses Redis cache + pg_class reltuples above 5k rows)
async function getFastRowCount(table: "users" | "profiles" | "wallet_ledger", cacheKey: string, ttlSec = 20): Promise<number> {
  const cached = await redis.get(cacheKey);
  if (cached !== null && Number.isFinite(Number(cached))) return Number(cached);
  const fullTable = `public.${table}`;
  const [estRow] = await sql`select greatest(0, coalesce(reltuples::bigint, 0))::bigint as est from pg_class where oid = ${fullTable}::regclass`;
  const est = Number(estRow?.est || 0);
  let count = est;
  if (est < 5000) {
    if (table === "users") {
      const [r] = await sql`select count(*)::integer as cnt from public.users`;
      count = Number(r?.cnt || 0);
    } else if (table === "profiles") {
      const [r] = await sql`select count(*)::integer as cnt from public.profiles`;
      count = Number(r?.cnt || 0);
    } else {
      const [r] = await sql`select count(*)::bigint as cnt from public.wallet_ledger`;
      count = Number(r?.cnt || 0);
    }
  }
  await redis.set(cacheKey, String(count), "EX", ttlSec);
  return count;
}

const LUA_INCR_IF_EXISTS = `if redis.call("EXISTS", KEYS[1]) == 1 then return redis.call("INCR", KEYS[1]) end return 0`;
function safeIncrIfCached(cacheKey: string) {
  redis.eval(LUA_INCR_IF_EXISTS, 1, cacheKey).catch(() => {});
}

async function ensurePerformanceIndexes() {
  try {
    await Promise.all([
      sql`alter table public.income_settings add column if not exists extra_config jsonb not null default '{}'::jsonb`,
      sql`alter table public.withdrawal_requests add column if not exists tx_id text default ''`,
      sql`alter table public.app_settings add column if not exists captcha_mode text not null default 'standard'`,
      sql`create index if not exists idx_profiles_created_at on public.profiles(created_at desc)`,
      sql`create index if not exists idx_profiles_email_lower on public.profiles(lower(email))`,
      sql`create index if not exists idx_users_email_lower on public.users(lower(email))`,
      sql`create index if not exists idx_deposits_status_id on public.deposits(status, id desc)`,
      sql`create index if not exists idx_withdrawals_status_id on public.withdrawal_requests(status, id desc)`,
    ]);
  } catch (e) {
    console.error("[ensurePerformanceIndexes]", e);
  }
}
ensurePerformanceIndexes();

async function ensureMonetizationTables() {
  try {
    await sql`
      create table if not exists public.monetization_settings (
        id integer primary key default 1 check (id = 1),
        ads_enabled boolean not null default false,
        top_banner_img text default '',
        top_banner_link text default '',
        ad_script_url text default '',
        ad_container_id text default '',
        direct_link_url text default '',
        direct_link_label text default '🎁 Sponsored Offer — Check Now',
        offerwall_enabled boolean not null default false,
        offerwall_name text default 'Offerwall Tasks',
        offerwall_url text default '',
        user_share_pct numeric(5, 2) not null default 60.00 check (user_share_pct between 1 and 95),
        postback_secret text not null default '',
        updated_at timestamptz not null default now()
      )
    `;
    const randSecret = randomCode(24);
    await sql`
      insert into public.monetization_settings (id, postback_secret)
      values (1, ${randSecret})
      on conflict (id) do nothing
    `;
    await sql`
      update public.monetization_settings
      set postback_secret = ${randSecret}
      where id = 1 and coalesce(postback_secret, '') = ''
    `;
    await sql`
      create table if not exists public.offerwall_postbacks (
        id bigserial primary key,
        tx_id text unique not null,
        user_id uuid not null references public.users(id) on delete cascade,
        network text not null default 'offerwall',
        gross_usdt numeric(14, 4) not null check (gross_usdt > 0),
        user_share_usdt numeric(14, 4) not null check (user_share_usdt >= 0),
        admin_profit_usdt numeric(14, 4) not null check (admin_profit_usdt >= 0),
        created_at timestamptz not null default now()
      )
    `;
    await sql`create index if not exists idx_offerwall_postbacks_user on public.offerwall_postbacks(user_id, created_at desc)`;
  } catch (e) {
    console.error("[ensureMonetizationTables]", e);
  }
}
ensureMonetizationTables();

async function ensureSecurityTables() {
  try {
    await sql`alter table public.users add column if not exists security_pin_hash text not null default ''`;
    await sql`alter table public.users add column if not exists totp_secret text not null default ''`;
    await sql`alter table public.users add column if not exists totp_enabled boolean not null default false`;
    await sql`alter table public.users add column if not exists token_version integer not null default 1`;
    await sql`
      create table if not exists public.security_audit_logs (
        id bigserial primary key,
        user_id uuid references public.users(id) on delete set null,
        email text not null default '',
        event_type text not null,
        ip_hash text not null default '',
        ip_masked text not null default '',
        device_fp text not null default '',
        details text not null default '',
        created_at timestamptz not null default now()
      )
    `;
    await sql`create index if not exists idx_sec_audit_user_created on public.security_audit_logs(user_id, created_at desc)`;
    await sql`create index if not exists idx_sec_audit_created on public.security_audit_logs(created_at desc)`;
  } catch (e) {
    console.error("[ensureSecurityTables]", e);
  }
}
ensureSecurityTables();

async function logSecurityEvent(
  eventType: string,
  ip: string,
  opts: { userId?: string | null; email?: string; deviceFp?: string; details?: string } = {}
) {
  try {
    const ipHash = sha256Hex("ip:" + ip + ":" + JWT_SECRET.slice(0, 8)).slice(0, 24);
    const ipM = maskIp(ip);
    await sql`
      insert into public.security_audit_logs (user_id, email, event_type, ip_hash, ip_masked, device_fp, details)
      values (
        ${opts.userId || null},
        ${String(opts.email || "").slice(0, 140)},
        ${eventType.slice(0, 48)},
        ${ipHash},
        ${ipM},
        ${String(opts.deviceFp || "").slice(0, 12)},
        ${String(opts.details || "").slice(0, 200)}
      )
    `;
  } catch {}
}

async function getCachedMonetizationPublic() {
  return await getCachedConfigRow(
    "cache:monetization_public",
    () => sql`
      select ads_enabled, top_banner_img, top_banner_link, ad_script_url, ad_container_id,
             direct_link_url, direct_link_label, offerwall_enabled, offerwall_name,
             offerwall_url, user_share_pct
      from public.monetization_settings where id = 1
    `,
    { ads_enabled: false, offerwall_enabled: false, user_share_pct: 60 }
  );
}

function isSafeHttpsUrl(v: unknown): string {
  const s = String(v || "").trim();
  if (!s) return "";
  if (!/^https:\/\/[^\s"'<>]+$/i.test(s)) {
    throw new Error("Only valid https:// URLs are allowed.");
  }
  return s.slice(0, 500);
}

function constantTimeEqual(a: string, b: string): boolean {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function issueCaptchaChallenge(userId: string, purpose = "earn") {
  let codeLen = purpose === "auth" ? 5 : 6;
  if (purpose === "earn") {
    const appSet = await getCachedAppSettings();
    const cm = parseCaptchaMode(appSet?.captcha_mode);
    if (!cm.random_enabled) {
      throw new Error("Captcha solving is currently paused by Admin.");
    }
    codeLen = cm.length;
  }
  const code = randomCode(codeLen);
  const token = await signCaptchaToken({
    uid: userId,
    purpose,
    code,
    nid: crypto.randomUUID(),
    exp: Date.now() + 180_000,
  });
  return { challenge_id: token, nonce: token, svg: renderCaptchaSvg(code) };
}

async function bootstrapAdmin() {
  if (!BOOTSTRAP_ADMIN_EMAIL || !BOOTSTRAP_ADMIN_PASSWORD) return;
  try {
    const existing = await sql`select id from public.users where email = ${BOOTSTRAP_ADMIN_EMAIL} limit 1`;
    if (existing.length) {
      await sql`update public.users set role = 'admin' where id = ${existing[0].id}`;
      await sql`update public.profiles set is_admin = true, account_status = 'active' where id = ${existing[0].id}`;
      return;
    }
    const pwdHash = await hashPassword(BOOTSTRAP_ADMIN_PASSWORD);
    const [u] = await sql`
      insert into public.users (email, password_hash, role)
      values (${BOOTSTRAP_ADMIN_EMAIL}, ${pwdHash}, 'admin') returning id, email
    `;
    await sql`
      insert into public.profiles (id, email, full_name, referral_code, account_status, is_admin)
      values (${u.id}, ${u.email}, 'Administrator', ${'ADM' + randomCode(5)}, 'active', true)
    `;
    console.log(`Bootstrapped admin account: ${u.email}`);
  } catch (e) {
    console.error("[bootstrapAdmin]", e);
  }
}
bootstrapAdmin();

async function isUserAdmin(user: { id: string; email: string; role: string }): Promise<boolean> {
  if (ADMIN_EMAILS.has(user.email.toLowerCase())) return true;
  const rows = await sql`
    select u.role, p.is_admin
    from public.users u
    left join public.profiles p on p.id = u.id
    where u.id = ${user.id} limit 1
  `;
  if (!rows.length) return false;
  return rows[0].role === "admin" || Boolean(rows[0].is_admin);
}

// ----------------------------------------------------------------------------
// Auth Routes (5-Layer Security Gate)
// ----------------------------------------------------------------------------
async function verifyAuthSecCaptcha(token: unknown, code: unknown): Promise<boolean> {
  const v = await verifyCaptchaToken(String(token || ""));
  if (!v || v.purpose !== "auth") return false;
  if (String(code || "").trim().toUpperCase() !== String(v.code || "").toUpperCase()) return false;
  const used = await redis.set(`auth_cap_used:${v.nid}`, "1", "EX", 240, "NX");
  return Boolean(used);
}

async function handleAuth(pathname: string, req: Request): Promise<Response> {
  const ip = clientIp(req);
  const hdrDfp = deviceFingerprint(req.headers.get("x-device-token") || "");

  if (pathname === "/api/auth/login-challenge" && (req.method === "GET" || req.method === "POST")) {
    if (!(await checkRateLimit(`rl:lchap:${sha256Hex(ip).slice(0, 16)}`, 40, 60))) {
      return jsonRes({ error: "Too many challenge requests. Please wait." }, 429, req);
    }
    const ch = await issueCaptchaChallenge("auth-gate", "auth");
    return jsonRes({ challenge_token: ch.challenge_id, svg: ch.svg }, 200, req);
  }

  if (pathname === "/api/auth/signup" && req.method === "POST") {
    if (!(await checkRateLimit(`rl:signup:${ip}`, 15, 300))) {
      return jsonRes({ error: "Too many signup attempts. Please wait a few minutes." }, 429, req);
    }
    const body: any = await req.json().catch(() => ({}));
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const pin = String(body.security_pin || "").trim();
    const dfp = hdrDfp || deviceFingerprint(String(body.device_token || ""));

    if (!email || !email.includes("@")) return jsonRes({ error: "Invalid email or mobile ID." }, 400, req);
    if (password.length < 8 || password.length > 128) return jsonRes({ error: "Password must be 8 to 128 characters." }, 400, req);
    if (!/^\d{4,6}$/.test(pin)) return jsonRes({ error: "Enter a 4 to 6 digit numeric Security PIN." }, 400, req);
    if (!(await verifyAuthSecCaptcha(body.sec_captcha_token, body.sec_captcha_code))) {
      return jsonRes({ error: "Server Security Code invalid or expired. Please refresh the code." }, 400, req);
    }
    if (!(await verifyTurnstile(body.captchaToken))) {
      return jsonRes({ error: "Cloudflare human verification failed. Please retry captcha." }, 400, req);
    }

    const appSet = await getCachedAppSettings();
    if (appSet && !appSet.registration_open) {
      return jsonRes({ error: "Registrations are currently closed by admin." }, 403, req);
    }
    const cnt = await getFastRowCount("users", "cache:users_count", 20);
    if (appSet && cnt >= Number(appSet.max_registered)) {
      return jsonRes({ error: "Registration limit reached." }, 403, req);
    }

    const dup = await sql`select id from public.users where lower(email) = ${email} limit 1`;
    if (dup.length) return jsonRes({ error: "Account already registered. Please log in." }, 400, req);

    const [pwdHash, pinHash] = await Promise.all([hashPassword(password), hashPassword(pin)]);
    const isAdmin = ADMIN_EMAILS.has(email);
    const role = isAdmin ? "admin" : "user";
    const [u] = await sql`
      insert into public.users (email, password_hash, security_pin_hash, role, token_version)
      values (${email}, ${pwdHash}, ${pinHash}, ${role}, 1)
      returning id, email, role, created_at
    `;
    await sql`
      insert into public.profiles (id, email, referral_code, account_status, is_admin)
      values (${u.id}, ${u.email}, ${"SC" + randomCode(6)}, 'active', ${isAdmin})
    `;
    safeIncrIfCached("cache:users_count");
    safeIncrIfCached("cache:reg_count");
    logSecurityEvent("signup_success", ip, { userId: u.id, email: u.email, deviceFp: dfp, details: "5-layer account registered" });

    const access_token = await issueJwt({ id: u.id, email: u.email, role: u.role }, dfp, 1);
    return jsonRes({ user: u, session: { access_token, user: u } }, 200, req);
  }

  if (pathname === "/api/auth/login" && req.method === "POST") {
    if (!(await checkRateLimit(`rl:login:${ip}`, 25, 300))) {
      return jsonRes({ error: "Too many login attempts from your network. Please wait 5 minutes." }, 429, req);
    }
    const body: any = await req.json().catch(() => ({}));
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const pin = String(body.security_pin || "").trim();
    const totpCode = String(body.totp_code || "").trim();
    const dfp = hdrDfp || deviceFingerprint(String(body.device_token || ""));

    if (!email || !password) return jsonRes({ error: "Email/ID and password are required." }, 400, req);

    // Per-account brute-force lockout (5 fails -> 15 min lock)
    const failKey = `login_fail:${sha256Hex(email).slice(0, 24)}`;
    const fails = Number((await redis.get(failKey)) || 0);
    if (fails >= 5) {
      logSecurityEvent("login_locked_attempt", ip, { email, deviceFp: dfp, details: "Account in 15m brute-force cooldown" });
      return jsonRes({ error: "Account temporarily locked for 15 minutes due to 5 failed attempts." }, 429, req);
    }

    // Shield 3: Server Cryptographic Captcha
    if (!(await verifyAuthSecCaptcha(body.sec_captcha_token, body.sec_captcha_code))) {
      return jsonRes({ error: "Server Security Code invalid or expired. Tap refresh & enter the code." }, 400, req);
    }

    // Shield 4: Cloudflare Turnstile
    if (!(await verifyTurnstile(body.captchaToken))) {
      return jsonRes({ error: "Cloudflare verification failed. Please retry." }, 400, req);
    }

    const [u] = await sql`
      select u.id, u.email, u.password_hash, u.security_pin_hash, u.totp_secret, u.totp_enabled,
             coalesce(u.token_version, 1)::integer as token_version, u.role, p.account_status
      from public.users u
      left join public.profiles p on p.id = u.id
      where lower(u.email) = ${email} limit 1
    `;
    const recordFail = async (ev: string, reason: string) => {
      const n = await redis.incr(failKey);
      if (n === 1) await redis.expire(failKey, 900);
      if (n === 5) await redis.expire(failKey, 900);
      logSecurityEvent(n >= 5 ? "login_locked" : ev, ip, { userId: u?.id, email, deviceFp: dfp, details: reason });
    };

    // Shield 1: Password check
    if (!u || !(await verifyPassword(password, u.password_hash))) {
      await recordFail("login_failed_password", "Wrong password");
      return jsonRes({ error: "Invalid login credentials." }, 401, req);
    }
    if (u.account_status === "blocked") {
      logSecurityEvent("login_blocked_user", ip, { userId: u.id, email, deviceFp: dfp, details: "Blocked user login attempt" });
      return jsonRes({ error: "Account is blocked by admin." }, 403, req);
    }

    // Shield 2: Personal Security PIN (or seamless first-time PIN setup if unset)
    if (!u.security_pin_hash) {
      const setupToken = await signCaptchaToken({
        uid: u.id,
        purpose: "pin_setup",
        dfp,
        nid: crypto.randomUUID(),
        exp: Date.now() + 300_000,
      });
      return jsonRes({
        requires_pin_setup: true,
        setup_token: setupToken,
        message: "Shield 2 setup: Create a 4 to 6 digit Security PIN to activate your 5-Layer Login Protection.",
      }, 200, req);
    }
    if (!/^\d{4,6}$/.test(pin) || !(await verifyPassword(pin, u.security_pin_hash))) {
      await recordFail("login_failed_pin", "Wrong 6-digit Security PIN");
      return jsonRes({ error: "Invalid Security PIN (Shield 2).", code: "PIN_INVALID" }, 401, req);
    }

    // Optional Extra Shield: Authenticator TOTP 2FA (when enabled)
    if (u.totp_enabled && u.totp_secret) {
      const totpRes = verifyTotpCode(u.totp_secret, totpCode);
      if (!totpRes.ok) {
        await recordFail("login_failed_totp", "Invalid 2FA Authenticator code");
        return jsonRes({ error: "Valid 6-digit Authenticator 2FA code required.", code: "TOTP_REQUIRED" }, 401, req);
      }
      const replayGuard = await redis.set(`totp_used:${u.id}:${totpRes.step}`, "1", "EX", 120, "NX");
      if (!replayGuard) {
        return jsonRes({ error: "Authenticator code already used. Wait 30s for next code." }, 401, req);
      }
    }

    await redis.del(failKey);
    await redis.set(`tv:${u.id}`, String(u.token_version), "EX", 300);
    logSecurityEvent("login_success", ip, { userId: u.id, email: u.email, deviceFp: dfp, details: "5-layer login verified" });

    // Shield 5: Device-bound JWT + Token Version
    const access_token = await issueJwt({ id: u.id, email: u.email, role: u.role }, dfp, u.token_version);
    return jsonRes({
      user: { id: u.id, email: u.email, role: u.role, is_anonymous: false },
      session: { access_token, user: { id: u.id, email: u.email, role: u.role, is_anonymous: false } },
    }, 200, req);
  }

  if (pathname === "/api/auth/setup-pin" && req.method === "POST") {
    if (!(await checkRateLimit(`rl:pinsetup:${ip}`, 15, 300))) {
      return jsonRes({ error: "Too many PIN setup attempts." }, 429, req);
    }
    const body: any = await req.json().catch(() => ({}));
    const setupData = await verifyCaptchaToken(String(body.setup_token || ""));
    if (!setupData || setupData.purpose !== "pin_setup" || !UUID_RE.test(String(setupData.uid || ""))) {
      return jsonRes({ error: "PIN setup session expired. Please sign in again." }, 401, req);
    }
    const dfp = hdrDfp || deviceFingerprint(String(body.device_token || ""));
    if (setupData.dfp && (!dfp || !constantTimeEqual(String(setupData.dfp), dfp))) {
      return jsonRes({ error: "Device mismatch during PIN setup." }, 403, req);
    }
    const used = await redis.set(`pin_setup_used:${setupData.nid}`, "1", "EX", 360, "NX");
    if (!used) return jsonRes({ error: "Setup token already used. Please log in." }, 400, req);

    const pin = String(body.security_pin || "").trim();
    if (!/^\d{4,6}$/.test(pin)) return jsonRes({ error: "Security PIN must be 4 to 6 digits." }, 400, req);

    const [u] = await sql`
      select id, email, role, security_pin_hash, coalesce(token_version, 1)::integer as token_version
      from public.users where id = ${setupData.uid} limit 1
    `;
    if (!u) return jsonRes({ error: "Account not found." }, 404, req);
    if (u.security_pin_hash) return jsonRes({ error: "Security PIN is already set. Log in normally." }, 400, req);

    const pinHash = await hashPassword(pin);
    await sql`update public.users set security_pin_hash = ${pinHash} where id = ${u.id}`;
    await redis.set(`tv:${u.id}`, String(u.token_version), "EX", 300);
    logSecurityEvent("pin_setup", ip, { userId: u.id, email: u.email, deviceFp: dfp, details: "Initial Security PIN activated" });

    const access_token = await issueJwt({ id: u.id, email: u.email, role: u.role }, dfp, u.token_version);
    return jsonRes({
      user: { id: u.id, email: u.email, role: u.role, is_anonymous: false },
      session: { access_token, user: { id: u.id, email: u.email, role: u.role, is_anonymous: false } },
      message: "5-Layer Security PIN activated!",
    }, 200, req);
  }

  if (pathname === "/api/auth/user" && req.method === "GET") {
    const user = await authenticateRequest(req);
    if (!user) return jsonRes({ user: null }, 200, req);
    return jsonRes({ user: { ...user, is_anonymous: false } }, 200, req);
  }

  if (pathname === "/api/auth/update-user" && req.method === "POST") {
    const user = await authenticateRequest(req);
    if (!user) return jsonRes({ error: "Login required." }, 401, req);
    const body: any = await req.json().catch(() => ({}));
    if (body.password) {
      if (String(body.password).length < 8) return jsonRes({ error: "Password must be at least 8 characters." }, 400, req);
      await sql`update public.users set password_hash = ${await hashPassword(String(body.password))} where id = ${user.id}`;
      await bumpTokenVersion(user.id);
      logSecurityEvent("password_changed", ip, { userId: user.id, email: user.email, deviceFp: hdrDfp, details: "User updated password" });
    }
    if (body.email) {
      const nextEmail = String(body.email).trim().toLowerCase();
      await sql`update public.users set email = ${nextEmail} where id = ${user.id}`;
      await sql`update public.profiles set email = ${nextEmail} where id = ${user.id}`;
    }
    return jsonRes({ user }, 200, req);
  }

  return jsonRes({ error: "Unknown auth endpoint" }, 404, req);
}

// ----------------------------------------------------------------------------
// Main Router (with Automatic Gzip Compression & Security Headers)
// ----------------------------------------------------------------------------
async function routeRequest(req: Request): Promise<Response> {
    if (req.method === "OPTIONS") return new Response("ok", { status: 200, headers: buildCorsHeaders(req) });

    const contentLength = Number(req.headers.get("content-length") || 0);
    if (contentLength > 600_000) {
      return jsonRes({ error: "Payload too large." }, 413, req);
    }

    const url = new URL(req.url);
    const path = url.pathname;

    if (path === "/health" || path === "/") {
      try {
        await Promise.all([sql`select 1`, redis.ping()]);
        return jsonRes({ ok: true, status: "healthy", mode: "hetzner-standalone" }, 200, req);
      } catch (e: any) {
        return jsonRes({ ok: false, error: e?.message || "unhealthy" }, 503, req);
      }
    }

    if (path === "/captcha.svg") {
      const verified = await verifyCaptchaToken(url.searchParams.get("n") || "");
      if (!verified?.code) return new Response("Expired", { status: 400, headers: buildCorsHeaders(req) });
      return new Response(renderCaptchaSvg(String(verified.code)), {
        status: 200,
        headers: { ...buildCorsHeaders(req), "Content-Type": "image/svg+xml", "Cache-Control": "no-store" },
      });
    }

    if (path.startsWith("/api/auth/")) {
      return await handleAuth(path, req);
    }

    // Public RPCs
    if (path === "/api/rpc/public_registration_count") {
      const cnt = await getFastRowCount("profiles", "cache:reg_count", 30);
      return jsonRes({ data: cnt });
    }

    if (path === "/api/postback/offerwall") {
      try {
        const bodyData: Record<string, any> = req.method === "POST"
          ? await req.json().catch(async () => Object.fromEntries(new URLSearchParams(await req.text().catch(() => ""))))
          : {};
        const q = url.searchParams;
        const param = (keys: string[]) => {
          for (const k of keys) {
            const v = q.get(k) ?? bodyData[k];
            if (v !== undefined && v !== null && String(v).trim() !== "") return String(v).trim();
          }
          return "";
        };
        const secret = param(["secret", "key", "sig"]);
        const userId = param(["user_id", "uid", "subid", "subid1"]);
        const txId = param(["tx_id", "trans_id", "transaction_id", "tid"]).slice(0, 120);
        const payoutRaw = Number(param(["payout", "amount", "usd", "currency_amount"]));
        const network = param(["network", "wall"]) || "offerwall";

        const [cfg] = await sql`select postback_secret, user_share_pct, offerwall_enabled from public.monetization_settings where id = 1`;
        if (!cfg || !constantTimeEqual(secret, String(cfg.postback_secret || ""))) {
          return jsonRes({ error: "Invalid postback secret." }, 403);
        }
        if (!UUID_RE.test(userId)) return jsonRes({ error: "Invalid user_id." }, 400);
        if (!txId) return jsonRes({ error: "tx_id is required." }, 400);
        if (!Number.isFinite(payoutRaw) || payoutRaw <= 0 || payoutRaw > 5000) {
          return jsonRes({ error: "Invalid payout amount." }, 400);
        }

        const sharePct = Math.min(95, Math.max(1, Number(cfg.user_share_pct || 60)));
        const grossUsdt = Math.round(payoutRaw * 10000) / 10000;
        const userShareUsdt = Math.round(grossUsdt * (sharePct / 100) * 10000) / 10000;
        const adminProfitUsdt = Math.round((grossUsdt - userShareUsdt) * 10000) / 10000;

        const credited = await sql.begin(async (tx: any) => {
          const [u] = await tx`select id from public.users where id = ${userId} limit 1`;
          if (!u) throw new Error("User not found.");
          const ins = await tx`
            insert into public.offerwall_postbacks (tx_id, user_id, network, gross_usdt, user_share_usdt, admin_profit_usdt)
            values (${txId}, ${userId}, ${network.slice(0, 40)}, ${grossUsdt}, ${userShareUsdt}, ${adminProfitUsdt})
            on conflict (tx_id) do nothing
            returning id
          `;
          if (!ins.length) return false;
          if (userShareUsdt > 0) {
            await tx`
              insert into public.wallet_ledger (user_id, entry_type, amount, description)
              values (${userId}, 'offerwall_income', ${userShareUsdt}, ${`${network} task reward (${sharePct}% share)`})
            `;
          }
          return true;
        });
        return jsonRes({ ok: true, status: credited ? "credited" : "duplicate", tx_id: txId, user_share_usdt: userShareUsdt, admin_profit_usdt: adminProfitUsdt });
      } catch (e: any) {
        return jsonRes({ error: e?.message || "Postback error" }, 400);
      }
    }

    // Public & Authenticated Table Reads
    if (path.startsWith("/api/table/")) {
      const table = path.replace("/api/table/", "");
      if (table === "public_withdraw_config") {
        return jsonRes({ data: await getCachedWithdrawConfig() });
      }
      if (table === "compounding_settings") {
        return jsonRes({ data: await getCachedCompoundingSettings() });
      }
      if (table === "monetization_settings") {
        return jsonRes({ data: await getCachedMonetizationPublic() });
      }
      if (table === "profiles") {
        const user = await authenticateRequest(req);
        if (!user) return jsonRes({ error: "Unauthorized" }, 401, req);
        const [row] = await sql`
          select id, email, full_name, phone, gender, date_of_birth, city, state, pin_code,
                 referral_code, referred_by, account_status, balance_usdt, device_locked, is_admin, created_at
          from public.profiles where id = ${user.id} limit 1
        `;
        return jsonRes({ data: row || null }, 200, req);
      }
      return jsonRes({ error: "Forbidden table" }, 403, req);
    }

    const user = await authenticateRequest(req);
    if (!user) return jsonRes({ error: "Login required or device session expired." }, 401, req);

    if (path === "/api/rpc/my_team_list") {
      const body: any = await req.json().catch(() => ({}));
      const maxLevel = Math.max(1, Math.min(8, Number(body.max_level || 8)));
      const rows = await sql`select * from public.my_team_list(${user.id}::uuid, ${maxLevel})`;
      return jsonRes({ data: rows }, 200, req);
    }

    const body: Record<string, any> = await req.json().catch(() => ({}));

    // register-device
    if (path === "/api/functions/register-device") {
      const deviceToken = String(body.device_token || "").trim();
      const [appSet, [prof]] = await Promise.all([
        getCachedAppSettings(),
        sql`select id, full_name, referred_by, account_status, device_locked, device_token from public.profiles where id = ${user.id} limit 1`,
      ]);
      if (!prof) return jsonRes({ error: "Profile not found." }, 404, req);
      if (prof.account_status === "blocked") {
        return jsonRes({ error: "Account blocked by admin.", code: "DEVICE_LOCKED" }, 403, req);
      }

      if (appSet?.device_lock_enabled && prof.device_locked && deviceToken) {
        if (prof.device_token && prof.device_token !== deviceToken) {
          return jsonRes({ error: "This account is locked to another device.", code: "DEVICE_LOCKED" }, 403, req);
        }
        const other = await sql`
          select id from public.profiles where device_token = ${deviceToken} and id <> ${user.id} limit 1
        `;
        if (other.length) {
          return jsonRes({ error: "This device is already linked to another account.", code: "DEVICE_TAKEN" }, 403, req);
        }
      }

      if (body.full_name) {
        let sponsorId = prof.referred_by;
        if (!sponsorId && body.referral_code) {
          const ref = String(body.referral_code).trim().toUpperCase();
          const [sp] = await sql`select id from public.profiles where referral_code = ${ref} and id <> ${user.id} limit 1`;
          if (sp) sponsorId = sp.id;
        }
        await sql`
          update public.profiles
          set full_name = ${String(body.full_name).trim()},
              phone = coalesce(${body.phone ? String(body.phone) : null}, phone),
              gender = coalesce(${body.gender ? String(body.gender) : null}, gender),
              referred_by = ${sponsorId},
              device_token = coalesce(device_token, ${deviceToken || null})
          where id = ${user.id}
        `;
        return jsonRes({ ok: true, needs_details: false }, 200, req);
      }

      if (!prof.device_token && deviceToken) {
        await sql`update public.profiles set device_token = ${deviceToken} where id = ${user.id}`;
      }
      return jsonRes({ ok: true, needs_details: !prof.full_name }, 200, req);
    }

    // user-finance
    if (path === "/api/functions/user-finance") {
      return await handleUserFinance(String(body.action || ""), body, user, req);
    }

    // admin-control
    if (path === "/api/functions/admin-control") {
      if (!(await isUserAdmin(user))) {
        logSecurityEvent("unauthorized_admin_attempt", clientIp(req), { userId: user.id, email: user.email, details: `Action: ${String(body.action || "")}` });
        return jsonRes({ error: "Forbidden: Admin privileges required." }, 403, req);
      }
      return await handleAdminControl(String(body.action || ""), body, user, req);
    }

    return jsonRes({ error: "Unknown endpoint" }, 404, req);
}

const server = Bun.serve({
  port: PORT,
  async fetch(req: Request): Promise<Response> {
    const res = await routeRequest(req);
    const ae = req.headers.get("accept-encoding") || "";
    const ct = res.headers.get("content-type") || "";
    const cl = Number(res.headers.get("content-length") || 0);
    if (
      ae.includes("gzip") &&
      !res.headers.has("content-encoding") &&
      (ct.includes("image/svg+xml") || (ct.includes("application/json") && (cl === 0 || cl >= 1024)))
    ) {
      const raw = new Uint8Array(await res.arrayBuffer());
      if (raw.byteLength >= 1024) {
        const gz = gzipSync(raw, { level: 4 });
        const headers = new Headers(res.headers);
        headers.set("Content-Encoding", "gzip");
        headers.set("Vary", "Accept-Encoding");
        headers.delete("Content-Length");
        return new Response(gz, { status: res.status, headers });
      }
      return new Response(raw, { status: res.status, headers: res.headers });
    }
    return res;
  },
});

// ----------------------------------------------------------------------------
// User Finance Handlers
// ----------------------------------------------------------------------------
async function getUserTodayCaptchaState(userId: string) {
  const today = todayIst();
  const dailyKey = `cap_day:${today}:${userId}`;
  const [profRows, pendingRaw, redisDayRaw] = await Promise.all([
    sql`select balance_usdt, total_captchas_solved, today_captchas_count, to_char((today_captchas_date)::date, 'YYYY-MM-DD') as db_day from public.profiles where id = ${userId} limit 1`,
    redis.hget("pending:captchas", userId),
    redis.get(dailyKey),
  ]);
  const prof = profRows[0] || { balance_usdt: 0, total_captchas_solved: 0, today_captchas_count: 0, db_day: "" };
  const [pCnt, pUsdt] = (pendingRaw || "0:0").split(":").map(Number);
  const dbToday = prof.db_day === today ? Number(prof.today_captchas_count || 0) : 0;
  const redisDay = Number(redisDayRaw || 0);
  const todayPassed = Math.max(redisDay, dbToday + (pCnt || 0));
  if (todayPassed > 0 && redisDay < todayPassed) {
    await redis.set(dailyKey, String(todayPassed), "EX", 100_000);
  }
  return { prof, pCnt: pCnt || 0, pUsdt: pUsdt || 0, todayPassed, dailyKey, dbToday };
}

async function handleUserFinance(action: string, body: Record<string, any>, user: { id: string; email?: string; role?: string }, req?: Request): Promise<Response> {
  try {
    if (action === "captcha_new") {
      const [incSet, state] = await Promise.all([
        getCachedIncomeSettings(),
        getUserTodayCaptchaState(user.id),
      ]);
      const limit = Math.max(0, Number(incSet.captcha_daily_limit ?? 50));
      const rewardUsdt = Math.max(0, Number(incSet.captcha_reward_usdt ?? 0.01));
      const rewardInr = Math.round(rewardUsdt * USDT_INR_RATE * 100) / 100;
      if (limit > 0 && state.todayPassed >= limit) {
        return jsonRes({
          limit_reached: true,
          today_passed: state.todayPassed,
          captcha_daily_limit: limit,
          reward_inr: rewardInr,
          reward_usdt: rewardUsdt,
        });
      }
      return jsonRes({
        ...(await issueCaptchaChallenge(user.id)),
        today_passed: state.todayPassed,
        captcha_daily_limit: limit,
        reward_inr: rewardInr,
        reward_usdt: rewardUsdt,
      });
    }

    if (action === "captcha_submit") {
      if (!(await checkRateLimit(`rl:cap:${user.id}`, 60, 60))) {
        return jsonRes({ error: "Too fast! Slow down slightly." }, 429);
      }
      const verified = await verifyCaptchaToken(String(body.challenge_id || body.nonce || ""));
      if (!verified || verified.uid !== user.id) return jsonRes({ error: "Captcha expired. Get a new one." }, 400);
      const setOk = await redis.set(`cap_used:${verified.nid}`, "1", "EX", 240, "NX");
      if (!setOk) return jsonRes({ error: "Captcha already submitted." }, 400);

      const [incSet, state] = await Promise.all([
        getCachedIncomeSettings(),
        getUserTodayCaptchaState(user.id),
      ]);
      const limit = Math.max(0, Number(incSet.captcha_daily_limit ?? 50));
      const rewardUsdt = Math.max(0, Number(incSet.captcha_reward_usdt ?? 0.01));
      const rewardInr = Math.round(rewardUsdt * USDT_INR_RATE * 100) / 100;

      if (state.todayPassed >= limit) {
        return jsonRes({
          ok: true,
          reward_paid: false,
          limit_reached: true,
          today_passed: state.todayPassed,
          captcha_daily_limit: limit,
          reward_inr: rewardInr,
          next: null,
        });
      }

      if (String(body.answer || "").trim().toUpperCase() !== String(verified.code).toUpperCase()) {
        const next = await issueCaptchaChallenge(user.id);
        return jsonRes({ ok: false, today_passed: state.todayPassed, captcha_daily_limit: limit, next });
      }

      const incrVal = await redis.incr(state.dailyKey);
      const newCount = Math.max(state.todayPassed + 1, incrVal);
      if (newCount !== incrVal || newCount === 1) {
        await redis.set(state.dailyKey, String(newCount), "EX", 100_000);
      }

      const incomeEnabled = incSet.income_enabled !== false;
      const rewardPaid = incomeEnabled && newCount <= limit && rewardUsdt > 0;
      if (rewardPaid) {
        await redis.eval(LUA_ADD_PENDING, 1, "pending:captchas", user.id, "1", String(rewardUsdt));
      }
      const limitReached = newCount >= limit;
      const next = limitReached ? null : await issueCaptchaChallenge(user.id);
      return jsonRes({
        ok: true,
        reward_paid: rewardPaid,
        limit_reached: limitReached,
        today_passed: newCount,
        captcha_daily_limit: limit,
        reward_inr: rewardInr,
        reward_usdt: rewardUsdt,
        next,
      });
    }

    if (action === "wallet") {
      const [capState, deposits, withdrawals, incSet, ledgerSums] = await Promise.all([
        getUserTodayCaptchaState(user.id),
        sql`select * from public.deposits where user_id = ${user.id} order by created_at desc limit 20`,
        sql`select * from public.withdrawal_requests where user_id = ${user.id} order by created_at desc limit 20`,
        getCachedIncomeSettings(),
        sql`select entry_type, coalesce(sum(amount), 0) as total_usdt from public.wallet_ledger where user_id = ${user.id} group by entry_type`,
      ]);
      const { prof, pCnt, pUsdt, todayPassed } = capState;
      const totalUsdt = Number(prof.balance_usdt || 0) + pUsdt;
      const depUsdt = deposits.filter((d: any) => d.status === "approved").reduce((s: number, d: any) => s + Number(d.amount_usdt || 0), 0);
      const rewardUsdt = Number(incSet.captcha_reward_usdt ?? 0.01);
      const rewardInr = Number(incSet.captcha_reward_inr ?? Math.round(rewardUsdt * USDT_INR_RATE * 100) / 100);
      const limit = Number(incSet.captcha_daily_limit ?? 50);

      const incomeByType: Record<string, number> = {};
      for (const r of ledgerSums) {
        incomeByType[String(r.entry_type)] = Math.round(Number(r.total_usdt || 0) * USDT_INR_RATE * 100) / 100;
      }
      if (pUsdt > 0) {
        incomeByType.captcha_income = Math.round(((incomeByType.captcha_income || 0) + pUsdt * USDT_INR_RATE) * 100) / 100;
      }

      return jsonRes({
        balance_usdt: Math.round(totalUsdt * 10000) / 10000,
        balance_inr: Math.round(totalUsdt * USDT_INR_RATE * 100) / 100,
        tasks_completed: Number(prof.total_captchas_solved || 0) + pCnt,
        today_passed: todayPassed,
        captcha_daily_limit: limit,
        captcha_reward_usdt: rewardUsdt,
        captcha_reward_inr: rewardInr,
        income_by_type: incomeByType,
        today_income_inr: Math.round(todayPassed * rewardUsdt * USDT_INR_RATE * 100) / 100,
        total_income_inr: Math.round(totalUsdt * USDT_INR_RATE * 100) / 100,
        deposited_usdt: Math.round(depUsdt * 100) / 100,
        available_deposit_usdt: Math.round(depUsdt * 100) / 100,
        deposits,
        withdrawals,
        pending_condition: withdrawals.find((w: any) => w.status === "pending") || null,
      });
    }

    if (action === "history") {
      const limit = Math.min(50, Number(body.limit) || 20);
      const group = String(body.group || "all");
      const before = body.before ? new Date(String(body.before)) : null;
      let types: string[] | null = null;
      if (group === "deposit") types = ["deposit_credit"];
      else if (group === "withdrawal") types = ["withdrawal_reserve", "withdrawal_refund"];
      else if (group === "adjust") types = ["admin_adjustment"];
      else if (group === "income") {
        types = ["captcha_income", "signup_bonus", "fast_start_bonus", "streak_bonus", "level_once", "level_daily", "compounding_daily", "compounding_maturity", "offerwall_income"];
      }

      const rows = await sql`
        select * from public.wallet_ledger
        where user_id = ${user.id}
          ${before ? sql`and created_at < ${before}` : sql``}
          ${types ? sql`and entry_type = any(${types})` : sql``}
        order by created_at desc limit ${limit + 1}
      `;
      const hasMore = rows.length > limit;
      const page = hasMore ? rows.slice(0, limit) : rows;
      return jsonRes({
        entries: page.map((r: any) => ({ ...r, amount_inr: Math.round(Number(r.amount) * USDT_INR_RATE * 100) / 100 })),
        next_before: page.length ? page[page.length - 1].created_at : null,
        has_more: hasMore,
      });
    }

    if (action === "update_name") {
      const fullName = String(body.full_name || "").trim();
      if (fullName.length < 2) return jsonRes({ error: "Enter a valid name." }, 400);
      await sql`update public.profiles set full_name = ${fullName} where id = ${user.id}`;
      return jsonRes({ message: "Name updated.", full_name: fullName });
    }

    if (action === "create_deposit") {
      const amt = Number(body.amount_usdt);
      const txId = String(body.tx_id || "").trim();
      if (!Number.isFinite(amt) || amt < 1) return jsonRes({ error: "Minimum deposit is 1 USDT." }, 400);
      if (txId.length < 4) return jsonRes({ error: "Enter valid transaction ID." }, 400);
      await sql`insert into public.deposits (user_id, amount_usdt, tx_id, status) values (${user.id}, ${amt}, ${txId}, 'pending')`;
      return jsonRes({ message: "Deposit request submitted for admin approval." });
    }

    if (action === "request_withdrawal") {
      await flushPendingCaptchas();
      const amt = Number(body.amount_usdt);
      const addr = String(body.wallet_address || "").trim();
      if (!Number.isFinite(amt) || amt <= 0) return jsonRes({ error: "Invalid withdrawal amount." }, 400);
      if (!/^0x[a-fA-F0-9]{40}$/.test(addr)) return jsonRes({ error: "Invalid BEP-20 wallet address." }, 400);
      if (!(await verifyTurnstile(body.captchaToken))) {
        return jsonRes({ error: "Cloudflare human verification failed. Please verify again." }, 400);
      }

      const [wdCfg, [pSet], depRows, todayWdRows] = await Promise.all([
        getCachedWithdrawConfig(),
        sql`select withdraw_rule_json from public.platform_settings where id = 1`,
        sql`select coalesce(sum(amount_usdt), 0) as total from public.deposits where user_id = ${user.id} and status = 'approved'`,
        sql`select count(*)::integer as cnt from public.withdrawal_requests where user_id = ${user.id} and (created_at at time zone 'Asia/Kolkata')::date = (now() at time zone 'Asia/Kolkata')::date`,
      ]);
      const depUsdt = Number(depRows[0]?.total || 0);
      const rule = pSet?.withdraw_rule_json || {};
      if (rule.enabled && depUsdt < Number(rule.min_deposit_usdt || 0)) {
        return jsonRes({ error: `Minimum ${Number(rule.min_deposit_usdt)} USDT approved deposit required before withdrawal.` }, 400);
      }
      const chart = wdCfg?.chart && !Array.isArray(wdCfg.chart) ? wdCfg.chart : {};
      const dailyLimit = Number(chart.daily_limit ?? 2);
      if (dailyLimit > 0 && Number(todayWdRows[0]?.cnt || 0) >= dailyLimit) {
        return jsonRes({ error: `Daily withdrawal limit reached (${dailyLimit}/day).` }, 400);
      }
      const reqPct = Number(chart.deposit_percent ?? 40);
      const reqDep = Math.round(amt * (reqPct / 100) * 100) / 100;
      if (reqDep > 0 && depUsdt < reqDep) {
        return jsonRes({ error: `Deposit ${reqDep.toFixed(2)} USDT (${reqPct}%) required to withdraw ${amt} USDT.` }, 400);
      }

      await sql.begin(async (tx: any) => {
        const [prof] = await tx`select balance_usdt from public.profiles where id = ${user.id} for update`;
        if (Number(prof?.balance_usdt || 0) < amt) throw new Error("Insufficient wallet balance.");
        await tx`
          insert into public.wallet_ledger (user_id, entry_type, amount, description)
          values (${user.id}, 'withdrawal_reserve', ${-amt}, ${`Withdrawal request to ${addr}`})
        `;
        await tx`
          insert into public.withdrawal_requests (user_id, amount, payout_method, payout_details_masked, payout_address, required_deposit_usdt, status)
          values (${user.id}, ${amt}, 'USDT BEP-20', ${addr.slice(0, 6) + "..." + addr.slice(-4)}, ${addr}, ${reqDep}, 'pending')
        `;
      });
      return jsonRes({ message: "Withdrawal request submitted." });
    }

    if (action === "compounding_info") {
      const [settings, plans, [prof], pendingRaw] = await Promise.all([
        getCachedCompoundingSettings(),
        sql`select * from public.compounding_plans where user_id = ${user.id} order by id desc`,
        sql`select balance_usdt from public.profiles where id = ${user.id} limit 1`,
        redis.hget("pending:captchas", user.id),
      ]);
      const pUsdt = pendingRaw ? Number(pendingRaw.split(":")[1] || 0) : 0;
      const walletUsdt = Number(prof?.balance_usdt || 0) + pUsdt;
      return jsonRes({
        settings,
        plans,
        wallet_balance_usdt: Math.round(walletUsdt * 10000) / 10000,
        wallet_balance_inr: Math.round(walletUsdt * USDT_INR_RATE * 100) / 100,
      });
    }

    if (action === "compounding_start") {
      await flushPendingCaptchas();
      const amountInr = Number(body.amount_inr);
      if (!Number.isFinite(amountInr) || amountInr <= 0) return jsonRes({ error: "Enter a valid plan amount." }, 400);
      const settings = await getCachedCompoundingSettings();
      if (!settings?.enabled) return jsonRes({ error: "Compounding plan is currently paused by admin." }, 400);

      const allowed: number[] = (settings.allowed_amounts_inr || []).map(Number);
      if (!allowed.includes(amountInr)) {
        if (!settings.allow_custom_amount) return jsonRes({ error: `Select one of: ₹${allowed.join(", ₹")}` }, 400);
        if (amountInr < Number(settings.min_custom_inr) || amountInr > Number(settings.max_custom_inr)) {
          return jsonRes({ error: `Amount must be between ₹${settings.min_custom_inr} and ₹${settings.max_custom_inr}.` }, 400);
        }
      }

      const reqUsdt = Math.round((amountInr / USDT_INR_RATE) * 10000) / 10000;
      const plan = await sql.begin(async (tx: any) => {
        const [prof] = await tx`select balance_usdt, account_status from public.profiles where id = ${user.id} for update`;
        if (settings.require_active_account && prof?.account_status !== "active") {
          throw new Error("Your account must be active.");
        }
        const [{ cnt }] = await tx`select count(*)::integer as cnt from public.compounding_plans where user_id = ${user.id} and status = 'active'`;
        if (cnt >= Number(settings.max_active_plans_per_user)) {
          throw new Error(`Maximum ${settings.max_active_plans_per_user} active plans allowed.`);
        }
        if (Number(prof?.balance_usdt || 0) < reqUsdt) {
          throw new Error(`Insufficient balance. Need ${reqUsdt.toFixed(2)} USDT (₹${amountInr}).`);
        }
        await tx`
          insert into public.wallet_ledger (user_id, entry_type, amount, description)
          values (${user.id}, 'compounding_invest', ${-reqUsdt}, ${`Started ${settings.duration_days}-Day Compounding Plan (₹${amountInr})`})
        `;
        const proj = calcProjectedBalance(amountInr, Number(settings.daily_rate_pct), Number(settings.duration_days));
        const [p] = await tx`
          insert into public.compounding_plans (
            user_id, principal_inr, principal_usdt, current_balance_inr,
            daily_rate_pct, duration_days, projected_maturity_inr, credit_mode, status
          ) values (
            ${user.id}, ${amountInr}, ${reqUsdt}, ${amountInr},
            ${settings.daily_rate_pct}, ${settings.duration_days}, ${proj}, ${settings.credit_mode}, 'active'
          ) returning *
        `;
        return p;
      });
      return jsonRes({ message: `Compounding plan #${plan.id} started!`, plan });
    }

    if (action === "compounding_logs") {
      const logs = await sql`
        select * from public.compounding_daily_logs
        where plan_id = ${Number(body.plan_id)} and user_id = ${user.id}
        order by day_number desc limit 60
      `;
      return jsonRes({ logs });
    }

    if (action === "compounding_early_exit") {
      const settings = await getCachedCompoundingSettings();
      if (!settings?.early_exit_enabled) return jsonRes({ error: "Early exit disabled by admin." }, 403);
      const [plan] = await sql`
        select * from public.compounding_plans
        where id = ${Number(body.plan_id)} and user_id = ${user.id} and status in ('active', 'paused')
      `;
      if (!plan) return jsonRes({ error: "Active plan not found." }, 404);
      const baseInr = plan.credit_mode === "daily_to_main_wallet" ? Number(plan.principal_inr) : Number(plan.current_balance_inr);
      const payoutInr = Math.round(baseInr * (1 - Number(settings.early_exit_penalty_pct) / 100) * 100) / 100;
      const payoutUsdt = Math.round((payoutInr / USDT_INR_RATE) * 10000) / 10000;
      await sql`update public.compounding_plans set status = 'cancelled', matured_at = now() where id = ${plan.id}`;
      await sql`
        insert into public.wallet_ledger (user_id, entry_type, amount, description)
        values (${user.id}, 'compounding_maturity', ${payoutUsdt}, ${`Plan #${plan.id} early exit (₹${payoutInr})`})
      `;
      return jsonRes({ message: `Plan closed. ₹${payoutInr.toLocaleString("en-IN")} credited.` });
    }

    if (action === "my_tickets") {
      const tickets = await sql`select * from public.support_tickets where user_id = ${user.id} order by updated_at desc limit 50`;
      return jsonRes({ tickets });
    }
    if (action === "ticket_messages") {
      const [t] = await sql`select id from public.support_tickets where id = ${Number(body.ticket_id)} and user_id = ${user.id}`;
      if (!t) return jsonRes({ error: "Ticket not found." }, 404);
      const messages = await sql`select * from public.ticket_messages where ticket_id = ${t.id} order by created_at asc`;
      return jsonRes({ messages });
    }
    if (action === "create_ticket") {
      const subject = String(body.subject || "").trim();
      const message = String(body.message || "").trim();
      if (subject.length < 3 || message.length < 5) return jsonRes({ error: "Enter subject and message." }, 400);
      const [t] = await sql`insert into public.support_tickets (user_id, subject) values (${user.id}, ${subject}) returning *`;
      await sql`insert into public.ticket_messages (ticket_id, sender, body) values (${t.id}, 'user', ${message})`;
      return jsonRes({ message: "Ticket created.", ticket: t });
    }
    if (action === "ticket_reply") {
      const [t] = await sql`select id from public.support_tickets where id = ${Number(body.ticket_id)} and user_id = ${user.id}`;
      if (!t) return jsonRes({ error: "Ticket not found." }, 404);
      await sql`insert into public.ticket_messages (ticket_id, sender, body) values (${t.id}, 'user', ${String(body.message || "").trim()})`;
      await sql`update public.support_tickets set updated_at = now(), status = 'open' where id = ${t.id}`;
      return jsonRes({ message: "Reply sent." });
    }

    if (action === "offerwall_info") {
      const [cfg, logs] = await Promise.all([
        getCachedMonetizationPublic(),
        sql`select tx_id, network, user_share_usdt, created_at from public.offerwall_postbacks where user_id = ${user.id} order by id desc limit 20`,
      ]);
      return jsonRes({ config: cfg, user_id: user.id, recent_credits: logs });
    }

    if (action === "security_status") {
      const [[u], logs] = await Promise.all([
        sql`select security_pin_hash <> '' as pin_set, totp_enabled, coalesce(token_version, 1) as token_version from public.users where id = ${user.id} limit 1`,
        sql`select event_type, ip_masked, device_fp, details, created_at from public.security_audit_logs where user_id = ${user.id} order by id desc limit 10`,
      ]);
      return jsonRes({
        pin_set: Boolean(u?.pin_set),
        totp_enabled: Boolean(u?.totp_enabled),
        token_version: Number(u?.token_version || 1),
        recent_logs: logs,
      });
    }

    if (action === "change_security_pin") {
      const curPwd = String(body.current_password || "");
      const newPin = String(body.new_pin || "").trim();
      if (!curPwd) return jsonRes({ error: "Enter your current password." }, 400);
      if (!/^\d{4,6}$/.test(newPin)) return jsonRes({ error: "Security PIN must be 4 to 6 digits." }, 400);
      const [u] = await sql`select id, email, role, password_hash from public.users where id = ${user.id} limit 1`;
      if (!u || !(await verifyPassword(curPwd, u.password_hash))) {
        return jsonRes({ error: "Current password is incorrect." }, 401);
      }
      const pinHash = await hashPassword(newPin);
      await sql`update public.users set security_pin_hash = ${pinHash} where id = ${user.id}`;
      const tv = await bumpTokenVersion(user.id);
      const dfp = deviceFingerprint(req?.headers.get("x-device-token") || "");
      const access_token = await issueJwt({ id: u.id, email: u.email, role: u.role }, dfp, tv);
      if (req) logSecurityEvent("pin_changed", clientIp(req), { userId: u.id, email: u.email, deviceFp: dfp, details: "User updated 5-layer PIN" });
      return jsonRes({ message: "Security PIN updated & all other sessions signed out.", access_token });
    }

    if (action === "logout_all_devices") {
      await bumpTokenVersion(user.id);
      if (req) logSecurityEvent("logout_all", clientIp(req), { userId: user.id, email: user.email || "", details: "User revoked all active device sessions" });
      return jsonRes({ message: "All devices logged out. Please sign in again." });
    }

    return jsonRes({ error: `Unknown user action: ${action}` }, 400);
  } catch (err: any) {
    return jsonRes({ error: err?.message || "Server error" }, 400);
  }
}

// ----------------------------------------------------------------------------
// Admin Control Handlers
// ----------------------------------------------------------------------------
async function handleAdminControl(
  action: string,
  body: Record<string, any>,
  adminUser: { id: string; email: string; role: string },
  req?: Request
): Promise<Response> {
  try {
    if (action === "get_settings") {
      const [appSet, wdCfg, cnt] = await Promise.all([
        getCachedAppSettings(),
        getCachedWithdrawConfig(),
        getFastRowCount("profiles", "cache:reg_count", 15),
      ]);
      return jsonRes({
        settings: appSet,
        withdrawal_config: wdCfg,
        registration: { total_registered: cnt, max_registered: Number(appSet?.max_registered || 1000000) },
      });
    }

    if (action === "list_users") {
      const q = String(body.query || "").trim();
      const lim = Math.min(200, Math.max(10, Number(body.limit) || 50));
      const users = q
        ? await sql`
            select id, email, full_name,
                   case when length(coalesce(phone, '')) >= 4 then 'XXXXXX' || right(phone, 4) else '-' end as phone,
                   account_status, balance_usdt as wallet_balance, created_at
            from public.profiles
            where email ilike ${"%" + q + "%"} or full_name ilike ${"%" + q + "%"} or phone ilike ${"%" + q + "%"}
            order by created_at desc limit ${lim}
          `
        : await sql`
            select id, email, full_name,
                   case when length(coalesce(phone, '')) >= 4 then 'XXXXXX' || right(phone, 4) else '-' end as phone,
                   account_status, balance_usdt as wallet_balance, created_at
            from public.profiles order by created_at desc limit ${lim}
          `;
      return jsonRes({ users });
    }

    async function resolveAdminTargetUid(rawInput: unknown): Promise<string> {
      const q = String(rawInput || "").trim();
      if (!q) throw new Error("Enter a valid User ID (UUID) or Email.");
      if (UUID_RE.test(q)) return q;
      const cleanEmail = /^\d{10}$/.test(q) ? `${q}@smartcaptcha.local` : q.toLowerCase();
      const [u] = await sql`select id from public.users where lower(email) = ${cleanEmail} limit 1`;
      if (!u) throw new Error("User not found for: " + q);
      return String(u.id);
    }

    if (action === "user_detail") {
      const uid = await resolveAdminTargetUid(body.user_id);
      const [[profile], ledger, withdrawals] = await Promise.all([
        sql`
          select id, email, full_name, phone, gender, date_of_birth, city, state, pin_code,
                 referral_code, referred_by, account_status, device_locked, is_admin, balance_usdt, created_at
          from public.profiles where id = ${uid} limit 1
        `,
        sql`select * from public.wallet_ledger where user_id = ${uid} order by created_at desc limit 50`,
        sql`select * from public.withdrawal_requests where user_id = ${uid} order by created_at desc limit 30`,
      ]);
      if (!profile) return jsonRes({ error: "User profile not found." }, 404);
      return jsonRes({ profile, wallet_balance: Number(profile?.balance_usdt || 0), ledger, withdrawals });
    }

    if (action === "set_user_status") {
      const uid = await resolveAdminTargetUid(body.user_id);
      const st = String(body.status || "");
      if (!["active", "review", "blocked", "pending"].includes(st)) return jsonRes({ error: "Invalid account status." }, 400);
      await sql`update public.profiles set account_status = ${st} where id = ${uid}`;
      if (st === "blocked") await bumpTokenVersion(uid);
      return jsonRes({ message: "User status updated." });
    }
    if (action === "reset_device_lock") {
      const uid = await resolveAdminTargetUid(body.user_id);
      await sql`update public.profiles set device_token = null where id = ${uid}`;
      return jsonRes({ message: "Device lock reset." });
    }
    if (action === "reset_user_password") {
      const uid = await resolveAdminTargetUid(body.user_id);
      const pwd = String(body.password || "");
      if (pwd.length < 8 || pwd.length > 128) return jsonRes({ error: "Password must be 8 to 128 characters." }, 400);
      await sql`update public.users set password_hash = ${await hashPassword(pwd)} where id = ${uid}`;
      await bumpTokenVersion(uid);
      return jsonRes({ message: "User password reset." });
    }
    if (action === "change_admin_password") {
      const curPwd = String(body.current_password || "");
      const newPwd = String(body.new_password || "");
      if (!curPwd) return jsonRes({ error: "Enter your current password." }, 400);
      if (newPwd.length < 8 || newPwd.length > 128) return jsonRes({ error: "New password must be 8 to 128 characters." }, 400);
      const [me] = await sql`select id, password_hash from public.users where id = ${adminUser.id} limit 1`;
      if (!me || !(await verifyPassword(curPwd, me.password_hash))) {
        return jsonRes({ error: "Current password is incorrect." }, 400);
      }
      await sql`update public.users set password_hash = ${await hashPassword(newPwd)} where id = ${adminUser.id}`;
      const tv = await bumpTokenVersion(adminUser.id);
      const dfp = deviceFingerprint(req?.headers.get("x-device-token") || "");
      const access_token = await issueJwt({ id: adminUser.id, email: adminUser.email, role: adminUser.role }, dfp, tv);
      return jsonRes({ message: "Your Admin Panel password has been updated & other sessions logged out.", access_token });
    }
    if (action === "list_admins") {
      const envList = Array.from(ADMIN_EMAILS);
      const admins = await sql`
        select u.id, u.email, u.role, u.created_at,
               coalesce(p.full_name, '') as full_name,
               coalesce(p.is_admin, false) as is_admin,
               coalesce(p.account_status, 'active') as account_status
        from public.users u
        left join public.profiles p on p.id = u.id
        where u.role = 'admin'
           or coalesce(p.is_admin, false) = true
           or (${envList.length > 0} and lower(u.email) = any(${envList}))
        order by u.created_at asc
      `;
      return jsonRes({
        admins: admins.map((a: any) => ({
          id: a.id,
          email: a.email,
          full_name: a.full_name,
          role: a.role,
          account_status: a.account_status,
          created_at: a.created_at,
          is_env_root: ADMIN_EMAILS.has(String(a.email || "").toLowerCase()),
          is_self: a.id === adminUser.id,
        })),
      });
    }
    if (action === "grant_admin") {
      const raw = String(body.target || body.user_id || body.email || "").trim();
      const pwd = String(body.password || "");
      const fullName = String(body.full_name || "").trim();
      if (!raw) return jsonRes({ error: "Enter a User ID (UUID) or Email address." }, 400);
      if (pwd && (pwd.length < 8 || pwd.length > 128)) {
        return jsonRes({ error: "Password must be 8 to 128 characters." }, 400);
      }
      const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(raw);
      const foundRows = isUuid
        ? await sql`select id, email, role from public.users where id = ${raw} limit 1`
        : await sql`select id, email, role from public.users where lower(email) = ${raw.toLowerCase()} limit 1`;

      if (foundRows.length) {
        const target = foundRows[0];
        if (pwd) {
          await sql`update public.users set role = 'admin', password_hash = ${await hashPassword(pwd)} where id = ${target.id}`;
        } else {
          await sql`update public.users set role = 'admin' where id = ${target.id}`;
        }
        const [prof] = await sql`select id from public.profiles where id = ${target.id} limit 1`;
        if (prof) {
          await sql`
            update public.profiles
            set is_admin = true,
                account_status = 'active',
                full_name = coalesce(${fullName || null}, full_name)
            where id = ${target.id}
          `;
        } else {
          await sql`
            insert into public.profiles (id, email, full_name, referral_code, account_status, is_admin)
            values (${target.id}, ${target.email}, ${fullName || "Admin"}, ${"ADM" + randomCode(5)}, 'active', true)
          `;
        }
        return jsonRes({
          message: `Admin panel access linked to ${target.email}${pwd ? " (with new password)" : ""}.`,
          admin: { id: target.id, email: target.email },
        });
      }

      if (isUuid || !raw.includes("@")) {
        return jsonRes({ error: "User ID not found. Enter a valid registered User UUID or an Email + Password." }, 404);
      }
      if (!pwd) {
        return jsonRes({ error: "This email is not registered yet. Enter a password (min 8 chars) to create a new admin account." }, 400);
      }
      const emailLower = raw.toLowerCase();
      const [created] = await sql`
        insert into public.users (email, password_hash, role)
        values (${emailLower}, ${await hashPassword(pwd)}, 'admin')
        returning id, email
      `;
      await sql`
        insert into public.profiles (id, email, full_name, referral_code, account_status, is_admin)
        values (${created.id}, ${created.email}, ${fullName || "Admin"}, ${"ADM" + randomCode(5)}, 'active', true)
      `;
      return jsonRes({
        message: `New Admin account created and granted access: ${created.email}`,
        admin: { id: created.id, email: created.email },
      });
    }
    if (action === "update_admin_password") {
      const targetId = String(body.user_id || "").trim();
      const newPwd = String(body.new_password || body.password || "");
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(targetId)) {
        return jsonRes({ error: "Valid admin User ID is required." }, 400);
      }
      if (newPwd.length < 8 || newPwd.length > 128) {
        return jsonRes({ error: "New password must be 8 to 128 characters." }, 400);
      }
      const [target] = await sql`
        select u.id, u.email, u.role, coalesce(p.is_admin, false) as is_admin
        from public.users u
        left join public.profiles p on p.id = u.id
        where u.id = ${targetId} limit 1
      `;
      if (!target) return jsonRes({ error: "Admin account not found." }, 404);
      if (target.role !== "admin" && !target.is_admin && !ADMIN_EMAILS.has(String(target.email || "").toLowerCase())) {
        return jsonRes({ error: "Selected user does not have admin access." }, 400);
      }
      await sql`update public.users set password_hash = ${await hashPassword(newPwd)} where id = ${target.id}`;
      await bumpTokenVersion(target.id);
      return jsonRes({ message: `Admin password updated for ${target.email}.` });
    }
    if (action === "revoke_admin") {
      const targetId = String(body.user_id || "").trim();
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(targetId)) {
        return jsonRes({ error: "Valid admin User ID is required." }, 400);
      }
      if (targetId === adminUser.id) {
        return jsonRes({ error: "You cannot remove your own currently signed-in admin access." }, 400);
      }
      const [target] = await sql`select id, email from public.users where id = ${targetId} limit 1`;
      if (!target) return jsonRes({ error: "Admin account not found." }, 404);
      if (ADMIN_EMAILS.has(String(target.email || "").toLowerCase())) {
        return jsonRes({ error: "Root admin configured in server .env cannot be removed from panel." }, 403);
      }
      await sql`update public.users set role = 'user' where id = ${target.id}`;
      await sql`update public.profiles set is_admin = false where id = ${target.id}`;
      await bumpTokenVersion(target.id);
      return jsonRes({ message: `Admin access removed from ${target.email}.` });
    }
    if (action === "update_user_profile") {
      const uid = await resolveAdminTargetUid(body.user_id);
      const refRaw = String(body.referral_code || "").trim().toUpperCase();
      if (refRaw === "NONE") {
        await sql`update public.profiles set referred_by = null where id = ${uid}`;
      } else if (refRaw) {
        const [sp] = await sql`select id from public.profiles where referral_code = ${refRaw} and id <> ${uid} limit 1`;
        if (!sp) return jsonRes({ error: "Sponsor referral code not found." }, 404);
        await sql`update public.profiles set referred_by = ${sp.id} where id = ${uid}`;
      }
      await sql`
        update public.profiles set
          full_name = coalesce(${body.full_name ? String(body.full_name).trim() : null}, full_name),
          phone = coalesce(${body.phone ? String(body.phone).trim() : null}, phone),
          gender = coalesce(${body.gender !== undefined && body.gender !== "" ? String(body.gender) : null}, gender),
          state = coalesce(${body.state !== undefined && body.state !== "" ? String(body.state).trim() : null}, state),
          city = coalesce(${body.city !== undefined && body.city !== "" ? String(body.city).trim() : null}, city),
          pin_code = coalesce(${body.pin_code !== undefined && body.pin_code !== "" ? String(body.pin_code).trim() : null}, pin_code)
        where id = ${uid}
      `;
      return jsonRes({ message: "Profile updated." });
    }
    if (action === "adjust_wallet") {
      const uid = await resolveAdminTargetUid(body.user_id);
      const amt = Number(body.amount);
      if (!Number.isFinite(amt) || amt === 0) return jsonRes({ error: "Invalid adjustment amount." }, 400);
      await sql`
        insert into public.wallet_ledger (user_id, entry_type, amount, description)
        values (${uid}, 'admin_adjustment', ${amt}, ${String(body.reason || "Admin adjustment")})
      `;
      return jsonRes({ message: `Wallet adjusted by ${amt} USDT.` });
    }

    if (action === "list_withdrawals") {
      const st = String(body.status || "all");
      const withdrawals = st === "all"
        ? await sql`select * from public.withdrawal_requests order by id desc limit 100`
        : await sql`select * from public.withdrawal_requests where status = ${st} order by id desc limit 100`;
      return jsonRes({ withdrawals });
    }
    if (action === "set_withdrawal_condition") {
      await sql`update public.withdrawal_requests set required_deposit_usdt = ${Number(body.required_deposit_usdt || 0)} where id = ${Number(body.withdrawal_id)}`;
      return jsonRes({ message: "Condition updated." });
    }
    if (action === "settle_withdrawal") {
      const wid = Number(body.withdrawal_id);
      const dec = String(body.decision || "");
      const note = String(body.note || "");
      const txId = String(body.tx_id || "").trim();
      if (!["approved", "rejected"].includes(dec)) return jsonRes({ error: "Invalid decision." }, 400);
      const settled = await sql.begin(async (tx: any) => {
        const [w] = await tx`
          update public.withdrawal_requests
          set status = ${dec}, admin_note = ${note}, tx_id = ${txId || null}, settled_at = now()
          where id = ${wid} and status = 'pending'
          returning *
        `;
        if (!w) return null;
        if (dec === "rejected") {
          await tx`
            insert into public.wallet_ledger (user_id, entry_type, amount, description)
            values (${w.user_id}, 'withdrawal_refund', ${w.amount}, ${`Withdrawal #${wid} rejected: ${note}`})
          `;
        }
        return w;
      });
      if (!settled) return jsonRes({ error: "Pending withdrawal not found." }, 404);
      return jsonRes({ message: `Withdrawal #${wid} ${dec}.` });
    }

    if (action === "list_deposits") {
      const st = String(body.status || "all");
      const uid = String(body.user_id || "").trim();
      const deposits = await sql`
        select * from public.deposits
        where (${st === "all"} or status = ${st})
          and (${!UUID_RE.test(uid)} or user_id = ${UUID_RE.test(uid) ? uid : "00000000-0000-0000-0000-000000000000"}::uuid)
        order by id desc limit 100
      `;
      return jsonRes({
        deposits: deposits.map((d: any) => ({
          ...d,
          amount_inr: Math.round(Number(d.amount_usdt || 0) * USDT_INR_RATE * 100) / 100,
        })),
      });
    }
    if (action === "settle_deposit") {
      const did = Number(body.deposit_id);
      const dec = String(body.decision || "");
      if (!["approved", "rejected"].includes(dec)) return jsonRes({ error: "Invalid decision." }, 400);
      const settled = await sql.begin(async (tx: any) => {
        const [d] = await tx`
          update public.deposits
          set status = ${dec}, admin_note = ${String(body.note || "")}, settled_at = now()
          where id = ${did} and status = 'pending'
          returning *
        `;
        if (!d) return null;
        if (dec === "approved") {
          await tx`
            insert into public.wallet_ledger (user_id, entry_type, amount, description)
            values (${d.user_id}, 'deposit_credit', ${d.amount_usdt}, ${`Deposit #${did} approved (${d.tx_id})`})
          `;
        }
        return d;
      });
      if (!settled) return jsonRes({ error: "Pending deposit not found." }, 404);
      return jsonRes({ message: `Deposit #${did} ${dec}.` });
    }

    if (action === "set_levels") {
      await sql`update public.app_settings set level_count = ${Number(body.level_count)}, level_income = ${JSON.stringify(body.level_income || [])}::jsonb where id = 1`;
      await redis.del("cache:app_settings");
      return jsonRes({ message: "Level settings saved." });
    }
    if (action === "set_device_lock") {
      await sql`update public.app_settings set device_lock_enabled = ${Boolean(body.enabled)} where id = 1`;
      await redis.del("cache:app_settings");
      return jsonRes({ message: "Device lock updated." });
    }
    if (action === "set_registration") {
      await sql`update public.app_settings set registration_open = ${Boolean(body.open)} where id = 1`;
      await redis.del("cache:app_settings");
      return jsonRes({ message: "Registration status updated." });
    }
    if (action === "set_registration_limit") {
      await sql`update public.app_settings set max_registered = ${Number(body.max_registered)} where id = 1`;
      await redis.del("cache:app_settings");
      return jsonRes({ message: "Registration limit updated." });
    }
    if (action === "get_captcha_mode") {
      const s = await getCachedAppSettings();
      const cm = parseCaptchaMode(s?.captcha_mode);
      return jsonRes({ random_enabled: cm.random_enabled, length: cm.length, mode: cm.random_enabled ? "standard" : "off" });
    }
    if (action === "set_captcha_mode") {
      const randomEnabled = body.random_enabled !== undefined ? Boolean(body.random_enabled) : String(body.mode || "standard") !== "off";
      const len = Math.min(8, Math.max(4, Math.round(Number(body.length || 5))));
      const val = JSON.stringify({ random_enabled: randomEnabled, length: len });
      await sql`
        insert into public.app_settings (id, captcha_mode, updated_at)
        values (1, ${val}, now())
        on conflict (id) do update set captcha_mode = excluded.captcha_mode, updated_at = now()
      `;
      await redis.del("cache:app_settings");
      return jsonRes({ message: `Captcha updated (${randomEnabled ? "ON" : "OFF"}, ${len} chars).`, random_enabled: randomEnabled, length: len });
    }

    if (action === "get_deposit_address") {
      const [c] = await sql`select deposit_address, deposit_qr from public.public_withdraw_config where id = 1`;
      const addr = c?.deposit_address || "";
      const qr = c?.deposit_qr || "";
      return jsonRes({ address: addr, qr, deposit_address: addr, deposit_qr: qr });
    }
    if (action === "set_deposit_address") {
      const addr = String(body.address ?? body.deposit_address ?? "").trim();
      const hasQr = body.qr !== undefined || body.deposit_qr !== undefined;
      const qr = String(body.qr ?? body.deposit_qr ?? "");
      if (hasQr) {
        await sql`
          insert into public.public_withdraw_config (id, deposit_address, deposit_qr, updated_at)
          values (1, ${addr}, ${qr}, now())
          on conflict (id) do update set deposit_address = excluded.deposit_address, deposit_qr = excluded.deposit_qr, updated_at = now()
        `;
      } else {
        await sql`
          insert into public.public_withdraw_config (id, deposit_address, updated_at)
          values (1, ${addr}, now())
          on conflict (id) do update set deposit_address = excluded.deposit_address, updated_at = now()
        `;
      }
      await redis.del("cache:public_withdraw_config");
      return jsonRes({ message: "Deposit address updated." });
    }
    if (action === "set_withdrawal_amounts") {
      await sql`update public.public_withdraw_config set amounts = ${JSON.stringify(body.amounts || [])}::jsonb, updated_at = now() where id = 1`;
      await redis.del("cache:public_withdraw_config");
      return jsonRes({ message: "Withdrawal amounts saved." });
    }
    if (action === "set_amount_conditions") {
      const conds = body.conditions ?? body.amount_conditions ?? [];
      await sql`update public.public_withdraw_config set amount_conditions = ${JSON.stringify(conds)}::jsonb, updated_at = now() where id = 1`;
      await redis.del("cache:public_withdraw_config");
      return jsonRes({ message: "Amount conditions saved." });
    }
    if (action === "get_withdraw_chart") {
      const [c] = await sql`select chart from public.public_withdraw_config where id = 1`;
      return jsonRes({ chart: c?.chart || {} });
    }
    if (action === "set_withdraw_chart") {
      const chart = body.chart || {
        deposit_percent: Number(body.deposit_percent ?? 40),
        net_percent: Number(body.net_percent ?? 60),
        daily_limit: Number(body.daily_limit ?? 2),
        processing: String(body.processing || "1 - 12 Hours (Estimated)"),
      };
      await sql`update public.public_withdraw_config set chart = ${JSON.stringify(chart)}::jsonb, updated_at = now() where id = 1`;
      await redis.del("cache:public_withdraw_config");
      return jsonRes({ message: "Withdraw chart updated." });
    }
    if (action === "get_withdraw_rule") {
      const [p] = await sql`select withdraw_rule_json from public.platform_settings where id = 1`;
      const r = p?.withdraw_rule_json || {};
      return jsonRes({ enabled: Boolean(r.enabled), min_deposit_usdt: Number(r.min_deposit_usdt || 0), rule: r });
    }
    if (action === "set_withdraw_rule") {
      const r = body.rule || { enabled: Boolean(body.enabled), min_deposit_usdt: Number(body.min_deposit_usdt || 0) };
      await sql`
        insert into public.platform_settings (id, withdraw_rule_json, updated_at)
        values (1, ${JSON.stringify(r)}::jsonb, now())
        on conflict (id) do update set withdraw_rule_json = excluded.withdraw_rule_json, updated_at = now()
      `;
      return jsonRes({ message: "Withdrawal rules updated." });
    }

    if (action === "get_income_settings") {
      const [[row], [spentRow], pendingRows] = await Promise.all([
        sql`select * from public.income_settings where id = 1`,
        sql`
          select coalesce(sum(amount), 0) as total_usdt
          from public.wallet_ledger
          where amount > 0
            and entry_type in ('captcha_income','signup_bonus','fast_start_bonus','streak_bonus','level_once','level_daily')
            and (created_at at time zone 'Asia/Kolkata')::date = (now() at time zone 'Asia/Kolkata')::date
        `,
        redis.hvals("pending:captchas").catch(() => []),
      ]);
      const pendingUsdt = (pendingRows || []).reduce((acc: number, v: string) => acc + Number((v || "0:0").split(":")[1] || 0), 0);
      const spentTodayInr = Math.round((Number(spentRow?.total_usdt || 0) + pendingUsdt) * USDT_INR_RATE * 100) / 100;
      const settings = normalizeIncomeSettings(row || {});
      return jsonRes({ settings, spent_today_inr: spentTodayInr });
    }
    if (action === "set_income_settings") {
      const [curRow] = await sql`select * from public.income_settings where id = 1`;
      const cur = normalizeIncomeSettings(curRow || {});
      const rawLimit = Number(body.captcha_daily_limit);
      const limit = body.captcha_daily_limit !== undefined && Number.isFinite(rawLimit)
        ? Math.max(0, Math.round(rawLimit))
        : cur.captcha_daily_limit;
      const rawCapInr = Number(body.captcha_reward_inr);
      const capUsdt = body.captcha_reward_inr !== undefined && Number.isFinite(rawCapInr)
        ? Math.max(0, Math.round((rawCapInr / USDT_INR_RATE) * 10000) / 10000)
        : (body.captcha_reward_usdt !== undefined && Number.isFinite(Number(body.captcha_reward_usdt)) ? Math.max(0, Number(body.captcha_reward_usdt)) : cur.captcha_reward_usdt);
      const rawSignInr = Number(body.signup_bonus_inr);
      const signUsdt = body.signup_bonus_inr !== undefined && Number.isFinite(rawSignInr)
        ? Math.max(0, Math.round((rawSignInr / USDT_INR_RATE) * 10000) / 10000)
        : (body.signup_bonus_usdt !== undefined && Number.isFinite(Number(body.signup_bonus_usdt)) ? Math.max(0, Number(body.signup_bonus_usdt)) : cur.signup_bonus_usdt);
      const rawFastInr = Number(body.fast_start_bonus_inr);
      const fastUsdt = body.fast_start_bonus_inr !== undefined && Number.isFinite(rawFastInr)
        ? Math.max(0, Math.round((rawFastInr / USDT_INR_RATE) * 10000) / 10000)
        : (body.fast_start_bonus_usdt !== undefined && Number.isFinite(Number(body.fast_start_bonus_usdt)) ? Math.max(0, Number(body.fast_start_bonus_usdt)) : cur.fast_start_bonus_usdt);
      const rawStreakInr = Number(body.streak_bonus_inr);
      const streakUsdt = body.streak_bonus_inr !== undefined && Number.isFinite(rawStreakInr)
        ? Math.max(0, Math.round((rawStreakInr / USDT_INR_RATE) * 10000) / 10000)
        : (body.streak_bonus_usdt !== undefined && Number.isFinite(Number(body.streak_bonus_usdt)) ? Math.max(0, Number(body.streak_bonus_usdt)) : cur.streak_bonus_usdt);

      const extra = {
        income_enabled: body.income_enabled !== undefined ? Boolean(body.income_enabled) : cur.income_enabled,
        captcha_daily_limit: limit,
        captcha_reward_usdt: capUsdt,
        captcha_reward_inr: body.captcha_reward_inr !== undefined && Number.isFinite(rawCapInr) ? Math.max(0, rawCapInr) : Math.round(capUsdt * USDT_INR_RATE * 100) / 100,
        signup_bonus_usdt: signUsdt,
        signup_bonus_inr: body.signup_bonus_inr !== undefined && Number.isFinite(rawSignInr) ? Math.max(0, rawSignInr) : Math.round(signUsdt * USDT_INR_RATE * 100) / 100,
        fast_start_bonus_usdt: fastUsdt,
        fast_start_bonus_inr: body.fast_start_bonus_inr !== undefined && Number.isFinite(rawFastInr) ? Math.max(0, rawFastInr) : Math.round(fastUsdt * USDT_INR_RATE * 100) / 100,
        fast_start_directs: body.fast_start_directs !== undefined && Number.isFinite(Number(body.fast_start_directs)) ? Math.max(1, Number(body.fast_start_directs)) : cur.fast_start_directs,
        streak_bonus_usdt: streakUsdt,
        streak_bonus_inr: body.streak_bonus_inr !== undefined && Number.isFinite(rawStreakInr) ? Math.max(0, rawStreakInr) : Math.round(streakUsdt * USDT_INR_RATE * 100) / 100,
        streak_days: body.streak_days !== undefined && Number.isFinite(Number(body.streak_days)) ? Math.max(1, Number(body.streak_days)) : cur.streak_days,
        daily_company_cap_inr: body.daily_company_cap_inr !== undefined && Number.isFinite(Number(body.daily_company_cap_inr)) ? Math.max(0, Number(body.daily_company_cap_inr)) : cur.daily_company_cap_inr,
        level_once_inr: Array.isArray(body.level_once_inr) ? body.level_once_inr.map((n: any) => Math.max(0, Number(n) || 0)) : cur.level_once_inr,
        level_daily_inr: Array.isArray(body.level_daily_inr) ? body.level_daily_inr.map((n: any) => Math.max(0, Number(n) || 0)) : cur.level_daily_inr,
        level_daily_directs: Array.isArray(body.level_daily_directs) ? body.level_daily_directs.map((n: any) => Math.max(0, Number(n) || 0)) : cur.level_daily_directs,
      };
      await sql`
        insert into public.income_settings (
          id, captcha_daily_limit, captcha_reward_usdt, signup_bonus_usdt,
          fast_start_bonus_usdt, streak_bonus_usdt, extra_config, updated_at
        ) values (
          1, ${limit}, ${capUsdt}, ${signUsdt}, ${fastUsdt}, ${streakUsdt}, ${JSON.stringify(extra)}::jsonb, now()
        )
        on conflict (id) do update set
          captcha_daily_limit = excluded.captcha_daily_limit,
          captcha_reward_usdt = excluded.captcha_reward_usdt,
          signup_bonus_usdt = excluded.signup_bonus_usdt,
          fast_start_bonus_usdt = excluded.fast_start_bonus_usdt,
          streak_bonus_usdt = excluded.streak_bonus_usdt,
          extra_config = excluded.extra_config,
          updated_at = now()
      `;
      await redis.del("cache:income_settings");
      return jsonRes({ message: `Income settings saved! Daily Captcha Limit: ${limit}, Reward: ₹${extra.captcha_reward_inr}`, settings: extra });
    }
    if (action === "income_summary") {
      const [[tot], [wal], byType] = await Promise.all([
        sql`
          select coalesce(sum(case when amount > 0 then amount else 0 end), 0) as total_credited,
                 coalesce(sum(case when amount < 0 then abs(amount) else 0 end), 0) as total_debited
          from public.wallet_ledger
        `,
        sql`select coalesce(sum(balance_usdt), 0) as user_wallets_total from public.profiles`,
        sql`
          select entry_type as type, count(*)::integer as count, coalesce(sum(amount), 0) as total
          from public.wallet_ledger
          group by entry_type order by count desc
        `,
      ]);
      return jsonRes({
        summary: {
          total_credited: Number(tot?.total_credited || 0),
          total_debited: Number(tot?.total_debited || 0),
          user_wallets_total: Number(wal?.user_wallets_total || 0),
          by_type: byType,
        },
      });
    }
    if (action === "list_ledger") {
      const q = String(body.query || "").trim();
      const t = String(body.type || "all").trim();
      const lim = Math.min(200, Math.max(10, Number(body.limit) || 50));
      const off = Math.max(0, Number(body.offset) || 0);
      const entries = await sql`
        select w.*, coalesce(p.full_name, '') as full_name, coalesce(p.email, '') as email
        from public.wallet_ledger w
        left join public.profiles p on p.id = w.user_id
        where (${t === "all" || !t} or w.entry_type = ${t})
          and (${!q} or coalesce(p.email, '') ilike ${"%" + q + "%"} or coalesce(p.full_name, '') ilike ${"%" + q + "%"} or coalesce(w.description, '') ilike ${"%" + q + "%"})
        order by w.id desc limit ${lim} offset ${off}
      `;
      return jsonRes({ entries });
    }
    if (action === "run_daily_income") {
      await flushPendingCaptchas();
      return jsonRes({ message: "Flushed pending Redis earnings to PostgreSQL." });
    }
    if (action === "capacity_snapshot") {
      let memTotalMb = 0, memAvailMb = 0, swapTotalMb = 0, swapFreeMb = 0;
      try {
        const memRaw = readFileSync("/proc/meminfo", "utf8");
        const grab = (k: string) => {
          const m = memRaw.match(new RegExp(`^${k}:\\s+(\\d+)`, "m"));
          return m ? Math.round(Number(m[1]) / 1024) : 0;
        };
        memTotalMb = grab("MemTotal");
        memAvailMb = grab("MemAvailable") || grab("MemFree");
        swapTotalMb = grab("SwapTotal");
        swapFreeMb = grab("SwapFree");
      } catch {}

      let diskTotalGb = 0, diskUsedGb = 0, diskFreeGb = 0, diskUsedPct = 0;
      try {
        const p = Bun.spawnSync(["df", "-k", "/app/scale-server.ts"]);
        const lines = p.stdout.toString().trim().split(/\r?\n/);
        const cols = (lines[lines.length - 1] || "").trim().split(/\s+/);
        if (cols.length >= 5) {
          diskTotalGb = Math.round(((Number(cols[1]) || 0) / 1048576) * 100) / 100;
          diskUsedGb = Math.round(((Number(cols[2]) || 0) / 1048576) * 100) / 100;
          diskFreeGb = Math.round(((Number(cols[3]) || 0) / 1048576) * 100) / 100;
          diskUsedPct = Number(String(cols[4]).replace("%", "")) || 0;
        }
      } catch {}

      const [[dbRow], users, ledger_rows, appSet, pendingRedis, redisMemRaw] = await Promise.all([
        sql`select pg_database_size(current_database())::bigint as size_bytes, pg_size_pretty(pg_database_size(current_database())) as size_pretty`,
        getFastRowCount("profiles", "cache:reg_count", 15),
        getFastRowCount("wallet_ledger", "cache:ledger_count", 15),
        getCachedAppSettings(),
        redis.hlen("pending:captchas"),
        redis.info("memory").catch(() => ""),
      ]);

      const maxReg = Number(appSet?.max_registered || 1000000);
      const remainingReg = Math.max(0, maxReg - Number(users || 0));
      const memUsedMb = Math.max(0, memTotalMb - memAvailMb);
      const redisMemMatch = String(redisMemRaw || "").match(/used_memory_human:([^\r\n]+)/);
      const capacity = {
        server_ram: {
          total_mb: memTotalMb,
          used_mb: memUsedMb,
          free_mb: memAvailMb,
          used_pct: memTotalMb > 0 ? Math.round((memUsedMb / memTotalMb) * 100) : 0,
          swap_total_mb: swapTotalMb,
          swap_used_mb: Math.max(0, swapTotalMb - swapFreeMb),
        },
        disk_storage: {
          total_gb: diskTotalGb,
          used_gb: diskUsedGb,
          free_gb: diskFreeGb,
          used_pct: diskUsedPct,
        },
        database: {
          size_bytes: Number(dbRow?.size_bytes || 0),
          size_pretty: String(dbRow?.size_pretty || "0 MB"),
          total_users: Number(users || 0),
          max_registered: maxReg,
          remaining_registrations: remainingReg,
          ledger_rows: Number(ledger_rows || 0),
        },
        redis: {
          used_memory: redisMemMatch ? redisMemMatch[1].trim() : "-",
          pending_captcha_users: pendingRedis,
        },
        uptime_seconds: Math.round(process.uptime()),
      };
      return jsonRes({ registered_users: users, pending_redis_users: pendingRedis, capacity });
    }

    if (action === "list_tickets") {
      const st = String(body.status || "all");
      const tickets = await sql`
        select t.*, coalesce(p.email, '') as email
        from public.support_tickets t
        left join public.profiles p on p.id = t.user_id
        where (${st === "all" || !st} or t.status = ${st})
        order by t.updated_at desc limit 100
      `;
      return jsonRes({ tickets });
    }
    if (action === "ticket_messages") {
      const messages = await sql`select * from public.ticket_messages where ticket_id = ${Number(body.ticket_id)} order by created_at asc`;
      return jsonRes({ messages });
    }
    if (action === "reply_ticket") {
      const tid = Number(body.ticket_id);
      const msgBody = String(body.message || "").trim();
      if (msgBody) {
        await sql`insert into public.ticket_messages (ticket_id, sender, body) values (${tid}, 'admin', ${msgBody})`;
      }
      const nextSt = body.close ? "closed" : "answered";
      await sql`update public.support_tickets set status = ${nextSt}, updated_at = now() where id = ${tid}`;
      return jsonRes({ message: body.close ? "Ticket closed." : "Reply sent." });
    }

    // Compounding Admin Actions
    if (action === "get_compounding_settings") {
      const [[s], [st], [spentRow]] = await Promise.all([
        sql`select * from public.compounding_settings where id = 1`,
        sql`
          select count(*)::integer as total_plans,
                 count(*) filter (where status='active')::integer as active_plans,
                 coalesce(sum(principal_inr), 0) as total_invested_inr,
                 coalesce(sum(total_profit_inr), 0) as total_profit_inr
          from public.compounding_plans
        `,
        sql`select coalesce(sum(profit_inr), 0) as spent_today_inr from public.compounding_daily_logs where credit_date = (now() at time zone 'Asia/Kolkata')::date`,
      ]);
      return jsonRes({
        settings: s,
        stats: {
          total_plans: Number(st?.total_plans || 0),
          active_plans: Number(st?.active_plans || 0),
          total_invested_inr: Number(st?.total_invested_inr || 0),
          total_profit_inr: Number(st?.total_profit_inr || 0),
          spent_today_inr: Number(spentRow?.spent_today_inr || 0),
        },
      });
    }
    if (action === "set_compounding_settings") {
      await sql`
        update public.compounding_settings set
          enabled = coalesce(${body.enabled ?? null}, enabled),
          duration_days = coalesce(${body.duration_days ?? null}, duration_days),
          daily_rate_pct = coalesce(${body.daily_rate_pct ?? null}, daily_rate_pct),
          monthly_target_pct = coalesce(${body.monthly_target_pct ?? null}, monthly_target_pct),
          allowed_amounts_inr = coalesce(${body.allowed_amounts_inr ? JSON.stringify(body.allowed_amounts_inr) : null}::jsonb, allowed_amounts_inr),
          allow_custom_amount = coalesce(${body.allow_custom_amount ?? null}, allow_custom_amount),
          min_custom_inr = coalesce(${body.min_custom_inr ?? null}, min_custom_inr),
          max_custom_inr = coalesce(${body.max_custom_inr ?? null}, max_custom_inr),
          max_active_plans_per_user = coalesce(${body.max_active_plans_per_user ?? null}, max_active_plans_per_user),
          credit_mode = coalesce(${body.credit_mode ?? null}, credit_mode),
          early_exit_enabled = coalesce(${body.early_exit_enabled ?? null}, early_exit_enabled),
          early_exit_penalty_pct = coalesce(${body.early_exit_penalty_pct ?? null}, early_exit_penalty_pct),
          require_active_account = coalesce(${body.require_active_account ?? null}, require_active_account),
          daily_company_cap_inr = coalesce(${body.daily_company_cap_inr ?? null}, daily_company_cap_inr),
          updated_at = now()
        where id = 1
      `;
      await redis.del("cache:compounding_settings");
      return jsonRes({ message: "Compounding settings saved." });
    }
    if (action === "list_compounding_plans") {
      const st = String(body.status || "all");
      const q = String(body.query || "").trim();
      const plans = await sql`
        select cp.*, coalesce(p.full_name, '-') as user_name, coalesce(p.email, '') as user_email
        from public.compounding_plans cp
        left join public.profiles p on p.id = cp.user_id
        where (${st === "all" || !st} or cp.status = ${st})
          and (${!q} or coalesce(p.email, '') ilike ${"%" + q + "%"} or coalesce(p.full_name, '') ilike ${"%" + q + "%"})
        order by cp.id desc limit 100
      `;
      const [stats] = await sql`
        select count(*) filter (where status='active')::integer as active_count,
               coalesce(sum(principal_inr) filter (where status='active'), 0) as total_principal_inr,
               coalesce(sum(total_profit_inr), 0) as total_profit_inr
        from public.compounding_plans
      `;
      return jsonRes({ plans, stats });
    }
    if (action === "assign_compounding_plan") {
      const amtInr = Number(body.amount_inr);
      if (!Number.isFinite(amtInr) || amtInr <= 0) return jsonRes({ error: "Invalid INR amount." }, 400);
      const q = String(body.user_query || body.user_id || "").trim();
      const [targetUser] = UUID_RE.test(q)
        ? await sql`select id, balance_usdt from public.profiles where id = ${q} limit 1`
        : await sql`select id, balance_usdt from public.profiles where lower(email) = ${q.toLowerCase()} limit 1`;
      if (!targetUser) return jsonRes({ error: "User not found." }, 404);
      const uid = String(targetUser.id);
      const reqUsdt = Math.round((amtInr / USDT_INR_RATE) * 10000) / 10000;
      const [s] = await sql`select * from public.compounding_settings where id = 1`;
      const dur = Number(body.duration_days || s.duration_days || 365);
      const rate = Number(body.daily_rate_pct ?? s.daily_rate_pct ?? 0.746585);
      const plan = await sql.begin(async (tx: any) => {
        if (body.deduct_wallet) {
          const [p] = await tx`select balance_usdt from public.profiles where id = ${uid} for update`;
          if (Number(p?.balance_usdt || 0) < reqUsdt) throw new Error("User has insufficient wallet balance.");
          await tx`
            insert into public.wallet_ledger (user_id, entry_type, amount, description)
            values (${uid}, 'compounding_invest', ${-reqUsdt}, ${`Admin assigned ${dur}-Day Compounding Plan (₹${amtInr})`})
          `;
        }
        const [ins] = await tx`
          insert into public.compounding_plans (
            user_id, principal_inr, principal_usdt, current_balance_inr, daily_rate_pct, duration_days,
            projected_maturity_inr, credit_mode, status, created_by_admin, admin_note
          ) values (
            ${uid}, ${amtInr}, ${reqUsdt}, ${amtInr}, ${rate}, ${dur},
            ${calcProjectedBalance(amtInr, rate, dur)}, ${s.credit_mode}, 'active', true, ${String(body.note || "Assigned by admin")}
          ) returning *
        `;
        return ins;
      });
      return jsonRes({ message: `Assigned Plan #${plan.id}`, plan });
    }
    if (action === "manage_compounding_plan") {
      const pid = Number(body.plan_id);
      const op = String(body.operation);
      const [plan] = await sql`select * from public.compounding_plans where id = ${pid}`;
      if (!plan) return jsonRes({ error: "Plan not found." }, 404);
      if (op === "pause") await sql`update public.compounding_plans set status = 'paused' where id = ${pid}`;
      else if (op === "resume") await sql`update public.compounding_plans set status = 'active' where id = ${pid}`;
      else if (op === "complete" || op === "complete_now") {
        const payInr = plan.credit_mode === "daily_to_main_wallet" ? Number(plan.principal_inr) : Number(plan.current_balance_inr);
        await sql`update public.compounding_plans set status = 'completed', matured_at = now() where id = ${pid}`;
        await sql`insert into public.wallet_ledger (user_id, entry_type, amount, description) values (${plan.user_id}, 'compounding_maturity', ${payInr / USDT_INR_RATE}, ${`Admin matured Plan #${pid} (₹${payInr})`})`;
      } else if (op === "cancel_refund") {
        await sql`update public.compounding_plans set status = 'cancelled', matured_at = now() where id = ${pid}`;
        await sql`insert into public.wallet_ledger (user_id, entry_type, amount, description) values (${plan.user_id}, 'withdrawal_refund', ${plan.principal_usdt}, ${`Plan #${pid} refunded by admin`})`;
      }
      return jsonRes({ message: `Plan #${pid} ${op} done.` });
    }
    if (action === "admin_compounding_logs") {
      const logs = await sql`select * from public.compounding_daily_logs where plan_id = ${Number(body.plan_id)} order by day_number desc limit 100`;
      return jsonRes({ logs });
    }
    if (action === "run_daily_compounding") {
      const day = String(body.day || todayIst());
      let processed = 0, completed = 0, profit = 0, more = true;
      while (more) {
        const [r] = await sql`select public.run_daily_compounding_batch(${day}::date, 5000) as res`;
        processed += Number(r?.res?.processed_plans || 0);
        completed += Number(r?.res?.completed_plans || 0);
        profit += Number(r?.res?.total_profit_inr || 0);
        more = Boolean(r?.res?.has_more);
      }
      return jsonRes({ ok: true, processed_plans: processed, completed_plans: completed, total_profit_inr: profit, message: `Credited ${processed} plans (₹${profit.toFixed(2)}).` });
    }

    if (action === "get_monetization") {
      const [[cfg], [stats], recent] = await Promise.all([
        sql`select * from public.monetization_settings where id = 1`,
        sql`
          select count(*)::integer as total_tx,
                 coalesce(sum(gross_usdt), 0) as total_gross_usdt,
                 coalesce(sum(admin_profit_usdt), 0) as total_admin_profit_usdt,
                 coalesce(sum(user_share_usdt), 0) as total_user_paid_usdt
          from public.offerwall_postbacks
        `,
        sql`
          select p.id, p.tx_id, p.user_id, p.network, p.gross_usdt, p.user_share_usdt, p.admin_profit_usdt, p.created_at,
                 coalesce(pr.email, '') as email
          from public.offerwall_postbacks p
          left join public.profiles pr on pr.id = p.user_id
          order by p.id desc limit 25
        `,
      ]);
      return jsonRes({ settings: cfg, stats, recent });
    }
    if (action === "set_monetization") {
      const topBannerImg = isSafeHttpsUrl(body.top_banner_img);
      const topBannerLink = isSafeHttpsUrl(body.top_banner_link);
      const adScriptUrl = isSafeHttpsUrl(body.ad_script_url);
      const adContainerId = String(body.ad_container_id || "").trim().replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 80);
      const directLinkUrl = isSafeHttpsUrl(body.direct_link_url);
      const directLinkLabel = String(body.direct_link_label || "🎁 Sponsored Offer — Check Now").trim().slice(0, 80);
      const offerwallName = String(body.offerwall_name || "Offerwall Tasks").trim().slice(0, 60);
      const offerwallUrl = isSafeHttpsUrl(body.offerwall_url);
      const sharePct = Number(body.user_share_pct ?? 60);
      if (!Number.isFinite(sharePct) || sharePct < 1 || sharePct > 95) {
        return jsonRes({ error: "User share must be between 1% and 95%." }, 400);
      }
      await sql`
        update public.monetization_settings set
          ads_enabled = ${Boolean(body.ads_enabled)},
          top_banner_img = ${topBannerImg},
          top_banner_link = ${topBannerLink},
          ad_script_url = ${adScriptUrl},
          ad_container_id = ${adContainerId},
          direct_link_url = ${directLinkUrl},
          direct_link_label = ${directLinkLabel},
          offerwall_enabled = ${Boolean(body.offerwall_enabled)},
          offerwall_name = ${offerwallName},
          offerwall_url = ${offerwallUrl},
          user_share_pct = ${sharePct},
          updated_at = now()
        where id = 1
      `;
      await redis.del("cache:monetization_public");
      return jsonRes({ message: "Ads & Offerwall settings saved." });
    }
    if (action === "rotate_postback_secret") {
      const nextSecret = randomCode(24);
      await sql`update public.monetization_settings set postback_secret = ${nextSecret}, updated_at = now() where id = 1`;
      return jsonRes({ postback_secret: nextSecret, message: "New Postback Secret generated. Update your Offerwall network URL!" });
    }

    // ---- 5-Layer Security Center & Audit Logs ----
    if (action === "get_security_center") {
      const [[me], [stats], logs] = await Promise.all([
        sql`select security_pin_hash <> '' as pin_set, totp_enabled, coalesce(token_version, 1) as token_version from public.users where id = ${adminUser.id} limit 1`,
        sql`
          select count(*) filter (where event_type like 'login_failed%' and created_at > now() - interval '24 hours')::integer as fails_24h,
                 count(*) filter (where event_type = 'login_locked' and created_at > now() - interval '24 hours')::integer as locks_24h,
                 count(*) filter (where event_type = 'login_success' and created_at > now() - interval '24 hours')::integer as logins_24h
          from public.security_audit_logs
        `,
        sql`select id, email, event_type, ip_masked, device_fp, details, created_at from public.security_audit_logs order by id desc limit 40`,
      ]);
      return jsonRes({
        my_security: { pin_set: Boolean(me?.pin_set), totp_enabled: Boolean(me?.totp_enabled), token_version: Number(me?.token_version || 1) },
        stats: stats || { fails_24h: 0, locks_24h: 0, logins_24h: 0 },
        logs,
      });
    }
    if (action === "set_admin_security_pin") {
      const curPwd = String(body.current_password || "");
      const newPin = String(body.new_pin || "").trim();
      if (!curPwd) return jsonRes({ error: "Enter your current password." }, 400);
      if (!/^\d{4,6}$/.test(newPin)) return jsonRes({ error: "Admin Security PIN must be 4 to 6 digits." }, 400);
      const [me] = await sql`select id, password_hash from public.users where id = ${adminUser.id} limit 1`;
      if (!me || !(await verifyPassword(curPwd, me.password_hash))) {
        return jsonRes({ error: "Current password is incorrect." }, 401);
      }
      await sql`update public.users set security_pin_hash = ${await hashPassword(newPin)} where id = ${adminUser.id}`;
      const tv = await bumpTokenVersion(adminUser.id);
      const dfp = deviceFingerprint(req?.headers.get("x-device-token") || "");
      const access_token = await issueJwt({ id: adminUser.id, email: adminUser.email, role: adminUser.role }, dfp, tv);
      if (req) logSecurityEvent("admin_pin_changed", clientIp(req), { userId: adminUser.id, email: adminUser.email, deviceFp: dfp, details: "Admin updated 6-digit Security PIN" });
      return jsonRes({ message: "Admin 6-digit Security PIN updated & old sessions revoked.", access_token });
    }
    if (action === "setup_admin_totp") {
      const secret = generateBase32Secret(20);
      await sql`update public.users set totp_secret = ${secret}, totp_enabled = false where id = ${adminUser.id}`;
      const label = encodeURIComponent(`SmartCaptcha:${adminUser.email}`);
      const otpauth_uri = `otpauth://totp/${label}?secret=${secret}&issuer=SmartCaptcha&digits=6&period=30`;
      return jsonRes({ secret, otpauth_uri, message: "Scan/enter this secret in Google Authenticator, then enter the 6-digit code to activate." });
    }
    if (action === "enable_admin_totp") {
      const curPwd = String(body.current_password || "");
      const otp = String(body.totp_code || "").trim();
      const [me] = await sql`select id, password_hash, totp_secret from public.users where id = ${adminUser.id} limit 1`;
      if (!me || !(await verifyPassword(curPwd, me.password_hash))) return jsonRes({ error: "Current password is incorrect." }, 401);
      if (!me.totp_secret) return jsonRes({ error: "Click Generate Authenticator Key first." }, 400);
      if (!verifyTotpCode(me.totp_secret, otp).ok) return jsonRes({ error: "Invalid 6-digit Authenticator code." }, 400);
      await sql`update public.users set totp_enabled = true where id = ${adminUser.id}`;
      const tv = await bumpTokenVersion(adminUser.id);
      const dfp = deviceFingerprint(req?.headers.get("x-device-token") || "");
      const access_token = await issueJwt({ id: adminUser.id, email: adminUser.email, role: adminUser.role }, dfp, tv);
      if (req) logSecurityEvent("totp_enabled", clientIp(req), { userId: adminUser.id, email: adminUser.email, deviceFp: dfp, details: "Admin enabled Google Authenticator 2FA" });
      return jsonRes({ message: "Google Authenticator 2FA is now ACTIVE on your Admin login!", access_token });
    }
    if (action === "disable_admin_totp") {
      const curPwd = String(body.current_password || "");
      const otp = String(body.totp_code || "").trim();
      const [me] = await sql`select id, password_hash, totp_secret from public.users where id = ${adminUser.id} limit 1`;
      if (!me || !(await verifyPassword(curPwd, me.password_hash))) return jsonRes({ error: "Current password is incorrect." }, 401);
      if (me.totp_secret && !verifyTotpCode(me.totp_secret, otp).ok) return jsonRes({ error: "Enter valid current 6-digit Authenticator code to disable 2FA." }, 400);
      await sql`update public.users set totp_enabled = false, totp_secret = '' where id = ${adminUser.id}`;
      if (req) logSecurityEvent("totp_disabled", clientIp(req), { userId: adminUser.id, email: adminUser.email, details: "Admin disabled TOTP 2FA" });
      return jsonRes({ message: "Authenticator 2FA disabled." });
    }
    if (action === "unlock_login_email") {
      const targetEmail = String(body.email || "").trim().toLowerCase();
      if (!targetEmail) return jsonRes({ error: "Enter email or mobile login ID to unlock." }, 400);
      const failKey = `login_fail:${sha256Hex(targetEmail).slice(0, 24)}`;
      await redis.del(failKey);
      return jsonRes({ message: `Login cooldown cleared for ${targetEmail}.` });
    }
    if (action === "logout_all_sessions") {
      const targetId = UUID_RE.test(String(body.user_id || "")) ? String(body.user_id) : adminUser.id;
      await bumpTokenVersion(targetId);
      if (req) logSecurityEvent("logout_all", clientIp(req), { userId: targetId, email: adminUser.email, details: "Admin forced logout of all sessions" });
      return jsonRes({ message: targetId === adminUser.id ? "All your Admin sessions logged out." : "All user sessions logged out." });
    }

    return jsonRes({ error: `Unknown admin action: ${action}` }, 400);
  } catch (err: any) {
    return jsonRes({ error: err?.message || "Admin error" }, 400);
  }
}

async function shutdown() {
  console.log("Flushing pending Redis captcha rewards before exit...");
  await flushPendingCaptchas();
  server.stop();
  await sql.end();
  redis.disconnect();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

console.log(`SmartCaptcha Hetzner Scale Server running on port ${PORT}`);
