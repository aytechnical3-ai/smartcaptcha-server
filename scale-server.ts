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

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL || "";
const REDIS_URL = process.env.REDIS_URL || "redis://127.0.0.1:6379";
const JWT_SECRET = process.env.JWT_SECRET || "change-this-32char-jwt-secret";
const CAPTCHA_HMAC_SECRET = process.env.CAPTCHA_HMAC_SECRET || JWT_SECRET;
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
const FLUSH_INTERVAL_MS = Number(process.env.FLUSH_INTERVAL_MS || 30000);

if (!DATABASE_URL) throw new Error("DATABASE_URL is required");

const sql = postgres(DATABASE_URL, {
  max: Number(process.env.PG_POOL_MAX || 25),
  idle_timeout: 20,
  connect_timeout: 10,
  prepare: false,
});

const redis = new Redis(REDIS_URL, {
  maxRetriesPerRequest: 2,
  enableReadyCheck: true,
});

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

function jsonRes(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
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

// PBKDF2-SHA256 Password Hashing (Zero native dependency)
async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  const toHex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
  return `pbkdf2$${toHex(salt)}$${toHex(new Uint8Array(bits))}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "pbkdf2") return false;
  const fromHex = (h: string) => new Uint8Array(h.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
  const salt = fromHex(parts[1]);
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  const actualHex = Array.from(new Uint8Array(bits)).map((x) => x.toString(16).padStart(2, "0")).join("");
  return actualHex === parts[2];
}

async function issueJwt(user: { id: string; email: string; role: string }): Promise<string> {
  return await new SignJWT({ email: user.email, role: user.role })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(user.id)
    .setIssuedAt()
    .setExpirationTime("30d")
    .sign(enc.encode(JWT_SECRET));
}

async function authenticateRequest(req: Request): Promise<{ id: string; email: string; role: string } | null> {
  const auth = req.headers.get("authorization") || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, enc.encode(JWT_SECRET));
    if (!payload.sub) return null;
    return {
      id: String(payload.sub),
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
// Redis -> PostgreSQL Batch Flush Worker
// ----------------------------------------------------------------------------
let flushing = false;
async function flushPendingCaptchas(): Promise<{ users: number; captchas: number }> {
  if (flushing) return { users: 0, captchas: 0 };
  flushing = true;
  try {
    const exists = await redis.exists("pending:captchas");
    if (!exists) return { users: 0, captchas: 0 };
    const processingKey = `pending:captchas:flush:${Date.now()}:${Math.random().toString(36).slice(2, 7)}`;
    try { await redis.rename("pending:captchas", processingKey); } catch { return { users: 0, captchas: 0 }; }

    const rawMap = await redis.hgetall(processingKey);
    const payload: Array<{ user_id: string; solved: number; reward_usdt: number }> = [];
    for (const [userId, val] of Object.entries(rawMap)) {
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
  } catch (err) {
    console.error("[flushPendingCaptchas error]", err);
    return { users: 0, captchas: 0 };
  } finally {
    flushing = false;
  }
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

async function getCachedIncomeSettings() {
  return await getCachedConfigRow(
    "cache:income_settings",
    () => sql`select * from public.income_settings where id = 1`,
    { captcha_daily_limit: 50, captcha_reward_usdt: 0.01 }
  );
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
    { registration_open: true, max_registered: 1000000, device_lock_enabled: true }
  );
}

async function issueCaptchaChallenge(userId: string) {
  const code = randomCode(6);
  const token = await signCaptchaToken({
    uid: userId,
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
// Auth Routes
// ----------------------------------------------------------------------------
async function handleAuth(pathname: string, req: Request): Promise<Response> {
  const ip = clientIp(req);
  if (pathname === "/api/auth/signup" && req.method === "POST") {
    if (!(await checkRateLimit(`rl:signup:${ip}`, 15, 300))) {
      return jsonRes({ error: "Too many signup attempts. Please wait a few minutes." }, 429);
    }
    const body: any = await req.json().catch(() => ({}));
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!email || !email.includes("@")) return jsonRes({ error: "Invalid email or mobile ID." }, 400);
    if (password.length < 8) return jsonRes({ error: "Password must be at least 8 characters." }, 400);
    if (!(await verifyTurnstile(body.captchaToken))) {
      return jsonRes({ error: "Human verification failed. Please retry captcha." }, 400);
    }

    const appSet = await getCachedAppSettings();
    if (appSet && !appSet.registration_open) {
      return jsonRes({ error: "Registrations are currently closed by admin." }, 403);
    }
    const [{ cnt }] = await sql`select count(*)::integer as cnt from public.users`;
    if (appSet && cnt >= Number(appSet.max_registered)) {
      return jsonRes({ error: "Registration limit reached." }, 403);
    }

    const dup = await sql`select id from public.users where email = ${email} limit 1`;
    if (dup.length) return jsonRes({ error: "Account already registered. Please log in." }, 400);

    const pwdHash = await hashPassword(password);
    const isAdmin = ADMIN_EMAILS.has(email);
    const role = isAdmin ? "admin" : "user";
    const [u] = await sql`
      insert into public.users (email, password_hash, role)
      values (${email}, ${pwdHash}, ${role})
      returning id, email, role, created_at
    `;
    await sql`
      insert into public.profiles (id, email, referral_code, account_status, is_admin)
      values (${u.id}, ${u.email}, ${"SC" + randomCode(6)}, 'active', ${isAdmin})
    `;

    const access_token = await issueJwt({ id: u.id, email: u.email, role: u.role });
    return jsonRes({ user: u, session: { access_token, user: u } });
  }

  if (pathname === "/api/auth/login" && req.method === "POST") {
    if (!(await checkRateLimit(`rl:login:${ip}`, 25, 300))) {
      return jsonRes({ error: "Too many login attempts. Please wait 5 minutes." }, 429);
    }
    const body: any = await req.json().catch(() => ({}));
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!(await verifyTurnstile(body.captchaToken))) {
      return jsonRes({ error: "Human verification failed. Please retry." }, 400);
    }
    const [u] = await sql`select id, email, password_hash, role from public.users where email = ${email} limit 1`;
    if (!u || !(await verifyPassword(password, u.password_hash))) {
      return jsonRes({ error: "Invalid login credentials." }, 401);
    }
    const [prof] = await sql`select account_status from public.profiles where id = ${u.id} limit 1`;
    if (prof?.account_status === "blocked") {
      return jsonRes({ error: "Account is blocked by admin." }, 403);
    }
    const access_token = await issueJwt({ id: u.id, email: u.email, role: u.role });
    return jsonRes({
      user: { id: u.id, email: u.email, role: u.role, is_anonymous: false },
      session: { access_token, user: { id: u.id, email: u.email, role: u.role, is_anonymous: false } },
    });
  }

  if (pathname === "/api/auth/user" && req.method === "GET") {
    const user = await authenticateRequest(req);
    if (!user) return jsonRes({ user: null }, 200);
    return jsonRes({ user: { ...user, is_anonymous: false } });
  }

  if (pathname === "/api/auth/update-user" && req.method === "POST") {
    const user = await authenticateRequest(req);
    if (!user) return jsonRes({ error: "Login required." }, 401);
    const body: any = await req.json().catch(() => ({}));
    if (body.password) {
      if (String(body.password).length < 8) return jsonRes({ error: "Password must be at least 8 characters." }, 400);
      await sql`update public.users set password_hash = ${await hashPassword(String(body.password))} where id = ${user.id}`;
    }
    if (body.email) {
      const nextEmail = String(body.email).trim().toLowerCase();
      await sql`update public.users set email = ${nextEmail} where id = ${user.id}`;
      await sql`update public.profiles set email = ${nextEmail} where id = ${user.id}`;
    }
    return jsonRes({ user });
  }

  return jsonRes({ error: "Unknown auth endpoint" }, 404);
}

// ----------------------------------------------------------------------------
// Main Router (with Automatic Gzip Compression to Cut Egress Bandwidth ~70%)
// ----------------------------------------------------------------------------
async function routeRequest(req: Request): Promise<Response> {
    if (req.method === "OPTIONS") return new Response("ok", { status: 200, headers: CORS_HEADERS });

    const url = new URL(req.url);
    const path = url.pathname;

    if (path === "/health" || path === "/") {
      try {
        await Promise.all([sql`select 1`, redis.ping()]);
        return jsonRes({ ok: true, status: "healthy", mode: "hetzner-standalone" });
      } catch (e: any) {
        return jsonRes({ ok: false, error: e?.message || "unhealthy" }, 503);
      }
    }

    if (path === "/captcha.svg") {
      const verified = await verifyCaptchaToken(url.searchParams.get("n") || "");
      if (!verified?.code) return new Response("Expired", { status: 400 });
      return new Response(renderCaptchaSvg(String(verified.code)), {
        status: 200,
        headers: { ...CORS_HEADERS, "Content-Type": "image/svg+xml", "Cache-Control": "no-store" },
      });
    }

    if (path.startsWith("/api/auth/")) {
      return await handleAuth(path, req);
    }

    // Public RPCs
    if (path === "/api/rpc/public_registration_count") {
      const cached = await redis.get("cache:reg_count");
      if (cached !== null) return jsonRes({ data: Number(cached) });
      const [{ cnt }] = await sql`select count(*)::integer as cnt from public.profiles`;
      await redis.set("cache:reg_count", String(cnt), "EX", 30);
      return jsonRes({ data: cnt });
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
      if (table === "profiles") {
        const user = await authenticateRequest(req);
        if (!user) return jsonRes({ error: "Unauthorized" }, 401);
        const [row] = await sql`select * from public.profiles where id = ${user.id} limit 1`;
        return jsonRes({ data: row || null });
      }
      return jsonRes({ error: "Forbidden table" }, 403);
    }

    const user = await authenticateRequest(req);
    if (!user) return jsonRes({ error: "Login required." }, 401);

    if (path === "/api/rpc/my_team_list") {
      const body: any = await req.json().catch(() => ({}));
      const maxLevel = Math.max(1, Math.min(8, Number(body.max_level || 8)));
      const rows = await sql`select * from public.my_team_list(${user.id}::uuid, ${maxLevel})`;
      return jsonRes({ data: rows });
    }

    const body: Record<string, any> = await req.json().catch(() => ({}));

    // register-device
    if (path === "/api/functions/register-device") {
      const deviceToken = String(body.device_token || "").trim();
      const [appSet] = await sql`select device_lock_enabled from public.app_settings where id = 1`;
      const [prof] = await sql`select * from public.profiles where id = ${user.id} limit 1`;
      if (!prof) return jsonRes({ error: "Profile not found." }, 404);
      if (prof.account_status === "blocked") {
        return jsonRes({ error: "Account blocked by admin.", code: "DEVICE_LOCKED" }, 403);
      }

      if (appSet?.device_lock_enabled && prof.device_locked && deviceToken) {
        if (prof.device_token && prof.device_token !== deviceToken) {
          return jsonRes({ error: "This account is locked to another device.", code: "DEVICE_LOCKED" }, 403);
        }
        const other = await sql`
          select id from public.profiles where device_token = ${deviceToken} and id <> ${user.id} limit 1
        `;
        if (other.length) {
          return jsonRes({ error: "This device is already linked to another account.", code: "DEVICE_TAKEN" }, 403);
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
        return jsonRes({ ok: true, needs_details: false });
      }

      if (!prof.device_token && deviceToken) {
        await sql`update public.profiles set device_token = ${deviceToken} where id = ${user.id}`;
      }
      return jsonRes({ ok: true, needs_details: !prof.full_name });
    }

    // user-finance
    if (path === "/api/functions/user-finance") {
      return await handleUserFinance(String(body.action || ""), body, user);
    }

    // admin-control
    if (path === "/api/functions/admin-control") {
      if (!(await isUserAdmin(user))) {
        return jsonRes({ error: "Forbidden: Admin privileges required." }, 403);
      }
      return await handleAdminControl(String(body.action || ""), body, user);
    }

    return jsonRes({ error: "Unknown endpoint" }, 404);
}

const server = Bun.serve({
  port: PORT,
  async fetch(req: Request): Promise<Response> {
    const res = await routeRequest(req);
    const ae = req.headers.get("accept-encoding") || "";
    const ct = res.headers.get("content-type") || "";
    if (
      ae.includes("gzip") &&
      !res.headers.has("content-encoding") &&
      (ct.includes("application/json") || ct.includes("image/svg+xml"))
    ) {
      const raw = new Uint8Array(await res.arrayBuffer());
      if (raw.byteLength >= 320) {
        const gz = gzipSync(raw, { level: 6 });
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
async function handleUserFinance(action: string, body: Record<string, any>, user: { id: string }): Promise<Response> {
  try {
    if (action === "captcha_new") {
      return jsonRes(await issueCaptchaChallenge(user.id));
    }

    if (action === "captcha_submit") {
      if (!(await checkRateLimit(`rl:cap:${user.id}`, 60, 60))) {
        return jsonRes({ error: "Too fast! Slow down slightly." }, 429);
      }
      const verified = await verifyCaptchaToken(String(body.challenge_id || body.nonce || ""));
      if (!verified || verified.uid !== user.id) return jsonRes({ error: "Captcha expired. Get a new one." }, 400);
      const setOk = await redis.set(`cap_used:${verified.nid}`, "1", "EX", 240, "NX");
      if (!setOk) return jsonRes({ error: "Captcha already submitted." }, 400);

      const next = await issueCaptchaChallenge(user.id);
      if (String(body.answer || "").trim().toUpperCase() !== String(verified.code).toUpperCase()) {
        return jsonRes({ ok: false, next });
      }

      const incSet = await getCachedIncomeSettings();
      const limit = Number(incSet.captcha_daily_limit || 50);
      const rewardUsdt = Number(incSet.captcha_reward_usdt || 0.01);
      const dailyKey = `cap_day:${todayIst()}:${user.id}`;
      const newCount = await redis.incr(dailyKey);
      if (newCount === 1) await redis.expire(dailyKey, 100_000);

      const rewardPaid = newCount <= limit;
      if (rewardPaid) {
        await redis.eval(LUA_ADD_PENDING, 1, "pending:captchas", user.id, "1", String(rewardUsdt));
      }
      return jsonRes({ ok: true, reward_paid: rewardPaid, today_passed: newCount, captcha_daily_limit: limit, next });
    }

    if (action === "wallet") {
      const [profRows, pendingRaw, deposits, withdrawals, incSet] = await Promise.all([
        sql`select balance_usdt, total_captchas_solved, today_captchas_count, today_captchas_date from public.profiles where id = ${user.id} limit 1`,
        redis.hget("pending:captchas", user.id),
        sql`select * from public.deposits where user_id = ${user.id} order by created_at desc limit 20`,
        sql`select * from public.withdrawal_requests where user_id = ${user.id} order by created_at desc limit 20`,
        getCachedIncomeSettings(),
      ]);
      const prof = profRows[0] || { balance_usdt: 0, total_captchas_solved: 0, today_captchas_count: 0 };
      const [pCnt, pUsdt] = (pendingRaw || "0:0").split(":").map(Number);
      const totalUsdt = Number(prof.balance_usdt || 0) + (pUsdt || 0);
      const today = todayIst();
      const dbToday = String(prof.today_captchas_date || "").slice(0, 10) === today ? Number(prof.today_captchas_count || 0) : 0;
      const depUsdt = deposits.filter((d: any) => d.status === "approved").reduce((s: number, d: any) => s + Number(d.amount_usdt || 0), 0);
      return jsonRes({
        balance_usdt: Math.round(totalUsdt * 10000) / 10000,
        balance_inr: Math.round(totalUsdt * USDT_INR_RATE * 100) / 100,
        tasks_completed: Number(prof.total_captchas_solved || 0) + (pCnt || 0),
        today_passed: dbToday + (pCnt || 0),
        captcha_daily_limit: Number(incSet.captcha_daily_limit || 50),
        today_income_inr: Math.round((dbToday + (pCnt || 0)) * Number(incSet.captcha_reward_usdt || 0.01) * USDT_INR_RATE * 100) / 100,
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
        types = ["captcha_income", "signup_bonus", "fast_start_bonus", "streak_bonus", "level_once", "level_daily", "compounding_daily", "compounding_maturity"];
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

      await sql.begin(async (tx: any) => {
        const [prof] = await tx`select balance_usdt from public.profiles where id = ${user.id} for update`;
        if (Number(prof?.balance_usdt || 0) < amt) throw new Error("Insufficient wallet balance.");
        await tx`
          insert into public.wallet_ledger (user_id, entry_type, amount, description)
          values (${user.id}, 'withdrawal_reserve', ${-amt}, ${`Withdrawal request to ${addr}`})
        `;
        await tx`
          insert into public.withdrawal_requests (user_id, amount, payout_method, payout_details_masked, payout_address, status)
          values (${user.id}, ${amt}, 'USDT BEP-20', ${addr.slice(0, 6) + "..." + addr.slice(-4)}, ${addr}, 'pending')
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
      const [settings] = await sql`select * from public.compounding_settings where id = 1`;
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
      const [settings] = await sql`select * from public.compounding_settings where id = 1`;
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
  adminUser: { id: string; email: string; role: string }
): Promise<Response> {
  try {
    if (action === "get_settings") {
      const [[appSet], [wdCfg], [{ cnt }]] = await Promise.all([
        sql`select * from public.app_settings where id = 1`,
        sql`select * from public.public_withdraw_config where id = 1`,
        sql`select count(*)::integer as cnt from public.profiles`,
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
            select id, email, full_name, phone, account_status, balance_usdt as wallet_balance, created_at
            from public.profiles
            where email ilike ${"%" + q + "%"} or full_name ilike ${"%" + q + "%"} or phone ilike ${"%" + q + "%"}
            order by created_at desc limit ${lim}
          `
        : await sql`
            select id, email, full_name, phone, account_status, balance_usdt as wallet_balance, created_at
            from public.profiles order by created_at desc limit ${lim}
          `;
      return jsonRes({ users });
    }

    if (action === "user_detail") {
      const uid = String(body.user_id || "");
      const [[profile], ledger] = await Promise.all([
        sql`select * from public.profiles where id = ${uid} limit 1`,
        sql`select * from public.wallet_ledger where user_id = ${uid} order by created_at desc limit 50`,
      ]);
      return jsonRes({ profile, wallet_balance: Number(profile?.balance_usdt || 0), ledger });
    }

    if (action === "set_user_status") {
      await sql`update public.profiles set account_status = ${String(body.status)} where id = ${String(body.user_id)}`;
      return jsonRes({ message: "User status updated." });
    }
    if (action === "reset_device_lock") {
      await sql`update public.profiles set device_token = null where id = ${String(body.user_id)}`;
      return jsonRes({ message: "Device lock reset." });
    }
    if (action === "reset_user_password") {
      const pwd = String(body.password || "");
      if (pwd.length < 8 || pwd.length > 128) return jsonRes({ error: "Password must be 8 to 128 characters." }, 400);
      await sql`update public.users set password_hash = ${await hashPassword(pwd)} where id = ${String(body.user_id)}`;
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
      return jsonRes({ message: "Your Admin Panel password has been updated. Use the new password on next login." });
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
      return jsonRes({ message: `Admin access removed from ${target.email}.` });
    }
    if (action === "update_user_profile") {
      await sql`
        update public.profiles set full_name = coalesce(${body.full_name || null}, full_name), phone = coalesce(${body.phone || null}, phone)
        where id = ${String(body.user_id)}
      `;
      return jsonRes({ message: "Profile updated." });
    }
    if (action === "adjust_wallet") {
      const uid = String(body.user_id);
      const amt = Number(body.amount);
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
      const dec = String(body.decision);
      const note = String(body.note || "");
      const [w] = await sql`select * from public.withdrawal_requests where id = ${wid} limit 1`;
      if (!w || w.status !== "pending") return jsonRes({ error: "Pending withdrawal not found." }, 404);
      await sql`update public.withdrawal_requests set status = ${dec}, admin_note = ${note}, settled_at = now() where id = ${wid}`;
      if (dec === "rejected") {
        await sql`
          insert into public.wallet_ledger (user_id, entry_type, amount, description)
          values (${w.user_id}, 'withdrawal_refund', ${w.amount}, ${`Withdrawal #${wid} rejected: ${note}`})
        `;
      }
      return jsonRes({ message: `Withdrawal #${wid} ${dec}.` });
    }

    if (action === "list_deposits") {
      const st = String(body.status || "all");
      const deposits = st === "all"
        ? await sql`select * from public.deposits order by id desc limit 100`
        : await sql`select * from public.deposits where status = ${st} order by id desc limit 100`;
      return jsonRes({ deposits });
    }
    if (action === "settle_deposit") {
      const did = Number(body.deposit_id);
      const dec = String(body.decision);
      const [d] = await sql`select * from public.deposits where id = ${did} limit 1`;
      if (!d || d.status !== "pending") return jsonRes({ error: "Pending deposit not found." }, 404);
      await sql`update public.deposits set status = ${dec}, admin_note = ${String(body.note || "")}, settled_at = now() where id = ${did}`;
      if (dec === "approved") {
        await sql`
          insert into public.wallet_ledger (user_id, entry_type, amount, description)
          values (${d.user_id}, 'deposit_credit', ${d.amount_usdt}, ${`Deposit #${did} approved (${d.tx_id})`})
        `;
      }
      return jsonRes({ message: `Deposit #${did} ${dec}.` });
    }

    if (action === "set_levels") {
      await sql`update public.app_settings set level_count = ${Number(body.level_count)}, level_income = ${JSON.stringify(body.level_income || [])}::jsonb where id = 1`;
      return jsonRes({ message: "Level settings saved." });
    }
    if (action === "set_device_lock") {
      await sql`update public.app_settings set device_lock_enabled = ${Boolean(body.enabled)} where id = 1`;
      return jsonRes({ message: "Device lock updated." });
    }
    if (action === "set_registration") {
      await sql`update public.app_settings set registration_open = ${Boolean(body.open)} where id = 1`;
      return jsonRes({ message: "Registration status updated." });
    }
    if (action === "set_registration_limit") {
      await sql`update public.app_settings set max_registered = ${Number(body.max_registered)} where id = 1`;
      return jsonRes({ message: "Registration limit updated." });
    }
    if (action === "get_captcha_mode") {
      const [s] = await sql`select captcha_mode from public.app_settings where id = 1`;
      return jsonRes({ mode: s?.captcha_mode || "standard" });
    }
    if (action === "set_captcha_mode") {
      await sql`update public.app_settings set captcha_mode = ${String(body.mode || "standard")} where id = 1`;
      return jsonRes({ message: "Captcha mode updated." });
    }

    if (action === "get_deposit_address") {
      const [c] = await sql`select deposit_address, deposit_qr from public.public_withdraw_config where id = 1`;
      return jsonRes(c || { deposit_address: "", deposit_qr: "" });
    }
    if (action === "set_deposit_address") {
      await sql`update public.public_withdraw_config set deposit_address = ${String(body.deposit_address || "")}, deposit_qr = ${String(body.deposit_qr || "")} where id = 1`;
      await redis.del("cache:public_withdraw_config");
      return jsonRes({ message: "Deposit address updated." });
    }
    if (action === "set_withdrawal_amounts") {
      await sql`update public.public_withdraw_config set amounts = ${JSON.stringify(body.amounts || [])}::jsonb where id = 1`;
      await redis.del("cache:public_withdraw_config");
      return jsonRes({ message: "Withdrawal amounts saved." });
    }
    if (action === "set_amount_conditions") {
      await sql`update public.public_withdraw_config set amount_conditions = ${JSON.stringify(body.amount_conditions || [])}::jsonb where id = 1`;
      await redis.del("cache:public_withdraw_config");
      return jsonRes({ message: "Amount conditions saved." });
    }
    if (action === "get_withdraw_chart") {
      const [c] = await sql`select chart from public.public_withdraw_config where id = 1`;
      return jsonRes({ chart: c?.chart || [] });
    }
    if (action === "set_withdraw_chart") {
      await sql`update public.public_withdraw_config set chart = ${JSON.stringify(body.chart || [])}::jsonb where id = 1`;
      await redis.del("cache:public_withdraw_config");
      return jsonRes({ message: "Withdraw chart updated." });
    }
    if (action === "get_withdraw_rule") {
      const [p] = await sql`select withdraw_rule_json from public.platform_settings where id = 1`;
      return jsonRes({ rule: p?.withdraw_rule_json || {} });
    }
    if (action === "set_withdraw_rule") {
      await sql`update public.platform_settings set withdraw_rule_json = ${JSON.stringify(body.rule || body)}::jsonb where id = 1`;
      return jsonRes({ message: "Withdrawal rules updated." });
    }

    if (action === "get_income_settings") {
      const [s] = await sql`select * from public.income_settings where id = 1`;
      return jsonRes({ settings: s });
    }
    if (action === "set_income_settings") {
      await sql`
        update public.income_settings set
          captcha_daily_limit = coalesce(${body.captcha_daily_limit ?? null}, captcha_daily_limit),
          captcha_reward_usdt = coalesce(${body.captcha_reward_usdt ?? null}, captcha_reward_usdt),
          signup_bonus_usdt = coalesce(${body.signup_bonus_usdt ?? null}, signup_bonus_usdt),
          fast_start_bonus_usdt = coalesce(${body.fast_start_bonus_usdt ?? null}, fast_start_bonus_usdt),
          streak_bonus_usdt = coalesce(${body.streak_bonus_usdt ?? null}, streak_bonus_usdt)
        where id = 1
      `;
      await redis.del("cache:income_settings");
      return jsonRes({ message: "Income settings saved." });
    }
    if (action === "income_summary") {
      const [s] = await sql`select coalesce(sum(case when amount > 0 then amount else 0 end), 0) as total_in, count(*)::integer as entries from public.wallet_ledger`;
      return jsonRes(s);
    }
    if (action === "list_ledger") {
      const entries = await sql`select * from public.wallet_ledger order by id desc limit ${Math.min(200, Number(body.limit) || 50)}`;
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

      const [[dbRow], [{ users }], [{ ledger_rows }], [appSet], pendingRedis, redisMemRaw] = await Promise.all([
        sql`select pg_database_size(current_database())::bigint as size_bytes, pg_size_pretty(pg_database_size(current_database())) as size_pretty`,
        sql`select count(*)::integer as users from public.profiles`,
        sql`select count(*)::integer as ledger_rows from public.wallet_ledger`,
        sql`select max_registered from public.app_settings where id = 1`,
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
      const tickets = await sql`select * from public.support_tickets order by updated_at desc limit 100`;
      return jsonRes({ tickets });
    }
    if (action === "ticket_messages") {
      const messages = await sql`select * from public.ticket_messages where ticket_id = ${Number(body.ticket_id)} order by created_at asc`;
      return jsonRes({ messages });
    }
    if (action === "reply_ticket") {
      const tid = Number(body.ticket_id);
      await sql`insert into public.ticket_messages (ticket_id, sender, body) values (${tid}, 'admin', ${String(body.message || "").trim()})`;
      await sql`update public.support_tickets set status = 'answered', updated_at = now() where id = ${tid}`;
      return jsonRes({ message: "Reply sent." });
    }

    // Compounding Admin Actions
    if (action === "get_compounding_settings") {
      const [s] = await sql`select * from public.compounding_settings where id = 1`;
      return jsonRes({ settings: s });
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
      const plans = st === "all"
        ? await sql`select * from public.compounding_plans order by id desc limit 100`
        : await sql`select * from public.compounding_plans where status = ${st} order by id desc limit 100`;
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
      const uid = String(body.user_id);
      const [s] = await sql`select * from public.compounding_settings where id = 1`;
      const dur = Number(body.duration_days || s.duration_days || 365);
      const rate = Number(body.daily_rate_pct ?? s.daily_rate_pct ?? 0.746585);
      const [plan] = await sql`
        insert into public.compounding_plans (
          user_id, principal_inr, principal_usdt, current_balance_inr, daily_rate_pct, duration_days,
          projected_maturity_inr, credit_mode, status, created_by_admin, admin_note
        ) values (
          ${uid}, ${amtInr}, ${amtInr / USDT_INR_RATE}, ${amtInr}, ${rate}, ${dur},
          ${calcProjectedBalance(amtInr, rate, dur)}, ${s.credit_mode}, 'active', true, ${String(body.note || "Assigned by admin")}
        ) returning *
      `;
      return jsonRes({ message: `Assigned Plan #${plan.id}`, plan });
    }
    if (action === "manage_compounding_plan") {
      const pid = Number(body.plan_id);
      const op = String(body.operation);
      const [plan] = await sql`select * from public.compounding_plans where id = ${pid}`;
      if (!plan) return jsonRes({ error: "Plan not found." }, 404);
      if (op === "pause") await sql`update public.compounding_plans set status = 'paused' where id = ${pid}`;
      else if (op === "resume") await sql`update public.compounding_plans set status = 'active' where id = ${pid}`;
      else if (op === "complete") {
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
