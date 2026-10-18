/**
 * Pro signup Worker for StarSwarm Security Agentic Toolkit.
 * Stores an email and a timestamp. Does not store an IP address.
 */

const ALLOWED_ORIGIN = 'https://porschephotoshootz-afk.github.io';
const SIGNUP_SOURCE = 'toolkit-pro';
const RATE_WINDOW_SEC = 600;

export const RATE_LIMIT = 5;

const memoryBuckets = new Map();

export function resetSignupState() {
  memoryBuckets.clear();
}

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'none'",
  'Cache-Control': 'no-store',
  'Permissions-Policy': 'interest-cohort=()',
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin');
    if (origin && origin !== ALLOWED_ORIGIN) {
      return respond(request, 403, { ok: false, error: 'origin' });
    }
    if (request.method === 'OPTIONS') {
      return respond(request, 204, null);
    }
    if (request.method === 'POST' && url.pathname === '/api/signup') {
      return signup(request, env);
    }
    if (request.method === 'GET' && url.pathname === '/api/export') {
      return exportCsv(request, env, url);
    }
    return respond(request, 404, { ok: false });
  },
};

async function signup(request, env) {
  const length = Number(request.headers.get('Content-Length') || 0);
  if (length > 8192) return respond(request, 413, { ok: false, error: 'too-large' });

  let fields;
  try {
    fields = await readFields(request);
  } catch {
    return respond(request, 400, { ok: false, error: 'invalid-body' });
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await rateLimited(env, ip)) {
    return respond(request, 429, { ok: false, error: 'rate-limited' });
  }

  if (honeypotFilled(fields.company)) {
    return respond(request, 200, { ok: true });
  }

  const email = normalizeEmail(fields.email);
  if (!email) return respond(request, 400, { ok: false, error: 'invalid-email' });

  if (env.TURNSTILE_SECRET) {
    const verified = await verifyTurnstile(env, fields.turnstile, ip);
    if (!verified) return respond(request, 403, { ok: false, error: 'verification-failed' });
  }

  const key = `signup:${email}`;
  const existing = await env.SIGNUPS.get(key);
  if (!existing) {
    await env.SIGNUPS.put(key, JSON.stringify({
      ts: new Date().toISOString(),
      source: SIGNUP_SOURCE,
    }));
  }
  return respond(request, 200, { ok: true });
}

async function exportCsv(request, env, url) {
  const provided = bearer(request);
  const expected = env.EXPORT_TOKEN || '';
  if (!expected || !(await tokensMatch(provided, expected))) {
    return respond(request, 401, { ok: false });
  }
  if (url.searchParams.get('format') !== 'csv') {
    return respond(request, 400, { ok: false, error: 'format' });
  }
  const rows = await listSignups(env.SIGNUPS);
  const lines = ['email,timestamp', ...rows.map((row) => `${csvField(row.email)},${csvField(row.ts)}`)];
  return respond(request, 200, `${lines.join('\n')}\n`, { 'Content-Type': 'text/csv; charset=utf-8' });
}

async function readFields(request) {
  const type = request.headers.get('Content-Type') || '';
  if (type.includes('application/json')) {
    const body = await request.json();
    if (!body || typeof body !== 'object') throw new Error('invalid json');
    return {
      email: body.email,
      company: body.company,
      turnstile: body.turnstile || body['cf-turnstile-response'],
    };
  }
  const form = await request.formData();
  return {
    email: form.get('email'),
    company: form.get('company'),
    turnstile: form.get('turnstile') || form.get('cf-turnstile-response'),
  };
}

function honeypotFilled(value) {
  if (value == null) return false;
  if (typeof value === 'string') return value.trim() !== '';
  return true;
}

function normalizeEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  if (email.length < 6 || email.length > 254) return null;
  if (!/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(email)) {
    return null;
  }
  return email;
}

async function rateLimited(env, ip) {
  const bucketKey = await rateBucket(ip);
  const now = Date.now();
  const memory = memoryBuckets.get(bucketKey);
  if (!memory || now - memory.start >= RATE_WINDOW_SEC * 1000) {
    memoryBuckets.set(bucketKey, { start: now, count: 1 });
  } else {
    memory.count += 1;
    if (memory.count > RATE_LIMIT) return true;
  }
  const current = Number(await env.SIGNUPS.get(bucketKey)) || 0;
  if (current >= RATE_LIMIT) return true;
  await env.SIGNUPS.put(bucketKey, String(current + 1), { expirationTtl: RATE_WINDOW_SEC });
  return false;
}

async function rateBucket(ip) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`signup-rate:${ip}`));
  const hex = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return `rate:${hex}`;
}

async function verifyTurnstile(env, token, ip) {
  if (typeof token !== 'string' || !token.trim() || token.length > 2048) return false;
  const body = new URLSearchParams({
    secret: env.TURNSTILE_SECRET,
    response: token,
  });
  if (ip && ip !== 'unknown') body.set('remoteip', ip);
  let result;
  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) return false;
    result = await response.json();
  } catch {
    return false;
  }
  return result?.success === true;
}

async function listSignups(kv) {
  const rows = [];
  let cursor;
  do {
    const page = await kv.list({ prefix: 'signup:', cursor });
    for (const key of page.keys) {
      if (!key.name.startsWith('signup:')) continue;
      const raw = await kv.get(key.name);
      if (!raw) continue;
      try {
        const parsed = JSON.parse(raw);
        rows.push({ email: key.name.slice('signup:'.length), ts: parsed.ts || '' });
      } catch {
        // Skip a record that is not the signup shape.
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  rows.sort((a, b) => a.email.localeCompare(b.email));
  return rows;
}

function bearer(request) {
  const header = request.headers.get('Authorization') || '';
  const match = header.match(/^Bearer\s+(\S+)\s*$/i);
  return match ? match[1] : '';
}

export async function tokensMatch(provided, expected) {
  if (!provided || !expected) return false;
  const encoder = new TextEncoder();
  const [providedHash, expectedHash] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(provided)),
    crypto.subtle.digest('SHA-256', encoder.encode(expected)),
  ]);
  const left = new Uint8Array(providedHash);
  const right = new Uint8Array(expectedHash);
  if (crypto.subtle.timingSafeEqual) return crypto.subtle.timingSafeEqual(left, right);
  let diff = left.length ^ right.length;
  for (let i = 0; i < left.length; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
}

function csvField(value) {
  const text = String(value ?? '');
  const safe = /^[=+\-@]/.test(text) ? `'${text}` : text;
  return `"${safe.replaceAll('"', '""')}"`;
}

function corsHeaders(request) {
  if (request.headers.get('Origin') === ALLOWED_ORIGIN) {
    return {
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      Vary: 'Origin',
    };
  }
  return { Vary: 'Origin' };
}

function respond(request, status, payload, extra = {}) {
  const entry = { message: 'request', path: new URL(request.url).pathname, status };
  if (status >= 400) console.error(JSON.stringify(entry));
  else console.log(JSON.stringify(entry));
  const headers = { ...SECURITY_HEADERS, ...corsHeaders(request), ...extra };
  if (payload == null) return new Response(null, { status, headers });
  if (typeof payload === 'string') return new Response(payload, { status, headers });
  headers['Content-Type'] = 'application/json; charset=utf-8';
  return new Response(JSON.stringify(payload), { status, headers });
}
