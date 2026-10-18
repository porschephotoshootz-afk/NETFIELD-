import worker, { RATE_LIMIT, resetSignupState, tokensMatch } from './worker.js';

const ORIGIN = 'https://porschephotoshootz-afk.github.io';
const TOKEN = 'test-export-token';

export async function runSignupTests(assert) {
  await testTokens(assert);
  await testValidJson(assert);
  await testValidForm(assert);
  await testDuplicate(assert);
  await testBadEmail(assert);
  await testHoneypot(assert);
  await testMemoryRateLimit(assert);
  await testKvRateLimit(assert);
  await testCors(assert);
  await testExport(assert);
  await testTurnstileOff(assert);
  await testTurnstileOn(assert);
  resetSignupState();
}

function mockKv() {
  const store = new Map();
  return {
    store,
    async get(key) {
      return store.has(key) ? store.get(key).value : null;
    },
    async put(key, value, opts = {}) {
      store.set(key, { value: String(value), opts });
    },
    async list({ prefix = '' } = {}) {
      const keys = [...store.keys()].filter((name) => name.startsWith(prefix)).sort();
      return { keys: keys.map((name) => ({ name })), list_complete: true };
    },
  };
}

function env(kv, extra = {}) {
  return { SIGNUPS: kv, EXPORT_TOKEN: TOKEN, ...extra };
}

async function post(kv, body, { headers = {}, json = true, extraEnv = {} } = {}) {
  const requestHeaders = { Origin: ORIGIN, ...headers };
  let payload;
  if (json) {
    requestHeaders['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  } else {
    requestHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
    payload = new URLSearchParams(body);
  }
  const response = await worker.fetch(new Request('https://toolkit-signup.starswarm.workers.dev/api/signup', {
    method: 'POST',
    headers: requestHeaders,
    body: payload,
  }), env(kv, extraEnv));
  const text = await response.text();
  return { status: response.status, headers: response.headers, body: text ? JSON.parse(text) : null };
}

async function testTokens(assert) {
  assert(await tokensMatch('same-token', 'same-token'), 'equal tokens match');
  assert(!(await tokensMatch('same-token', 'same-tokEn')), 'different tokens do not match');
  assert(!(await tokensMatch('short', 'much-longer-token')), 'different lengths do not match');
  assert(!(await tokensMatch('', 'same-token')), 'an empty token does not match');
}

async function testValidJson(assert) {
  resetSignupState();
  const kv = mockKv();
  const result = await post(kv, { email: ' Ada@Example.com ', company: '' }, {
    headers: { 'CF-Connecting-IP': '203.0.113.10' },
  });
  assert(result.status === 200 && result.body.ok === true, 'valid signup returns ok');
  assert(result.headers.get('Access-Control-Allow-Origin') === ORIGIN, 'signup allows the pages origin');
  assert(result.headers.get('X-Content-Type-Options') === 'nosniff', 'signup sends nosniff');
  assert(result.headers.get('Cache-Control') === 'no-store', 'signup is not cached');
  const stored = JSON.parse(kv.store.get('signup:ada@example.com').value);
  assert(stored.source === 'toolkit-pro', 'signup source is toolkit-pro');
  assert(typeof stored.ts === 'string' && stored.ts.includes('T'), 'signup stores a timestamp');
  assert(!Object.hasOwn(stored, 'ip'), 'signup record has no ip');
  assert(![...kv.store.keys()].some((key) => key.includes('203.0.113.10')), 'rate key does not store the raw ip');
  const rate = [...kv.store.keys()].find((key) => key.startsWith('rate:'));
  assert(rate && kv.store.get(rate).opts.expirationTtl === 600, 'rate counter has a 10 minute ttl');
}

async function testValidForm(assert) {
  resetSignupState();
  const kv = mockKv();
  const result = await post(kv, { email: 'form@example.com', company: '' }, {
    json: false,
    headers: { 'CF-Connecting-IP': '203.0.113.11' },
  });
  assert(result.status === 200 && result.body.ok === true, 'form signup returns ok');
  assert(kv.store.has('signup:form@example.com'), 'form signup is stored');
}

async function testDuplicate(assert) {
  resetSignupState();
  const kv = mockKv();
  const headers = { 'CF-Connecting-IP': '203.0.113.12' };
  const first = await post(kv, { email: 'dup@example.com', company: '' }, { headers });
  const original = kv.store.get('signup:dup@example.com').value;
  const second = await post(kv, { email: 'DUP@example.com', company: '' }, { headers });
  assert(first.status === 200 && second.status === 200, 'duplicate signup still returns ok');
  assert(kv.store.get('signup:dup@example.com').value === original, 'duplicate keeps the original timestamp');
}

async function testBadEmail(assert) {
  resetSignupState();
  const kv = mockKv();
  for (const email of ['not-an-email', 'a@b', ' ', '']) {
    const result = await post(kv, { email, company: '' }, {
      headers: { 'CF-Connecting-IP': '203.0.113.13' },
    });
    assert(result.status === 400, `bad email is rejected (${email || 'empty'})`);
  }
  assert(![...kv.store.keys()].some((key) => key.startsWith('signup:')), 'bad email stores nothing');
}

async function testHoneypot(assert) {
  resetSignupState();
  const kv = mockKv();
  const result = await post(kv, { email: 'bot@example.com', company: 'Acme' }, {
    headers: { 'CF-Connecting-IP': '203.0.113.14' },
  });
  assert(result.status === 200 && result.body.ok === true, 'honeypot returns ok silently');
  assert(!kv.store.has('signup:bot@example.com'), 'honeypot stores nothing');
}

async function testMemoryRateLimit(assert) {
  resetSignupState();
  const kv = mockKv();
  const headers = { 'CF-Connecting-IP': '203.0.113.15' };
  for (let i = 0; i < RATE_LIMIT; i += 1) {
    const result = await post(kv, { email: `mem${i}@example.com`, company: '' }, { headers });
    assert(result.status === 200, `signup ${i + 1} is inside the memory limit`);
  }
  const blocked = await post(kv, { email: 'mem-over@example.com', company: '' }, { headers });
  assert(blocked.status === 429, 'the next signup from that address is rate limited');
  assert(!kv.store.has('signup:mem-over@example.com'), 'a limited signup is not stored');
}

async function testKvRateLimit(assert) {
  resetSignupState();
  const kv = mockKv();
  const ip = '203.0.113.16';
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`signup-rate:${ip}`));
  const hex = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  await kv.put(`rate:${hex}`, String(RATE_LIMIT), { expirationTtl: 600 });
  const blocked = await post(kv, { email: 'kv-over@example.com', company: '' }, {
    headers: { 'CF-Connecting-IP': ip },
  });
  assert(blocked.status === 429, 'a full KV counter rate limits a fresh isolate');
  assert(!kv.store.has('signup:kv-over@example.com'), 'KV rate limit stores nothing');
}

async function testCors(assert) {
  resetSignupState();
  const kv = mockKv();
  const allowed = await worker.fetch(new Request('https://toolkit-signup.starswarm.workers.dev/api/signup', {
    method: 'OPTIONS',
    headers: { Origin: ORIGIN },
  }), env(kv));
  assert(allowed.status === 204, 'preflight from the pages origin succeeds');
  assert(allowed.headers.get('Access-Control-Allow-Origin') === ORIGIN, 'preflight echoes only the pages origin');
  assert(allowed.headers.get('Content-Security-Policy') === "default-src 'none'", 'preflight sends a locked content security policy');

  const blocked = await post(kv, { email: 'cors@example.com', company: '' }, {
    headers: { Origin: 'https://evil.example', 'CF-Connecting-IP': '203.0.113.17' },
  });
  assert(blocked.status === 403, 'a different origin is rejected');
  assert(blocked.headers.get('Access-Control-Allow-Origin') !== 'https://evil.example', 'a different origin is not reflected');
  assert(!kv.store.has('signup:cors@example.com'), 'a rejected origin stores nothing');
}

async function testExport(assert) {
  resetSignupState();
  const kv = mockKv();
  await post(kv, { email: 'export@example.com', company: '' }, {
    headers: { 'CF-Connecting-IP': '203.0.113.18' },
  });
  await kv.put('rate:should-not-export', '1', { expirationTtl: 600 });

  const missing = await worker.fetch(new Request('https://toolkit-signup.starswarm.workers.dev/api/export?format=csv'), env(kv));
  assert(missing.status === 401, 'export without a token is rejected');
  const missingText = await missing.text();
  assert(!missingText.includes('export@example.com'), 'a rejected export does not list emails');

  const wrong = await worker.fetch(new Request('https://toolkit-signup.starswarm.workers.dev/api/export?format=csv', {
    headers: { Authorization: 'Bearer not-the-token' },
  }), env(kv));
  assert(wrong.status === 401, 'export with the wrong token is rejected');

  const right = await worker.fetch(new Request('https://toolkit-signup.starswarm.workers.dev/api/export?format=csv', {
    headers: { Authorization: `Bearer ${TOKEN}` },
  }), env(kv));
  const csv = await right.text();
  assert(right.status === 200, 'export with the token succeeds');
  assert(right.headers.get('Content-Type').includes('text/csv'), 'export is csv');
  assert(csv.startsWith('email,timestamp\n'), 'export has a header');
  assert(csv.includes('export@example.com'), 'export includes the signup');
  assert(!csv.includes('should-not-export'), 'export does not include rate counters');

  const format = await worker.fetch(new Request('https://toolkit-signup.starswarm.workers.dev/api/export', {
    headers: { Authorization: `Bearer ${TOKEN}` },
  }), env(kv));
  assert(format.status === 400, 'export requires format=csv');

  const list = await worker.fetch(new Request('https://toolkit-signup.starswarm.workers.dev/api/signups'), env(kv));
  assert(list.status === 404, 'there is no public listing endpoint');
}

async function testTurnstileOff(assert) {
  resetSignupState();
  const kv = mockKv();
  let calls = 0;
  const original = globalThis.fetch;
  globalThis.fetch = async () => {
    calls += 1;
    return new Response('{}');
  };
  try {
    const result = await post(kv, { email: 'plain@example.com', company: '' }, {
      headers: { 'CF-Connecting-IP': '203.0.113.19' },
    });
    assert(result.status === 200, 'signup works when Turnstile is unset');
    assert(calls === 0, 'Turnstile is not called when the secret is unset');
    assert(kv.store.has('signup:plain@example.com'), 'signup is stored without Turnstile');
  } finally {
    globalThis.fetch = original;
  }
}

async function testTurnstileOn(assert) {
  resetSignupState();
  const kv = mockKv();
  const extraEnv = { TURNSTILE_SECRET: 'turnstile-test-secret' };
  const headers = { 'CF-Connecting-IP': '203.0.113.20' };
  const missing = await post(kv, { email: 'gated@example.com', company: '' }, { headers, extraEnv });
  assert(missing.status === 403, 'Turnstile rejects a missing token');
  assert(!kv.store.has('signup:gated@example.com'), 'a missing Turnstile token stores nothing');

  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ success: false }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
  try {
    const bad = await post(kv, { email: 'gated@example.com', company: '', turnstile: 'bad-token' }, { headers, extraEnv });
    assert(bad.status === 403, 'Turnstile rejects a failed siteverify');
  } finally {
    globalThis.fetch = original;
  }
  assert(!kv.store.has('signup:gated@example.com'), 'a failed Turnstile check stores nothing');

  globalThis.fetch = async (url) => {
    assert(String(url).includes('/turnstile/v0/siteverify'), 'siteverify is the only Turnstile call');
    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  try {
    const good = await post(kv, { email: 'gated@example.com', company: '', turnstile: 'good-token' }, { headers, extraEnv });
    assert(good.status === 200 && good.body.ok === true, 'a verified Turnstile token is accepted');
  } finally {
    globalThis.fetch = original;
  }
  assert(kv.store.has('signup:gated@example.com'), 'a verified signup is stored');
}
