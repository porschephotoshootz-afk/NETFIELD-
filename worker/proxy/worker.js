/**
 * toolkit.starswarm.workers.dev
 * Serves StarSwarm Security Agentic Toolkit from its GitHub Pages build.
 * If the Pages site ever moves, change UPSTREAM and redeploy. Nothing else.
 */

const UPSTREAM = 'https://porschephotoshootz-afk.github.io/StarSwarm-Agentic-Security-Toolkit/';

const PASS_HEADERS = [
  'content-type',
  'cache-control',
  'etag',
  'last-modified',
  'expires',
  'accept-ranges',
];

const REQUEST_HEADERS = ['accept', 'accept-language', 'if-none-match', 'if-modified-since', 'range'];

const CSP = [
  "default-src 'self'",
  "script-src 'self' https://challenges.cloudflare.com",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self' https://toolkit-signup.starswarm.workers.dev https://api.anthropic.com https://api.openai.com https://challenges.cloudflare.com https://solana-rpc.publicnode.com https://public.rpc.solanavibestation.com https://solana.api.pocket.network https://api.mainnet-beta.solana.com https://cloudflare-eth.com https://ethereum-rpc.publicnode.com https://api.etherscan.io https://pro-api.solscan.io",
  'frame-src https://challenges.cloudflare.com',
  "manifest-src 'self'",
  "worker-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

const SECURITY_HEADERS = {
  'Content-Security-Policy': CSP,
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
  'Strict-Transport-Security': 'max-age=31536000',
};

function upstreamUrl(requestUrl, upstream = UPSTREAM) {
  const url = new URL(requestUrl);
  const base = new URL(upstream);
  const path = url.pathname.replace(/^\/+/, '');
  const target = new URL(path, base);
  if (!target.href.startsWith(base.href)) return null;
  target.search = url.search;
  return target;
}

function rewriteLocation(location, requestUrl, upstream = UPSTREAM) {
  if (!location) return null;
  const base = new URL(upstream);
  const resolved = new URL(location, base);
  if (!resolved.href.startsWith(base.href) && resolved.href !== base.href.replace(/\/$/, '')) return null;
  const rest = resolved.href.startsWith(base.href) ? resolved.href.slice(base.href.length) : '';
  const out = new URL(`/${rest}`, requestUrl);
  return out.href;
}

export default {
  async fetch(request) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return finish(new Response('Method not allowed', { status: 405, headers: { Allow: 'GET, HEAD', 'Content-Type': 'text/plain; charset=utf-8' } }));
    }
    const target = upstreamUrl(request.url);
    if (!target) return finish(new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }));

    const headers = new Headers();
    for (const name of REQUEST_HEADERS) {
      const value = request.headers.get(name);
      if (value) headers.set(name, value);
    }

    let upstream;
    try {
      upstream = await fetch(target.href, { method: request.method, headers, redirect: 'manual' });
    } catch {
      return finish(new Response('Upstream unavailable', { status: 502, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }));
    }

    if (upstream.status >= 300 && upstream.status < 400 && upstream.headers.get('location')) {
      const location = rewriteLocation(upstream.headers.get('location'), request.url);
      if (!location) return finish(new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }));
      return finish(new Response(null, { status: upstream.status, headers: { Location: location, 'Cache-Control': 'no-store' } }));
    }

    if (upstream.status === 404) {
      return finish(new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } }));
    }

    const out = new Headers();
    for (const name of PASS_HEADERS) {
      const value = upstream.headers.get(name);
      if (value) out.set(name, value);
    }
    const path = new URL(request.url).pathname;
    if (path === '/sw.js') out.set('Cache-Control', 'no-cache');
    return finish(new Response(upstream.body, { status: upstream.status, headers: out }));
  },
};

function finish(response) {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) response.headers.set(name, value);
  return response;
}
