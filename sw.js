const CACHE = 'starswarm-toolkit-v7';

const ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './css/app.css',
  './js/analyzers.js',
  './js/samples.js',
  './js/study.js',
  './js/app.js',
  './js/config.js',
  './js/deep.js',
  './js/alerts.js',
  './js/wallet.js',
  './data/threats.json',
  './data/bots.json',
  './data/hotfixes.json',
  './data/scam-addresses.json',
  './images/shield.png',
  './images/cover.jpg',
  './fonts/outfit-latin.woff2',
  './fonts/jetbrains-mono-latin.woff2',
  './fonts/inter-latin-400.woff2',
  './fonts/inter-latin-700.woff2',
  './fonts/cinzel-latin-700.woff2',
  './fonts/cinzel-decorative-latin-700.woff2',
  './icons/favicon-32.png',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-maskable-512.png',
  './icons/apple-touch-icon.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || event.request.method !== 'GET') return;
  event.respondWith(networkFirst(event.request));
});

async function networkFirst(request) {
  const cache = await caches.open(CACHE);
  try {
    const response = await fetch(request);
    if (response.ok) cache.put(request, response.clone());
    return response;
  } catch {
    const cached = await cache.match(request);
    if (cached) return cached;
    if (request.mode === 'navigate') {
      const shell = await cache.match('./index.html');
      if (shell) return shell;
    }
    throw new Error('offline');
  }
}
