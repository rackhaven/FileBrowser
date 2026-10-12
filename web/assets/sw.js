// Service worker for the PWA.
//
// Caching policy, chosen deliberately:
//   * The app shell (HTML, CSS, JS, icons) is cached, so the app opens
//     instantly and still launches with no signal.
//   * API responses are NEVER cached. File listings are private, and a stale
//     listing could offer a file that has since been deleted or hidden.
//   * Downloads are never cached either; they are large, private, and the
//     browser manages them.
//
// Everything is NETWORK FIRST with a cache fallback rather than cache first.
// Cache-first for code is a trap: a deploy of app.js would not reach anyone
// until someone remembered to bump VERSION here, and would then not reach them
// at all until every tab was closed. Network-first keeps the offline benefit
// while making a deploy visible on the next load. The versioned cache is still
// cleaned up on activate so old assets do not accumulate.

const VERSION = 'fb-v1';
const SHELL = [
  '/',
  '/static/styles.css',
  '/static/app.js',
  '/static/icon-192.png',
  '/static/icon-512.png',
  '/static/icon-180.png',
  '/manifest.webmanifest',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(VERSION)
      // addAll is atomic: if one asset 404s the whole install fails rather
      // than leaving a half-cached shell that breaks offline use.
      .then((cache) => cache.addAll(SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

/** Network first, falling back to the cache, refreshing the cache on success. */
async function networkFirst(request) {
  const cache = await caches.open(VERSION);
  try {
    const res = await fetch(request);
    // Only cache complete, same-origin successes. Opaque or error responses
    // must never enter the cache.
    if (res.ok && res.type === 'basic') cache.put(request, res.clone());
    return res;
  } catch (err) {
    const hit = await cache.match(request, { ignoreSearch: request.mode === 'navigate' });
    if (hit) return hit;
    throw err;
  }
}

self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Only handle plain GETs; uploads and logins must reach the network.
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Never cache private or dynamic routes.
  if (url.pathname.startsWith('/api/')) return;
  if (url.pathname === '/healthz') return;

  // Navigations and static assets both get network-first with a cache
  // fallback, which is what keeps the app usable offline while ensuring a
  // deploy is picked up immediately.
  if (request.mode === 'navigate' || url.pathname.startsWith('/static/')) {
    event.respondWith(networkFirst(request));
  }
});
