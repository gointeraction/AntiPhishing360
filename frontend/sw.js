const CACHE_NAME = 'detector360-edge-v2.6.0';
const SHELL_ASSETS = [
  '/',
  '/index.html',
  '/guardian.html',
  '/login.html',
  '/register.html',
  '/dashboard.html',
  '/scan.html',
  '/scan-new.html',
  '/manifest.webmanifest',
  '/css/tokens.css',
  '/css/landing.css',
  '/css/senior.css',
  '/css/app.css',
  '/js/api-client.js',
  '/js/icons.js',
  '/js/senior-shield.js',
  '/js/guardian-view.js',
  '/js/landing.js',
  '/js/auth.js',
  '/js/dashboard.js',
  '/js/forensic-viewer.js',
  '/js/export-service.js',
  '/js/pwa-install.js',
  '/assets/icon-shield.svg',
  '/assets/favicon.svg'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  // Never cache live API responses, restricted C.I.C.P.C command pages, or byte-range video streams in SW
  if (
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/cicpc') ||
    url.pathname.endsWith('.mp4') ||
    url.pathname.endsWith('.webm')
  ) {
    return;
  }

  // Clean route navigation support offline
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req).catch(async () => {
        if (url.pathname.startsWith('/scan/') && url.pathname !== '/scan/new') {
          return (await caches.match('/scan.html')) || (await caches.match('/index.html'));
        }
        if (url.pathname === '/scan/new') return await caches.match('/scan-new.html');
        if (url.pathname === '/login') return await caches.match('/login.html');
        if (url.pathname === '/register') return await caches.match('/register.html');
        if (url.pathname === '/dashboard') return await caches.match('/dashboard.html');
        return await caches.match('/index.html');
      })
    );
    return;
  }

  // Stale-while-revalidate for static assets
  event.respondWith(
    caches.match(req).then((cached) => {
      const networkFetch = fetch(req)
        .then((res) => {
          if (res && res.status === 200 && url.origin === self.location.origin) {
            const clone = res.clone();
            caches.open(CACHE_NAME).then((c) => c.put(req, clone));
          }
          return res;
        })
        .catch(() => cached);
      return cached || networkFetch;
    })
  );
});
