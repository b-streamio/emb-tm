// SPDX-License-Identifier: GPL-2.0-only
// Offline cache: the app shell, the component library, every example
// listed in examples/index.json and every EMB3D release listed in
// data/stix/index.json are cached at install (the wasm and the releases as
// .gz, see `make build`).
// Requests go to the network first, so an online visit always gets the newest
// build, and fall back to the cache when offline.
const CACHE = 'emb3d-workbench';
const SHELL = [
  './', 'index.html', 'emb3d-wb.js', 'emb3d-wb_bg.wasm.gz', 'style.css', 'manifest.webmanifest',
  'icon.svg', 'icon-192.png', 'icon-512.png', 'library/components.json', 'data/stix/index.json',
  'examples/index.json',
];

self.addEventListener('install', (e) => e.waitUntil((async () => {
  const cache = await caches.open(CACHE);
  await cache.addAll(SHELL);
  const list = async (url) => (await cache.match(url)).json();
  await cache.addAll((await list('data/stix/index.json')).versions.map((v) => 'data/stix/' + v.file + '.gz'));
  await cache.addAll((await list('examples/index.json')).examples.map((x) => 'examples/' + x.file));
  await self.skipWaiting();
})()));

self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;
  e.respondWith(fetch(req).then((res) => {
    if (res.ok) { const copy = res.clone(); e.waitUntil(caches.open(CACHE).then((c) => c.put(req, copy))); }
    return res;
  }).catch(async () => (await caches.match(req, { ignoreSearch: true }))
    || (req.mode === 'navigate' ? caches.match('index.html') : Response.error())));
});
