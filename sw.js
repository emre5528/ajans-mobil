"use strict";
const surum = "ajans-mobil-shell-v2";
const dosyalar = ["./", "index.html", "app.js?v=2", "app.css?v=2", "manifest.webmanifest", "icon-192.png", "icon-512.png"];
const adresler = new Set(dosyalar.map(ad => new URL(ad, self.registration.scope).href));

self.addEventListener("install", event => {
    event.waitUntil(caches.open(surum).then(cache => cache.addAll(dosyalar)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", event => {
    event.waitUntil(caches.keys().then(anahtarlar => Promise.all(anahtarlar.filter(
        ad => ad.startsWith("ajans-mobil-shell-") && ad !== surum
    ).map(ad => caches.delete(ad)))).then(() => self.clients.claim()));
});

self.addEventListener("fetch", event => {
    const istek = event.request;
    if (istek.method !== "GET" || istek.headers.has("Authorization")) return;
    if (istek.mode === "navigate" && adresler.has(new URL(istek.url).origin + new URL(istek.url).pathname)) {
        event.respondWith(fetch(istek).catch(() => caches.match("./")));
    } else if (adresler.has(istek.url)) {
        event.respondWith(caches.match(istek).then(yanit => yanit || fetch(istek)));
    }
});
