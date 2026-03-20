/* ═══════════════════════════════════════
   Come Home Big Girl — Service Worker
   Background Push Notifications
   ═══════════════════════════════════════ */

self.addEventListener('install', function(e) {
    self.skipWaiting();
});

self.addEventListener('activate', function(e) {
    e.waitUntil(self.clients.claim());
});

self.addEventListener('push', function(e) {
    var data = { title: 'Come Home Big Girl', body: 'Something happened!', tag: 'bg-push', url: '/' };
    if (e.data) {
        try { data = Object.assign(data, e.data.json()); } catch(err) { data.body = e.data.text(); }
    }
    var options = {
        body: data.body,
        tag: data.tag || ('bg-push-' + Date.now()),
        icon: data.icon || undefined,
        badge: data.badge || undefined,
        vibrate: [200, 100, 200, 100, 200],
        requireInteraction: true,
        data: { url: data.url || '/' },
        actions: data.actions || []
    };
    e.waitUntil(self.registration.showNotification(data.title, options));
});

self.addEventListener('notificationclick', function(e) {
    e.notification.close();
    var url = (e.notification.data && e.notification.data.url) || '/';
    e.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clients) {
            for (var i = 0; i < clients.length; i++) {
                if (clients[i].url.indexOf(url) !== -1 && 'focus' in clients[i]) {
                    return clients[i].focus();
                }
            }
            if (self.clients.openWindow) return self.clients.openWindow(url);
        })
    );
});
