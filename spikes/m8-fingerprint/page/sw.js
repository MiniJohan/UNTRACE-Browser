importScripts('/fp/fp.js');
self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });
self.addEventListener('message', function (e) {
  var port = e.ports[0];
  FP.collect('serviceWorker', self).then(function (r) { port.postMessage(r); });
});
