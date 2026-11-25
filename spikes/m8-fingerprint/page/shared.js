importScripts('/fp/fp.js');
onconnect = function (e) {
  var port = e.ports[0];
  port.onmessage = function () {
    FP.collect('sharedWorker', self).then(function (r) { port.postMessage(r); });
  };
};
