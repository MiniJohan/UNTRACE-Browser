importScripts('/fp/fp.js');
onmessage = function () {
  FP.collect('worker', self).then(function (r) { postMessage(r); });
};
