'use strict';
// UNTRACE M8 fingerprint probe. Collects what a fingerprinting script can read, in the page,
// in frames and in workers. Everything stays on this computer: results go back to the
// loopback test server that served this file.
var FP = (function () {
  function safe(f) {
    try {
      var v = f();
      return v === undefined ? '(undefined)' : v;
    } catch (e) {
      return 'ERR:' + (e && e.name);
    }
  }
  async function safeA(f, ms) {
    try {
      var v = await Promise.race([
        f(),
        new Promise(function (_, rej) {
          setTimeout(function () { rej({ name: 'Timeout' }); }, ms || 4000);
        }),
      ]);
      return v === undefined ? '(undefined)' : v;
    } catch (e) {
      return 'ERR:' + (e && e.name);
    }
  }
  function hashStr(s) {
    var h = 0x811c9dc5;
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return ('0000000' + h.toString(16)).slice(-8);
  }
  function hashBytes(a) {
    var h = 0x811c9dc5;
    for (var i = 0; i < a.length; i++) {
      h ^= a[i];
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return ('0000000' + h.toString(16)).slice(-8);
  }
  function protoNames(g, o) {
    var s = new Set();
    var p = o;
    while (p && p !== g.Object.prototype) {
      g.Object.getOwnPropertyNames(p).forEach(function (n) { s.add(n); });
      p = g.Object.getPrototypeOf(p);
    }
    return Array.from(s).sort();
  }

  function canvas2d(g) {
    var c = g.document ? g.document.createElement('canvas') : new g.OffscreenCanvas(240, 60);
    c.width = 240;
    c.height = 60;
    var x = c.getContext('2d');
    x.textBaseline = 'top';
    x.font = '16px Arial';
    x.fillStyle = '#f60';
    x.fillRect(110, 1, 62, 20);
    x.fillStyle = '#069';
    x.fillText('UNTRACE fp ☺ 😀', 2, 15);
    x.fillStyle = 'rgba(102,204,0,0.7)';
    x.fillText('UNTRACE fp ☺', 4, 17);
    x.beginPath();
    x.arc(50, 30, 20, 0, Math.PI * 2);
    x.stroke();
    return hashBytes(x.getImageData(0, 0, 240, 60).data);
  }

  function webgl(g) {
    var c = g.document ? g.document.createElement('canvas') : new g.OffscreenCanvas(1, 1);
    var gl = c.getContext('webgl');
    if (!gl) return '(none)';
    var ext = gl.getExtension('WEBGL_debug_renderer_info');
    var ps = [gl.MAX_TEXTURE_SIZE, gl.MAX_RENDERBUFFER_SIZE, gl.MAX_VIEWPORT_DIMS, gl.ALIASED_LINE_WIDTH_RANGE,
      gl.ALIASED_POINT_SIZE_RANGE, gl.MAX_VERTEX_ATTRIBS, gl.MAX_VARYING_VECTORS, gl.MAX_FRAGMENT_UNIFORM_VECTORS,
      gl.MAX_VERTEX_UNIFORM_VECTORS, gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS];
    return {
      vendor: gl.getParameter(gl.VENDOR),
      renderer: gl.getParameter(gl.RENDERER),
      unmaskedVendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : '(no ext)',
      unmaskedRenderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : '(no ext)',
      version: gl.getParameter(gl.VERSION),
      extensions: hashStr((gl.getSupportedExtensions() || []).join(',')),
      params: hashStr(ps.map(function (p) { return String(gl.getParameter(p)); }).join('|')),
    };
  }

  async function audio(g) {
    var C = g.OfflineAudioContext;
    if (!C) return '(none)';
    var ctx = new C(1, 5000, 44100);
    var osc = ctx.createOscillator();
    var comp = ctx.createDynamicsCompressor();
    osc.type = 'triangle';
    osc.frequency.value = 10000;
    comp.threshold.value = -50;
    comp.knee.value = 40;
    comp.ratio.value = 12;
    comp.attack.value = 0;
    comp.release.value = 0.25;
    osc.connect(comp);
    comp.connect(ctx.destination);
    osc.start(0);
    var buf = await ctx.startRendering();
    var d = buf.getChannelData(0);
    var s = 0;
    for (var i = 4500; i < 5000; i++) s += Math.abs(d[i]);
    return s.toFixed(10);
  }

  var FONTS = ['Arial', 'Arial Black', 'Aptos', 'Bahnschrift', 'Calibri', 'Cambria', 'Candara', 'Cascadia Code',
    'Comic Sans MS', 'Consolas', 'Constantia', 'Corbel', 'Courier New', 'Ebrima', 'Franklin Gothic Medium',
    'Gabriola', 'Gadugi', 'Georgia', 'HoloLens MDL2 Assets', 'Impact', 'Ink Free', 'Javanese Text',
    'Leelawadee UI', 'Lucida Console', 'Lucida Sans Unicode', 'Malgun Gothic', 'Marlett', 'Microsoft Himalaya',
    'Microsoft JhengHei', 'Microsoft Sans Serif', 'Microsoft YaHei', 'MS Gothic', 'MV Boli', 'Myanmar Text',
    'Nirmala UI', 'Palatino Linotype', 'Segoe MDL2 Assets', 'Segoe Fluent Icons', 'Segoe Print', 'Segoe Script',
    'Segoe UI', 'Segoe UI Emoji', 'Segoe UI Variable', 'SimSun', 'Sitka Text', 'Sylfaen', 'Symbol', 'Tahoma',
    'Times New Roman', 'Trebuchet MS', 'Verdana', 'Webdings', 'Wingdings', 'Yu Gothic', 'Roboto', 'Helvetica',
    'Ubuntu', 'Noto Sans', 'Fira Code', 'JetBrains Mono', 'Source Code Pro', 'Century Gothic', 'Garamond',
    'Bookman Old Style', 'Book Antiqua', 'Wide Latin', 'Blender Pro', 'Minecraft'];

  function fonts(g) {
    var c = g.document.createElement('canvas').getContext('2d');
    var base = ['monospace', 'serif', 'sans-serif'];
    var txt = 'mmmmmmmmmmlliWWW@#0123';
    var w = {};
    base.forEach(function (b) { c.font = '72px ' + b; w[b] = c.measureText(txt).width; });
    var found = FONTS.filter(function (f) {
      return base.some(function (b) { c.font = '72px "' + f + '", ' + b; return c.measureText(txt).width !== w[b]; });
    });
    return { count: found.length, hash: hashStr(found.join(',')), list: found };
  }

  async function voices(g) {
    var s = g.speechSynthesis;
    if (!s) return '(none)';
    var v = s.getVoices();
    if (!v.length) {
      await new Promise(function (r) { s.onvoiceschanged = r; setTimeout(r, 1500); });
      v = s.getVoices();
    }
    return {
      count: v.length,
      hash: hashStr(v.map(function (x) { return x.name + '|' + x.lang + '|' + x.localService; }).join(',')),
      names: v.map(function (x) { return x.name; }),
    };
  }

  var PERMS = ['geolocation', 'notifications', 'camera', 'microphone', 'midi', 'clipboard-read', 'clipboard-write',
    'persistent-storage', 'background-sync', 'accelerometer', 'gyroscope', 'magnetometer', 'local-fonts',
    'storage-access', 'window-management', 'screen-wake-lock', 'payment-handler', 'idle-detection'];

  async function permissions(n) {
    if (!n.permissions) return '(none)';
    var out = {};
    for (var i = 0; i < PERMS.length; i++) {
      var p = PERMS[i];
      out[p] = await safeA(function () { return n.permissions.query({ name: p }).then(function (r) { return r.state; }); }, 1500);
    }
    return out;
  }

  function media(g) {
    var q = function (m) { return g.matchMedia(m).matches; };
    return {
      dark: q('(prefers-color-scheme: dark)'),
      reducedMotion: q('(prefers-reduced-motion: reduce)'),
      moreContrast: q('(prefers-contrast: more)'),
      forcedColors: q('(forced-colors: active)'),
      pointerFine: q('(pointer: fine)'),
      hover: q('(hover: hover)'),
      p3: q('(color-gamut: p3)'),
      hdr: q('(dynamic-range: high)'),
      reducedTransparency: q('(prefers-reduced-transparency: reduce)'),
    };
  }

  function webviewObject(g) {
    if (typeof g.chrome === 'undefined') return '(no chrome object)';
    if (!('webview' in g.chrome)) return '(absent)';
    var d = g.Object.getOwnPropertyDescriptor(g.chrome, 'webview');
    return {
      ownDescriptor: d ? { configurable: d.configurable, enumerable: d.enumerable, writable: d.writable, accessor: !!d.get } : '(inherited)',
      members: g.Object.getOwnPropertyNames(g.chrome.webview).concat(protoNames(g, g.Object.getPrototypeOf(g.chrome.webview))).sort(),
      postMessage: typeof g.chrome.webview.postMessage,
    };
  }

  async function collect(where, g) {
    g = g || self;
    var n = g.navigator;
    var o = { where: where, secureContext: safe(function () { return g.isSecureContext; }) };
    o.userAgent = safe(function () { return n.userAgent; });
    o.appVersion = safe(function () { return n.appVersion; });
    o.platform = safe(function () { return n.platform; });
    o.vendor = safe(function () { return n.vendor; });
    o.language = safe(function () { return n.language; });
    o.languages = safe(function () { return Array.from(n.languages).join(','); });
    o.hardwareConcurrency = safe(function () { return n.hardwareConcurrency; });
    o.deviceMemory = safe(function () { return n.deviceMemory; });
    o.webdriver = safe(function () { return n.webdriver; });
    o.doNotTrack = safe(function () { return n.doNotTrack; });
    o.globalPrivacyControl = safe(function () { return n.globalPrivacyControl; });
    o.pdfViewerEnabled = safe(function () { return n.pdfViewerEnabled; });
    o.maxTouchPoints = safe(function () { return n.maxTouchPoints; });
    o.cookieEnabled = safe(function () { return n.cookieEnabled; });
    o.plugins = safe(function () { return Array.from(n.plugins).map(function (p) { return p.name; }).join(','); });
    o.mimeTypes = safe(function () { return Array.from(n.mimeTypes).map(function (m) { return m.type; }).join(','); });
    if (n.userAgentData) {
      o.uaBrands = n.userAgentData.brands.map(function (b) { return b.brand + '/' + b.version; }).join(', ');
      o.uaMobile = n.userAgentData.mobile;
      o.uaPlatform = n.userAgentData.platform;
      o.uaHigh = await safeA(async function () {
        var h = await n.userAgentData.getHighEntropyValues(['architecture', 'bitness', 'model', 'platformVersion',
          'fullVersionList', 'uaFullVersion', 'wow64', 'formFactors']);
        return {
          architecture: h.architecture, bitness: h.bitness, model: h.model, platformVersion: h.platformVersion,
          uaFullVersion: h.uaFullVersion, wow64: h.wow64, formFactors: String(h.formFactors),
          fullVersionList: (h.fullVersionList || []).map(function (b) { return b.brand + '/' + b.version; }).join(', '),
        };
      });
    } else {
      o.uaBrands = '(no userAgentData)';
    }
    o.intl = safe(function () {
      var r = g.Intl.DateTimeFormat().resolvedOptions();
      return [r.locale, r.calendar, r.numberingSystem, r.timeZone].join('|');
    });
    o.tzOffset = new g.Date(2026, 0, 1).getTimezoneOffset();
    o.math = [Math.tan(-1e300), Math.acosh(1e300), Math.expm1(1), Math.sinh(1), Math.cbrt(Math.PI)].join(',');
    o.chromeObject = safe(function () {
      return typeof g.chrome === 'undefined' ? '(none)' : g.Object.getOwnPropertyNames(g.chrome).sort().join(',');
    });
    o.chromeWebview = safe(function () { return webviewObject(g); });
    o.globals = safe(function () { return g.Object.getOwnPropertyNames(g).sort(); });
    o.navigatorMembers = safe(function () { return protoNames(g, n); });
    o.storageQuotaMB = await safeA(async function () { var e = await n.storage.estimate(); return Math.round(e.quota / 1e6); });
    o.permissions = await permissions(n);
    o.canvas2d = safe(function () { return canvas2d(g); });
    o.webgl = safe(function () { return webgl(g); });
    o.rtcPeerConnection = typeof g.RTCPeerConnection;
    if (g.document) {
      o.screen = safe(function () {
        var s = g.screen;
        return [s.width, s.height, s.availWidth, s.availHeight, s.colorDepth, s.pixelDepth, g.devicePixelRatio].join(',');
      });
      o.media = safe(function () { return media(g); });
      o.fonts = safe(function () { return fonts(g); });
      o.audio = await safeA(function () { return audio(g); });
      o.voices = await safeA(function () { return voices(g); }, 3000);
      o.mediaDevices = await safeA(async function () {
        var d = await n.mediaDevices.enumerateDevices();
        return d.map(function (x) { return x.kind; }).sort().join(',');
      });
    }
    // Lets the server record the request headers this context sends.
    o.echo = await safeA(function () {
      return g.fetch('/fp/echo?ctx=' + encodeURIComponent(where), { cache: 'no-store' }).then(function (r) { return r.status; });
    });
    return o;
  }

  return { collect: collect, safe: safe, safeA: safeA, hashStr: hashStr };
})();
