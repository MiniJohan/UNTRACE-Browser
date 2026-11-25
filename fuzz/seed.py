"""Write small seed corpora for the fuzz targets (fuzz/corpus/<target>/seed-*). Run from the
repository root: python -I fuzz/seed.py. The fuzzer grows each corpus from these."""
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
LISTS = os.path.join(ROOT, '..', 'crates', 'untrace-filter', 'lists')


def put(target, items):
    d = os.path.join(ROOT, 'corpus', target)
    os.makedirs(d, exist_ok=True)
    for i, data in enumerate(items):
        if isinstance(data, str):
            data = data.encode('utf-8')
        with open(os.path.join(d, f'seed-{i:03}'), 'wb') as f:
            f.write(data)


def lines(name, keep, n):
    with open(os.path.join(LISTS, name), encoding='utf-8') as f:
        return [l.rstrip('\n') for l in f if keep(l)][:n]


put('proxy_head', [
    'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic dTpw\r\n\r\n',
    'GET http://example.com/a?b=c HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, X-Foo\r\nX-Foo: 1\r\nProxy-Connection: close\r\n\r\n',
    'CONNECT [fe80::1]:8443 HTTP/1.1\r\nHost: [fe80::1]:8443\r\n\r\n',
    'POST http://127.0.0.1:8080/x HTTP/1.0\r\nContent-Length: 3\r\nTE: trailers\r\nUpgrade: websocket\r\n\r\n',
])

put('web_urls', [
    'https://example.com/path?utm_source=a&fbclid=b&keep=1#f',
    'http://192.168.1.1/admin',
    'file:///C:/Windows/win.ini',
    'ms-settings:privacy',
    'https://xn--80ak6aa92e.com/',
    'http://[::1]:3000/',
    'setup.exe.pdf',
    'Report 2026.docm',
    'https://user:pass@sub.example.co.uk:8443/a/b/../c',
    'printer.local',
    'error at https://example.com/x in www.example.org/path',
])

put('settings_file', [
    '{"schema":1,"theme":"system","search":{"engine":"duck-duck-go"},"protections":{"filter.block_ads":true,'
    '"privacy.tracking_prevention":"balanced"}}',
    '{"schema":1,"theme":"dark","search":{"engine":"custom","custom_template":"https://s.example/?q=%s"},'
    '"protections":{"filter.block_ads":"yes","unknown.id":false},"filter_exceptions":["example.com","EXAMPLE.com",'
    '"a..b"],"local_network_sites":["router.example"],"custom_doh":{"template":"https://dns.example/dns-query",'
    '"address":"192.0.2.53"}}',
])

# D-055: byte 0 even = an imported HTML file, odd = UNTRACE's own bookmarks.json.
bm_html = open(os.path.join(ROOT, '..', 'crates', 'untrace-core', 'src', 'bookmarks.rs'), encoding='utf-8').read()
bm_html = bm_html[bm_html.index('const CHROME: &str = r#"') + 24:]
bm_html = bm_html[:bm_html.index('"#;')]
put('bookmarks_file', [
    b'\x00' + bm_html.encode(),
    b'\x00<DL><DT><H3>A</H3><DL><DT><A HREF="https://a.example/?x=1&amp;y=2">A &#38; B</A></DL></DL>',
    b'\x01{"schema":1,"next_id":3,"items":[{"kind":"bookmark","id":1,"title":"t","url":"https://e.example"},'
    b'{"kind":"folder","id":2,"title":"F","items":[{"kind":"bookmark","id":2,"title":"","url":"javascript:x"}]}]}',
])

lists = [('easylist.txt', 0), ('easyprivacy.txt', 1), ('urlhaus-domains.txt', 2), ('phishing-domains.txt', 3)]
put('block_list', [bytes([i]) + ''.join(l + '\n' for l in lines(n, lambda l: True, 60)).encode() for n, i in lists])

put('cosmetic_rules', [
    '\n'.join(lines('easylist.txt', lambda l: '##' in l or '#@#' in l, 80)),
    'example.com##.ad\nexample.com#@#.ad\n##div:-abp-has(> .sponsored)\n##.x:has-text(Ad)\n'
    'example.org##+js(set, a, 1)\n##a { color: red }\n###id /* c */\n##@media x\nexample.com#$#hide\n',
])

put('user_input', [
    'example.com',
    'what is untrace\x01',
    'https://search.example/?q=%s\x01https://search.example/?q=%s',
    'https://dns.quad9.net/dns-query\x019.9.9.9',
    'https://[2620:fe::fe]/dns-query\x012620:fe::fe',
    'localhost:3000',
    'Example.CO.uk',
])

put('request_match', [
    'https://www.google-analytics.com/collect?v=1\x01https://example.com/',
    'https://ads.example.com/banner.js\x01https://news.example.org/',
    'https://example.com/\x01https://example.com/',
    'wss://socket.example/\x01https://example.com/',
])
print('seeded')
