// Builds crates/untrace-filter/resources/ubo-scriptlets.json from a uBlock Origin source tree
// (D-057). The scriptlets are uBlock Origin's own code (GPL-3.0); this only repackages them as
// the resource list the matching library (adblock-rust) loads: one entry per function, with its
// aliases, the helper functions it needs and whether only trusted lists may use it.
//
// Usage (from the repository root):
//   node scripts/ubo-scriptlets/build.mjs <uBlock source folder> <release tag>
// The source folder is an unpacked release, e.g. github.com/gorhill/uBlock/archive/refs/tags/1.77.2.tar.gz.

import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [src, tag] = process.argv.slice(2);
if (!src || !tag) {
    console.error('usage: node scripts/ubo-scriptlets/build.mjs <uBlock source folder> <release tag>');
    process.exit(2);
}
const entry = path.join(src, 'src', 'js', 'resources', 'scriptlets.js');
const { builtinScriptlets } = await import(pathToFileURL(entry).href);

const resources = [];
const names = new Set();
for (const s of builtinScriptlets) {
    const code = s.fn.toString();
    // The library calls a scriptlet by the name of its function: it must be a named function.
    // Helpers (`*.fn`) are only included as code, so a class or an async function is fine there.
    const isFunction = /^function\s+[^\s(){}]+\s*\(/.test(code);
    const isHelper = s.name.endsWith('.fn') && /^(class\s+[^\s{]+|async\s+function\s+[^\s(){}]+\s*\()/.test(code);
    if (!isFunction && !isHelper) {
        throw new Error(`${s.name}: not a named function or helper class`);
    }
    if (names.has(s.name)) {
        throw new Error(`${s.name}: listed twice`);
    }
    names.add(s.name);
    resources.push({
        name: s.name,
        aliases: s.aliases ?? [],
        // The library injects only `application/javascript` scriptlets (calling them by their
        // function's name); `fn/javascript` is for helpers included as dependencies.
        kind: { mime: s.name.endsWith('.fn') ? 'fn/javascript' : 'application/javascript' },
        content: Buffer.from(code, 'utf8').toString('base64'),
        dependencies: s.dependencies ?? [],
        // Bit 0: trusted. Only uBlock Origin's own lists may use these (`trusted-*` scriptlets
        // can insert arbitrary text into pages).
        permission: s.requiresTrust ? 1 : 0,
    });
}
for (const r of resources) {
    for (const d of r.dependencies) {
        if (!names.has(d)) {
            throw new Error(`${r.name}: missing dependency ${d}`);
        }
    }
}

const out = path.join('crates', 'untrace-filter', 'resources', 'ubo-scriptlets.json');
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(
    out,
    JSON.stringify({
        source: `https://github.com/gorhill/uBlock/tree/${tag}/src/js/resources`,
        version: tag,
        licence: 'GPL-3.0-or-later (uBlock Origin, Raymond Hill and contributors)',
        resources,
    }, null, 1) + '\n',
);
const trusted = resources.filter(r => r.permission === 1).length;
console.log(`${out}: ${resources.length} resources (${trusted} trusted) from uBlock Origin ${tag}`);
