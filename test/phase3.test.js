// Phase 3: library entry point, Markdown output, per-package cache.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as lib from '../src/index.js';
import { formatMarkdown } from '../src/format.js';
import { scan } from '../src/scan.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const osvCache = path.join(root, 'bench', 'osv-cache');
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), `reachable-${p}-`));

test('the library entry point loads and exposes the public API', () => {
  for (const name of ['scan', 'exitCodeFor', 'formatText', 'formatJson', 'formatMarkdown', 'decideAlert', 'ANALYZER_VERSION']) {
    assert.ok(name in lib, name);
  }
});

// ---------------------------------------------------------------- markdown

test('markdown: summary, reachable table, collapsed sections, footer; pipes escaped', async () => {
  const report = await scan(path.join(root, 'bench/fixtures/19-gateway-chain'), { offline: true, cacheDir: osvCache, llm: 'off', pkgCacheDir: false });
  const md = formatMarkdown(report);
  assert.match(md, /\*\*2 reachable\*\* · \*\*0 unreachable\*\* · \*\*3 can't tell\*\*/);
  assert.match(md, /\| Advisory \| Package \| Scope \| Affected \| Evidence \|/);
  assert.match(md, /\[GHSA-f23m-r3pf-42rh\]\(https:\/\/osv\.dev\/vulnerability\/GHSA-f23m-r3pf-42rh\)/);
  assert.match(md, /<details><summary>Can't tell \(3\), by reason<\/summary>/);
  assert.match(md, /\*\*`gateway_used`\*\* \(2\)/);
  assert.match(md, /it is not the same as exploitable/);
  const piped = JSON.parse(JSON.stringify(report));
  piped.results[0].evidence.references[0].chain.at(-1).text = 'a || b | c';
  assert.match(formatMarkdown(piped), /a \\\|\\\| b \\\| c/);
  const incomplete = { ...report, complete: false, errors: [{ code: 'parse_error', message: 'x.js:1: syntax error' }] };
  assert.match(formatMarkdown(incomplete), /\*\*Scan incomplete\.\*\*/);
});

test('--format markdown on the CLI, and a failed scan still exits 2 with a markdown notice', () => {
  const ok = spawnSync(process.execPath, [path.join(root, 'bin/reachable.js'), 'scan', path.join(root, 'bench/fixtures/01-named-import'), '--offline', '--cache-dir', osvCache, '--format', 'markdown', '--no-llm'], { encoding: 'utf8' });
  assert.equal(ok.status, 1);
  assert.match(ok.stdout, /^### reachable/);
  const bad = spawnSync(process.execPath, [path.join(root, 'bin/reachable.js'), 'scan', path.join(root, 'nope'), '--format', 'markdown'], { encoding: 'utf8' });
  assert.equal(bad.status, 2);
  assert.match(bad.stdout, /scan could not complete/);
});

// ---------------------------------------------------------------- cache

/** Two nested copies of the same package version (same integrity) at different paths, both calling minimist. */
function twoCopiesProject({ patched = false } = {}) {
  const dir = tmp('copies');
  const w = (rel, c) => { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), typeof c === 'string' ? c : JSON.stringify(c, null, 2)); };
  w('package.json', { name: 'copies', version: '1.0.0', dependencies: { 'fx-config-reader': '1.0.0', 'fx-email-renderer': '1.0.0' } });
  w('src/index.js', "require('fx-config-reader'); require('fx-email-renderer');\n");
  const helper = { version: '1.0.0', integrity: 'sha512-same-bytes-in-both-places', dependencies: { minimist: '1.2.0' } };
  w('package-lock.json', { name: 'copies', version: '1.0.0', lockfileVersion: 3, requires: true, packages: {
    '': { name: 'copies', version: '1.0.0', dependencies: { 'fx-config-reader': '1.0.0', 'fx-email-renderer': '1.0.0' } },
    'node_modules/fx-config-reader': { version: '1.0.0', dependencies: { 'fx-argv-helper': '1.0.0' } },
    'node_modules/fx-config-reader/node_modules/fx-argv-helper': helper,
    'node_modules/fx-email-renderer': { version: '1.0.0', dependencies: { 'fx-argv-helper': '1.0.0' } },
    'node_modules/fx-email-renderer/node_modules/fx-argv-helper': helper,
    'node_modules/minimist': { version: '1.2.0', integrity: 'sha512-minimist' },
  } });
  for (const parent of ['fx-config-reader', 'fx-email-renderer']) {
    w(`node_modules/${parent}/package.json`, { name: parent, version: '1.0.0', main: 'index.js' });
    w(`node_modules/${parent}/index.js`, "module.exports = require('fx-argv-helper');\n");
    w(`node_modules/${parent}/node_modules/fx-argv-helper/package.json`, { name: 'fx-argv-helper', version: '1.0.0', main: 'index.js' });
    w(`node_modules/${parent}/node_modules/fx-argv-helper/index.js`, "const minimist = require('minimist');\nmodule.exports = (a) => minimist(a);\n");
  }
  w('node_modules/minimist/package.json', { name: 'minimist', version: '1.2.0', main: 'index.js' });
  w('node_modules/minimist/index.js', 'module.exports = function (args) { return {}; };\n');
  if (patched) w('patches/fx-argv-helper+1.0.0.patch', 'diff --git a/index.js b/index.js\n');
  return dir;
}

const run = (dir, pkgCacheDir) => scan(dir, { offline: true, cacheDir: osvCache, llm: 'off', pkgCacheDir });
const evidenceFiles = (report) => report.results.flatMap((r) => r.reasons.flatMap((x) => x.locations.map((l) => l.file))).filter((f) => f.includes('fx-argv-helper')).sort();

test('cache: cold and warm runs give identical results, and paths stay correct for each install location', async () => {
  const dir = twoCopiesProject();
  const cacheDir = tmp('pkgcache');
  const none = await run(dir, false);
  const cold = await run(dir, cacheDir);
  const warm = await run(dir, cacheDir);
  assert.ok(warm.transitiveAnalysis.cache.hits > 0, 'warm run should hit the cache');
  assert.deepEqual(cold.results, none.results);
  assert.deepEqual(warm.results, cold.results);
  const files = evidenceFiles(warm);
  assert.ok(files.some((f) => f.startsWith('node_modules/fx-config-reader/node_modules/fx-argv-helper/')), files.join(', '));
  assert.ok(files.some((f) => f.startsWith('node_modules/fx-email-renderer/node_modules/fx-argv-helper/')), files.join(', '));
  assert.ok(warm.results.every((r) => r.reason === 'transitive_parent_uses_symbol'));
});

test('cache: a package patched by patch-package is never cached', async () => {
  const dir = twoCopiesProject({ patched: true });
  const cacheDir = tmp('pkgcache');
  await run(dir, cacheDir);
  const second = await run(dir, cacheDir);
  // fx-argv-helper (patched) is re-analysed; only other packages may hit.
  const files = fs.readdirSync(cacheDir, { recursive: true }).filter((f) => String(f).endsWith('.json'));
  for (const f of files) assert.doesNotMatch(fs.readFileSync(path.join(cacheDir, String(f)), 'utf8'), /"fx-argv-helper"/);
  assert.ok(second.results.every((r) => r.reason === 'transitive_parent_uses_symbol'));
});

test('cache: a changed analyzer version or integrity hash is a different key', () => {
  const c = new lib.PackageCache(tmp('k'));
  const a = c.keyFor(['p', '1.0.0', 'sha512-a']);
  assert.notEqual(a, c.keyFor(['p', '1.0.0', 'sha512-b']));
  assert.match(JSON.stringify(c.keyFor.toString()), /ANALYZER_VERSION/);
});

test("a bare '&' in JSX text is tolerated; real syntax errors and code-bearing errors are not", async () => {
  const { createParser } = await import('../src/parser.js');
  const { analyzeTree } = await import('../src/usage.js');
  const parse = await createParser();
  const run = (code) => { const t = parse(code, 'a.jsx'); const r = analyzeTree(t, code, 'a.jsx', new Set(['react'])); t.delete(); return r; };
  const ok = run("import React from 'react';\nexport const A = () => <h1 className=\"x\">React & Tailwind CSS</h1>;\nexport const B = () => <p>&</p>;");
  assert.equal(ok.parseErrors.length, 0);
  assert.equal(ok.tolerated.length, 2);
  // the word "React" inside the text must not count as a use of the react import
  assert.ok(!ok.uses.some((u) => u.end === 'escape'), JSON.stringify(ok.uses));
  assert.ok(run('export const C = () => <p>{a & }</p>;').parseErrors.length > 0);
  assert.ok(run('export const D = () => <p>x</p>; let y = ;').parseErrors.length > 0);
});
