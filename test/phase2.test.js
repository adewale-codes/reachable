// Phase 2: LLM guard and trust tier, LLM client failure modes, loader edges
// (transitive analysis), package file scoping, export detection, scope tags.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createParser } from '../src/parser.js';
import { analyzeTree } from '../src/usage.js';
import { decideAlert, indexUsage, loadAdvisoryData } from '../src/verdict.js';
import { applyGuard, parseAnswer, LlmExtractor, toSymbolInfo, cacheKey } from '../src/llm.js';
import { filesInScope, readExports, listPackageFiles } from '../src/packages.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const parse = await createParser();
const data = loadAdvisoryData();
const tracked = new Set(['lodash', 'minimist', 'ms', 'jsonwebtoken']);
const noMentions = { scripts: [], configs: [] };

function usageOf(files) {
  const usage = { imports: [], uses: [], unresolved: [], global: [], parseErrors: [], fileErrors: [], typeImports: [] };
  for (const [name, code] of Object.entries(files)) {
    const tree = parse(code, name);
    const r = analyzeTree(tree, code, name, tracked);
    tree.delete();
    for (const k of ['imports', 'uses', 'unresolved', 'global', 'parseErrors', 'typeImports']) usage[k].push(...r[k]);
  }
  return usage;
}
const inst = (over = {}) => ({ key: 'node_modules/lodash', name: 'lodash', installName: 'lodash', version: '4.17.20', direct: true, parentKeys: [], requiredBy: [], ...over });
const project = (files) => { const u = usageOf(files); return { usage: u, usageIndex: indexUsage(u), mentions: noMentions }; };
const loader = (label, files, extra = {}) => { const u = usageOf(files); return { key: `node_modules/${label}`, label: `${label}@1.0.0`, declared: true, status: 'ok', usage: u, usageIndex: indexUsage(u), mode: 'test', ...extra }; };
const llmInfo = (symbols) => ({ tier: 'llm', model: 'test-model', symbols: symbols.map((s) => ({ symbol: s, quote: `uses ${s}`, exportCheck: 'unknown' })) });

// ---------------------------------------------------------------- guard

const TEXT = 'Versions of foo before 2.0 are vulnerable.\n\nThe `parse` method   does not\nrestrict keys. Calling foo(input) with untrusted input is unsafe.';

test('parseAnswer accepts the schema (also inside a ```json fence) and rejects everything else', () => {
  assert.equal(parseAnswer('{"names_specific_api":true,"symbols":[{"symbol":"parse","quote":"x"}]}').ok, true);
  assert.equal(parseAnswer('```json\n{"names_specific_api":false,"symbols":[]}\n```').ok, true);
  for (const bad of ['', 'parse', '[]', '{"symbols":[]}', '{"names_specific_api":"yes","symbols":[]}',
    '{"names_specific_api":true,"symbols":{}}', '{"names_specific_api":true,"symbols":[{"symbol":"parse"}]}',
    '{"names_specific_api":true,"symbols":[{"symbol":"","quote":"x"}]}', '{"names_specific_api":true,"symbols":[{"symbol":1,"quote":"x"}]}']) {
    assert.equal(parseAnswer(bad).ok, false, bad);
  }
});

test('guard: quotes must be verbatim (whitespace-insensitive), name the symbol, and the symbol must be an identifier', () => {
  const g = applyGuard({ names_specific_api: true, symbols: [
    { symbol: 'parse', quote: 'The `parse` method does not restrict keys.' }, // whitespace differs only
    { symbol: 'stringify', quote: 'The `stringify` method does not restrict keys.' }, // not in text
    { symbol: 'parse2', quote: 'Versions of foo before 2.0' }, // verbatim but does not mention parse2
    { symbol: 'foo.parse', quote: 'The `parse` method' }, // not an identifier
    { symbol: '(module)', quote: 'Calling foo(input) with untrusted input is unsafe.' },
  ] }, TEXT, { determined: false });
  assert.deepEqual(g.kept.map((k) => k.symbol), ['parse', '(module)']);
  assert.deepEqual(g.dropped.map((d) => `${d.symbol}:${d.why}`), ['stringify:quote_not_in_advisory', 'parse2:quote_lacks_symbol', 'foo.parse:not_an_identifier']);
  assert.equal(g.kept[0].exportCheck, 'unknown');
});

test('guard: symbols that are certainly not exports are dropped; (module) needs a callable export', () => {
  const ans = { names_specific_api: true, symbols: [{ symbol: 'parse', quote: 'The `parse` method' }, { symbol: '(module)', quote: 'Calling foo(input)' }] };
  const notCallable = applyGuard(ans, TEXT, { determined: true, names: new Set(['stringify']), callable: false });
  assert.deepEqual(notCallable.kept, []);
  assert.deepEqual(notCallable.dropped.map((d) => d.why), ['not_an_export', 'not_an_export']);
  const ok = applyGuard(ans, TEXT, { determined: true, names: new Set(['parse']), callable: true });
  assert.deepEqual(ok.kept.map((k) => `${k.symbol}:${k.exportCheck}`), ['parse:confirmed', '(module):confirmed']);
});

test('toSymbolInfo: every failure mode becomes cant_tell reasons, never symbols', () => {
  assert.equal(toSymbolInfo({ status: 'unavailable', detail: 'x' }, null).tier, null);
  assert.equal(toSymbolInfo({ status: 'invalid', detail: 'x' }, null).reasons[1].code, 'llm_invalid_output');
  assert.equal(toSymbolInfo({ status: 'ok', text: TEXT, answer: { names_specific_api: false, symbols: [] } }, null).reasons[1].code, 'llm_no_specific_api');
  const allDropped = toSymbolInfo({ status: 'ok', text: TEXT, answer: { names_specific_api: true, symbols: [{ symbol: 'nope', quote: 'not there' }] } }, null);
  assert.equal(allDropped.tier, null);
  assert.equal(allDropped.reasons[1].code, 'llm_no_valid_symbols');
});

// ---------------------------------------------------------------- tier rule

const CLEAN_SNIPPETS = [
  "import _ from 'lodash'; _.get(o, 'a');",
  "const { map } = require('lodash'); map([], f);",
  "import 'lodash';",
  "const get = require('lodash/get'); get(o, 'x');",
  "import * as l from 'lodash'; l.kebabCase('A B');",
];

test('an llm-tier symbol never produces unreachable, even when the rest of the analysis is clean', () => {
  for (const code of CLEAN_SNIPPETS) {
    for (const syms of [['template'], ['toNumber', 'trim'], ['(module)'], ['zzz_not_real']]) {
      for (const packageEdges of [{ available: true, loaders: [] }, null]) {
        // Sanity: the same facts with curated-tier data ARE unreachable, so the
        // cant_tell below comes from the tier rule and nothing else.
        const curated = decideAlert({ advisoryId: 'X', instance: inst(), data, symbolInfo: { tier: 'curated', symbols: syms }, project: project({ 'a.js': code }), packageEdges });
        const d = decideAlert({ advisoryId: 'X', instance: inst(), data, symbolInfo: llmInfo(syms), project: project({ 'a.js': code }), packageEdges });
        assert.equal(curated.verdict, 'unreachable', `curated control: ${code} ${syms}`);
        assert.notEqual(d.verdict, 'unreachable', `${code} ${syms}`);
        assert.equal(d.verdict, 'cant_tell');
        assert.ok(d.reasons.some((r) => r.code === 'llm_tier_cannot_prove_unreachable'));
      }
    }
  }
});

test('an llm-tier symbol that is called is reachable, labelled source llm with its quote', () => {
  const d = decideAlert({ advisoryId: 'X', instance: inst(), data, symbolInfo: llmInfo(['template']), project: project({ 'a.js': "import _ from 'lodash';\n_.template(s);" }), packageEdges: { available: true, loaders: [] } });
  assert.equal(d.verdict, 'reachable');
  assert.equal(d.evidence.tier, 'llm');
  assert.equal(d.evidence.references[0].source, 'llm');
  assert.equal(d.evidence.references[0].quote, 'uses template');
});

// ---------------------------------------------------------------- loader edges

const curatedTemplate = { tier: 'curated', symbols: ['template'] };
const transitiveLodash = inst({ direct: false, parentKeys: ['node_modules/a'], requiredBy: ['a@1.0.0'] });

test('transitive: unreachable only when every loader passes', () => {
  const clean = loader('a', { 'node_modules/a/index.js': "const _ = require('lodash'); module.exports = (o) => _.get(o, 'x');" });
  const never = loader('b', { 'node_modules/b/index.js': 'module.exports = 1;' });
  const user = loader('c', { 'node_modules/c/index.js': "const t = require('lodash/template'); module.exports = t('x');" });
  const go = (loaders) => decideAlert({ advisoryId: 'X', instance: transitiveLodash, data, symbolInfo: curatedTemplate, project: project({ 'src.js': '1;' }), packageEdges: { available: true, loaders } });
  assert.equal(go([clean, never]).verdict, 'unreachable');
  const diamond = go([clean, user]);
  assert.equal(diamond.verdict, 'cant_tell');
  assert.equal(diamond.reasons[0].code, 'transitive_parent_uses_symbol');
});

test('transitive: a parent that uses the affected symbol is never promoted to reachable', () => {
  const user = loader('c', { 'node_modules/c/index.js': "const _ = require('lodash'); _.template('x');" });
  const d = decideAlert({ advisoryId: 'X', instance: transitiveLodash, data, symbolInfo: curatedTemplate, project: project({ 'src.js': "require('c');" }), packageEdges: { available: true, loaders: [user] } });
  assert.equal(d.verdict, 'cant_tell');
});

test('transitive: every kind of doubt inside a parent blocks unreachable', () => {
  const cases = {
    escape: "const _ = require('lodash'); module.exports = _;",
    dynamic: "const _ = require('lodash'); module.exports = (k) => _[k]();",
    dynamicRequire: 'module.exports = (n) => require(n);',
    evalUse: "require('lodash').get(o); eval(s);",
    nameAsString: "loadPlugin('lodash');",
    unparseable: "const _ = require('lodash'); _.get(o, ;",
  };
  for (const [what, code] of Object.entries(cases)) {
    const d = decideAlert({ advisoryId: 'X', instance: transitiveLodash, data, symbolInfo: curatedTemplate, project: project({ 'src.js': '1;' }), packageEdges: { available: true, loaders: [loader('a', { 'node_modules/a/index.js': code })] } });
    assert.equal(d.verdict, 'cant_tell', what);
  }
});

test('missing node_modules, missing parent and out-of-sync parent all stay cant_tell', () => {
  const go = (packageEdges) => decideAlert({ advisoryId: 'X', instance: transitiveLodash, data, symbolInfo: curatedTemplate, project: project({ 's.js': '1;' }), packageEdges });
  assert.equal(go({ available: false }).reasons[0].code, 'node_modules_missing');
  assert.equal(go({ available: true, loaders: [{ key: 'node_modules/a', label: 'a@1', status: 'missing' }] }).reasons[0].code, 'parent_not_installed');
  assert.equal(go({ available: true, loaders: [{ key: 'node_modules/a', label: 'a@1', status: 'out_of_sync', detail: 'x' }] }).reasons[0].code, 'node_modules_out_of_sync');
});

test('a direct dependency that other installed packages also load needs those loaders to pass', () => {
  const shared = inst({ parentKeys: ['node_modules/a'] });
  const proj = project({ 'src.js': "const _ = require('lodash'); _.get(o);" });
  const user = loader('a', { 'node_modules/a/index.js': "require('lodash/template')('x');" });
  assert.equal(decideAlert({ advisoryId: 'X', instance: shared, data, symbolInfo: curatedTemplate, project: proj, packageEdges: { available: false } }).reasons[0].code, 'node_modules_missing');
  assert.equal(decideAlert({ advisoryId: 'X', instance: shared, data, symbolInfo: curatedTemplate, project: proj, packageEdges: { available: true, loaders: [user] } }).reasons[0].code, 'transitive_parent_uses_symbol');
});

test('used_by_script and declared_unused split the never-imported reason; neither is unreachable', () => {
  const p = project({ 'src.js': '1;' });
  const d1 = decideAlert({ advisoryId: 'X', instance: inst(), data, symbolInfo: curatedTemplate, project: p, packageEdges: { available: true, loaders: [] } });
  assert.deepEqual([d1.verdict, d1.reasons[0].code], ['cant_tell', 'declared_unused']);
  const withScript = { ...p, mentions: { scripts: [{ file: 'package.json', line: null, text: '"x": "lodash-cli"', detail: 'npm script' }], configs: [] } };
  const d2 = decideAlert({ advisoryId: 'X', instance: inst(), data, symbolInfo: curatedTemplate, project: withScript, packageEdges: { available: true, loaders: [] } });
  assert.deepEqual([d2.verdict, d2.reasons[0].code], ['cant_tell', 'used_by_script']);
});

// ---------------------------------------------------------------- LLM client

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'reachable-llm-')); }
const VULN = { id: 'GHSA-test', summary: 'Bug in foo', details: TEXT };
const okReply = (text, extra = {}) => async () => ({ ok: true, status: 200, json: async () => ({ model: 'm', stop_reason: 'end_turn', content: [{ type: 'text', text }], ...extra }) });

test('LLM client: cache-only and no-key modes never call the API', async () => {
  let called = false;
  const fetchImpl = async () => { called = true; throw new Error('should not be called'); };
  assert.equal((await new LlmExtractor({ mode: 'cache', readDirs: [tmp()], fetchImpl }).extract({ advisoryId: 'A', pkg: 'foo', vuln: VULN })).status, 'unavailable');
  assert.equal((await new LlmExtractor({ mode: 'live', apiKey: null, readDirs: [tmp()], fetchImpl }).extract({ advisoryId: 'A', pkg: 'foo', vuln: VULN })).status, 'unavailable');
  assert.equal(called, false);
});

test('LLM client: answers are cached and replayed offline; refusals, bad JSON and server errors are failures', async () => {
  const dir = tmp();
  const good = '{"names_specific_api":true,"symbols":[{"symbol":"parse","quote":"The `parse` method"}]}';
  const live = new LlmExtractor({ mode: 'live', apiKey: 'k', readDirs: [dir], fetchImpl: okReply(good) });
  assert.equal((await live.extract({ advisoryId: 'A', pkg: 'foo', vuln: VULN })).status, 'ok');
  assert.ok(fs.existsSync(path.join(dir, cacheKey({ advisoryId: 'A', pkg: 'foo', text: 'Bug in foo\n\n' + TEXT }))));
  const replay = await new LlmExtractor({ mode: 'cache', readDirs: [dir], fetchImpl: async () => { throw new Error('no'); } }).extract({ advisoryId: 'A', pkg: 'foo', vuln: VULN });
  assert.equal(replay.answer.symbols[0].symbol, 'parse');
  // A changed advisory text is a cache miss.
  assert.equal((await new LlmExtractor({ mode: 'cache', readDirs: [dir] }).extract({ advisoryId: 'A', pkg: 'foo', vuln: { ...VULN, details: TEXT + ' (edited)' } })).status, 'unavailable');

  const refusal = new LlmExtractor({ mode: 'live', apiKey: 'k', readDirs: [tmp()], fetchImpl: okReply('', { stop_reason: 'refusal', stop_details: { category: 'cyber' } }) });
  const r1 = await refusal.extract({ advisoryId: 'A', pkg: 'foo', vuln: VULN });
  assert.equal(r1.status, 'unavailable');
  assert.match(r1.detail, /declined/);
  const garbage = new LlmExtractor({ mode: 'live', apiKey: 'k', readDirs: [tmp()], fetchImpl: okReply('sure! parse is affected') });
  assert.equal((await garbage.extract({ advisoryId: 'A', pkg: 'foo', vuln: VULN })).status, 'invalid');
  const down = new LlmExtractor({ mode: 'live', apiKey: 'k', readDirs: [tmp()], fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}) }) });
  assert.equal((await down.extract({ advisoryId: 'A', pkg: 'foo', vuln: VULN })).status, 'unavailable');
});

// ---------------------------------------------------------------- packages

function makePkg(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'reachable-pkg-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), typeof content === 'string' ? content : JSON.stringify(content));
  }
  return dir;
}
function scopeOf(dir, opts) {
  const pj = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  const all = listPackageFiles(dir);
  const rel = new Map();
  for (const f of all) {
    const code = fs.readFileSync(f, 'utf8');
    const t = parse(code, f);
    rel.set(f, analyzeTree(t, code, f, new Set()).relative);
    t.delete();
  }
  return filesInScope(dir, pj, all, rel, opts);
}

test('package scope: an exports map limits files to the entry closure; bin-only files need a script', () => {
  const dir = makePkg({
    'package.json': { name: 'p', version: '1.0.0', exports: { '.': './lib/index.js' }, bin: { p: './bin/cli.js' } },
    'lib/index.js': "module.exports = require('./util');", 'lib/util.js': 'module.exports = 1;',
    'lib/unused.js': "require('lodash');", 'bin/cli.js': "require('../lib/index.js'); require('minimist');",
  });
  const names = (s) => s.files.map((f) => path.relative(dir, f).split(path.sep).join('/')).sort();
  assert.deepEqual(names(scopeOf(dir)), ['lib/index.js', 'lib/util.js']);
  assert.deepEqual(names(scopeOf(dir, { includeBin: true })), ['bin/cli.js', 'lib/index.js', 'lib/util.js']);
});

test('package scope: without an exports map every file counts (deep imports are possible), except bin-only files', () => {
  const dir = makePkg({
    'package.json': { name: 'p', version: '1.0.0', main: 'index.js', bin: 'bin/cli.js' },
    'index.js': 'module.exports = 1;', 'lib/deep.js': "require('lodash');", 'bin/cli.js': "require('minimist');",
  });
  const s = scopeOf(dir);
  assert.deepEqual(s.files.map((f) => path.relative(dir, f).split(path.sep).join('/')).sort(), ['index.js', 'lib/deep.js']);
  assert.match(s.mode, /no exports map/);
});

test('export detection: determined for plain CommonJS shapes, undetermined for anything unusual', () => {
  const cases = [
    [{ 'index.js': "module.exports = { parse, stringify: s, run() {} };" }, true, ['parse', 'stringify', 'run'], false],
    [{ 'index.js': 'exports.a = 1; module.exports.b = 2;' }, true, ['a', 'b'], false],
    [{ 'index.js': 'module.exports = function (x) {}; module.exports.end = 1;' }, true, ['end'], true],
    [{ 'index.js': "const L = { parse }; module.exports = L;" }, true, ['parse'], false],
    [{ 'index.js': "module.exports = require('./lib');", 'lib.js': 'exports.z = 1;' }, true, ['z'], false],
    [{ 'index.js': '(function(){ var _ = {}; (typeof module)!="undefined" && (module.exports = _); })();' }, false],
    [{ 'index.js': 'Object.assign(module.exports, other);' }, false],
    [{ 'index.js': 'exports[name] = 1;' }, false],
    [{ 'index.js': "module.exports = { ...rest };" }, false],
  ];
  for (const [files, determined, names, callable] of cases) {
    const dir = makePkg({ 'package.json': { name: 'p', version: '1.0.0' }, ...files });
    const r = readExports(dir, parse);
    assert.equal(r.determined, determined, JSON.stringify(files));
    if (determined) {
      assert.deepEqual([...r.names].sort(), [...names].sort());
      assert.equal(r.callable, callable);
    }
  }
});

// ---------------------------------------------------------------- CLI

const bin = path.join(root, 'bin', 'reachable.js');
const fx = (n) => path.join(root, 'bench', 'fixtures', n);
function cli(args, env = {}) {
  const e = { ...process.env, NO_COLOR: '1', ...env };
  delete e.ANTHROPIC_API_KEY;
  const r = spawnSync(process.execPath, [bin, ...args, '--offline', '--cache-dir', path.join(root, 'bench', 'osv-cache')], { encoding: 'utf8', env: { ...e, ...env } });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

test('scope tags and --prod-only: dev alerts are hidden, never re-labelled', () => {
  const all = JSON.parse(cli(['scan', fx('32-scope-prod-dev'), '--json']).stdout);
  assert.deepEqual(all.results.map((r) => `${r.package}:${r.scope}:${r.verdict}`).sort(),
    ['json5:prod:reachable', 'minimist:dev:reachable', 'minimist:dev:reachable']);
  const prod = cli(['scan', fx('32-scope-prod-dev'), '--json', '--prod-only']);
  assert.equal(prod.code, 1);
  const rep = JSON.parse(prod.stdout);
  assert.deepEqual(rep.results.map((r) => r.package), ['json5']);
  assert.equal(rep.hiddenDevAlerts, 2);
});

test('no API key: Phase 1 behaviour, said once, exit codes unchanged', () => {
  const r = cli(['scan', fx('13-no-symbol-data')]);
  assert.equal(r.code, 0);
  assert.equal(r.stdout.match(/ANTHROPIC_API_KEY is not set/g).length, 1);
  const j = JSON.parse(cli(['scan', fx('13-no-symbol-data'), '--json']).stdout);
  assert.ok(j.results.every((x) => x.verdict === 'cant_tell' && x.reason === 'no_symbol_data'));
  assert.equal(cli(['scan', fx('01-named-import')]).code, 1);
});

test('no node_modules: transitive alerts are cant_tell / node_modules_missing, one npm ci hint, exit 0', () => {
  const r = cli(['scan', fx('27-node-modules-missing')]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /node_modules_missing/);
  assert.equal(r.stdout.match(/Run `npm ci`/g).length, 1);
});

test('a direct dependency with no declared dependents still counts undeclared loaders found in node_modules', () => {
  const sloppy = { ...loader('sloppy', { 'node_modules/sloppy/index.js': "require('lodash').template('x');" }), declared: false };
  const d = decideAlert({ advisoryId: 'X', instance: inst(), data, symbolInfo: curatedTemplate, project: project({ 'src.js': "require('lodash').get(o);" }), packageEdges: { available: true, loaders: [sloppy] } });
  assert.deepEqual([d.verdict, d.reasons[0].code], ['cant_tell', 'transitive_parent_uses_symbol']);
});
