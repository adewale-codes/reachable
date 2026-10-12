// Pre-publish fixes: subpath-aware symbols, Babel interop helpers, bundler
// external lists. Each fix may only move verdicts in the safe direction.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createParser } from '../src/parser.js';
import { analyzeTree, bundlerConfigKind } from '../src/usage.js';
import { decideAlert, indexUsage, loadAdvisoryData, symbolSpec, normalizeSubpath } from '../src/verdict.js';
import { applyGuard, namesDeepPath, parseAnswer } from '../src/llm.js';
import { buildMentionIndex } from '../src/mentions.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const parse = await createParser();
const data = loadAdvisoryData();
const tracked = new Set(['nanoid', 'lodash', 'minimist']);
function usageOf(files) {
  const u = { imports: [], uses: [], unresolved: [], global: [], parseErrors: [], fileErrors: [], typeImports: [], externalEntries: [] };
  for (const [name, code] of Object.entries(files)) {
    const t = parse(code, name);
    const r = analyzeTree(t, code, name, tracked);
    t.delete();
    for (const k of Object.keys(u)) if (r[k]) u[k].push(...r[k]);
  }
  return u;
}
const decideFor = (files, symbolInfo, pkg = 'nanoid') => {
  const usage = usageOf(files);
  return decideAlert({
    advisoryId: 'X', instance: { key: `node_modules/${pkg}`, name: pkg, installName: pkg, version: '1.0.0', direct: true, parentKeys: [], requiredBy: [] },
    data, symbolInfo, project: { usage, usageIndex: indexUsage(usage), mentions: { scripts: [], configs: [] } }, packageEdges: { available: true, loaders: [] },
  });
};

// ---------------------------------------------------------------- Fix 1: subpaths

test('subpath helpers', () => {
  assert.equal(normalizeSubpath('non-secure/index.js'), 'non-secure');
  assert.equal(normalizeSubpath(null), null);
  const s = symbolSpec(['a', { symbol: 'nanoid', module: 'nanoid/non-secure' }, { symbol: 'b', module: 'nanoid' }], 'nanoid');
  assert.deepEqual([...s.any].sort(), ['a', 'b']);
  assert.deepEqual([...s.byModule.get('non-secure')], ['nanoid']);
});

const qualified = (tier) => (tier === 'llm'
  ? { tier: 'llm', model: 'm', symbols: [{ symbol: 'nanoid', quote: 'q', module: 'nanoid/non-secure', exportCheck: 'unknown' }] }
  : { tier: 'curated', symbols: [{ symbol: 'nanoid', module: 'nanoid/non-secure' }] });

test('a symbol qualified to nanoid/non-secure: the main import is never reachable and NEVER unreachable', () => {
  for (const tier of ['llm', 'curated']) {
    for (const code of ["import { nanoid } from 'nanoid'; nanoid(n);", "import { customAlphabet } from 'nanoid'; customAlphabet('ab', 4);", "import 'nanoid';", "const { nanoid } = require('nanoid/index.js'); nanoid();"]) {
      const d = decideFor({ 'a.js': code }, qualified(tier));
      assert.equal(d.verdict, 'cant_tell', `${tier}: ${code}`);
      assert.ok(d.reasons.some((r) => r.code === 'other_entry_point'), `${tier}: ${code} ${d.reasons.map((r) => r.code)}`);
    }
  }
});

test('the qualified module itself is matched exactly (reachable), the unqualified case is unchanged', () => {
  assert.equal(decideFor({ 'a.js': "import { nanoid } from 'nanoid/non-secure'; nanoid(n);" }, qualified('llm')).verdict, 'reachable');
  assert.equal(decideFor({ 'a.js': "const { nanoid } = require('nanoid/non-secure/index.js'); nanoid(n);" }, qualified('curated')).verdict, 'reachable');
  // unqualified symbol: main import of the same name is reachable, as before
  assert.equal(decideFor({ 'a.js': "import { nanoid } from 'nanoid'; nanoid(n);" }, { tier: 'curated', symbols: ['nanoid'] }).verdict, 'reachable');
});

test('LLM guard: a module is kept only when it is a deep path of the package written in the advisory', () => {
  const text = 'An infinite loop in the nanoid function of its non-secure module (nanoid/non-secure).';
  const ans = parseAnswer(JSON.stringify({ names_specific_api: true, symbols: [
    { symbol: 'nanoid', quote: 'An infinite loop in the nanoid function', module: 'nanoid/non-secure' },
  ] })).value;
  assert.equal(applyGuard(ans, text, null, 'nanoid').kept[0].module, 'nanoid/non-secure');
  const notWritten = { names_specific_api: true, symbols: [{ symbol: 'nanoid', quote: 'An infinite loop in the nanoid function', module: 'nanoid/async' }] };
  const g = applyGuard(notWritten, text, null, 'nanoid');
  assert.equal(g.kept[0].module, undefined); // unqualified: applies to every entry point
  assert.equal(g.unqualified[0].why, 'module_not_in_advisory');
  const otherPkg = { names_specific_api: true, symbols: [{ symbol: 'nanoid', quote: 'An infinite loop in the nanoid function', module: 'uuid/v4' }] };
  assert.equal(applyGuard(otherPkg, 'uuid/v4 ' + text, null, 'nanoid').unqualified[0].why, 'module_not_a_deep_path_of_package');
  assert.equal(parseAnswer('{"names_specific_api":true,"symbols":[{"symbol":"a","quote":"b","module":3}]}').ok, false);
});

test('deep-path detection used to decide whether an old (v1) LLM answer can be reused', () => {
  assert.equal(namesDeepPath('its non-secure module (nanoid/non-secure)', 'nanoid'), true);
  assert.equal(namesDeepPath('https://github.com/ai/nanoid/blob/main/index.js', 'nanoid'), false);
  assert.equal(namesDeepPath('`@sequelize/core` is not affected', 'sequelize'), false);
  assert.equal(namesDeepPath('the /_next/image endpoint', 'next'), false);
});

// ---------------------------------------------------------------- Fix 2: Babel interop

const DEFAULT_HELPER = 'function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }';
const lodashTemplate = { tier: 'curated', symbols: ['template'] };
const lodashCase = (code) => decideFor({ 'lib/a.js': code }, lodashTemplate, 'lodash');

test('genuine Babel interop: transparent, so normal rules decide', () => {
  assert.equal(lodashCase(`var _l = _interopRequireDefault(require("lodash"));\n${DEFAULT_HELPER}\n_l.default.get(o, 'a');`).verdict, 'unreachable');
  assert.equal(lodashCase(`var _l = _interopRequireDefault(require("lodash"));\n${DEFAULT_HELPER}\n_l.default.template(s);`).verdict, 'reachable');
  assert.equal(lodashCase(`var _l = _interopRequireDefault(require("lodash"));\n${DEFAULT_HELPER}\n(0, _l.default)(s).value();`).reasons[0].code, 'gateway_used');
  assert.equal(lodashCase('var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");\nvar _l = _interopRequireDefault(require("lodash"));\n_l.default.get(o);').verdict, 'unreachable');
});

test('anything that is not exactly the genuine helper stays an escape', () => {
  const cases = {
    lookalike: 'var _l = _interopRequireDefault(require("lodash"));\nfunction _interopRequireDefault(obj) { log(obj); return obj && obj.__esModule ? obj : { default: obj }; }\n_l.default.get(o);',
    undefinedHelper: 'var _l = _interopRequireDefault(require("lodash"));\n_l.default.get(o);',
    reassigned: `var _l = _interopRequireDefault(require("lodash"));\n${DEFAULT_HELPER}\n_interopRequireDefault = wrap;\n_l.default.get(o);`,
    twoDefinitions: `var _l = _interopRequireDefault(require("lodash"));\n${DEFAULT_HELPER}\n${DEFAULT_HELPER}\n_l.default.get(o);`,
    secondArgument: `var _l = _interopRequireDefault(require("lodash"), extra);\n${DEFAULT_HELPER}\n_l.default.get(o);`,
    wrongRuntimePath: 'var _interopRequireDefault = require("my-helpers/interopRequireDefault");\nvar _l = _interopRequireDefault(require("lodash"));\n_l.default.get(o);',
    bindingPassed: `var _l = _interopRequireDefault(require("lodash"));\n${DEFAULT_HELPER}\nregister(_l);`,
    bindingStored: `var _l = _interopRequireDefault(require("lodash"));\n${DEFAULT_HELPER}\nmodule.exports = { lib: _l };`,
  };
  for (const [name, code] of Object.entries(cases)) {
    const d = lodashCase(code);
    assert.equal(d.verdict, 'cant_tell', name);
  }
});

test('(0, x)(...) is only a plain call for interop bindings', () => {
  // A plain require binding keeps the Phase 1 rule (comma expression = escape).
  assert.equal(decideFor({ 'a.js': "const _m = require('minimist');\n(0, _m)(argv);" }, { tier: 'curated', symbols: ['(module)'] }, 'minimist').verdict, 'cant_tell');
  assert.equal(decideFor({ 'a.js': `var _m = _interopRequireDefault(require("minimist"));\n${DEFAULT_HELPER}\n(0, _m.default)(argv);` }, { tier: 'curated', symbols: ['(module)'] }, 'minimist').verdict, 'reachable');
});

// ---------------------------------------------------------------- Fix 3: bundler externals

test('only literal entries of an external array in a root bundler config are exempt', () => {
  assert.equal(bundlerConfigKind('rollup.config.js'), 'external');
  assert.equal(bundlerConfigKind('webpack.config.cjs'), 'externals');
  assert.equal(bundlerConfigKind('src/rollup.config.js'), null);
  assert.equal(bundlerConfigKind('jest.config.js'), null);
  const safe = "import { get } from 'lodash'; get(o, 'a');";
  const v = (files) => decideFor({ 'src/a.js': safe, ...files }, lodashTemplate, 'lodash');
  assert.equal(v({ 'rollup.config.js': "export default { external: ['react', 'lodash'] };" }).verdict, 'unreachable');
  assert.equal(v({ 'vite.config.ts': "export default { build: { rollupOptions: { external: ['lodash'] } } };" }).verdict, 'unreachable');
  assert.equal(v({ 'webpack.config.js': "module.exports = { externals: ['lodash'] };" }).verdict, 'unreachable');
  const conservative = {
    spread: "export default { external: [...['lodash']] };",
    computed: "export default { external: (id) => ['lodash'].includes(id) };",
    concat: "export default { external: ['react'].concat('lodash') };",
    webpackObject: "module.exports = { externals: { lodash: '_' , other: 'lodash' } };",
    wrongKey: "export default { plugins: ['lodash'] };",
    alias: "export default { resolve: { alias: { utils: 'lodash' } } };",
  };
  for (const [name, cfg] of Object.entries(conservative)) {
    const file = name.startsWith('webpack') ? 'webpack.config.js' : 'rollup.config.js';
    assert.equal(v({ [file]: cfg }).verdict, 'cant_tell', name);
  }
  assert.equal(v({ 'src/rollup.config.js': "export default { external: ['lodash'] };" }).verdict, 'cant_tell'); // not at the root
  assert.equal(v({ 'jest.config.js': "module.exports = { external: ['lodash'] };" }).verdict, 'cant_tell'); // not a bundler config
});

test('an external entry is also blanked from the root-config mention check, nothing else is', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'reachable-ext-'));
  fs.writeFileSync(path.join(dir, 'vite.config.js'), "export default {\n  build: { rollupOptions: { external: ['lodash'] } },\n};\n");
  const entries = [{ file: 'vite.config.js', line: 2, text: "'lodash'" }];
  assert.equal(buildMentionIndex(dir, {}, entries)('lodash').configs.length, 0);
  assert.equal(buildMentionIndex(dir, {}, [])('lodash').configs.length, 1);
  fs.writeFileSync(path.join(dir, 'vite.config.js'), "export default {\n  build: { rollupOptions: { external: ['lodash'] } },\n  resolve: { alias: { u: 'lodash' } },\n};\n");
  assert.equal(buildMentionIndex(dir, {}, entries)('lodash').configs.length, 1);
});
