// Adversarial cases for the usage extractor + verdict engine. Each case is a
// small source file; the verdict is for the lodash `template` advisory
// (GHSA-35jh-r3h4-6jhm) on a direct lodash dependency. Most of these try to
// reach `template` in a way a naive analysis would miss: none may come out
// `unreachable`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createParser } from '../src/parser.js';
import { analyzeTree } from '../src/usage.js';
import { decide, indexUsage, loadAdvisoryData, classify } from '../src/verdict.js';

const parse = await createParser();
const data = loadAdvisoryData();
const ADVISORY = 'GHSA-35jh-r3h4-6jhm';
const lodash = { name: 'lodash', installName: 'lodash', version: '4.17.20', direct: true, requiredBy: [] };
const tracked = new Set(['lodash', 'minimist']);

function verdictFor(files, { advisory = ADVISORY, instance = lodash } = {}) {
  const usage = { imports: [], uses: [], unresolved: [], global: [], parseErrors: [], fileErrors: [] };
  for (const [name, code] of Object.entries(files)) {
    const tree = parse(code, name);
    const r = analyzeTree(tree, code, name, tracked);
    tree.delete();
    for (const k of ['imports', 'uses', 'unresolved', 'global', 'parseErrors']) usage[k].push(...r[k]);
  }
  return decide({ advisoryId: advisory, instance, data, usageIndex: indexUsage(usage), usage });
}

const cases = [
  // [description, source, file, verdict, reason]
  ['named import', "import { template } from 'lodash'; template('x');", 'a.js', 'reachable'],
  ['named import, unused, still a reference', "import { template } from 'lodash';", 'a.js', 'reachable'],
  ['default import member call', "import _ from 'lodash'; _.template('x');", 'a.js', 'reachable'],
  ['import { default as x }', "import { default as lo } from 'lodash'; lo.template('x');", 'a.js', 'reachable'],
  ['namespace .default', "import * as ns from 'lodash'; ns.default.template('x');", 'a.js', 'reachable'],
  ['string-literal member', "const _ = require('lodash'); _['template']('x');", 'a.js', 'reachable'],
  ['static concatenated key', "const _ = require('lodash'); _['temp' + 'late']('x');", 'a.js', 'reachable'],
  ['template-literal key', 'const _ = require(\'lodash\'); _[`template`]("x");', 'a.js', 'reachable'],
  ['optional chaining', "const _ = require('lodash'); _?.template?.('x');", 'a.js', 'reachable'],
  ['require().member', "require('lodash').template('x');", 'a.js', 'reachable'],
  ['alias of module', "const a = require('lodash'); const b = a; b.template('x');", 'a.js', 'reachable'],
  ['alias of function', "const _ = require('lodash'); const t = _.template; t('x');", 'a.js', 'reachable'],
  ['destructure with rename', "const { template: t } = require('lodash'); t('x');", 'a.js', 'reachable'],
  ['nested destructure from alias', "const _ = require('lodash'); const { template } = _; template('x');", 'a.js', 'reachable'],
  ['rest pattern', "const { map, ...rest } = require('lodash'); rest.template('x');", 'a.js', 'reachable'],
  ['awaited dynamic import', "const m = await import('lodash'); m.default.template('x');", 'a.mjs', 'reachable'],
  ['awaited dynamic import destructure', "const { template } = await import('lodash');", 'a.mjs', 'reachable'],
  ['createRequire alias', "import { createRequire } from 'module'; const r = createRequire(import.meta.url); r('lodash').template('x');", 'a.mjs', 'reachable'],
  ['module.require', "module.require('lodash').template('x');", 'a.js', 'reachable'],
  ['TS import = require', "import lo = require('lodash'); lo.template('x');", 'a.ts', 'reachable'],
  ['TS non-null and as', "import _ from 'lodash'; (_ as any)!.template('x');", 'a.ts', 'reachable'],
  ['call/apply on function', "const _ = require('lodash'); _.template.call(null, 'x');", 'a.js', 'reachable'],
  ['inside JSX', "import _ from 'lodash'; export const C = () => <div>{_.template('x')()}</div>;", 'a.jsx', 'reachable'],
  ['chain wrapper', "import _ from 'lodash'; _.chain('x').template().value();", 'a.js', 'reachable'],
  ['module call wrapper', "import _ from 'lodash'; _('x').template();", 'a.js', 'reachable'],
  ['lodash/fp', "const fp = require('lodash/fp'); fp.template('x');", 'a.js', 'reachable'],
  ['deep import of affected file', "const t = require('lodash/template'); t('x');", 'a.js', 'reachable'],
  ['named re-export', "export { template } from 'lodash';", 'a.js', 'reachable'],

  ['unaffected use only', "import _ from 'lodash'; _.get(o, 'a'); _.map([], f);", 'a.js', 'unreachable'],
  ['side-effect import only', "import 'lodash';", 'a.js', 'unreachable'],
  ['typeof module', "const _ = require('lodash'); if (typeof _ === 'function') _.noop();", 'a.js', 'unreachable'],
  ['unaffected deep import', "const get = require('lodash/get'); get(o, 'a');", 'a.js', 'unreachable'],
  ['type-only import does not count', "import type { TemplateOptions } from 'lodash'; import _ from 'lodash'; _.get(o,'a');", 'a.ts', 'unreachable'],

  ['computed member', "const _ = require('lodash'); _[name]('x');", 'a.js', 'cant_tell', 'dynamic_member_access'],
  ['computed destructure key', "const { [name]: f } = require('lodash');", 'a.js', 'cant_tell', 'dynamic_member_access'],
  ['passed as argument', "const _ = require('lodash'); use(_);", 'a.js', 'cant_tell', 'module_escapes'],
  ['returned', "const _ = require('lodash'); function f() { return _; }", 'a.js', 'cant_tell', 'module_escapes'],
  ['stored in object shorthand', "const _ = require('lodash'); const o = { _ };", 'a.js', 'cant_tell', 'module_escapes'],
  ['module.exports =', "module.exports = require('lodash');", 'a.js', 'cant_tell', 'module_escapes'],
  ['exports.x =', "const _ = require('lodash'); exports.lib = _;", 'a.js', 'cant_tell', 'module_escapes'],
  ['export default', "import _ from 'lodash'; export default _;", 'a.js', 'cant_tell', 'module_escapes'],
  ['export { x }', "import _ from 'lodash'; export { _ };", 'a.js', 'cant_tell', 'module_escapes'],
  ['export const alias', "export const lib = require('lodash');", 'a.js', 'cant_tell', 'module_escapes'],
  ['export * as ns', "export * as lo from 'lodash';", 'a.js', 'cant_tell', 'module_escapes'],
  ['export { default }', "export { default } from 'lodash';", 'a.js', 'cant_tell', 'module_escapes'],
  ['global assignment', "globalThis.lo = require('lodash');", 'a.js', 'cant_tell', 'module_escapes'],
  ['logical or', "const lib = require('lodash') || other; lib.template('x');", 'a.js', 'cant_tell', 'module_escapes'],
  ['spread', "const _ = require('lodash'); const all = { ..._ };", 'a.js', 'cant_tell', 'module_escapes'],
  ['Object.values', "const _ = require('lodash'); Object.values(_);", 'a.js', 'cant_tell', 'module_escapes'],
  ['class field', "const _ = require('lodash'); class A { lib = _; }", 'a.js', 'cant_tell', 'module_escapes'],
  ['default parameter', "const _ = require('lodash'); function f(l = _) { return l.template; }", 'a.js', 'cant_tell', 'module_escapes'],
  ['export * from', "export * from 'lodash';", 'a.js', 'cant_tell', 'reexport_all'],
  ['dynamic require', "require(name);", 'a.js', 'cant_tell', 'dynamic_require'],
  ['dynamic import', "await import(name);", 'a.mjs', 'cant_tell', 'dynamic_import'],
  ['dynamic deep require', "require('lodash/' + name);", 'a.js', 'cant_tell', 'dynamic_subpath'],
  ['import().then', "import('lodash').then((m) => m.template('x'));", 'a.mjs', 'cant_tell', 'dynamic_import_promise'],
  ['require aliased', "const r = require; r('lodash').template('x');", 'a.js', 'cant_tell', 'require_escapes'],
  ['require.call', "require.call(null, 'lodash').template('x');", 'a.js', 'cant_tell', 'require_escapes'],
  ['eval', "import { get } from 'lodash'; get(o); eval(code);", 'a.js', 'cant_tell', 'eval_present'],
  ['indirect eval', "import { get } from 'lodash'; get(o); (0, eval)(code);", 'a.js', 'cant_tell', 'eval_present'],
  ['window.eval', "import { get } from 'lodash'; get(o); window.eval(code);", 'a.js', 'cant_tell', 'eval_present'],
  ['new Function', "import { get } from 'lodash'; get(o); new Function('return 1');", 'a.js', 'cant_tell', 'eval_present'],
  ['Function()', "import { get } from 'lodash'; get(o); Function('return 1')();", 'a.js', 'cant_tell', 'eval_present'],
  ['string setTimeout', "import { get } from 'lodash'; get(o); setTimeout('run()', 10);", 'a.js', 'cant_tell', 'eval_present'],
  ['vm module', "import { get } from 'lodash'; import vm from 'node:vm'; get(o);", 'a.js', 'cant_tell', 'eval_present'],
  ['name as string (mock)', "import { get } from 'lodash'; get(o); jest.mock('lodash');", 'a.js', 'cant_tell', 'name_as_string'],
  ['name as string (global require)', "globalThis['require']('lodash').template('x');", 'a.js', 'cant_tell', 'name_as_string'],
  ['gateway with no affected call', "import _ from 'lodash'; _.chain([1]).map(f).value();", 'a.js', 'cant_tell', 'gateway_used'],
  ['private deep import', "const baseGet = require('lodash/_baseGet');", 'a.js', 'cant_tell', 'unmapped_subpath'],
  ['indirect same-name property', "import _ from 'lodash'; _.get(o, 'x').template('y');", 'a.js', 'cant_tell', 'indirect_reference'],
  ['parse error', "import _ from 'lodash'; _.get(o, ;", 'a.js', 'cant_tell', 'parse_error'],
  ['never imported', 'console.log(1);', 'a.js', 'cant_tell', 'declared_unused'],
];

for (const [desc, code, file, verdict, reason] of cases) {
  test(`${verdict}${reason ? `/${reason}` : ''}: ${desc}`, () => {
    const d = verdictFor({ [file]: code });
    assert.equal(d.verdict, verdict, `reasons: ${d.reasons.map((r) => r.code).join(', ')}`);
    if (reason) assert.ok(d.reasons.some((r) => r.code === reason), `expected reason ${reason}, got ${d.reasons.map((r) => r.code).join(', ')}`);
  });
}

test('module escape in one file blocks unreachable for the whole package', () => {
  const d = verdictFor({ 'a.js': "import _ from 'lodash'; _.get(o);", 'b.js': "import _ from 'lodash'; register(_);" });
  assert.equal(d.verdict, 'cant_tell');
});

test('reachable evidence is the chain from import to use', () => {
  const d = verdictFor({ 'a.js': "const _ = require('lodash');\nconst t = _.template;\n\nt('x');" });
  assert.equal(d.verdict, 'reachable');
  const chains = d.evidence.references.map((r) => r.chain.map((s) => `${s.file}:${s.line}`).join(' -> '));
  assert.ok(chains.includes('a.js:1 -> a.js:2 -> a.js:4'), chains.join(' | '));
});

test('(module) symbol: calling the main export is reachable, using nothing is unreachable', () => {
  const instance = { name: 'minimist', installName: 'minimist', version: '1.2.0', direct: true, requiredBy: [] };
  const advisory = 'GHSA-xvch-5gv4-984h';
  assert.equal(verdictFor({ 'a.js': "require('minimist')(process.argv);" }, { advisory, instance }).verdict, 'reachable');
  assert.equal(verdictFor({ 'a.js': "import m from 'minimist'; m.call(null, argv);" }, { advisory, instance }).verdict, 'reachable');
  assert.equal(verdictFor({ 'a.js': "import * as m from 'minimist'; m.default(argv);" }, { advisory, instance }).verdict, 'reachable');
  assert.equal(verdictFor({ 'a.js': "const m = require('minimist');" }, { advisory, instance }).verdict, 'unreachable');
  assert.equal(verdictFor({ 'a.js': "const m = require('minimist'); run(m);" }, { advisory, instance }).verdict, 'cant_tell');
});

test('transitive and uncurated advisories are never analysed', () => {
  assert.equal(verdictFor({ 'a.js': "import _ from 'lodash'; _.get(o);" }, { instance: { ...lodash, direct: false } }).reasons[0].code, 'transitive_not_analysed');
  assert.equal(verdictFor({ 'a.js': "import _ from 'lodash'; _.get(o);" }, { advisory: 'GHSA-29mw-wpgm-hmr9' }).reasons[0].code, 'no_symbol_data');
});

test('classify never returns affected for unrelated chains', () => {
  const S = new Set(['template']);
  const G = new Set(['chain']);
  assert.equal(classify([{ t: 'prop', name: 'get' }, { t: 'call' }], S, G, 'harmless').kind, 'none');
  assert.equal(classify([], S, G, 'escape').kind, 'escape');
  assert.equal(classify([{ t: 'prop', name: 'get' }], S, G, 'escape').kind, 'none');
  assert.equal(classify([], S, G, 'dynamic').kind, 'dynamic');
});

test("a bare '&' inside a JSX attribute string is tolerated, other syntax errors are not", () => {
  const ok = verdictFor({ 'a.jsx': "import _ from 'lodash'; _.get(o); export const L = () => <a href=\"https://x.test/?a=1&b=2\">x</a>;" });
  assert.equal(ok.verdict, 'unreachable');
  const bad = verdictFor({ 'a.jsx': "import _ from 'lodash'; _.get(o); export const L = () => <a href={1 +}>x</a>;" });
  assert.equal(bad.verdict, 'cant_tell');
  assert.ok(bad.reasons.some((r) => r.code === 'parse_error'));
});

test("a phantom (undeclared, hoisted) dependency called by the project's own code is reachable", () => {
  const instance = { name: 'minimist', installName: 'minimist', key: 'node_modules/minimist', version: '0.0.8', direct: false, parentKeys: ['node_modules/mkdirp'], requiredBy: ['mkdirp@0.5.1'] };
  const d = verdictFor({ 'a.js': "require('minimist')(process.argv);" }, { advisory: 'GHSA-xvch-5gv4-984h', instance });
  assert.equal(d.verdict, 'reachable');
});
