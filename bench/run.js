#!/usr/bin/env node
// Ground-truth benchmark. Scans every fixture offline (recorded OSV data in
// bench/osv-cache, recorded LLM answers in bench/llm-cache plus any
// fixture-local llm-cache/), compares each verdict to the hand-written
// expected.json, and prints confusion matrices for Phase 2 and for a Phase 1
// baseline run of the same fixtures, with the cant_tell rate of each.
//
// expected.json, per advisory:
//   expected  the verdict the tool must give
//   reason    for cant_tell, a reason code that must be among the reasons
//   truth     whether the fixture code can actually trigger the advisory
//             (reachable | unreachable | unknown), judged by reading it
//   scope     (optional) prod | dev, checked when present
//
// Fails (exit 1) on any mismatch, and above all on any false "unreachable":
// a Phase 2 verdict of unreachable where the truth is not unreachable.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(here, 'fixtures');
const cacheDir = path.join(here, 'osv-cache');
const llmCache = path.join(here, 'llm-cache');
const VERDICTS = ['reachable', 'unreachable', 'cant_tell'];
const PHASE1_FIXTURE_COUNT = 22; // fixtures 01-22 existed in Phase 1

const fixtures = fs.readdirSync(fixturesDir).filter((d) => fs.existsSync(path.join(fixturesDir, d, 'expected.json'))).sort();

const mk = () => ({ truth: {}, expected: {}, n: 0, cantTell: 0, falseUnreachable: [], falseReachable: [] });
const phase2 = { all: mk(), old: mk() };
const phase1 = { all: mk(), old: mk() };
const bump = (m, a, b) => { m[a] = m[a] || {}; m[a][b] = (m[a][b] || 0) + 1; };
const record = (bucket, e, verdict, where) => {
  bucket.n++;
  if (verdict === 'cant_tell') bucket.cantTell++;
  bump(bucket.truth, e.truth, verdict);
  bump(bucket.expected, e.expected, verdict);
  if (verdict === 'unreachable' && e.truth !== 'unreachable') bucket.falseUnreachable.push(`${where}: ${e.id} (truth: ${e.truth})`);
  if (verdict === 'reachable' && e.truth === 'unreachable') bucket.falseReachable.push(`${where}: ${e.id}`);
};

let total = 0;
let passed = 0;
const failures = [];

for (const [index, name] of fixtures.entries()) {
  const dir = path.join(fixturesDir, name);
  const isOld = index < PHASE1_FIXTURE_COUNT;
  const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
  const local = path.join(dir, 'llm-cache');
  const llmCacheDirs = [...(fs.existsSync(local) ? [local] : []), llmCache];
  let report;
  let base;
  try {
    report = await scan(dir, { offline: true, cacheDir, llm: 'cache', llmCacheDirs });
    base = await scan(dir, { offline: true, cacheDir, phase1Baseline: true });
  } catch (err) {
    failures.push(`${name}: scan failed: ${err.message}`);
    console.log(`FAIL  ${name}  scan failed: ${err.message}`);
    continue;
  }
  if (!report.complete) failures.push(`${name}: scan incomplete: ${report.errors.map((e) => e.message).join('; ')}`);

  const key = (r) => `${r.id}|${r.package}|${r.version}`;
  const actual = new Map(report.results.map((r) => [key(r), r]));
  const baseline = new Map(base.results.map((r) => [key(r), r]));
  const seen = new Set();
  const rows = [];
  for (const e of expected.results) {
    const k = key(e);
    seen.add(k);
    total++;
    const r = actual.get(k);
    if (!r) {
      failures.push(`${name}: ${e.id} ${e.package}@${e.version} expected ${e.expected} but no result was reported`);
      rows.push(`    ✗ ${e.id} ${e.package}@${e.version}: missing`);
      continue;
    }
    record(phase2.all, e, r.verdict, name);
    if (isOld) record(phase2.old, e, r.verdict, name);
    const b = baseline.get(k);
    if (b) {
      record(phase1.all, e, b.verdict, name);
      if (isOld) record(phase1.old, e, b.verdict, name);
    }
    const codes = r.reasons.map((x) => x.code);
    const scopeOk = !e.scope || e.scope === r.scope;
    const ok = r.verdict === e.expected && (!e.reason || codes.includes(e.reason)) && scopeOk;
    if (ok) passed++;
    else failures.push(`${name}: ${e.id} ${e.package}@${e.version} expected ${e.expected}${e.reason ? ` (${e.reason})` : ''}${e.scope ? ` scope ${e.scope}` : ''}, got ${r.verdict} (${codes.join(', ') || '-'}) scope ${r.scope}`);
    const shown = r.verdict === 'cant_tell' ? `cant_tell/${r.reason}` : r.verdict;
    const tags = [r.scope, r.symbolTier === 'llm' ? 'llm' : null, b && b.verdict !== r.verdict ? `phase1: ${b.verdict}` : null].filter(Boolean).join(', ');
    rows.push(`    ${ok ? '✓' : '✗'} ${e.id}  ${e.package}@${e.version}  ${shown}  [${tags}]${ok ? '' : `   (expected ${e.expected}${e.reason ? `/${e.reason}` : ''})`}`);
  }
  for (const [k, r] of actual) {
    if (!seen.has(k)) {
      failures.push(`${name}: unexpected result ${r.id} ${r.package}@${r.version} (${r.verdict}); label it in expected.json`);
      rows.push(`    ✗ ${r.id}  ${r.package}@${r.version}  ${r.verdict}   (not labelled)`);
    }
  }
  const bad = rows.some((x) => x.startsWith('    ✗'));
  console.log(`${bad ? 'FAIL' : 'ok  '}  ${name}  ${expected.description}`);
  for (const row of rows) console.log(row);
}

function printMatrix(title, rowsLabel, m, rowKeys) {
  const w = 13;
  console.log(`\n${title}`);
  console.log(`  ${rowsLabel.padEnd(w)}${VERDICTS.map((v) => `→${v}`.padStart(w)).join('')}${'total'.padStart(8)}`);
  for (const k of rowKeys) {
    const row = m[k] || {};
    const n = VERDICTS.reduce((s, v) => s + (row[v] || 0), 0);
    if (!n) continue;
    console.log(`  ${k.padEnd(w)}${VERDICTS.map((v) => String(row[v] || 0).padStart(w)).join('')}${String(n).padStart(8)}`);
  }
}
const pct = (b) => (b.n ? `${b.cantTell}/${b.n} (${((100 * b.cantTell) / b.n).toFixed(1)}%)` : '-');

console.log(`\n${fixtures.length} fixtures, ${total} labelled advisory alerts, ${passed} match expected verdict`);
printMatrix('Phase 2 confusion matrix, all fixtures: ground truth (rows) vs tool verdict (columns)', 'truth', phase2.all.truth, ['reachable', 'unreachable', 'unknown']);
printMatrix('Phase 1 baseline on the same fixtures: ground truth (rows) vs verdict (columns)', 'truth', phase1.all.truth, ['reachable', 'unreachable', 'unknown']);
printMatrix('Phase 2 expected verdict (rows) vs tool verdict (columns)', 'expected', phase2.all.expected, [...VERDICTS, 'TODO_LLM']);

console.log('\ncant_tell rate                     Phase 1 baseline    Phase 2');
console.log(`  original ${PHASE1_FIXTURE_COUNT} fixtures            ${pct(phase1.old).padEnd(20)}${pct(phase2.old)}`);
console.log(`  all ${fixtures.length} fixtures                 ${pct(phase1.all).padEnd(20)}${pct(phase2.all)}`);

console.log(`\nFalse "unreachable" in Phase 2 (tool said unreachable, truth is not): ${phase2.all.falseUnreachable.length}`);
for (const f of phase2.all.falseUnreachable) console.log(`  !! ${f}`);
console.log(`False "unreachable" the Phase 1 rules would have given on these fixtures: ${phase1.all.falseUnreachable.length}`);
for (const f of phase1.all.falseUnreachable) console.log(`  (phase 1) ${f}`);
console.log(`False "reachable" in Phase 2 (tool said reachable, truth is unreachable): ${phase2.all.falseReachable.length}`);
for (const f of phase2.all.falseReachable) console.log(`  - ${f}`);

if (failures.length) {
  console.log(`\n${failures.length} failure(s):`);
  for (const f of failures) console.log(`  - ${f}`);
}
const ok = failures.length === 0 && phase2.all.falseUnreachable.length === 0;
console.log(`\nBENCHMARK ${ok ? 'PASSED' : 'FAILED'}`);
process.exitCode = ok ? 0 : 1;
