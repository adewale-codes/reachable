#!/usr/bin/env node
// Ground-truth benchmark. Scans every fixture offline (recorded OSV data in
// bench/osv-cache), compares each verdict to the hand-written expected.json,
// and prints confusion matrices.
//
// expected.json, per advisory:
//   expected  the verdict the tool must give
//   reason    for cant_tell, a reason code that must be among the reasons
//   truth     whether the fixture code can actually trigger the advisory
//             (reachable | unreachable | unknown), judged by reading it
//
// Fails (exit 1) on any mismatch, and above all on any false "unreachable":
// a tool verdict of unreachable where the truth is not unreachable.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(here, 'fixtures');
const cacheDir = path.join(here, 'osv-cache');
const VERDICTS = ['reachable', 'unreachable', 'cant_tell'];

const fixtures = fs.readdirSync(fixturesDir).filter((d) => fs.existsSync(path.join(fixturesDir, d, 'expected.json'))).sort();

const truthMatrix = {}; // truth -> verdict -> n
const expectedMatrix = {}; // expected -> verdict -> n
const bump = (m, a, b) => { m[a] = m[a] || {}; m[a][b] = (m[a][b] || 0) + 1; };

let total = 0;
let passed = 0;
const failures = [];
const falseUnreachable = [];
const falseReachable = [];

for (const name of fixtures) {
  const dir = path.join(fixturesDir, name);
  const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
  let report;
  try {
    report = await scan(dir, { offline: true, cacheDir });
  } catch (err) {
    failures.push(`${name}: scan failed: ${err.message}`);
    console.log(`  FAIL  ${name}  scan failed: ${err.message}`);
    continue;
  }
  if (!report.complete) failures.push(`${name}: scan incomplete: ${report.errors.map((e) => e.message).join('; ')}`);

  const actual = new Map(report.results.map((r) => [`${r.id}|${r.package}|${r.version}`, r]));
  const seen = new Set();
  const rows = [];
  for (const e of expected.results) {
    const key = `${e.id}|${e.package}|${e.version}`;
    seen.add(key);
    total++;
    const r = actual.get(key);
    if (!r) {
      failures.push(`${name}: ${e.id} ${e.package}@${e.version} expected ${e.expected} but no result was reported`);
      rows.push(`    ✗ ${e.id} ${e.package}@${e.version}: missing`);
      continue;
    }
    bump(truthMatrix, e.truth, r.verdict);
    bump(expectedMatrix, e.expected, r.verdict);
    const codes = r.reasons.map((x) => x.code);
    const ok = r.verdict === e.expected && (!e.reason || codes.includes(e.reason));
    if (ok) passed++;
    else failures.push(`${name}: ${e.id} ${e.package}@${e.version} expected ${e.expected}${e.reason ? ` (${e.reason})` : ''}, got ${r.verdict}${codes.length ? ` (${codes.join(', ')})` : ''}`);
    if (r.verdict === 'unreachable' && e.truth !== 'unreachable') falseUnreachable.push(`${name}: ${e.id} (truth: ${e.truth})`);
    if (r.verdict === 'reachable' && e.truth === 'unreachable') falseReachable.push(`${name}: ${e.id}`);
    const shown = r.verdict === 'cant_tell' ? `cant_tell/${r.reason}` : r.verdict;
    rows.push(`    ${ok ? '✓' : '✗'} ${e.id}  ${e.package}@${e.version}  ${shown}${ok ? '' : `   (expected ${e.expected}${e.reason ? `/${e.reason}` : ''})`}`);
  }
  for (const [key, r] of actual) {
    if (!seen.has(key)) {
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

console.log(`\n${fixtures.length} fixtures, ${total} labelled advisory alerts, ${passed} match expected verdict`);
printMatrix('Confusion matrix: ground truth (rows) vs tool verdict (columns)', 'truth', truthMatrix, ['reachable', 'unreachable', 'unknown']);
printMatrix('Confusion matrix: expected verdict (rows) vs tool verdict (columns)', 'expected', expectedMatrix, VERDICTS);

console.log(`\nFalse "unreachable" (tool said unreachable, truth is not): ${falseUnreachable.length}`);
for (const f of falseUnreachable) console.log(`  !! ${f}`);
console.log(`False "reachable" (tool said reachable, truth is unreachable): ${falseReachable.length}`);
for (const f of falseReachable) console.log(`  - ${f}`);

if (failures.length) {
  console.log(`\n${failures.length} failure(s):`);
  for (const f of failures) console.log(`  - ${f}`);
}
const ok = failures.length === 0 && falseUnreachable.length === 0;
console.log(`\nBENCHMARK ${ok ? 'PASSED' : 'FAILED'}`);
process.exitCode = ok ? 0 : 1;
