#!/usr/bin/env node
// Compares two corpus result folders (e.g. cold vs warm cache) on everything
// that matters: completeness, errors, summary, and every result (verdict,
// reasons, evidence). Volatile fields (timestamps, timings, cache and network
// statistics) are ignored.
//
// Usage: node bench/real/diff-results.js <dirA> <dirB> [--verdicts-only]

import fs from 'node:fs';
import path from 'node:path';

const [a, b] = process.argv.slice(2).filter((x) => !x.startsWith('--'));
const verdictsOnly = process.argv.includes('--verdicts-only');
const slugs = fs.readdirSync(a).filter((f) => f.endsWith('.json') && f !== 'summary.json');
const comparable = (file) => {
  const { report } = JSON.parse(fs.readFileSync(file, 'utf8'));
  const results = report.results.map((r) => (verdictsOnly
    ? { id: r.id, path: r.lockfilePath, verdict: r.verdict }
    : r));
  return { complete: report.complete, errors: report.errors, summary: report.summary, results };
};
let differing = 0;
for (const f of slugs) {
  if (!fs.existsSync(path.join(b, f))) { console.log(`${f}: missing in ${b}`); differing++; continue; }
  const x = comparable(path.join(a, f));
  const y = comparable(path.join(b, f));
  if (JSON.stringify(x) === JSON.stringify(y)) { console.log(`${f}: identical`); continue; }
  differing++;
  console.log(`${f}: DIFFERENT  ${JSON.stringify(x.summary)} vs ${JSON.stringify(y.summary)}`);
  const key = (r) => `${r.id}|${r.lockfilePath || r.path}`;
  const ya = new Map(y.results.map((r) => [key(r), r]));
  for (const r of x.results) {
    const o = ya.get(key(r));
    if (!o) console.log(`   only in A: ${key(r)} ${r.verdict}`);
    else if (o.verdict !== r.verdict) console.log(`   verdict ${key(r)}: ${r.verdict} -> ${o.verdict}`);
    else if (JSON.stringify(o) !== JSON.stringify(r)) console.log(`   details ${key(r)} (${r.verdict})`);
  }
}
console.log(`\n${slugs.length} repos compared, ${differing} differ`);
process.exitCode = differing ? 1 : 0;
