#!/usr/bin/env node
// Lists what has to be verified by hand for one corpus result: every reachable
// and unreachable verdict with its evidence, and a deterministic 20 % sample of
// cant_tell verdicts (every 5th, sorted by id + package path).
//
// Usage: node bench/real/list-verdicts.js <slug> [--dir <results dir>]

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const slug = process.argv[2];
const dirArg = process.argv.indexOf('--dir');
const resultsDir = dirArg > 0 ? process.argv[dirArg + 1] : path.join(here, 'results');
const { meta, report } = JSON.parse(fs.readFileSync(path.join(resultsDir, `${slug}.json`), 'utf8'));
console.log(`# ${meta.repo} @ ${meta.sha.slice(0, 7)} (${meta.style})  ${JSON.stringify(report.summary)}  npm ci: ${meta.npmCi && meta.npmCi.ok ? 'ok' : JSON.stringify(meta.npmCi)}`);
const loc = (l) => `${l.file}${l.line ? `:${l.line}` : ''}`;
for (const r of report.results.filter((x) => x.verdict !== 'cant_tell')) {
  console.log(`\n${r.verdict.toUpperCase()} ${r.id} ${r.package}@${r.version} [${r.lockfilePath}] ${r.direct ? 'direct' : 'transitive'} ${r.scope} tier=${r.symbolTier} symbols=${(r.affectedSymbols || []).join(',')}`);
  if (r.verdict === 'reachable') {
    for (const e of r.evidence.references.slice(0, 4)) console.log(`   ${e.source === 'llm' ? `[llm: ${String(e.quote).slice(0, 120)}] ` : ''}${e.chain.map((s) => `${loc(s)} ${s.text}`).join('  ->  ')}`);
  } else {
    const e = r.evidence;
    if (e.importCount) console.log(`   project imports: ${e.importSites.map(loc).join(', ')} (${e.usesChecked} uses)`);
    for (const L of e.loaders || []) console.log(`   loader ${L.loader}${L.declared === false ? ' (undeclared)' : ''}: ${L.result}`);
  }
}
const cant = report.results.filter((x) => x.verdict === 'cant_tell').sort((a, b) => `${a.id}${a.lockfilePath}`.localeCompare(`${b.id}${b.lockfilePath}`));
const sample = cant.filter((_, i) => i % 5 === 0);
console.log(`\n## cant_tell sample: ${sample.length} of ${cant.length}`);
for (const r of sample) {
  const first = r.reasons[0];
  console.log(`CANT_TELL ${r.id} ${r.package}@${r.version} [${r.lockfilePath}] ${r.direct ? 'direct' : 'transitive'} reasons=${r.reasons.map((x) => x.code).join(',')}`);
  for (const l of (first.locations || []).slice(0, 2)) console.log(`   ${loc(l)} ${l.text || ''} ${l.detail ? `[${l.detail}]` : ''}`);
  if (r.llm) console.log(`   llm: ${r.llm.status} kept=${(r.llm.kept || []).map((k) => k.symbol).join(',')} dropped=${(r.llm.dropped || []).map((d) => `${d.symbol}:${d.why}`).join(',')}`);
}
