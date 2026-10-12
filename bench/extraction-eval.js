#!/usr/bin/env node
// Extraction eval. Runs the LLM extractor over the curated advisories AS IF
// they had no curated entry, and scores the guarded result against the
// curated truth: symbols found, missed, extra, and guard rejections.
//
// Then a measured experiment (NOT acted on anywhere): if LLM data were
// allowed to prove `unreachable`, what would the benchmark verdicts be?
//   (a) curated advisories, with the LLM's symbols substituted for the curated ones
//   (b) uncurated advisories, with the LLM tier promoted to curated
// Reported: truth-unreachable alerts it would label unreachable, and any
// false unreachable it would produce. Phase 2 does not promote, whatever this shows.
//
// Usage: node bench/extraction-eval.js          recorded answers only (offline)
//        node bench/extraction-eval.js --live   call the API for missing answers (needs ANTHROPIC_API_KEY)

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LlmExtractor, toSymbolInfo, DEFAULT_LLM_MODEL } from '../src/llm.js';
import { readExports } from '../src/packages.js';
import { createParser } from '../src/parser.js';
import { loadAdvisoryData } from '../src/verdict.js';
import { scan } from '../src/scan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const live = process.argv.includes('--live');
const data = loadAdvisoryData();
const parse = await createParser();
const llm = new LlmExtractor({
  mode: live ? 'live' : 'cache', apiKey: process.env.ANTHROPIC_API_KEY || null,
  model: process.env.REACHABLE_LLM_MODEL || DEFAULT_LLM_MODEL, readDirs: [path.join(here, 'llm-cache')],
});

const evalPkgs = path.join(here, 'eval-packages', 'node_modules');
const exportsFor = (pkg) => (fs.existsSync(path.join(evalPkgs, pkg, 'package.json'))
  ? readExports(path.join(evalPkgs, pkg), parse)
  : { determined: false, why: 'not installed (run npm run bench:setup)' });

const rows = [];
const llmSymbols = new Map(); // advisory id -> guarded symbols (for the experiment)
const totals = { curated: 0, found: 0, missed: 0, extra: 0, dropped: 0, unavailable: 0 };
for (const [id, entry] of Object.entries(data.advisories)) {
  const vulnFile = path.join(here, 'osv-cache', 'vulns', `${id}.json`);
  const vuln = JSON.parse(fs.readFileSync(vulnFile, 'utf8')).vuln;
  const res = await llm.extract({ advisoryId: id, pkg: entry.package, vuln });
  const exp = exportsFor(entry.package);
  const info = toSymbolInfo(res, exp);
  const truth = new Set(entry.symbols);
  const kept = info.tier === 'llm' ? info.symbols.map((s) => s.symbol) : [];
  const dropped = (info.llm && info.llm.dropped) || [];
  const found = kept.filter((s) => truth.has(s));
  const missed = [...truth].filter((s) => !kept.includes(s));
  const extra = kept.filter((s) => !truth.has(s));
  totals.curated += truth.size; totals.found += found.length; totals.missed += missed.length;
  totals.extra += extra.length; totals.dropped += dropped.length;
  if (res.status !== 'ok') totals.unavailable++;
  llmSymbols.set(id, kept);
  rows.push({
    id, pkg: entry.package, curated: [...truth].join(', '),
    llm: res.status === 'ok' ? (kept.join(', ') || '(none kept)') : `(${res.status}: ${res.detail})`,
    found: found.length, missed: missed.join(', ') || '-', extra: extra.join(', ') || '-',
    dropped: dropped.map((d) => `${d.symbol}:${d.why}`).join('; ') || '-',
    exports: exp.determined ? 'checked' : 'unknown',
  });
}

const cols = [['id', 22], ['pkg', 14], ['curated', 34], ['llm', 34], ['found', 6], ['missed', 26], ['extra', 16], ['dropped', 30], ['exports', 8]];
const line = (r) => cols.map(([k, w]) => String(r[k]).slice(0, w - 1).padEnd(w)).join('');
console.log(`Extraction eval: ${rows.length} curated advisories, model ${llm.model}, ${live ? 'live (missing answers fetched)' : 'recorded answers only'}\n`);
console.log(line(Object.fromEntries(cols.map(([k]) => [k, k]))));
for (const r of rows) console.log(line(r));
console.log(`\nCurated symbols ${totals.curated}: found ${totals.found}, missed ${totals.missed}; extra LLM symbols ${totals.extra}; ` +
  `guard rejections ${totals.dropped}; advisories with no usable answer ${totals.unavailable}.`);
const perfect = rows.filter((r) => r.missed === '-' && r.extra === '-').length;
console.log(`Exact symbol-set match on ${perfect} of ${rows.length} advisories. Advisories with a miss: ${rows.filter((r) => r.missed !== '-').map((r) => r.id).join(', ') || 'none'}.`);

// ---------------------------------------------------------------- experiment
console.log('\nExperiment (measured only, not acted on): what if LLM data could prove unreachable?');
const fixturesDir = path.join(here, 'fixtures');
const fixtures = fs.readdirSync(fixturesDir).filter((d) => fs.existsSync(path.join(fixturesDir, d, 'expected.json'))).sort();
const exp = { a: { tu: 0, correct: 0, falseU: [] }, b: { tu: 0, correct: 0, falseU: [] } };
for (const name of fixtures) {
  const dir = path.join(fixturesDir, name);
  const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
  const local = path.join(dir, 'llm-cache');
  const llmCacheDirs = [...(fs.existsSync(local) ? [local] : []), path.join(here, 'llm-cache')];
  const common = { offline: true, cacheDir: path.join(here, 'osv-cache'), llm: 'cache', llmCacheDirs };
  const curatedOverride = (id, pkg) => (data.advisories[id] && data.advisories[id].package === pkg ? llmSymbols.get(id) : undefined);
  const ra = await scan(dir, { ...common, experiment: { curatedOverride } });
  const rb = await scan(dir, { ...common, experiment: { promoteLlm: true } });
  for (const e of expected.results) {
    const k = (r) => r.id === e.id && r.package === e.package && r.version === e.version;
    const isCurated = Boolean(data.advisories[e.id] && data.advisories[e.id].package === e.package);
    const [bucket, report] = isCurated ? [exp.a, ra] : [exp.b, rb];
    const r = report.results.find(k);
    if (!r) continue;
    if (e.truth === 'unreachable') { bucket.tu++; if (r.verdict === 'unreachable') bucket.correct++; }
    if (r.verdict === 'unreachable' && e.truth !== 'unreachable') bucket.falseU.push(`${name} ${e.id} (truth ${e.truth}; LLM symbols: ${(r.affectedSymbols || []).join(', ')})`);
  }
}
for (const [k, label] of [['a', '(a) curated advisories, LLM symbols instead of curated'], ['b', '(b) uncurated advisories, LLM tier promoted']]) {
  const b = exp[k];
  console.log(`  ${label}: ${b.correct} of ${b.tu} truth-unreachable alerts labelled unreachable; false unreachable: ${b.falseU.length}`);
  for (const f of b.falseU) console.log(`    !! ${f}`);
}
console.log('  Phase 2 does not promote LLM data to unreachable regardless of these numbers.');
