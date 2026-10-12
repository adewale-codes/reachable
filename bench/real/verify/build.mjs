// Merges hand-verification files into bench/real/verified.json and checks
// coverage: every reachable/unreachable verdict in bench/real/results must
// have exactly one entry.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const proj = path.resolve(here, '..', '..', '..');
const entries = [];
const spotChecks = [];
const changes = [];
for (const f of fs.readdirSync(here).filter((x) => /^\d.*\.mjs$/.test(x)).sort()) {
  const m = await import(pathToFileURL(path.join(here, f)).href);
  entries.push(...m.entries);
  spotChecks.push(...m.spotChecks);
  if (m.changes) changes.push(...m.changes);
}

const corpus = JSON.parse(fs.readFileSync(`${proj}/bench/real/corpus.json`, 'utf8')).repos;
const perRepo = [];
const missing = [];
const matched = new Set();
let totalAlerts = 0; let totalCant = 0;
for (const c of corpus) {
  const file = `${proj}/bench/real/results/${c.repo.replace('/', '__')}.json`;
  if (!fs.existsSync(file)) { perRepo.push({ repo: c.repo, sha: c.sha, style: c.style, scanned: false }); continue; }
  const { meta, report } = JSON.parse(fs.readFileSync(file, 'utf8'));
  totalAlerts += report.summary.alerts; totalCant += report.summary.cant_tell;
  for (const r of report.results.filter((x) => x.verdict !== 'cant_tell')) {
    const pkg = `${r.package}@${r.version}`;
    const cands = entries.filter((e) => e.repo === c.repo && e.advisory === r.id && e.package === pkg && e.verdict === r.verdict &&
      (!e.instance || e.instance === r.lockfilePath));
    if (cands.length !== 1) missing.push(`${c.repo} ${r.id} ${pkg} ${r.lockfilePath} ${r.verdict} (matches: ${cands.length})`);
    else matched.add(cands[0]);
  }
  const sc = spotChecks.find((s) => s.repo === c.repo);
  perRepo.push({ repo: c.repo, sha: c.sha, style: c.style, summary: report.summary, cantTellRate: +(report.summary.cant_tell / Math.max(1, report.summary.alerts)).toFixed(3),
    npmCi: meta.npmCi ? meta.npmCi.ok : null, cantTellSpotCheck: sc || null });
}
const orphan = entries.filter((e) => !matched.has(e));
const count = (pred) => entries.filter(pred).length;
const summary = {
  verifiedVerdicts: entries.length,
  reachable: { total: count((e) => e.verdict === 'reachable'), correct: count((e) => e.verdict === 'reachable' && e.judgement === 'correct'),
    correctButNotExploitable: count((e) => e.verdict === 'reachable' && e.judgement === 'correct-but-not-exploitable'), wrong: count((e) => e.verdict === 'reachable' && e.judgement === 'wrong') },
  unreachable: { total: count((e) => e.verdict === 'unreachable'), correct: count((e) => e.verdict === 'unreachable' && e.judgement === 'correct'), wrong: count((e) => e.verdict === 'unreachable' && e.judgement === 'wrong') },
  byTier: { curated: count((e) => e.tier === 'curated'), llm: count((e) => e.tier === 'llm'), llmWrong: count((e) => e.tier === 'llm' && e.judgement === 'wrong') },
  cantTellSpotChecks: { checked: spotChecks.reduce((s, x) => s + x.checked, 0), of: spotChecks.reduce((s, x) => s + x.of, 0), untruthful: spotChecks.reduce((s, x) => s + x.untruthful, 0) },
  alerts: totalAlerts, cantTell: totalCant, cantTellRate: +(totalCant / Math.max(1, totalAlerts)).toFixed(3),
};
const out = {
  description: 'Hand verification of every reachable and unreachable verdict in the Phase 3 real-repo corpus (bench/real/results), plus a >=20% spot check of cant_tell reason codes per repo. judgement: correct | wrong | correct-but-not-exploitable. This is what was checked by reading the code; it is not an accuracy rate.',
  verifiedOn: '2026-10-12',
  summary, changesFromPrepublishFixes: changes, repos: perRepo, entries: entries.map(({ instance, ...e }) => ({ ...e, ...(instance ? { instance } : {}) })),
};
fs.writeFileSync(`${proj}/bench/real/verified.json`, JSON.stringify(out, null, 2) + '\n');
console.log(JSON.stringify(summary, null, 2));
console.log(`coverage: ${missing.length} unverified verdicts, ${orphan.length} entries with no matching verdict`);
missing.forEach((m) => console.log('  MISSING', m));
orphan.forEach((o) => console.log('  ORPHAN', o.repo, o.advisory, o.package, o.verdict));
