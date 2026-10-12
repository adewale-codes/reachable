#!/usr/bin/env node
// Re-records the OSV responses used by the benchmark into bench/osv-cache/.
// With --llm, also records LLM symbol-extraction answers for every fixture
// alert that needs one into bench/llm-cache/ (needs ANTHROPIC_API_KEY).
// Hand-written answers in a fixture's own llm-cache/ are read first and never
// overwritten. Needs network access. The benchmark itself (bench/run.js) runs offline
// against these recordings, so it is deterministic.
//
// Re-recording can change the advisory list (OSV adds and edits advisories),
// in which case expected.json files must be re-labelled by hand.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readInventory } from '../src/inventory.js';
import { OsvClient } from '../src/osv.js';
import { scan } from '../src/scan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(here, 'fixtures');
const cacheDir = path.join(here, 'osv-cache');

const fixtures = fs.readdirSync(fixturesDir).filter((d) => fs.statSync(path.join(fixturesDir, d)).isDirectory()).sort();
const client = new OsvClient({ cacheDir, offline: false });
for (const name of fixtures) {
  const inv = readInventory(path.join(fixturesDir, name));
  const ids = await client.queryPackages(inv.instances.map((i) => ({ name: i.name, version: i.version })));
  await client.getVulns([...ids.values()].flat());
  const lines = inv.instances
    .map((i) => `    ${i.direct ? 'direct    ' : 'transitive'} ${i.name}@${i.version}: ${(ids.get(`${i.name}@${i.version}`) || []).map((v) => v.id).join(' ') || '-'}`);
  console.log(`${name}\n${lines.join('\n')}`);
}
if (client.stats.networkError) {
  console.error(`OSV was not reachable (${client.stats.networkError}); recordings were NOT refreshed.`);
  process.exitCode = 2;
} else {
  console.log(`\nrecorded into ${path.relative(process.cwd(), cacheDir)}: ${client.stats.queriesFromNetwork} package queries, ${client.stats.vulnsFromNetwork} advisory records fetched`);
}

if (process.argv.includes('--llm')) {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('--llm needs ANTHROPIC_API_KEY');
    process.exitCode = 2;
  } else {
    const llmCache = path.join(here, 'llm-cache');
    let calls = 0;
    for (const name of fixtures) {
      const dir = path.join(fixturesDir, name);
      const local = path.join(dir, 'llm-cache');
      const report = await scan(dir, {
        offline: true, cacheDir, llm: 'live', llmCacheDirs: [...(fs.existsSync(local) ? [local] : []), llmCache], llmWriteDir: llmCache,
      });
      calls += report.llm.calls || 0;
      const failed = report.results.filter((r) => r.reasons.some((x) => x.code === 'llm_unavailable' || x.code === 'llm_invalid_output'));
      for (const r of failed) console.error(`  ${name}: ${r.id} ${r.reasons.map((x) => x.code).join(', ')}`);
    }
    console.log(`LLM answers: ${calls} new API call(s), stored in ${path.relative(process.cwd(), llmCache)}`);
  }
}
