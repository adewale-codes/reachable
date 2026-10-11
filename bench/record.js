#!/usr/bin/env node
// Re-records the OSV responses used by the benchmark into bench/osv-cache/.
// Needs network access. The benchmark itself (bench/run.js) runs offline
// against these recordings, so it is deterministic.
//
// Re-recording can change the advisory list (OSV adds and edits advisories),
// in which case expected.json files must be re-labelled by hand.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readInventory } from '../src/inventory.js';
import { OsvClient } from '../src/osv.js';

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
