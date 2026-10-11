// Orchestrates one scan: inventory -> usage -> advisories -> verdicts.

import fs from 'node:fs';
import path from 'node:path';
import { readInventory } from './inventory.js';
import { OsvClient } from './osv.js';
import { extractUsage } from './usage.js';
import { computeVerdicts, loadAdvisoryData } from './verdict.js';
import { ScanError } from './errors.js';

const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
export const VERSION = pkg.version;

/**
 * @param {string} projectDir
 * @param {{ offline?: boolean, cacheDir?: string, osvUrl?: string, dataPath?: string, fetchImpl?: Function }} [opts]
 * @returns report object (see README "JSON output"). Throws ScanError when the scan cannot run at all.
 */
export async function scan(projectDir, opts = {}) {
  const root = path.resolve(projectDir);
  let stat;
  try {
    stat = fs.statSync(root);
  } catch {
    throw new ScanError(`project path does not exist: ${root}`, 'bad_path');
  }
  if (!stat.isDirectory()) throw new ScanError(`project path is not a directory: ${root}`, 'bad_path');

  const inventory = readInventory(root);
  const data = loadAdvisoryData(opts.dataPath);

  const tracked = new Set([...inventory.directNames, ...inventory.topLevelNames]);
  const usage = await extractUsage(root, { tracked, packageJson: inventory.packageJson });

  const osv = new OsvClient({ cacheDir: opts.cacheDir, offline: opts.offline, baseUrl: opts.osvUrl, fetchImpl: opts.fetchImpl });
  const vulnIds = await osv.queryPackages(inventory.instances.map((i) => ({ name: i.name, version: i.version })));
  const refs = [...vulnIds.values()].flat();
  const vulnDetails = await osv.getVulns(refs);

  const { results, withdrawn } = computeVerdicts({ inventory, vulnIds, vulnDetails, usage, data });

  const errors = [
    ...inventory.errors,
    ...usage.parseErrors.map((e) => ({ code: 'parse_error', message: `${e.file}${e.line ? `:${e.line}` : ''}: ${e.message}${e.text ? ` (${e.text})` : ''}` })),
    ...usage.fileErrors.map((e) => ({ code: 'file_unreadable', message: `${e.file}: ${e.message}` })),
  ];
  const warnings = [...inventory.warnings, ...usage.warnings];
  if (osv.stats.networkError) {
    warnings.push(`OSV could not be reached (${osv.stats.networkError}); advisory data came from the local cache` +
      `${osv.stats.oldestCacheEntry ? ` (oldest entry fetched ${osv.stats.oldestCacheEntry})` : ''}. Advisories published since then are missing.`);
  }

  const unknown = new Map();
  for (const u of usage.unknownImports) if (!unknown.has(u.specifier)) unknown.set(u.specifier, u);

  const summary = { alerts: results.length, reachable: 0, unreachable: 0, cant_tell: 0 };
  for (const r of results) summary[r.verdict]++;

  return {
    tool: { name: 'reachable', version: VERSION },
    project: { path: root, name: inventory.projectName },
    scannedAt: new Date().toISOString(),
    complete: errors.length === 0,
    errors,
    warnings,
    summary,
    inventory: {
      lockfileVersion: inventory.lockfileVersion,
      installed: inventory.instances.length,
      direct: inventory.instances.filter((i) => i.direct).length,
      transitive: inventory.instances.filter((i) => !i.direct).length,
    },
    source: { filesScanned: usage.filesScanned, parseErrors: usage.parseErrors.length },
    osv: { ...osv.stats, cacheDir: osv.cacheDir, url: osv.baseUrl },
    unresolvedImports: [...unknown.values()].map(({ specifier, file, line }) => ({ specifier, file, line })),
    withdrawn,
    results,
  };
}

/** 2 = scan incomplete, 1 = something reachable (or cant_tell with strict), 0 = otherwise. */
export function exitCodeFor(report, { strict = false } = {}) {
  if (!report.complete) return 2;
  if (report.summary.reachable > 0) return 1;
  if (strict && report.summary.cant_tell > 0) return 1;
  return 0;
}
