// Orchestrates one scan: inventory -> usage -> advisories -> symbol data
// (curated or LLM) -> loader analysis in node_modules -> verdicts.

import fs from 'node:fs';
import path from 'node:path';
import { readInventory } from './inventory.js';
import { OsvClient, defaultCacheDir } from './osv.js';
import { extractUsage } from './usage.js';
import { decideAlert, indexUsage, loadAdvisoryData } from './verdict.js';
import { PackageAnalyzer } from './transitive.js';
import { buildMentionIndex } from './mentions.js';
import { LlmExtractor, toSymbolInfo, DEFAULT_LLM_MODEL } from './llm.js';
import { readExports, binNames } from './packages.js';
import { createParser } from './parser.js';
import { ScanError } from './errors.js';
import { PackageCache, ANALYZER_VERSION } from './pkgcache.js';

const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
export const VERSION = pkg.version;

/**
 * @param {string} projectDir
 * @param {object} [opts]
 * @param {boolean} [opts.offline]        OSV from cache only
 * @param {string}  [opts.cacheDir]       OSV cache dir (LLM cache defaults to <cacheDir>/llm)
 * @param {'auto'|'live'|'cache'|'off'} [opts.llm]  auto = live when ANTHROPIC_API_KEY is set, else off
 * @param {string[]} [opts.llmCacheDirs]  LLM cache dirs searched in order
 * @param {boolean} [opts.transitive]     analyse loaders in node_modules (default true)
 * @param {boolean} [opts.prodOnly]       hide dev-only alerts (never changes a verdict)
 * @param {string|false} [opts.pkgCacheDir] per-package analysis cache (default <user cache>/packages; false = off)
 * @param {number}  [opts.concurrency]    packages analysed at once
 * @param {function} [opts.onProgress]   (message) => void, for long scans
 * @param {boolean} [opts.phase1Baseline] reproduce Phase 1 verdict rules (benchmark comparison only)
 * @param {object}  [opts.experiment]     MEASUREMENT ONLY, used by bench/extraction-eval.js, never by the CLI:
 *        { curatedOverride(id, pkg) -> symbols[]|undefined, promoteLlm: boolean }. Promoting LLM data to the
 *        curated tier is exactly what Phase 2 forbids; the eval uses it to measure what promotion would do.
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

  const baseline = Boolean(opts.phase1Baseline);
  const transitive = !baseline && opts.transitive !== false;
  const inventory = readInventory(root);
  const data = loadAdvisoryData(opts.dataPath);

  const tracked = new Set([...inventory.directNames, ...inventory.topLevelNames]);
  const usage = await extractUsage(root, { tracked, packageJson: inventory.packageJson });
  const projectIndex = indexUsage(usage);

  const cacheDir = opts.cacheDir || defaultCacheDir();
  const osv = new OsvClient({ cacheDir, offline: opts.offline, baseUrl: opts.osvUrl, fetchImpl: opts.fetchImpl });
  const vulnIds = await osv.queryPackages(inventory.instances.map((i) => ({ name: i.name, version: i.version })));
  const vulnDetails = await osv.getVulns([...vulnIds.values()].flat());

  // ---- LLM tier setup
  const apiKey = opts.apiKey !== undefined ? opts.apiKey : (process.env.ANTHROPIC_API_KEY || null);
  let llmMode = baseline ? 'off' : (opts.llm || 'auto');
  // auto: live when a key is set (recorded answers only under --offline), otherwise off.
  if (llmMode === 'auto') llmMode = apiKey ? (opts.offline ? 'cache' : 'live') : 'off';
  const llm = llmMode === 'off' ? null : new LlmExtractor({
    mode: llmMode, apiKey, model: opts.llmModel || process.env.REACHABLE_LLM_MODEL || DEFAULT_LLM_MODEL,
    readDirs: opts.llmCacheDirs || [path.join(cacheDir, 'llm')], writeDir: opts.llmWriteDir,
  });
  const notices = [];
  if (!llm) {
    notices.push(baseline ? 'Phase 1 baseline mode.' : (opts.llm === 'off'
      ? 'LLM symbol extraction is off (--no-llm): advisories without curated data stay cant_tell / no_symbol_data.'
      : 'LLM symbol extraction is off because ANTHROPIC_API_KEY is not set: advisories without curated data stay cant_tell / no_symbol_data.'));
  } else if (llmMode === 'cache') {
    notices.push('LLM symbol extraction uses recorded responses only (no API calls).');
  }

  // ---- collect alerts
  const alerts = [];
  const withdrawn = [];
  for (const instance of inventory.instances) {
    for (const ref of vulnIds.get(`${instance.name}@${instance.version}`) || []) {
      const vuln = vulnDetails.get(ref.id) || {};
      if (vuln.withdrawn) { withdrawn.push({ id: ref.id, package: instance.name, version: instance.version, withdrawn: vuln.withdrawn }); continue; }
      alerts.push({ instance, id: ref.id, vuln });
    }
  }

  // ---- symbol data per alert
  const parse = await createParser();
  const exportsCache = new Map();
  const exportsOf = (instance) => {
    if (!exportsCache.has(instance.key)) {
      const dir = path.join(root, instance.key);
      exportsCache.set(instance.key, fs.existsSync(path.join(dir, 'package.json')) ? readExports(dir, parse) : { determined: false, why: 'package not installed' });
    }
    return exportsCache.get(instance.key);
  };
  const projectLoads = (inst) => {
    const f = projectIndex.byPkg.get(inst.installName);
    return (inst.direct || inst.key === `node_modules/${inst.installName}`) && Boolean(f && f.imports.length);
  };
  const exp = opts.experiment || null;
  for (const a of alerts) {
    const entry = data.advisories[a.id];
    const override = exp && exp.curatedOverride ? exp.curatedOverride(a.id, a.instance.name) : undefined;
    if (override !== undefined) {
      a.symbolInfo = override.length ? { tier: 'curated', symbols: override, source: 'experiment' } : { tier: null, reasons: [{ code: 'no_symbol_data' }] };
    } else if (entry && entry.package === a.instance.name) {
      a.symbolInfo = { tier: 'curated', symbols: entry.symbols, source: entry.source };
    } else if (llm && projectLoads(a.instance)) {
      const r = await llm.extract({ advisoryId: a.id, pkg: a.instance.name, vuln: a.vuln });
      a.symbolInfo = toSymbolInfo(r, exportsOf(a.instance), a.instance.name);
      if (exp && exp.promoteLlm && a.symbolInfo.tier === 'llm') a.symbolInfo = { tier: 'curated', symbols: a.symbolInfo.symbols.map((x) => x.symbol), source: 'experiment', llm: a.symbolInfo.llm };
    } else {
      a.symbolInfo = { tier: null, reasons: [{ code: 'no_symbol_data', llmNote: llm ? 'LLM extraction skipped: the project does not import this package, so an LLM answer could not change the verdict' : null }] };
    }
  }

  // ---- loaders in node_modules (only where they can change the verdict)
  // Loader analysis can only matter for curated data. A direct dependency with
  // no declared dependents still gets it when node_modules exists, because an
  // installed package may require it without declaring it (hoisting).
  const nodeModules = fs.existsSync(path.join(root, 'node_modules'));
  const needsEdges = (a) => a.symbolInfo.tier === 'curated' && (!a.instance.direct || a.instance.parentKeys.length > 0 || nodeModules);
  const targets = [...new Map(alerts.filter(needsEdges).map((a) => [a.instance.key, a.instance])).values()];
  const mentionsOf = buildMentionIndex(root, inventory.packageJson, usage.externalEntries);
  const scriptsBinUsed = (pj) => binNames(pj).some((b) => mentionsOf(b).scripts.length > 0);
  const pkgCache = opts.pkgCacheDir === false ? null : new PackageCache(opts.pkgCacheDir || path.join(defaultCacheDir(), 'packages'));
  const analyzer = transitive && targets.length
    ? new PackageAnalyzer(root, inventory, targets, { binUsed: scriptsBinUsed, cache: pkgCache, concurrency: opts.concurrency, onProgress: opts.onProgress })
    : null;
  if (analyzer) await analyzer.prepare(targets);
  const edgeCache = new Map();

  const results = [];
  for (const a of alerts) {
    const inst = a.instance;
    const lockEntry = inventory.lockPackages[inst.key] || {};
    const mentions = mentionsOf(inst.installName, lockEntry.bin && typeof lockEntry.bin === 'object' ? Object.keys(lockEntry.bin) : []);
    let packageEdges;
    if (baseline) {
      packageEdges = inst.direct ? { available: true, loaders: [] } : null;
    } else if (!transitive) {
      packageEdges = null;
    } else if (!needsEdges(a)) {
      packageEdges = { available: true, loaders: [] };
    } else {
      if (!edgeCache.has(inst.key)) edgeCache.set(inst.key, await analyzer.edgesFor(inst));
      packageEdges = edgeCache.get(inst.key);
    }
    let paths = null;
    if (!inst.direct) {
      const p = inventory.pathsTo(inst.key, 200);
      paths = { total: p.paths.length, complete: p.complete, sample: p.paths.slice(0, 3).map((x) => x.map(inventory.label)) };
    }
    const d = decideAlert({
      advisoryId: a.id, instance: inst, data, symbolInfo: a.symbolInfo, packageEdges, paths,
      project: { usageIndex: projectIndex, usage, mentions: baseline ? { scripts: [], configs: [] } : mentions },
    });
    const entry = data.advisories[a.id];
    results.push({
      id: a.id,
      aliases: a.vuln.aliases || [],
      summary: a.vuln.summary || (a.vuln.details || '').split('\n')[0].slice(0, 120),
      severity: (a.vuln.database_specific && a.vuln.database_specific.severity) || null,
      url: `https://osv.dev/vulnerability/${a.id}`,
      package: inst.name,
      installName: inst.installName,
      version: inst.version,
      lockfilePath: inst.key,
      direct: inst.direct,
      scope: inst.scope,
      dev: inst.dev,
      symbolTier: a.symbolInfo.tier,
      affectedSymbols: a.symbolInfo.tier === 'curated' ? a.symbolInfo.symbols : a.symbolInfo.tier === 'llm' ? a.symbolInfo.symbols.map((s) => s.symbol) : null,
      symbolSource: a.symbolInfo.tier === 'curated' && entry ? entry.source : a.symbolInfo.tier === 'llm' ? `llm:${a.symbolInfo.model}` : null,
      llm: a.symbolInfo.llm || null,
      verdict: d.verdict,
      reason: d.reasons.length ? d.reasons[0].code : null,
      reasons: d.reasons,
      evidence: d.evidence,
    });
  }
  const rank = { reachable: 0, cant_tell: 1, unreachable: 2 };
  results.sort((x, y) => rank[x.verdict] - rank[y.verdict] || x.package.localeCompare(y.package) ||
    x.version.localeCompare(y.version) || x.id.localeCompare(y.id));

  if (transitive && analyzer && !analyzer.available) {
    notices.push('node_modules is not installed, so packages that load vulnerable dependencies could not be analysed. Run `npm ci` and scan again.');
  }

  const errors = [
    ...inventory.errors,
    ...usage.parseErrors.map((e) => ({ code: 'parse_error', message: `${e.file}${e.line ? `:${e.line}` : ''}: ${e.message}${e.text ? ` (${e.text})` : ''}` })),
    ...usage.fileErrors.map((e) => ({ code: 'file_unreadable', message: `${e.file}: ${e.message}` })),
  ];
  const warnings = [...inventory.warnings, ...usage.warnings, ...(analyzer ? analyzer.warnings : [])];
  if (osv.stats.networkError) {
    warnings.push(`OSV could not be reached (${osv.stats.networkError}); advisory data came from the local cache` +
      `${osv.stats.oldestCacheEntry ? ` (oldest entry fetched ${osv.stats.oldestCacheEntry})` : ''}. Advisories published since then are missing.`);
  }
  const llmFailures = results.filter((r) => r.reasons.some((x) => x.code === 'llm_unavailable' || x.code === 'llm_invalid_output'));
  if (llmFailures.length) warnings.push(`LLM symbol extraction failed for ${llmFailures.length} alert(s); they stay cant_tell (see llm_unavailable / llm_invalid_output).`);

  const unknown = new Map();
  for (const u of usage.unknownImports) if (!unknown.has(u.specifier)) unknown.set(u.specifier, u);

  const shown = opts.prodOnly ? results.filter((r) => r.scope === 'prod') : results;
  const summary = { alerts: shown.length, reachable: 0, unreachable: 0, cant_tell: 0 };
  for (const r of shown) summary[r.verdict]++;
  const scopeCounts = { prod: results.filter((r) => r.scope === 'prod').length, dev: results.filter((r) => r.scope === 'dev').length };

  return {
    tool: { name: 'reachable', version: VERSION },
    project: { path: root, name: inventory.projectName },
    scannedAt: new Date().toISOString(),
    complete: errors.length === 0,
    errors,
    warnings,
    notices,
    summary,
    scopeCounts,
    prodOnly: Boolean(opts.prodOnly),
    hiddenDevAlerts: opts.prodOnly ? results.length - shown.length : 0,
    inventory: {
      lockfileVersion: inventory.lockfileVersion,
      installed: inventory.instances.length,
      direct: inventory.instances.filter((i) => i.direct).length,
      transitive: inventory.instances.filter((i) => !i.direct).length,
      nodeModules: fs.existsSync(path.join(root, 'node_modules')),
    },
    source: { filesScanned: usage.filesScanned, parseErrors: usage.parseErrors.length },
    osv: { ...osv.stats, cacheDir: osv.cacheDir, url: osv.baseUrl },
    llm: llm ? { mode: llmMode, model: llm.model, ...llm.stats } : { mode: 'off' },
    transitiveAnalysis: transitive ? { packagesAnalysed: analyzer ? analyzer.packagesAnalysed : 0, nodeModules: analyzer ? analyzer.available : null, cache: pkgCache ? { dir: pkgCache.dir, ...pkgCache.stats } : 'off' } : { off: true },
    analyzerVersion: ANALYZER_VERSION,
    unresolvedImports: [...unknown.values()].map(({ specifier, file, line }) => ({ specifier, file, line })),
    withdrawn,
    results: shown,
  };
}

/** 2 = scan incomplete, 1 = something reachable (or cant_tell with strict), 0 = otherwise. */
export function exitCodeFor(report, { strict = false } = {}) {
  if (!report.complete) return 2;
  if (report.summary.reachable > 0) return 1;
  if (strict && report.summary.cant_tell > 0) return 1;
  return 0;
}
