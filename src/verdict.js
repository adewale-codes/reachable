// Verdict engine. One verdict per (advisory, installed package instance):
//
//   reachable    the project's own code references an affected symbol
//   unreachable  ONLY when every condition for proof holds (see decideAlert)
//   cant_tell    everything else, always with machine-readable reason codes
//
// `unreachable` is never a default: it is returned only when the list of
// reasons to doubt it is empty.
//
// Model (Phase 2): an installed instance can be loaded by the project's code
// and by other installed packages (its "loaders": declared dependents plus
// packages found requiring it without declaring it). Every loader is an edge.
// The project edge can prove `reachable`. A package edge can only pass or
// raise doubt: a dependency that uses the affected function is reported as
// cant_tell / transitive_parent_uses_symbol, never reachable, because we do
// not yet know whether the project reaches that code (Phase 3).
//
// Trust tiers: curated symbol data may produce any verdict. LLM-extracted
// data may produce reachable or cant_tell, NEVER unreachable (enforced at the
// end of decideAlert, after every other rule).

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

export const DEFAULT_DATA_PATH = fileURLToPath(new URL('../data/advisories.json', import.meta.url));

export function loadAdvisoryData(file = DEFAULT_DATA_PATH) {
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  return { packages: data.packages || {}, advisories: data.advisories || {}, excluded: data.excluded || {} };
}

const where = (c) => c.where || 'the project';

// Order = priority when picking the primary reason.
export const REASONS = {
  transitive_not_analysed: (c) => `${c.pkg} is only a transitive dependency${c.requiredBy ? ` (required by ${c.requiredBy})` : ''}. Transitive analysis is turned off for this scan.`,
  transitive_parent_uses_symbol: (c) => `A package that loads ${c.pkg} references ${c.symbols}. Whether your code reaches that part of the package is not analysed yet, so this is not reported as reachable.`,
  no_symbol_data: (c) => `There is no curated record of which ${c.pkg} functions this advisory affects, so usage cannot be matched against it.${c.excluded ? ` (Left out on purpose: ${c.excluded})` : ''}${c.llmNote ? ` LLM: ${c.llmNote.replace(/^LLM extraction /, '')}.` : ''}`,
  llm_unavailable: (c) => `LLM symbol extraction did not run for this advisory (${c.detail || 'no response'}).`,
  llm_invalid_output: (c) => `The LLM's answer for this advisory did not match the required schema and was rejected (${c.detail || 'invalid'}).`,
  llm_no_specific_api: () => 'The LLM read the advisory as not naming a specific function of the package.',
  llm_no_valid_symbols: (c) => `Every symbol the LLM proposed was rejected by the guard (${c.detail || 'see dropped'}).`,
  node_modules_missing: (c) => `node_modules is not installed, so the packages that load ${c.pkg} could not be inspected. Run npm ci and scan again.`,
  parent_not_installed: (c) => `A package that loads ${c.pkg} is in the lockfile but not in node_modules.`,
  node_modules_out_of_sync: () => 'The version installed in node_modules differs from package-lock.json, so the installed code is not the locked code. Run npm ci.',
  parent_unparseable: (c) => `Code in a package that loads ${c.pkg} could not be parsed (minified, bundled, very large or unsupported syntax), so its use of ${c.pkg} is unknown.`,
  parse_error: () => 'Some source files of the project could not be parsed completely. Code in them may use the affected function.',
  file_unreadable: () => 'Some source files could not be read. Code in them may use the affected function.',
  used_by_script: (c) => `${c.pkg} is referenced by an npm script, a bin entry or a config file at the project root, so tooling may load and run it outside the scanned source.`,
  declared_unused: (c) => `${c.pkg} is a direct dependency but nothing in the scanned source, npm scripts or root config files refers to it${c.typeOnly ? ' (only type-only imports were found)' : ''}. That is not proof: it may be loaded by a file type or tool that was not checked.`,
  module_escapes: (c) => `In ${where(c)}, the ${c.pkg} module object is handed to code this analysis does not follow (passed, returned, exported or stored), so the receiving code could call ${c.symbols}.`,
  dynamic_member_access: (c) => `In ${where(c)}, ${c.pkg} is indexed with a computed key (like lib[name]); the key could name ${c.symbols}.`,
  gateway_used: (c) => `In ${where(c)}, a ${c.pkg} call that returns an object exposing the package's other functions is used (for example a chain wrapper), so later calls on it could reach ${c.symbols}.`,
  indirect_reference: (c) => `In ${where(c)}, a property named like an affected function (${c.symbols}) is read from a value obtained through ${c.pkg}.`,
  other_entry_point: (c) => `According to the advisory data the affected function${c.modules ? ` lives in ${c.modules}` : ''}, but ${c.pkg} is loaded through a different entry point here. A same-named function elsewhere is not proof of use, and other entry points may share the vulnerable code, so this is neither reachable nor proven unreachable.`,
  unmapped_subpath: (c) => `In ${where(c)}, ${c.pkg} is loaded through a deep import path with no mapping to the package's exports.`,
  dynamic_subpath: (c) => `In ${where(c)}, a computed deep path inside ${c.pkg} is loaded at run time.`,
  dynamic_import_promise: (c) => `In ${where(c)}, import('${c.pkg}') is not directly awaited; the module flows through a promise this analysis does not follow.`,
  reexport_all: (c) => `In ${where(c)}, export * from '${c.pkg}' re-exports every function in the package, including ${c.symbols}.`,
  alias_config: (c) => `In ${where(c)}, a path-alias configuration maps an alias onto ${c.pkg}; imports through that alias are not tracked.`,
  name_as_string: (c) => `In ${where(c)}, the name '${c.pkg}' appears as a string outside an import, so it may be loaded indirectly (bundler alias, plugin loader, mock, config).`,
  dynamic_require: (c) => `In ${where(c)}, require() is called with a non-literal argument, so it could load ${c.pkg}.`,
  dynamic_import: (c) => `In ${where(c)}, import() is called with a non-literal argument, so it could load ${c.pkg}.`,
  require_escapes: (c) => `In ${where(c)}, the require function itself is aliased or passed around, so some module loads may be hidden.`,
  eval_present: (c) => `In ${where(c)}, eval, new Function, a string timer or the vm module is used; code built at run time could call the affected function.`,
  llm_tier_cannot_prove_unreachable: () => 'The affected functions come from LLM extraction, which may have missed one. LLM-sourced data can show a call is reachable but is never allowed to prove unreachable.',
};
const REASON_ORDER = Object.keys(REASONS);
const MAX_LOCATIONS = 10;

function stripExt(s) {
  return s.replace(/\.(c|m)?js$/, '');
}

/** 'non-secure/index.js' -> 'non-secure'; '' -> null. */
export function normalizeSubpath(sub) {
  if (!sub) return null;
  const s = String(sub).replace(/^\.\//, '').replace(/\/+$/, '').replace(/\.(c|m)?js$/, '').replace(/\/index$/, '');
  return s || null;
}

/**
 * Affected symbols, split by entry point. A symbol is either a bare name (it
 * applies to every entry point of the package, the conservative default) or
 * { symbol, module } where module names a deep entry point such as
 * 'nanoid/non-secure'. A module equal to the bare package name counts as unqualified.
 */
export function symbolSpec(symbols, pkg) {
  const any = new Set();
  const byModule = new Map();
  for (const s of symbols) {
    const name = typeof s === 'string' ? s : s.symbol;
    const mod = typeof s === 'string' ? null : s.module;
    const sub = mod && mod.startsWith(`${pkg}/`) ? normalizeSubpath(mod.slice(pkg.length + 1)) : null;
    if (!sub) { any.add(name); continue; }
    if (!byModule.has(sub)) byModule.set(sub, new Set());
    byModule.get(sub).add(name);
  }
  return { any, byModule };
}

/** Map a deep import ('lodash/fp/merge') onto export steps, if the package's data allows it. */
export function resolveSubpath(subpath, rules) {
  if (!subpath) return { ok: true, prefix: [] };
  const sp = rules && rules.subpaths;
  if (!sp || sp.mode !== 'export-per-file') return { ok: false };
  const segs = subpath.split('/').filter(Boolean).map(stripExt);
  if (segs.length === 0) return { ok: true, prefix: [] };
  if (segs.length === 1 && (sp.moduleAliases || []).includes(segs[0])) return { ok: true, prefix: [] };
  if (sp.privatePrefix && segs.some((s) => s.startsWith(sp.privatePrefix))) return { ok: false };
  return { ok: true, prefix: segs.map((name) => ({ t: 'prop', name })) };
}

/**
 * Classify one use of a package value against a set of affected symbols.
 * @param steps  [{t:'prop',name}|{t:'call'}] starting from the package's main export
 * @param S      Set of affected symbols ('(module)' = calling the main export)
 * @param G      Set of gateway exports for the package
 * @param end    how the value was last used: harmless|binding|alias|escape|dynamic
 */
export function classify(steps, S, G, end) {
  let i = steps.length && steps[0].t === 'prop' && steps[0].name === 'default' ? 1 : 0;
  let state = 'module';
  let via = null;
  for (; i < steps.length; i++) {
    const s = steps[i];
    if (state === 'module') {
      const callsModule = s.t === 'call' || ['call', 'apply', 'bind'].includes(s.name);
      if (callsModule) {
        if (S.has('(module)')) return { kind: 'affected', symbol: '(module)' };
        state = 'gateway'; via = 'calling the module itself';
      } else if (S.has(s.name)) {
        return { kind: 'affected', symbol: s.name };
      } else if (G.has(s.name)) {
        state = 'gateway'; via = s.name;
      } else {
        state = 'export'; via = s.name;
      }
    } else if (s.t === 'prop' && S.has(s.name)) {
      if (state === 'gateway') return { kind: 'affected', symbol: s.name, via };
      return { kind: 'indirect', symbol: s.name, via };
    }
  }
  if (end === 'dynamic') return state === 'export' ? { kind: 'none' } : { kind: 'dynamic' };
  if (state === 'gateway') return { kind: 'gateway', via };
  if (state === 'module' && end === 'escape') return { kind: 'escape' };
  return { kind: 'none' };
}

function locKey(l) {
  return `${l.file}:${l.line}`;
}

export function symbolList(symbols) {
  return symbols.map((s) => (s === '(module)' ? 'the main export (called directly)' : s)).join(', ');
}

/** Group package-scoped usage facts by install name once. */
export function indexUsage(usage) {
  const byPkg = new Map();
  const get = (pkg) => {
    if (!byPkg.has(pkg)) byPkg.set(pkg, { imports: [], uses: [], unresolved: [], typeImports: [] });
    return byPkg.get(pkg);
  };
  for (const x of usage.imports) get(x.pkg).imports.push(x);
  for (const x of usage.uses) get(x.pkg).uses.push(x);
  for (const x of usage.unresolved) get(x.pkg).unresolved.push(x);
  for (const x of usage.typeImports || []) get(x.pkg).typeImports.push(x);
  return { byPkg, empty: { imports: [], uses: [], unresolved: [], typeImports: [] } };
}

/**
 * Phase 1 analysis of how one body of code (the project, or one installed
 * package) uses one package, for one set of affected symbols.
 * @returns {{ kind: 'reachable', references } | { kind: 'clean', importSites, importCount, usesChecked }
 *          | { kind: 'not_imported', typeOnly } | { kind: 'doubt', doubts: [{code, location}] }}
 */
export function analyzeUse({ installName, S, spec: specIn = null, rules, usageIndex, usage }) {
  // S (a Set of bare names) is the pre-subpath form; spec splits symbols by entry point.
  const spec = specIn || { any: S, byModule: new Map() };
  const G = new Set((rules && rules.gateways) || []);
  const qualifiedNames = new Set([...spec.byModule.values()].flatMap((x) => [...x]));
  const modulesText = [...spec.byModule.keys()].map((m) => `'${installName}/${m}'`).join(', ');
  const facts = usageIndex.byPkg.get(installName) || usageIndex.empty;
  const doubts = [];
  const doubt = (code, l) => doubts.push({ code, location: l ? { file: l.file, line: l.line, text: l.text, detail: l.detail } : null });

  const affected = [];
  for (const imp of facts.imports) {
    const key = normalizeSubpath(imp.subpath);
    const qualified = key !== null && spec.byModule.has(key);
    // Subpath-qualified data never proves anything about OTHER entry points.
    if (spec.byModule.size && !qualified) doubt('other_entry_point', { ...imp, detail: `loaded as '${installName}${imp.subpath ? `/${imp.subpath}` : ''}'; advisory names ${modulesText}` });
    if (!resolveSubpath(imp.subpath, rules).ok && !(qualified && spec.any.size === 0)) doubt('unmapped_subpath', { ...imp, detail: `'${installName}/${imp.subpath}'` });
  }
  for (const use of facts.uses) {
    const at = { file: use.file, line: use.line, text: use.text };
    const key = normalizeSubpath(use.subpath);
    if (key !== null && spec.byModule.has(key)) {
      // The use comes through exactly the entry point the advisory names.
      const q = classify(use.steps, spec.byModule.get(key), new Set(), use.end);
      if (q.kind === 'affected') { affected.push({ symbol: q.symbol, use, via: q.via, module: `${installName}/${key}` }); continue; }
    }
    const r = resolveSubpath(use.subpath, rules);
    if (!r.ok) continue; // already reported as unmapped_subpath (or handled above)
    const steps = [...r.prefix, ...use.steps];
    if (qualifiedNames.size && !(key !== null && spec.byModule.has(key))) {
      const o = classify(steps, qualifiedNames, G, use.end);
      if (o.kind === 'affected') doubt('other_entry_point', { ...at, detail: `${o.symbol} here comes from '${installName}${use.subpath ? `/${use.subpath}` : ''}', not ${modulesText}` });
    }
    const c = spec.any.size ? classify(steps, spec.any, G, use.end) : classify(steps, new Set(), G, use.end);
    switch (c.kind) {
      case 'affected': affected.push({ symbol: c.symbol, use, via: c.via }); break;
      case 'escape': doubt('module_escapes', { ...at, detail: use.endDesc }); break;
      case 'dynamic': doubt('dynamic_member_access', { ...at, detail: use.endDesc }); break;
      case 'gateway': doubt('gateway_used', { ...at, detail: `via ${c.via}` }); break;
      case 'indirect': doubt('indirect_reference', { ...at, detail: `.${c.symbol} read on the result of ${c.via}` }); break;
      default: break;
    }
  }

  if (affected.length) {
    const seen = new Set();
    const evidence = [];
    for (const a of affected) {
      const chain = [];
      for (const s of [...a.use.trail, { file: a.use.file, line: a.use.line, text: a.use.text }]) {
        if (!chain.length || locKey(chain[chain.length - 1]) !== locKey(s)) chain.push({ file: s.file, line: s.line, text: s.text });
      }
      const k = `${a.symbol}@${locKey(chain[chain.length - 1])}`;
      if (seen.has(k)) continue;
      seen.add(k);
      evidence.push({ symbol: a.symbol, via: a.via || null, ...(a.module ? { module: a.module } : {}), chain });
    }
    // Drop chains that are a prefix of a longer chain for the same symbol.
    const sig = (e) => e.chain.map(locKey).join('>');
    const maximal = evidence.filter((e) => !evidence.some((o) => o !== e && o.symbol === e.symbol &&
      o.chain.length > e.chain.length && sig(o).startsWith(sig(e) + '>')));
    maximal.sort((x, y) => y.chain.length - x.chain.length);
    return { kind: 'reachable', references: maximal };
  }

  for (const u of facts.unresolved) doubt(u.code, u);
  for (const g of usage.global) doubt(g.code, g);
  for (const e of usage.parseErrors) doubt('parse_error', { ...e, detail: e.message });
  for (const e of usage.fileErrors || []) doubt('file_unreadable', { file: e.file, line: null, text: '', detail: e.message });

  if (facts.imports.length === 0) {
    // Not loaded statically. Any doubt (dynamic require, eval, name as string,
    // unparseable file) still means it might be loaded.
    if (doubts.length) return { kind: 'doubt', doubts };
    return { kind: 'not_imported', typeOnly: facts.typeImports.length > 0 };
  }
  if (doubts.length) return { kind: 'doubt', doubts };

  const importSites = [];
  const seenImports = new Set();
  for (const imp of facts.imports) {
    if (seenImports.has(locKey(imp))) continue;
    seenImports.add(locKey(imp));
    importSites.push({ file: imp.file, line: imp.line, text: imp.text });
  }
  return { kind: 'clean', importSites: importSites.slice(0, 20), importCount: importSites.length, usesChecked: facts.uses.length };
}

/**
 * Decide one alert.
 *
 * @param p.instance      inventory instance (key, name, installName, direct, parentKeys, requiredBy)
 * @param p.symbolInfo    { tier: 'curated', symbols, source }
 *                      | { tier: 'llm', symbols: [{symbol, quote}], model, dropped }
 *                      | { tier: null, reasons: [{code, detail}] }
 * @param p.project       { usageIndex, usage, mentions: {scripts:[], configs:[]} }  (Phase 1 facts)
 * @param p.packageEdges  null (transitive analysis off)
 *                      | { available: false }  (no node_modules)
 *                      | { available: true, loaders: [{ key, label, declared, status, usage, usageIndex, mode }] }
 * @param p.paths         { paths: [[label...]], total, complete } for evidence
 */
export function decideAlert({ advisoryId, instance, data, symbolInfo, project, packageEdges, paths = null }) {
  const pkg = instance.name;
  const reasons = new Map();
  const add = (code, location = null, ctx = {}) => {
    if (!reasons.has(code)) reasons.set(code, { locations: [], seen: new Set(), count: 0, ctx });
    const r = reasons.get(code);
    Object.assign(r.ctx, ctx);
    if (location) {
      const k = `${locKey(location)}:${location.detail || ''}`;
      if (!r.seen.has(k)) { r.seen.add(k); r.count++; r.locations.push(location); }
    }
  };
  const finish = (verdict, evidence = null) => {
    const list = [...reasons.entries()]
      .sort((a, b) => REASON_ORDER.indexOf(a[0]) - REASON_ORDER.indexOf(b[0]))
      .map(([code, r]) => ({
        code,
        message: REASONS[code]({ pkg, ...r.ctx }),
        count: r.count,
        locations: r.locations.slice(0, MAX_LOCATIONS).map(({ file, line, text, detail }) => ({ file, line, text, detail })),
      }));
    return { verdict, reasons: list, evidence };
  };

  // ---- symbol data
  if (!symbolInfo.tier) {
    for (const r of symbolInfo.reasons) add(r.code, null, { excluded: data.excluded[advisoryId] || null, detail: r.detail, llmNote: r.llmNote });
    return finish('cant_tell');
  }
  const tier = symbolInfo.tier;
  const symbolEntries = symbolInfo.symbols; // curated: strings or {symbol, module}; llm: {symbol, quote, module?}
  const symbols = symbolEntries.map((s) => (typeof s === 'string' ? s : s.module && s.module !== pkg ? `${s.symbol} (${s.module})` : s.symbol));
  const spec = symbolSpec(symbolEntries, pkg);
  const S = spec.any;
  const rules = data.packages[pkg] || {};
  const ctx = { symbols: symbolList(symbols), modules: [...spec.byModule.keys()].map((m) => `'${pkg}/${m}'`).join(', ') || null };
  const quoteFor = (sym) => (tier === 'llm' ? (symbolInfo.symbols.find((s) => s.symbol === sym) || {}).quote : null);

  // ---- project edge: the developer's own code
  const topLevel = instance.key === `node_modules/${instance.installName}`;
  const projectFacts = project.usageIndex.byPkg.get(instance.installName);
  const projectLoads = instance.direct || (topLevel && projectFacts && projectFacts.imports.length > 0);
  let projectEvidence = null;
  if (projectLoads) {
    const r = analyzeUse({ installName: instance.installName, S, spec, rules, usageIndex: project.usageIndex, usage: project.usage });
    if (r.kind === 'reachable') {
      return finish('reachable', {
        tier,
        references: r.references.slice(0, 20).map((ref) => ({ ...ref, source: tier, quote: quoteFor(ref.symbol) })),
        referenceCount: r.references.length,
        ...(tier === 'llm' ? { model: symbolInfo.model } : {}),
      });
    }
    if (r.kind === 'doubt') r.doubts.forEach((d) => add(d.code, d.location, ctx));
    const mentioned = project.mentions.scripts.length || project.mentions.configs.length;
    if (r.kind === 'not_imported' && !mentioned) add('declared_unused', null, { ...ctx, typeOnly: r.typeOnly });
    if (r.kind === 'clean') projectEvidence = r;
  }
  // A package run by an npm script, named in the project's bin, or named in a
  // root config file is loaded by tooling, whether or not the code imports it.
  for (const l of [...project.mentions.scripts, ...project.mentions.configs]) add('used_by_script', l, ctx);

  // ---- LLM tier: can only ever be reachable (above) or cant_tell.
  if (tier === 'llm') {
    add('llm_tier_cannot_prove_unreachable');
    return finish('cant_tell');
  }

  // ---- package edges: every other installed package that loads this instance
  const edgeSummaries = [];
  // Declared dependents always require loader analysis. When loaders were
  // analysed anyway (node_modules present), every one of them counts, including
  // packages that load a direct dependency without declaring it.
  const needEdges = !instance.direct || instance.parentKeys.length > 0;
  if (needEdges || (packageEdges && packageEdges.available)) {
    if (packageEdges === null) {
      add('transitive_not_analysed', null, { requiredBy: instance.requiredBy.join(', ') || null });
    } else if (!packageEdges.available) {
      add('node_modules_missing', null);
    } else {
      for (const L of packageEdges.loaders) {
        const lctx = { ...ctx, where: L.label };
        if (L.status === 'missing') { add('parent_not_installed', { file: L.key, line: null, text: '', detail: L.label }, lctx); continue; }
        if (L.status === 'out_of_sync') { add('node_modules_out_of_sync', { file: `${L.key}/package.json`, line: null, text: '', detail: L.detail }, lctx); continue; }
        const r = analyzeUse({ installName: instance.installName, S, spec, rules, usageIndex: L.usageIndex, usage: L.usage });
        // Report unparseable code even when the parsed part already shows a use.
        for (const e of L.usage.parseErrors) add('parent_unparseable', { file: e.file, line: e.line, text: e.text, detail: e.message }, lctx);
        if (r.kind === 'reachable') {
          for (const ref of r.references.slice(0, 5)) {
            // chain = [import, reference, later uses of the result...]: point at the reference.
            const at = ref.chain[Math.min(1, ref.chain.length - 1)];
            add('transitive_parent_uses_symbol', { ...at, detail: `${L.label} uses ${ref.symbol}` }, ctx);
          }
          edgeSummaries.push({ loader: L.label, declared: L.declared, result: 'uses affected symbol' });
        } else if (r.kind === 'doubt') {
          for (const d of r.doubts) add(d.code === 'parse_error' || d.code === 'file_unreadable' ? 'parent_unparseable' : d.code, d.location, lctx);
          edgeSummaries.push({ loader: L.label, declared: L.declared, result: `doubt: ${[...new Set(r.doubts.map((d) => d.code))].join(', ')}` });
        } else if (r.kind === 'not_imported') {
          edgeSummaries.push({ loader: L.label, declared: L.declared, mode: L.mode, result: `never loads ${instance.installName} in the files that can run (${L.mode})` });
        } else {
          edgeSummaries.push({ loader: L.label, declared: L.declared, mode: L.mode, result: `imports ${instance.installName} at ${r.importSites.slice(0, 3).map(locKey).join(', ')}; ${r.usesChecked} uses checked, none affected` });
        }
      }
    }
  }

  if (reasons.size) return finish('cant_tell', edgeSummaries.length ? { tier, loaders: edgeSummaries, paths } : null);

  // Every condition for "unreachable" holds for every loader.
  return finish('unreachable', {
    tier,
    symbols,
    importSites: projectEvidence ? projectEvidence.importSites : [],
    importCount: projectEvidence ? projectEvidence.importCount : 0,
    usesChecked: projectEvidence ? projectEvidence.usesChecked : 0,
    loaders: edgeSummaries,
    paths,
  });
}

/** Phase 1 compatible wrapper: a direct dependency analysed from the project's code only. */
export function decide({ advisoryId, instance, data, usageIndex, usage, mentions = { scripts: [], configs: [] }, symbolInfo = null }) {
  const entry = data.advisories[advisoryId];
  const info = symbolInfo || (entry && entry.package === instance.name
    ? { tier: 'curated', symbols: entry.symbols, source: entry.source }
    : { tier: null, reasons: [{ code: 'no_symbol_data' }] });
  const packageEdges = instance.direct && !(instance.parentKeys || []).length ? { available: true, loaders: [] } : null;
  return decideAlert({
    advisoryId, instance: { parentKeys: [], requiredBy: [], key: `node_modules/${instance.installName}`, ...instance }, data, symbolInfo: info,
    project: { usageIndex, usage, mentions }, packageEdges,
  });
}
