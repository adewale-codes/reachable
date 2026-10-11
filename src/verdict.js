// Verdict engine. Combines advisories, curated symbol data and usage facts
// into one verdict per (advisory, installed package instance):
//
//   reachable    a reference to an affected symbol exists in scanned source
//   unreachable  ONLY when every condition for proof holds (see decide())
//   cant_tell    everything else, always with machine-readable reason codes
//
// `unreachable` is never a default: it is returned only when the list of
// reasons to doubt it is empty.

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

export const DEFAULT_DATA_PATH = fileURLToPath(new URL('../data/advisories.json', import.meta.url));

export function loadAdvisoryData(file = DEFAULT_DATA_PATH) {
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  return { packages: data.packages || {}, advisories: data.advisories || {}, excluded: data.excluded || {} };
}

// Order = priority when picking the primary reason.
export const REASONS = {
  transitive_not_analysed: (c) => `${c.pkg} is only a transitive dependency${c.requiredBy ? ` (required by ${c.requiredBy})` : ''}. Phase 1 analyses direct dependencies only, so the code paths that reach it were not checked.`,
  no_symbol_data: (c) => `There is no curated record of which ${c.pkg} functions this advisory affects${c.excluded ? ` (left out on purpose: ${c.excluded})` : ''}, so usage cannot be matched against it.`,
  parse_error: () => 'Some source files could not be parsed completely. Code in them may use the affected function.',
  file_unreadable: () => 'Some source files could not be read. Code in them may use the affected function.',
  no_import_found: (c) => `${c.pkg} is a direct dependency but no scanned source file imports it. It may still be used by its CLI binary, an npm script, a config file or another file that was not scanned.`,
  module_escapes: (c) => `The ${c.pkg} module object is handed to code this analysis does not follow (passed, returned, exported or stored), so the receiving code could call ${c.symbols}.`,
  dynamic_member_access: (c) => `${c.pkg} is indexed with a computed key (like lib[name]); the key could name ${c.symbols}.`,
  gateway_used: (c) => `A ${c.pkg} call that returns an object exposing the package's other functions is used (for example a chain wrapper), so later calls on it could reach ${c.symbols}.`,
  indirect_reference: (c) => `A property named like an affected function (${c.symbols}) is read from a value obtained through ${c.pkg}; the analysis cannot tell whether it is the affected function.`,
  unmapped_subpath: (c) => `${c.pkg} is loaded through a deep import path (like '${c.pkg}/something'), and there is no mapping from that path to the package's exports.`,
  dynamic_subpath: (c) => `A computed deep path inside ${c.pkg} is loaded at run time.`,
  dynamic_import_promise: (c) => `import('${c.pkg}') is not directly awaited; the module flows through a promise that this analysis does not follow.`,
  reexport_all: (c) => `export * from '${c.pkg}' re-exports every function in the package, including ${c.symbols}, to other modules.`,
  alias_config: (c) => `A path-alias configuration maps an alias onto ${c.pkg}; imports through that alias are not tracked.`,
  name_as_string: (c) => `The name '${c.pkg}' appears as a string outside an import. The package may be loaded indirectly (bundler alias, plugin loader, test mock or config).`,
  dynamic_require: () => 'require() is called with a non-literal argument somewhere in the project, so it could load this package.',
  dynamic_import: () => 'import() is called with a non-literal argument somewhere in the project, so it could load this package.',
  require_escapes: () => 'The require function itself is aliased or passed around somewhere in the project, so some module loads may be hidden.',
  eval_present: () => 'eval, new Function, a string timer or the vm module is used somewhere in the project. Code built at run time could call the affected function.',
};
const REASON_ORDER = Object.keys(REASONS);

const MAX_LOCATIONS = 10;

function stripExt(s) {
  return s.replace(/\.(c|m)?js$/, '');
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
 * Classify one use of a package value against an advisory.
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

function symbolList(symbols) {
  return symbols.map((s) => (s === '(module)' ? 'the main export (called directly)' : s)).join(', ');
}

/** Group package-scoped usage facts by install name once. */
export function indexUsage(usage) {
  const byPkg = new Map();
  const get = (pkg) => {
    if (!byPkg.has(pkg)) byPkg.set(pkg, { imports: [], uses: [], unresolved: [] });
    return byPkg.get(pkg);
  };
  for (const x of usage.imports) get(x.pkg).imports.push(x);
  for (const x of usage.uses) get(x.pkg).uses.push(x);
  for (const x of usage.unresolved) get(x.pkg).unresolved.push(x);
  return { byPkg, empty: { imports: [], uses: [], unresolved: [] } };
}

/**
 * Decide the verdict for one advisory on one installed instance.
 * @returns {{ verdict, reasons: {code,message,locations,count}[], evidence }}
 */
export function decide({ advisoryId, instance, data, usageIndex, usage }) {
  const pkg = instance.name;
  const reasons = new Map(); // code -> { locations: [], ctx }
  const add = (code, location, ctx = {}) => {
    if (!reasons.has(code)) reasons.set(code, { locations: [], seen: new Set(), count: 0, ctx });
    const r = reasons.get(code);
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

  if (!instance.direct) {
    add('transitive_not_analysed', null, { requiredBy: instance.requiredBy.join(', ') || null });
    // A hoisted transitive package can still be imported by the project's own
    // code without being declared (a "phantom" dependency). Show where.
    if (instance.key === `node_modules/${instance.installName}`) {
      const facts = usageIndex.byPkg.get(instance.installName);
      for (const imp of (facts && facts.imports) || []) {
        add('transitive_not_analysed', { file: imp.file, line: imp.line, text: imp.text, detail: 'imported by your code, but not declared in package.json' });
      }
    }
    return finish('cant_tell');
  }

  const entry = data.advisories[advisoryId];
  if (!entry || entry.package !== pkg) {
    add('no_symbol_data', null, { excluded: data.excluded[advisoryId] || null });
    return finish('cant_tell');
  }

  const S = new Set(entry.symbols);
  const rules = data.packages[pkg] || {};
  const G = new Set(rules.gateways || []);
  const ctx = { symbols: symbolList(entry.symbols) };
  const facts = usageIndex.byPkg.get(instance.installName) || usageIndex.empty;

  const affected = [];
  for (const imp of facts.imports) {
    if (!resolveSubpath(imp.subpath, rules).ok) {
      add('unmapped_subpath', { ...imp, detail: `'${instance.installName}/${imp.subpath}'` }, ctx);
    }
  }
  for (const use of facts.uses) {
    const r = resolveSubpath(use.subpath, rules);
    if (!r.ok) continue; // already reported as unmapped_subpath
    const c = classify([...r.prefix, ...use.steps], S, G, use.end);
    const where = { file: use.file, line: use.line, text: use.text };
    switch (c.kind) {
      case 'affected': affected.push({ symbol: c.symbol, use, via: c.via }); break;
      case 'escape': add('module_escapes', { ...where, detail: use.endDesc }, ctx); break;
      case 'dynamic': add('dynamic_member_access', { ...where, detail: use.endDesc }, ctx); break;
      case 'gateway': add('gateway_used', { ...where, detail: `via ${c.via}` }, ctx); break;
      case 'indirect': add('indirect_reference', { ...where, detail: `.${c.symbol} read on the result of ${c.via}` }, ctx); break;
      default: break;
    }
  }

  if (affected.length) {
    // Reachable: evidence is the chain from import to use for each reference.
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
      evidence.push({ symbol: a.symbol, via: a.via || null, chain });
    }
    // Drop chains that are a prefix of a longer chain for the same symbol
    // (import -> use is a prefix of import -> use -> later use of the result).
    const sig = (e) => e.chain.map(locKey).join('>');
    const maximal = evidence.filter((e) => !evidence.some((o) => o !== e && o.symbol === e.symbol &&
      o.chain.length > e.chain.length && sig(o).startsWith(sig(e) + '>')));
    maximal.sort((x, y) => y.chain.length - x.chain.length);
    reasons.clear();
    return finish('reachable', { references: maximal.slice(0, 20), referenceCount: maximal.length });
  }

  for (const u of facts.unresolved) add(u.code, { file: u.file, line: u.line, text: u.text, detail: u.detail }, ctx);
  if (facts.imports.length === 0) add('no_import_found', null, ctx);
  for (const g of usage.global) add(g.code, { file: g.file, line: g.line, text: g.text, detail: g.detail }, ctx);
  for (const e of usage.parseErrors) add('parse_error', { file: e.file, line: e.line, text: e.text, detail: e.message }, ctx);
  for (const e of usage.fileErrors) add('file_unreadable', { file: e.file, line: null, text: '', detail: e.message }, ctx);

  if (reasons.size) return finish('cant_tell');

  // Every condition for "unreachable" holds: direct dependency, imported at
  // least once, every import site static and mapped, nothing escaped, no
  // dynamic access, no project-wide dynamic loading or eval, every file
  // parsed, and no reference to any affected symbol.
  const importSites = [];
  const seenImports = new Set();
  for (const imp of facts.imports) {
    if (seenImports.has(locKey(imp))) continue;
    seenImports.add(locKey(imp));
    importSites.push({ file: imp.file, line: imp.line, text: imp.text });
  }
  return finish('unreachable', {
    symbols: entry.symbols,
    importSites: importSites.slice(0, 20),
    importCount: importSites.length,
    usesChecked: facts.uses.length,
  });
}

/**
 * @param inventory    from readInventory()
 * @param vulnIds      Map "name@version" -> [{id}]
 * @param vulnDetails  Map id -> OSV record
 * @param usage        from extractUsage()
 * @param data         from loadAdvisoryData()
 */
export function computeVerdicts({ inventory, vulnIds, vulnDetails, usage, data }) {
  const usageIndex = indexUsage(usage);
  const results = [];
  const withdrawn = [];
  for (const instance of inventory.instances) {
    for (const ref of vulnIds.get(`${instance.name}@${instance.version}`) || []) {
      const vuln = vulnDetails.get(ref.id) || {};
      if (vuln.withdrawn) { withdrawn.push({ id: ref.id, package: instance.name, version: instance.version, withdrawn: vuln.withdrawn }); continue; }
      const entry = data.advisories[ref.id];
      const d = decide({ advisoryId: ref.id, instance, data, usageIndex, usage });
      results.push({
        id: ref.id,
        aliases: vuln.aliases || [],
        summary: vuln.summary || (vuln.details || '').split('\n')[0].slice(0, 120),
        severity: (vuln.database_specific && vuln.database_specific.severity) || null,
        url: `https://osv.dev/vulnerability/${ref.id}`,
        package: instance.name,
        installName: instance.installName,
        version: instance.version,
        lockfilePath: instance.key,
        direct: instance.direct,
        dev: instance.dev,
        affectedSymbols: entry && entry.package === instance.name ? entry.symbols : null,
        symbolSource: entry && entry.package === instance.name ? entry.source : null,
        verdict: d.verdict,
        reason: d.reasons.length ? d.reasons[0].code : null,
        reasons: d.reasons,
        evidence: d.evidence,
      });
    }
  }
  const rank = { reachable: 0, cant_tell: 1, unreachable: 2 };
  results.sort((a, b) => rank[a.verdict] - rank[b.verdict] || a.package.localeCompare(b.package) ||
    a.version.localeCompare(b.version) || a.id.localeCompare(b.id));
  return { results, withdrawn };
}
