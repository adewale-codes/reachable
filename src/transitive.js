// Analysis of installed packages that load a vulnerable instance ("loaders").
// Requires node_modules. Each loader package is parsed once (all its source
// files), then restricted to the files that can run when it is loaded, and
// the same Phase 1 extractor facts are used to judge the edge.
//
// Phase 3: per-package results are cached on disk (src/pkgcache.js), keyed by
// name@version + lockfile integrity + ANALYZER_VERSION, and packages are read
// and analysed concurrently. Packages without an integrity hash, or patched by
// patch-package, are never cached.

import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { extractUsage } from './usage.js';
import { indexUsage } from './verdict.js';
import {
  readPackageJson, listPackageFiles, filesInScope, binNames, MAX_FILE_BYTES,
} from './packages.js';
import { resolveFrom } from './inventory.js';
import { pool } from './pkgcache.js';

// Every quoted token that could be a package name (optionally followed by a
// deep path): 'lodash', "lodash/merge", `@scope/pkg`. Same matching rule as
// Phase 2's text search, but collected once per package so it can be cached.
// Cached results must not depend on WHERE a package is installed: the same
// name@version can sit at several paths (e.g. two nested copies). Paths are
// stored relative to a placeholder and rebased on load.
const PKG_PLACEHOLDER = '<pkg>';
function rebase(value, from, to) {
  if (typeof value === 'string') return value === from || value.startsWith(from + '/') ? to + value.slice(from.length) : value;
  if (Array.isArray(value)) return value.map((v) => rebase(v, from, to));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, rebase(v, from, to)]));
  return value;
}

const TOKEN_RE = /['"`]((?:@[A-Za-z0-9][\w.-]*\/)?[A-Za-z0-9][\w.-]*)(?:\/[^'"`]*)?['"`]/g;

export const DEFAULT_CONCURRENCY = Math.max(2, Math.min(8, (os.cpus() || []).length || 4));

export class PackageAnalyzer {
  /**
   * @param projectRoot absolute path
   * @param inventory   from readInventory()
   * @param targets     installed instances (vulnerable ones) whose loaders are needed
   * @param opts.binUsed     (pj) => boolean: is one of this package's bins run by a project script?
   * @param opts.cache       PackageCache or null
   * @param opts.concurrency max packages read/analysed at once
   * @param opts.onProgress  (message) => void
   */
  constructor(projectRoot, inventory, targets, { binUsed = () => false, cache = null, concurrency = DEFAULT_CONCURRENCY, onProgress = null } = {}) {
    this.root = projectRoot;
    this.inv = inventory;
    this.binUsed = binUsed;
    this.cache = cache;
    this.concurrency = concurrency;
    this.onProgress = onProgress;
    this.available = fs.existsSync(path.join(projectRoot, 'node_modules'));
    this.trackedNames = new Set(targets.map((t) => t.installName));
    this.trackedKey = [...this.trackedNames].sort();
    this.results = new Map(); // pkgKey -> analysis
    this.mentionIndex = null; // pkgKey -> Set(token)
    this.warnings = [];
    this.patched = this.readPatches();
  }

  /** patch-package edits installed files after install: never trust a cache for those packages. */
  readPatches() {
    const out = new Set();
    try {
      for (const f of fs.readdirSync(path.join(this.root, 'patches'))) {
        const m = f.match(/^(.+?)\+\d.*\.patch$/);
        if (m) out.add(m[1].replace(/\+/g, '/'));
      }
    } catch { /* no patches dir */ }
    return out;
  }

  identity(pkgKey) {
    const e = this.inv.lockPackages[pkgKey] || {};
    const name = e.name || pkgKey.slice(pkgKey.lastIndexOf('node_modules/') + 'node_modules/'.length);
    if (!e.integrity || this.patched.has(name)) return null;
    return [name, e.version, e.integrity];
  }

  progress(msg) {
    if (this.onProgress) this.onProgress(msg);
  }

  async readSources(files) {
    const sources = new Map();
    await pool(files, 16, async (f) => {
      try { sources.set(f, await fsp.readFile(f, 'utf8')); } catch { /* reported by extractUsage */ }
    });
    return sources;
  }

  // ---------------------------------------------------------------- mentions

  /** Quoted package-name tokens of one installed package (cached). */
  async tokensOf(pkgKey) {
    const id = this.identity(pkgKey);
    if (id && this.cache) {
      const hit = this.cache.get('mentions', id);
      if (hit) return new Set(hit);
    }
    const dir = path.join(this.root, pkgKey);
    const tokens = new Set();
    await pool(listPackageFiles(dir), 16, async (f) => {
      let text;
      try {
        const st = await fsp.stat(f);
        if (st.size > 20 * 1024 * 1024) return;
        text = await fsp.readFile(f, 'utf8');
      } catch { return; }
      TOKEN_RE.lastIndex = 0;
      let m;
      while ((m = TOKEN_RE.exec(text))) tokens.add(m[1]);
    });
    if (id && this.cache) this.cache.set('mentions', id, [...tokens]);
    else if (this.cache) this.cache.stats.uncacheable++;
    return tokens;
  }

  /** Builds the token index for every installed package in the lockfile, once per scan. */
  async buildMentionIndex() {
    if (this.mentionIndex) return this.mentionIndex;
    const keys = Object.keys(this.inv.lockPackages).filter((k) => k.includes('node_modules/') && !this.inv.lockPackages[k].link &&
      fs.existsSync(path.join(this.root, k)));
    let done = 0;
    const tokens = await pool(keys, this.concurrency * 2, async (k) => {
      const t = await this.tokensOf(k);
      done++;
      if (done % 50 === 0 || done === keys.length) this.progress(`indexing installed packages ${done}/${keys.length}`);
      return t;
    });
    // Insert in a fixed order: reads finish in any order, but loader lists (and
    // therefore reports) must be identical from run to run, cached or not.
    const index = new Map(keys.map((k, i) => [k, tokens[i]]).sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0)));
    this.mentionIndex = index;
    return index;
  }

  /** Packages (lockfile keys) that load instance `inst`: declared dependents plus undeclared requirers. */
  async loadersOf(inst) {
    const keys = new Map(inst.parentKeys.filter((k) => k !== '').map((k) => [k, true]));
    if (this.available) {
      const index = await this.buildMentionIndex();
      for (const [pk, tokens] of index) {
        if (pk === inst.key || keys.has(pk) || !tokens.has(inst.installName)) continue;
        if (resolveFrom(this.inv.lockPackages, pk, inst.installName) === inst.key) keys.set(pk, false);
      }
    }
    return [...keys.entries()].map(([key, declared]) => ({ key, declared, label: this.inv.label(key) }));
  }

  // ---------------------------------------------------------------- package analysis

  /** Usage facts of one installed package, restricted to files that can run. Cached on disk and per scan. */
  async usageOf(pkgKey) {
    if (!this.results.has(pkgKey)) this.results.set(pkgKey, this.analyse(pkgKey));
    return this.results.get(pkgKey);
  }

  async analyse(pkgKey) {
    const dir = path.join(this.root, pkgKey);
    const lock = this.inv.lockPackages[pkgKey] || {};
    const pj = readPackageJson(dir);
    if (!pj) return { status: 'missing' };
    if (lock.version && pj.version !== lock.version) {
      return { status: 'out_of_sync', detail: `installed ${pj.version}, locked ${lock.version}` };
    }
    const includeBin = this.binUsed(pj);
    const id = this.identity(pkgKey);
    const parts = id ? [...id, this.trackedKey, includeBin] : null;
    if (parts && this.cache) {
      const hit = this.cache.get('analysis', parts);
      if (hit) return this.finish(rebase(hit, PKG_PLACEHOLDER, pkgKey));
    }

    const all = listPackageFiles(dir);
    const tooBig = [];
    const parseable = [];
    for (const f of all) {
      let size = 0;
      try { size = fs.statSync(f).size; } catch { /* treated below */ }
      (size > MAX_FILE_BYTES ? tooBig : parseable).push(f);
    }
    const sources = await this.readSources(parseable);
    const usage = await extractUsage(this.root, { tracked: this.trackedNames, files: parseable, sources, aliasConfigs: false });
    const rel = (abs) => path.relative(this.root, abs).split(path.sep).join('/');
    const relativeByFile = new Map();
    for (const r of usage.relative) {
      const abs = path.join(this.root, r.file);
      if (!relativeByFile.has(abs)) relativeByFile.set(abs, []);
      relativeByFile.get(abs).push(r);
    }
    const scope = filesInScope(dir, pj, all, relativeByFile, { includeBin });
    const inScope = new Set(scope.files.map(rel));
    const keep = (x) => inScope.has(x.file);
    const filtered = {
      imports: usage.imports.filter(keep),
      uses: usage.uses.filter(keep),
      unresolved: usage.unresolved.filter(keep),
      global: usage.global.filter(keep),
      parseErrors: usage.parseErrors.filter(keep),
      fileErrors: usage.fileErrors.filter(keep),
      typeImports: [],
    };
    for (const f of tooBig) {
      if (inScope.has(rel(f))) filtered.parseErrors.push({ file: rel(f), line: null, text: '', message: `larger than ${MAX_FILE_BYTES / 1024 / 1024} MB, not parsed` });
    }
    // A package.json "imports" map can alias a '#name' onto a dependency.
    if (pj.imports) {
      const targets = JSON.stringify(pj.imports);
      for (const name of this.trackedNames) {
        if (new RegExp(`"${name.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}(/[^"]*)?"`).test(targets)) {
          filtered.unresolved.push({ pkg: name, code: 'alias_config', detail: 'package.json "imports" maps onto it', file: `${pkgKey}/package.json`, line: null, text: '' });
        }
      }
    }
    const result = { status: 'ok', usage: filtered, mode: scope.mode, filesInScope: scope.files.length, binOnly: scope.binOnly.map(rel), bins: binNames(pj) };
    if (parts && this.cache) this.cache.set('analysis', parts, rebase(result, pkgKey, PKG_PLACEHOLDER));
    else if (this.cache) this.cache.stats.uncacheable++;
    return this.finish(result);
  }

  finish(result) {
    return { ...result, usageIndex: indexUsage(result.usage) };
  }

  /** Analyse every loader of every target concurrently, before verdicts are computed. */
  async prepare(targets) {
    if (!this.available) return;
    const loaderKeys = new Set();
    this.loaderLists = new Map();
    for (const t of targets) {
      const L = await this.loadersOf(t);
      this.loaderLists.set(t.key, L);
      L.forEach((l) => loaderKeys.add(l.key));
    }
    const keys = [...loaderKeys];
    let done = 0;
    await pool(keys, this.concurrency, async (k) => {
      await this.usageOf(k);
      done++;
      this.progress(`analysing packages that load vulnerable dependencies ${done}/${keys.length}`);
    });
  }

  /** Loader edges for one instance, ready for decideAlert(). */
  async edgesFor(inst) {
    if (!this.available) return { available: false };
    const list = (this.loaderLists && this.loaderLists.get(inst.key)) || await this.loadersOf(inst);
    const loaders = [];
    const ignored = [];
    for (const L of list) {
      const a = await this.usageOf(L.key);
      // An undeclared candidate was found by a plain text search. It only counts
      // as a loader if the parser sees the name in its code (an import, or the
      // name as a string literal); a mention inside a comment loads nothing.
      // A file that did not parse keeps the package as a loader (it may be code).
      if (!L.declared && a.status === 'ok') {
        const f = a.usageIndex.byPkg.get(inst.installName);
        const inCode = f && (f.imports.length || f.unresolved.length);
        if (!inCode && !a.usage.parseErrors.length) { ignored.push(`${L.label} (name appears only outside code)`); continue; }
      }
      loaders.push({ ...L, ...a });
    }
    return { available: true, loaders, ignored };
  }

  get packagesAnalysed() {
    return this.results.size;
  }
}
