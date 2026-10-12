// Analysis of installed packages that load a vulnerable instance ("loaders").
// Requires node_modules. Each loader package is parsed once (all its source
// files), then restricted to the files that can run when it is loaded, and
// the same Phase 1 extractor facts are used to judge the edge.

import fs from 'node:fs';
import path from 'node:path';
import { extractUsage } from './usage.js';
import { indexUsage } from './verdict.js';
import {
  readPackageJson, listPackageFiles, filesInScope, binNames, packageKeyOfFile, findNameMentions, MAX_FILE_BYTES,
} from './packages.js';
import { resolveFrom } from './inventory.js';

export class PackageAnalyzer {
  /**
   * @param projectRoot absolute path
   * @param inventory   from readInventory()
   * @param targets     installed instances (vulnerable ones) whose loaders are needed
   * @param binUsed     (pj) => boolean: is one of this package's bins run by a project script?
   */
  constructor(projectRoot, inventory, targets, { binUsed = () => false } = {}) {
    this.root = projectRoot;
    this.inv = inventory;
    this.binUsed = binUsed;
    this.available = fs.existsSync(path.join(projectRoot, 'node_modules'));
    this.trackedNames = new Set(targets.map((t) => t.installName));
    this.cache = new Map();
    this.mentions = null;
    this.warnings = [];
  }

  /** Packages (lockfile keys) that load instance `inst`: declared dependents plus undeclared requirers. */
  loadersOf(inst) {
    const keys = new Map(inst.parentKeys.filter((k) => k !== '').map((k) => [k, true]));
    if (this.available) {
      if (!this.mentions) this.mentions = findNameMentions(this.root, this.trackedNames);
      for (const file of this.mentions.get(inst.installName) || []) {
        const pk = packageKeyOfFile(file);
        if (!pk || pk === inst.key || keys.has(pk)) continue;
        if (!this.inv.lockPackages[pk]) {
          this.warnings.push(`${file} mentions ${inst.installName} but its package (${pk}) is not in package-lock.json; it was not analysed`);
          continue;
        }
        if (resolveFrom(this.inv.lockPackages, pk, inst.installName) === inst.key) keys.set(pk, false);
      }
    }
    return [...keys.entries()].map(([key, declared]) => ({ key, declared, label: this.inv.label(key) }));
  }

  /** Usage facts of one installed package, restricted to files that can run. Cached. */
  async usageOf(pkgKey) {
    if (this.cache.has(pkgKey)) return this.cache.get(pkgKey);
    const p = this.analyse(pkgKey);
    this.cache.set(pkgKey, p);
    return p;
  }

  async analyse(pkgKey) {
    const dir = path.join(this.root, pkgKey);
    const lock = this.inv.lockPackages[pkgKey] || {};
    const pj = readPackageJson(dir);
    if (!pj) return { status: 'missing' };
    if (lock.version && pj.version !== lock.version) {
      return { status: 'out_of_sync', detail: `installed ${pj.version}, locked ${lock.version}` };
    }
    const all = listPackageFiles(dir);
    const tooBig = [];
    const parseable = [];
    for (const f of all) {
      let size = 0;
      try { size = fs.statSync(f).size; } catch { /* treated below */ }
      (size > MAX_FILE_BYTES ? tooBig : parseable).push(f);
    }
    const usage = await extractUsage(this.root, { tracked: this.trackedNames, files: parseable, aliasConfigs: false });
    const rel = (abs) => path.relative(this.root, abs).split(path.sep).join('/');
    const relativeByFile = new Map();
    for (const r of usage.relative) {
      const abs = path.join(this.root, r.file);
      if (!relativeByFile.has(abs)) relativeByFile.set(abs, []);
      relativeByFile.get(abs).push(r);
    }
    const scope = filesInScope(dir, pj, all, relativeByFile, { includeBin: this.binUsed(pj) });
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
    return { status: 'ok', usage: filtered, usageIndex: indexUsage(filtered), mode: scope.mode, filesInScope: scope.files.length, binOnly: scope.binOnly.map(rel), bins: binNames(pj) };
  }

  /** Loader edges for one instance, ready for decideAlert(). */
  async edgesFor(inst) {
    if (!this.available) return { available: false };
    const loaders = [];
    const ignored = [];
    for (const L of this.loadersOf(inst)) {
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
}
