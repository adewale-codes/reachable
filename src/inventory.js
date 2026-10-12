// Dependency inventory: package-lock.json (lockfileVersion 2 or 3) -> installed
// package instances, each marked direct or transitive.

import fs from 'node:fs';
import path from 'node:path';
import { ScanError } from './errors.js';

const DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

function readJson(file, what) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    throw new ScanError(`cannot read ${what} at ${file}: ${err.code || err.message}`, 'missing_' + what.replace(/\W+/g, '_'));
  }
  try {
    return JSON.parse(text.replace(/^﻿/, ''));
  } catch (err) {
    throw new ScanError(`${what} at ${file} is not valid JSON: ${err.message}`, 'unparseable_' + what.replace(/\W+/g, '_'));
  }
}

/** "node_modules/a/node_modules/@s/b" -> "@s/b" */
function installNameFromKey(key) {
  const i = key.lastIndexOf('node_modules/');
  return i === -1 ? null : key.slice(i + 'node_modules/'.length);
}

/** Node-style resolution of `name` as seen from the package installed at `fromKey`. */
export function resolveFrom(packages, fromKey, name) {
  let base = fromKey;
  for (;;) {
    const candidate = base ? `${base}/node_modules/${name}` : `node_modules/${name}`;
    if (packages[candidate]) return candidate;
    if (!base) return null;
    const i = base.lastIndexOf('/node_modules/');
    base = i === -1 ? '' : base.slice(0, i);
  }
}

/**
 * @returns {{ projectName, lockfileVersion, instances: Instance[], directNames: string[],
 *             errors: {code,message}[], warnings: string[], workspaces: boolean }}
 * Instance: { key, name, installName, version, direct, dev, optional, requiredBy: string[] }
 */
export function readInventory(projectDir) {
  const pkgJson = readJson(path.join(projectDir, 'package.json'), 'package.json');
  const lock = readJson(path.join(projectDir, 'package-lock.json'), 'package-lock.json');

  const v = lock.lockfileVersion;
  if (v !== 2 && v !== 3) {
    throw new ScanError(
      `package-lock.json has lockfileVersion ${JSON.stringify(v)}; only versions 2 and 3 are supported. ` +
      'Regenerate it with npm 7 or later (npm install --package-lock-only).',
      'unsupported_lockfile');
  }
  const packages = lock.packages;
  if (!packages || typeof packages !== 'object') {
    throw new ScanError('package-lock.json has no "packages" section', 'unparseable_package_lock_json');
  }

  const errors = [];
  const warnings = [];

  // Direct = declared by the project itself.
  const declared = new Map(); // installName -> field
  for (const field of DEP_FIELDS) {
    for (const name of Object.keys(pkgJson[field] || {})) {
      if (!declared.has(name)) declared.set(name, field);
    }
  }

  const workspaces = Boolean(pkgJson.workspaces) ||
    Object.values(packages).some((e) => e && e.link === true);
  if (workspaces) {
    warnings.push('This project uses workspaces or linked local packages. Only dependencies declared in the root package.json are treated as direct; dependencies of workspace members are reported as transitive.');
  }

  // Dependency graph over lockfile keys ('' = the project itself).
  const children = new Map(); // key -> Set(key)
  const parents = new Map(); // key -> Set(key)
  for (const [key, entry] of Object.entries(packages)) {
    if (!entry || entry.link) continue;
    const fields = key === '' ? DEP_FIELDS : ['dependencies', 'optionalDependencies', 'peerDependencies'];
    for (const field of fields) {
      for (const dep of Object.keys(entry[field] || {})) {
        const target = resolveFrom(packages, key, dep);
        if (!target || target === key) continue;
        if (!children.has(key)) children.set(key, new Set());
        children.get(key).add(target);
        if (!parents.has(target)) parents.set(target, new Set());
        parents.get(target).add(key);
      }
    }
  }
  const reachable = new Set(['']);
  const queue = [''];
  while (queue.length) {
    for (const c of children.get(queue.shift()) || []) {
      if (!reachable.has(c)) { reachable.add(c); queue.push(c); }
    }
  }
  const label = (key) => (key === '' ? '(project)' : `${packages[key].name || installNameFromKey(key)}@${packages[key].version}`);

  const instances = [];
  for (const [key, entry] of Object.entries(packages)) {
    if (key === '' || !entry) continue;
    const installName = installNameFromKey(key);
    if (!installName) continue; // a workspace member's own folder, not an installed package
    if (entry.link) continue; // symlink to a local folder; its code is not from the registry
    if (!entry.version) {
      warnings.push(`lockfile entry ${key} has no version; it was not checked for advisories`);
      continue;
    }
    const direct = key === `node_modules/${installName}` && declared.has(installName);
    const parentKeys = [...(parents.get(key) || [])].filter((p) => p !== '' && reachable.has(p)).sort();
    instances.push({
      key,
      name: entry.name || installName,
      installName,
      version: entry.version,
      direct,
      dev: Boolean(entry.dev),
      optional: Boolean(entry.optional),
      // npm sets dev:true only when every path to the package starts at a
      // devDependency. devOptional / optional packages may still be on a prod
      // path, so they are tagged prod: hiding them under --prod-only would be
      // the unsafe direction.
      scope: entry.dev ? 'dev' : 'prod',
      parentKeys,
      requiredBy: parentKeys.map(label),
    });
  }

  for (const [name, field] of declared) {
    const entry = packages[`node_modules/${name}`];
    if (!entry) {
      if (field === 'peerDependencies') {
        warnings.push(`peer dependency ${name} is not installed; it was not checked`);
      } else {
        errors.push({
          code: 'lockfile_missing_dependency',
          message: `package.json declares ${name} (${field}) but package-lock.json has no node_modules/${name} entry. ` +
            'The lockfile is out of date, so this dependency could not be checked. Run npm install.',
        });
      }
    }
  }

  /**
   * Every path from the project through a direct dependency to `key`, as
   * lists of lockfile keys (excluding ''). Stops at `cap` paths; `complete`
   * says whether all were enumerated. Cycles are skipped.
   */
  function pathsTo(key, cap = 200) {
    const out = [];
    let complete = true;
    const walk = (node, trail) => {
      if (out.length >= cap) { complete = false; return; }
      if (node === '') { out.push(trail.slice().reverse()); return; }
      for (const p of parents.get(node) || []) {
        if (!reachable.has(p) || trail.includes(p)) continue;
        trail.push(p);
        walk(p, trail);
        trail.pop();
      }
    };
    walk(key, [key]);
    return { paths: out.map((p) => p.filter((k) => k !== '')), complete };
  }

  instances.sort((a, b) => a.key.localeCompare(b.key));
  return {
    projectName: pkgJson.name || path.basename(projectDir),
    lockfileVersion: v,
    instances,
    directNames: [...declared.keys()].sort(),
    topLevelNames: Object.keys(packages)
      .filter((k) => /^node_modules\/(@[^/]+\/)?[^/]+$/.test(k))
      .map((k) => k.slice('node_modules/'.length)),
    packageJson: pkgJson,
    lockPackages: packages,
    pathsTo,
    label,
    errors,
    warnings,
    workspaces,
  };
}
