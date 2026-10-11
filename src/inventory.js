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
function resolveFrom(packages, fromKey, name) {
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

  // Reverse edges for "required by".
  const requiredBy = new Map();
  for (const [key, entry] of Object.entries(packages)) {
    if (!entry || entry.link) continue;
    const from = key === '' ? '(project)' : `${entry.name || installNameFromKey(key)}@${entry.version}`;
    for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const dep of Object.keys(entry[field] || {})) {
        const target = resolveFrom(packages, key, dep);
        if (!target) continue;
        if (!requiredBy.has(target)) requiredBy.set(target, new Set());
        requiredBy.get(target).add(from);
      }
    }
  }

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
    instances.push({
      key,
      name: entry.name || installName,
      installName,
      version: entry.version,
      direct,
      dev: Boolean(entry.dev),
      optional: Boolean(entry.optional),
      requiredBy: [...(requiredBy.get(key) || [])].sort(),
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
    errors,
    warnings,
    workspaces,
  };
}
