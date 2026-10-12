// Installed-package helpers for Phase 2: which files of a package in
// node_modules can run when it is loaded, which packages can load a given
// installed instance, and (best effort) what a package exports.

import fs from 'node:fs';
import path from 'node:path';
import { SOURCE_EXTENSIONS } from './parser.js';

export const MAX_FILE_BYTES = 3 * 1024 * 1024; // larger files are treated as unparseable

export function readPackageJson(dir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8').replace(/^﻿/, ''));
  } catch {
    return null;
  }
}

function isSource(name) {
  return SOURCE_EXTENSIONS.has(path.extname(name).toLowerCase()) && !/\.d\.[cm]?ts$/i.test(name);
}

/** All source files of the package at `dir`, excluding nested node_modules (other packages). */
export function listPackageFiles(dir) {
  const out = [];
  const stack = [dir];
  while (stack.length) {
    const d = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (e.name !== 'node_modules' && e.name !== '.git') stack.push(full);
      } else if (e.isFile() && isSource(e.name)) {
        out.push(full);
      }
    }
  }
  return out.sort();
}

function collectTargets(value, out) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => collectTargets(v, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => collectTargets(v, out));
  return out;
}

const TRY_EXT = ['', '.js', '.cjs', '.mjs', '.jsx', '.ts', '.tsx', '.json', '.node'];

/** Node/bundler-style file resolution of a relative specifier. Returns an absolute path or null. */
export function resolveRelative(fromDir, spec) {
  const base = path.resolve(fromDir, spec);
  for (const ext of TRY_EXT) {
    const f = base + ext;
    try { if (fs.statSync(f).isFile()) return f; } catch { /* next */ }
  }
  try {
    if (fs.statSync(base).isDirectory()) {
      const pj = readPackageJson(base);
      if (pj && typeof pj.main === 'string') {
        const m = resolveRelative(base, './' + pj.main);
        if (m) return m;
      }
      for (const ext of TRY_EXT.slice(1)) {
        const f = path.join(base, 'index' + ext);
        try { if (fs.statSync(f).isFile()) return f; } catch { /* next */ }
      }
    }
  } catch { /* not found */ }
  return null;
}

function binEntries(pj) {
  if (!pj || !pj.bin) return {};
  if (typeof pj.bin === 'string') return { [(pj.name || '').replace(/^@[^/]+\//, '')]: pj.bin };
  return typeof pj.bin === 'object' ? pj.bin : {};
}

export function binNames(pj) {
  return Object.keys(binEntries(pj));
}

/**
 * Entry points of a package.
 * @returns {{ main: string[], bin: string[], wildcard: boolean, hasExports: boolean }} relative targets
 */
export function packageEntries(pj) {
  const main = [];
  let wildcard = false;
  if (pj.exports !== undefined) {
    const t = collectTargets(pj.exports, []);
    if (t.some((x) => x.includes('*'))) wildcard = true;
    main.push(...t.filter((x) => !x.includes('*')));
  }
  main.push(typeof pj.main === 'string' ? pj.main : 'index.js');
  if (typeof pj.module === 'string') main.push(pj.module);
  if (typeof pj.browser === 'string') main.push(pj.browser);
  else if (pj.browser && typeof pj.browser === 'object') main.push(...collectTargets(pj.browser, []).filter((x) => typeof x === 'string'));
  return { main, bin: Object.values(binEntries(pj)), wildcard, hasExports: pj.exports !== undefined };
}

/**
 * Files of the package that can run when a consumer loads it.
 *
 * - With an `exports` map (no wildcards): only files reachable from the
 *   exported entry points (plus main/module/browser) by static relative
 *   imports. Node refuses deep imports outside `exports`.
 * - Without one: consumers may deep-import any file, so every file counts.
 * - In both cases, files reachable ONLY from the package's `bin` scripts are
 *   left out unless the caller says a bin is used (e.g. by an npm script).
 * - If the closure cannot be computed reliably (wildcard exports, a
 *   `#imports` map, an unresolvable relative import), every file counts.
 *
 * @param relativeByFile Map absFile -> [{spec}] relative specifiers found in it
 */
export function filesInScope(dir, pj, allFiles, relativeByFile, { includeBin = false } = {}) {
  const entries = packageEntries(pj);
  const closure = (starts) => {
    const seen = new Set();
    const queue = [];
    let unresolved = 0;
    for (const s of starts) {
      const f = resolveRelative(dir, './' + s.replace(/^\.\//, ''));
      if (f) queue.push(f);
    }
    while (queue.length) {
      const f = queue.shift();
      if (seen.has(f)) continue;
      seen.add(f);
      for (const r of relativeByFile.get(f) || []) {
        const g = resolveRelative(path.dirname(f), r.spec);
        if (g) queue.push(g);
        else unresolved++;
      }
    }
    return { files: [...seen].filter(isSource), unresolved };
  };
  const mainC = closure(entries.main);
  const binC = closure(entries.bin);
  const reliable = !entries.wildcard && !pj.imports && mainC.unresolved === 0;
  let scope;
  let mode;
  if (entries.hasExports && reliable) {
    scope = new Set(mainC.files);
    mode = 'exports closure';
  } else {
    scope = new Set(allFiles);
    mode = entries.hasExports ? 'all files (exports closure not reliable)' : 'all files (no exports map, deep imports possible)';
  }
  const binOnly = binC.files.filter((f) => !mainC.files.includes(f));
  if (includeBin) binC.files.forEach((f) => scope.add(f));
  else binOnly.forEach((f) => scope.delete(f));
  return { files: [...scope].sort(), mode, binOnly: includeBin ? [] : binOnly };
}

/** "node_modules/a/node_modules/@s/b/lib/x.js" -> "node_modules/a/node_modules/@s/b" */
export function packageKeyOfFile(rel) {
  const m = rel.match(/^(.*node_modules\/(?:@[^/]+\/)?[^/]+)\//);
  return m ? m[1] : null;
}

/**
 * One pass over every source file in node_modules: for each package name in
 * `names`, which files mention it as a quoted string (a require/import, or a
 * name handed to a loader). Used to find packages that load an instance
 * without declaring it.
 * @returns Map name -> Set(relative file path)
 */
export function findNameMentions(projectRoot, names) {
  const hits = new Map([...names].map((n) => [n, new Set()]));
  if (!names.size) return hits;
  const esc = [...names].sort((a, b) => b.length - a.length).map((n) => n.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&'));
  const re = new RegExp(`['"\`](${esc.join('|')})(?:/[^'"\`]*)?['"\`]`, 'g');
  const stack = [path.join(projectRoot, 'node_modules')];
  while (stack.length) {
    const d = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) { if (e.name !== '.bin' && e.name !== '.cache') stack.push(full); continue; }
      if (!e.isFile() || !isSource(e.name)) continue;
      let text;
      try {
        if (fs.statSync(full).size > 20 * 1024 * 1024) continue;
        text = fs.readFileSync(full, 'utf8');
      } catch { continue; }
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text))) hits.get(m[1]).add(path.relative(projectRoot, full).split(path.sep).join('/'));
    }
  }
  return hits;
}

// ------------------------------------------------------------ exports (best effort)

/**
 * Best-effort static list of a package's exported names, from its main entry
 * file. Returns { determined: false } whenever the export surface cannot be
 * read with confidence (UMD wrappers, Object.assign, computed keys, ...).
 * Used only to DROP LLM-proposed symbols that are certainly not exports, so a
 * wrong "determined" can only turn an LLM reachable into cant_tell.
 */
export function readExports(dir, parseFn, depth = 0) {
  const pj = readPackageJson(dir);
  if (!pj) return { determined: false, why: 'package.json not readable' };
  let entry = null;
  if (pj.exports !== undefined) {
    const dot = typeof pj.exports === 'string' || Array.isArray(pj.exports) ? pj.exports : (pj.exports['.'] !== undefined ? pj.exports['.'] : pj.exports);
    const pick = (v) => (typeof v === 'string' ? v : v && typeof v === 'object' ? pick(v.require || v.node || v.import || v.default || Object.values(v)[0]) : null);
    entry = pick(dot);
  }
  entry = entry || (typeof pj.main === 'string' ? pj.main : 'index.js');
  const file = resolveRelative(dir, './' + entry.replace(/^\.\//, ''));
  if (!file || !/\.(c|m)?js$/.test(file)) return { determined: false, why: `entry ${entry} not found or not JavaScript` };
  return readFileExports(file, parseFn, depth);
}

function readFileExports(file, parseFn, depth) {
  if (depth > 3) return { determined: false, why: 'export chain too deep' };
  let src;
  try {
    if (fs.statSync(file).size > MAX_FILE_BYTES) return { determined: false, why: 'entry file too large' };
    src = fs.readFileSync(file, 'utf8');
  } catch { return { determined: false, why: 'entry file not readable' }; }
  const tree = parseFn(src, file);
  try {
    if (tree.rootNode.hasError) return { determined: false, why: 'entry file does not parse cleanly' };
    const names = new Set();
    let callable = false;
    let undetermined = null;
    let moduleExportsIdent = null;
    const objectKeys = (obj) => {
      for (const p of obj.namedChildren) {
        if (!p) continue;
        if (p.type === 'shorthand_property_identifier') names.add(p.text);
        else if (p.type === 'pair' || p.type === 'method_definition') {
          const k = p.childForFieldName(p.type === 'pair' ? 'key' : 'name');
          if (k && (k.type === 'property_identifier' || k.type === 'string')) names.add(k.text.replace(/^['"]|['"]$/g, ''));
          else undetermined = undetermined || 'computed key in exports object';
        } else if (p.type === 'spread_element') undetermined = undetermined || 'spread in exports object';
      }
    };
    const walk = (n) => {
      if (n.type === 'assignment_expression') {
        const left = n.childForFieldName('left');
        const right = n.childForFieldName('right');
        const lt = left.text.replace(/\s+/g, '');
        if (lt === 'module.exports') {
          if (right.type === 'object') objectKeys(right);
          else if (/function|arrow_function|class/.test(right.type)) callable = true;
          else if (right.type === 'identifier') moduleExportsIdent = right.text;
          else if (right.type === 'call_expression' && right.childForFieldName('function').text === 'require') {
            const arg = right.childForFieldName('arguments').namedChildren[0];
            const spec = arg && arg.type === 'string' ? arg.text.slice(1, -1) : null;
            const target = spec && spec.startsWith('.') ? resolveRelative(path.dirname(file), spec) : null;
            if (!target) undetermined = 'module.exports = require(<package>)';
            else {
              const r = readFileExports(target, parseFn, depth + 1);
              if (!r.determined) undetermined = r.why;
              else { r.names.forEach((x) => names.add(x)); callable = callable || r.callable; }
            }
          } else undetermined = `module.exports = ${right.type}`;
        } else {
          const m = lt.match(/^(?:module\.)?exports\.([A-Za-z_$][\w$]*)$/);
          if (m) names.add(m[1]);
          else if (/^(module\.)?exports\[/.test(lt)) undetermined = 'computed exports[...] assignment';
        }
      } else if (n.type === 'call_expression') {
        const t = n.childForFieldName('function').text;
        if (/^Object\.(assign|defineProperty|defineProperties)$/.test(t) && /\b(module\.)?exports\b/.test(n.childForFieldName('arguments').text)) undetermined = `${t}(exports, ...)`;
      } else if (n.type === 'export_statement') {
        const decl = n.childForFieldName('declaration');
        if (n.text.startsWith('export default')) { names.add('default'); callable = true; }
        if (decl) {
          const nm = decl.childForFieldName('name');
          if (nm) names.add(nm.text);
          for (const d of decl.namedChildren) if (d && d.type === 'variable_declarator' && d.childForFieldName('name').type === 'identifier') names.add(d.childForFieldName('name').text);
        }
        const clause = n.namedChildren.find((c) => c && c.type === 'export_clause');
        if (clause) for (const s of clause.namedChildren) if (s && s.type === 'export_specifier') names.add((s.childForFieldName('alias') || s.childForFieldName('name') || { text: 'default' }).text);
        if (!decl && !clause && n.childForFieldName('source') && !n.text.startsWith('export default')) undetermined = 'export * from ...';
      }
      for (const c of n.namedChildren) if (c) walk(c);
    };
    walk(tree.rootNode);
    if (moduleExportsIdent) {
      // module.exports = X; with X.foo = ... / const X = { ... } / function X() {}
      const walk2 = (n) => {
        if (n.type === 'variable_declarator' && n.childForFieldName('name').text === moduleExportsIdent) {
          const v = n.childForFieldName('value');
          if (v && v.type === 'object') objectKeys(v);
          else if (v && /function|arrow_function|class/.test(v.type)) callable = true;
          else undetermined = undetermined || `${moduleExportsIdent} is not a literal`;
        } else if (n.type === 'function_declaration' && n.childForFieldName('name').text === moduleExportsIdent) {
          callable = true;
        } else if (n.type === 'assignment_expression') {
          const m = n.childForFieldName('left').text.replace(/\s+/g, '').match(new RegExp(`^${moduleExportsIdent.replace(/\$/g, '\\$')}\\.([A-Za-z_$][\\w$]*)$`));
          if (m) names.add(m[1]);
        }
        for (const c of n.namedChildren) if (c) walk2(c);
      };
      walk2(tree.rootNode);
    }
    if (undetermined) return { determined: false, why: undetermined };
    if (!names.size && !callable) return { determined: false, why: 'no recognisable export form' };
    return { determined: true, names, callable };
  } finally {
    tree.delete();
  }
}
