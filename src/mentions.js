// Where the project refers to a package outside its source code: npm
// scripts, the project's own bin field, and well-known tool config files at
// the project root. A mention means tooling may load the package, so it is
// recorded as a reason (`used_by_script`); it never makes anything unreachable.

import fs from 'node:fs';
import path from 'node:path';

const CONFIG_FILES = [
  /^\.eslintrc(\.(js|cjs|json|yaml|yml))?$/, /^eslint\.config\.(js|cjs|mjs|ts)$/,
  /^jest\.config\.(js|cjs|mjs|ts|json)$/,
  /^\.babelrc(\.(js|cjs|json))?$/, /^babel\.config\.(js|cjs|mjs|json)$/,
  /^webpack\.config\.(js|cjs|mjs|ts)$/, /^vite\.config\.(js|cjs|mjs|ts|mts)$/,
  /^tsconfig(\..+)?\.json$/,
  /^\.prettierrc(\.(js|cjs|json|yaml|yml|toml))?$/, /^prettier\.config\.(js|cjs|mjs)$/,
];
const PKG_CONFIG_FIELDS = ['eslintConfig', 'jest', 'babel', 'prettier'];

function wordRe(word) {
  const w = word.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  return new RegExp(`(^|[^\\w@/.-])${w}($|[^\\w.-])`);
}

/** Short names tools accept for plugin packages, e.g. eslint-plugin-react -> "react", "plugin:react/". */
function toolShortNames(name) {
  const m = name.match(/^(?:(@[^/]+)\/)?(eslint-plugin|eslint-config|babel-plugin|babel-preset|prettier-plugin)(?:-(.+))?$/);
  if (!m) return null;
  const [, scope, kind, rest] = m;
  const short = rest ? (scope ? `${scope}/${rest}` : rest) : scope;
  if (!short) return null;
  return { family: kind.split('-')[0], names: [short, `plugin:${short}/`] };
}

/**
 * @param externalEntries literal entries of bundler `external` lists found by the
 *        extractor ({file, line, text}); they are blanked out before matching,
 *        because "do not bundle X" is not a use of X.
 */
export function buildMentionIndex(root, pkgJson, externalEntries = []) {
  const configs = [];
  let entries = [];
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { /* none */ }
  for (const e of entries) {
    if (!e.isFile() || !CONFIG_FILES.some((re) => re.test(e.name))) continue;
    try {
      const lines = fs.readFileSync(path.join(root, e.name), 'utf8').split(/\n/);
      for (const x of externalEntries.filter((y) => y.file === e.name)) {
        const i = x.line - 1;
        if (lines[i] !== undefined) lines[i] = lines[i].replace(x.text, ' '.repeat(x.text.length));
      }
      configs.push({ file: e.name, text: lines.join('\n') });
    } catch { /* unreadable */ }
  }
  for (const f of PKG_CONFIG_FIELDS) {
    if (pkgJson && pkgJson[f] !== undefined) configs.push({ file: `package.json#${f}`, text: JSON.stringify(pkgJson[f]) });
  }
  const scripts = Object.entries((pkgJson && pkgJson.scripts) || {});
  const binText = pkgJson && pkgJson.bin ? JSON.stringify(pkgJson.bin) : '';

  /** @returns {{scripts: Location[], configs: Location[]}} */
  return function mentionsOf(name, bins = []) {
    const out = { scripts: [], configs: [] };
    const res = [name, ...bins].map(wordRe);
    for (const [k, cmd] of scripts) {
      if (res.some((re) => re.test(cmd))) out.scripts.push({ file: 'package.json', line: null, text: `"${k}": "${cmd}"`, detail: 'npm script' });
    }
    if (binText && wordRe(name).test(binText)) out.scripts.push({ file: 'package.json', line: null, text: `"bin": ${binText}`, detail: 'bin entry' });
    const short = toolShortNames(name);
    for (const c of configs) {
      let hit = wordRe(name).test(c.text);
      if (!hit && short && c.file.toLowerCase().includes(short.family)) {
        hit = short.names.some((s) => c.text.includes(`"${s}`) || c.text.includes(`'${s}`) || c.text.includes(s.startsWith('plugin:') ? s : `"${s}"`));
      }
      if (hit) out.configs.push({ file: c.file, line: null, text: '', detail: 'root config file' });
    }
    return out;
  };
}
