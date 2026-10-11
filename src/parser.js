// Loads tree-sitter (WASM build) and the JavaScript / TypeScript grammars.
// The grammars are loaded from the .wasm files that ship inside the grammar
// packages, so no native compilation is needed on any platform.

import { createRequire } from 'node:module';
import path from 'node:path';
import { Parser, Language } from 'web-tree-sitter';

const require = createRequire(import.meta.url);

function grammarPath(pkg, file) {
  const dir = path.dirname(require.resolve(`${pkg}/package.json`));
  return path.join(dir, file);
}

let loading = null;

async function load() {
  await Parser.init();
  const [javascript, typescript, tsx] = await Promise.all([
    Language.load(grammarPath('tree-sitter-javascript', 'tree-sitter-javascript.wasm')),
    Language.load(grammarPath('tree-sitter-typescript', 'tree-sitter-typescript.wasm')),
    Language.load(grammarPath('tree-sitter-typescript', 'tree-sitter-tsx.wasm')),
  ]);
  return { javascript, typescript, tsx };
}

/** Returns a function parse(source, filename) -> tree. Caller must call tree.delete(). */
export async function createParser() {
  if (!loading) loading = load();
  const langs = await loading;
  const parser = new Parser();
  return function parse(source, filename) {
    const ext = path.extname(filename).toLowerCase();
    const lang = ext === '.ts' || ext === '.mts' || ext === '.cts' ? langs.typescript
      : ext === '.tsx' ? langs.tsx
        : langs.javascript;
    parser.setLanguage(lang);
    const tree = parser.parse(source);
    if (!tree) throw new Error(`tree-sitter returned no tree for ${filename}`);
    return tree;
  };
}

export const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx']);
