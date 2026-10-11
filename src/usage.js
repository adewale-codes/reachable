// Usage extractor. For every scanned source file, finds where tracked npm
// packages are imported and follows each imported value through member
// accesses, calls, aliases and destructuring.
//
// It records raw facts only. Which facts matter for which advisory is decided
// later by verdict.js, so this file knows nothing about vulnerabilities.
//
// Soundness rule: when a use of an imported value cannot be followed
// statically, the extractor records a fact saying so (escape, dynamic access,
// unresolved load, ...). It never silently drops a use. Matching is by name
// within a file (no scope analysis), which over-approximates: it can only add
// facts, never hide one.

import fs from 'node:fs';
import path from 'node:path';
import { builtinModules } from 'node:module';
import { createParser, SOURCE_EXTENSIONS } from './parser.js';

const BUILTINS = new Set(builtinModules);
const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn']);
const TIMER_FUNCTIONS = new Set(['setTimeout', 'setInterval', 'setImmediate']);
const GLOBAL_OBJECTS = new Set(['globalThis', 'window', 'global', 'self']);
const TRANSPARENT = new Set(['parenthesized_expression', 'await_expression', 'non_null_expression', 'as_expression', 'satisfies_expression', 'type_assertion']);
const TYPE_CONTEXTS = new Set(['type_query', 'type_annotation', 'type_arguments', 'generic_type', 'type_alias_declaration', 'interface_declaration']);
const HARMLESS_STATEMENTS = new Set(['expression_statement', 'if_statement', 'while_statement', 'do_statement', 'for_statement', 'switch_statement', 'template_substitution', 'unary_expression', 'update_expression', 'jsx_closing_element']);
const LOGICAL_OPERATORS = new Set(['&&', '||', '??']);

// ---------------------------------------------------------------- files

export function listSourceFiles(root) {
  const out = [];
  const skippedLinks = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      out.push({ file: dir, error: `cannot read directory: ${err.code || err.message}` });
      continue;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) {
        skippedLinks.push(path.relative(root, full));
        continue;
      }
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) stack.push(full);
      } else if (e.isFile()) {
        const ext = path.extname(e.name).toLowerCase();
        if (SOURCE_EXTENSIONS.has(ext) && !/\.d\.[cm]?ts$/i.test(e.name)) out.push({ file: full });
      }
    }
  }
  out.sort((a, b) => a.file.localeCompare(b.file));
  return { files: out, skippedLinks };
}

// ---------------------------------------------------------------- helpers

function field(parent, name, node) {
  const f = parent.childForFieldName(name);
  return Boolean(f && f.id === node.id);
}

function namedKids(node) {
  return node.namedChildren.filter((c) => c && c.type !== 'comment');
}

function hasAnonChild(node, type) {
  for (let i = 0; i < node.childCount; i++) {
    const c = node.child(i);
    if (c && !c.isNamed && c.type === type) return true;
  }
  return false;
}

function decodeEscape(seq) {
  const simple = { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', v: '\v', 0: '\0' };
  const body = seq.slice(1);
  if (body[0] in simple && body.length === 1) return simple[body[0]];
  if (body[0] === 'x') return String.fromCharCode(parseInt(body.slice(1), 16));
  if (body[0] === 'u') return String.fromCodePoint(parseInt(body.replace(/[u{}]/g, ''), 16));
  if (body[0] === '\n' || body[0] === '\r') return '';
  return body;
}

/** Static string value of an expression, or null if it is not a compile-time constant. */
export function staticString(node) {
  if (!node) return null;
  switch (node.type) {
    case 'parenthesized_expression':
      return staticString(namedKids(node)[0]);
    case 'string': {
      let s = '';
      for (const c of namedKids(node)) {
        if (c.type === 'string_fragment') s += c.text;
        else if (c.type === 'escape_sequence') s += decodeEscape(c.text);
        else return null;
      }
      return s;
    }
    case 'template_string': {
      let s = '';
      for (const c of namedKids(node)) {
        if (c.type === 'string_fragment') s += c.text;
        else if (c.type === 'escape_sequence') s += decodeEscape(c.text);
        else return null; // template_substitution
      }
      return s;
    }
    case 'binary_expression': {
      const op = node.childForFieldName('operator');
      if (!op || op.type !== '+') return null;
      const l = staticString(node.childForFieldName('left'));
      const r = staticString(node.childForFieldName('right'));
      return l !== null && r !== null ? l + r : null;
    }
    default:
      return null;
  }
}

/** Known constant prefix of a string-building expression ('lodash/' + x -> 'lodash/'). */
function staticPrefix(node) {
  if (!node) return '';
  const full = staticString(node);
  if (full !== null) return full;
  if (node.type === 'binary_expression') return staticPrefix(node.childForFieldName('left'));
  if (node.type === 'template_string') {
    let s = '';
    for (const c of namedKids(node)) {
      if (c.type === 'string_fragment') s += c.text;
      else break;
    }
    return s;
  }
  return '';
}

/**
 * tree-sitter-javascript rejects a bare `&name` (an unterminated HTML entity,
 * e.g. a URL query "?a=1&b=2") inside a JSX attribute string, although Babel
 * and TypeScript accept it. Such an error is harmless to this analysis only if
 * it sits entirely inside one properly delimited string literal, which cannot
 * contain code. Anything else stays a parse error.
 */
function isErrorInsideJsxString(node) {
  let n = node.parent;
  while (n && n.type !== 'string') {
    if (n.type === 'jsx_attribute' || n.type === 'program') return false;
    n = n.parent;
  }
  if (!n || !n.parent || n.parent.type !== 'jsx_attribute') return false;
  const text = n.text;
  const q = text[0];
  return (q === '"' || q === "'") && text.length >= 2 && text[text.length - 1] === q && !text.slice(1, -1).includes(q);
}

function isDeclarationIdentifier(node) {
  const p = node.parent;
  if (!p) return false;
  switch (p.type) {
    case 'variable_declarator':
      return field(p, 'name', node);
    case 'function_declaration': case 'function_expression': case 'generator_function_declaration':
    case 'generator_function': case 'class_declaration': case 'class': case 'abstract_class_declaration':
    case 'enum_declaration': case 'module': case 'internal_module':
      return field(p, 'name', node);
    case 'formal_parameters': case 'array_pattern': case 'rest_pattern':
    case 'import_specifier': case 'import_clause': case 'namespace_import': case 'import_require_clause':
    case 'namespace_export':
      return true;
    case 'required_parameter': case 'optional_parameter':
      return field(p, 'pattern', node);
    case 'arrow_function':
      return field(p, 'parameter', node);
    case 'catch_clause':
      return field(p, 'parameter', node);
    case 'pair_pattern':
      return field(p, 'value', node);
    case 'assignment_pattern':
      return field(p, 'left', node);
    case 'for_in_statement':
      return field(p, 'left', node);
    case 'assignment_expression':
      return field(p, 'left', node);
    case 'export_specifier': {
      // `export { x } from 'pkg'` names a remote export, not a local variable.
      const stmt = p.parent && p.parent.parent;
      return Boolean(stmt && stmt.type === 'export_statement' && stmt.childForFieldName('source'));
    }
    default:
      return false;
  }
}

// ---------------------------------------------------------------- per file

/**
 * Analyse one parsed file.
 * @param tree     tree-sitter tree
 * @param source   file text
 * @param file     path relative to project root (used in facts)
 * @param tracked  Set of package install names to follow
 */
export function analyzeTree(tree, source, file, tracked) {
  const lines = source.split(/\r?\n/);
  const lineText = (node) => {
    const t = (lines[node.startPosition.row] || '').trim();
    return t.length > 140 ? t.slice(0, 137) + '...' : t;
  };
  const loc = (node) => ({ file, line: node.startPosition.row + 1, text: lineText(node) });

  const result = {
    imports: [], // { pkg, subpath, form, file, line, text }
    uses: [], // { pkg, subpath, steps, end, endDesc, file, line, text, trail }
    unresolved: [], // package-level: { pkg, code, detail, file, line, text }
    global: [], // project-level: { code, detail, file, line, text }
    parseErrors: [],
    tolerated: [], // grammar errors known not to affect the analysis
    unknownImports: [],
  };

  // ---- one pass over the tree to collect the nodes we care about
  const identifiers = new Map(); // name -> [node] (uses only)
  const shorthands = new Map(); // name -> [node]  ({ x } object literal shorthand)
  const importStmts = [];
  const exportStmts = [];
  const calls = [];
  const news = [];
  const strings = [];
  const evalMembers = [];

  const cursor = tree.walk();
  for (;;) {
    const type = cursor.nodeType;
    if (type === 'ERROR' || cursor.nodeIsMissing) {
      const n = cursor.currentNode;
      if (isErrorInsideJsxString(n)) {
        result.tolerated.push({ ...loc(n), message: "'&' in a JSX attribute string (tree-sitter grammar limitation; the string holds no code)" });
      } else if (result.parseErrors.length < 5) {
        result.parseErrors.push({ ...loc(n), message: type === 'ERROR' ? 'syntax error' : `missing ${type}` });
      }
    }
    switch (type) {
      case 'identifier': {
        const n = cursor.currentNode;
        if (!isDeclarationIdentifier(n)) {
          const list = identifiers.get(n.text);
          if (list) list.push(n); else identifiers.set(n.text, [n]);
        }
        break;
      }
      case 'shorthand_property_identifier': {
        const n = cursor.currentNode;
        const list = shorthands.get(n.text);
        if (list) list.push(n); else shorthands.set(n.text, [n]);
        break;
      }
      case 'import_statement': importStmts.push(cursor.currentNode); break;
      case 'export_statement': exportStmts.push(cursor.currentNode); break;
      case 'call_expression': calls.push(cursor.currentNode); break;
      case 'new_expression': news.push(cursor.currentNode); break;
      case 'string': case 'template_string': strings.push(cursor.currentNode); break;
      case 'member_expression': {
        const n = cursor.currentNode;
        const prop = n.childForFieldName('property');
        if (prop && prop.text === 'eval') evalMembers.push(n);
        break;
      }
      default: break;
    }
    if (cursor.gotoFirstChild()) continue;
    let more = true;
    while (!cursor.gotoNextSibling()) {
      if (!cursor.gotoParent()) { more = false; break; }
    }
    if (!more) break;
  }
  cursor.delete();

  const consumedStrings = new Set(); // module specifiers already handled as imports

  const resolveSpecifier = (spec, node) => {
    if (spec.startsWith('node:')) return { builtin: spec.slice(5) };
    if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('#') || /^[a-zA-Z][a-zA-Z+.-]*:/.test(spec) || /^[a-zA-Z]:[\\/]/.test(spec)) return null;
    const parts = spec.split('/');
    let name; let rest;
    if (spec.startsWith('@')) {
      if (parts.length < 2 || !parts[1]) return null;
      name = `${parts[0]}/${parts[1]}`; rest = parts.slice(2);
    } else {
      name = parts[0]; rest = parts.slice(1);
    }
    const subpath = rest.length ? rest.join('/') : null;
    if (tracked.has(name)) return { pkg: name, subpath };
    if (BUILTINS.has(name) || BUILTINS.has(spec)) return { builtin: name };
    if (node) result.unknownImports.push({ specifier: spec, ...loc(node) });
    return null;
  };

  const flagGlobal = (code, node, detail) => result.global.push({ code, detail, ...loc(node) });
  const flagPkg = (pkg, code, node, detail) => result.unresolved.push({ pkg, code, detail, ...loc(node) });

  // ---- following a value upward through the expression that contains it
  const bindings = [];
  const seenBindings = new Set();

  // Names declared by `export const/let/var/function/class`: anything stored in
  // them is visible to other modules, so storing an imported value there escapes.
  const exportedNames = new Set();
  for (const st of exportStmts) {
    const decl = st.childForFieldName('declaration');
    if (!decl) continue;
    if (decl.type === 'lexical_declaration' || decl.type === 'variable_declaration') {
      for (const d of namedKids(decl)) {
        const nameNode = d.type === 'variable_declarator' && d.childForFieldName('name');
        if (!nameNode) continue;
        const stack = [nameNode];
        while (stack.length) {
          const n = stack.pop();
          if (n.type === 'identifier' || n.type === 'shorthand_property_identifier_pattern') exportedNames.add(n.text);
          else stack.push(...namedKids(n));
        }
      }
    } else {
      const nameNode = decl.childForFieldName('name');
      if (nameNode) exportedNames.add(nameNode.text);
    }
  }

  const MAX_STEPS = 12;
  const addBinding = (name, origin, steps, trail, declNode) => {
    if (exportedNames.has(name)) {
      emitUse(origin, steps, 'escape', `stored in exported variable ${name}`, declNode, trail);
    }
    if (steps.length > MAX_STEPS) {
      emitUse(origin, steps, 'escape', 'alias chain too long to follow', declNode, trail);
      return;
    }
    const key = `${name}|${origin.pkg}|${origin.subpath || ''}|${JSON.stringify(steps)}`;
    if (seenBindings.has(key)) return;
    seenBindings.add(key);
    bindings.push({ name, origin, steps, trail: [...trail, loc(declNode)] });
  };

  const emitUse = (origin, steps, end, endDesc, node, trail) => {
    result.uses.push({ pkg: origin.pkg, subpath: origin.subpath, steps, end, endDesc, ...loc(node), trail });
  };

  /** Destructuring an imported value: const { a, b: c, ...rest } = value */
  const bindPattern = (pattern, origin, steps, trail, siteNode) => {
    if (pattern.type !== 'object_pattern') {
      emitUse(origin, steps, 'escape', `destructured with a ${pattern.type.replace(/_/g, ' ')}`, siteNode, trail);
      return;
    }
    for (const el of namedKids(pattern)) {
      if (el.type === 'shorthand_property_identifier_pattern' || el.type === 'object_assignment_pattern') {
        const id = el.type === 'object_assignment_pattern' ? el.childForFieldName('left') : el;
        if (!id || id.type !== 'shorthand_property_identifier_pattern') {
          emitUse(origin, steps, 'escape', 'destructured with an unsupported pattern', el, trail);
          continue;
        }
        const s = [...steps, { t: 'prop', name: id.text }];
        emitUse(origin, s, 'binding', `bound to ${id.text}`, el, trail);
        addBinding(id.text, origin, s, trail, el);
      } else if (el.type === 'pair_pattern') {
        const keyNode = el.childForFieldName('key');
        let key = null;
        if (keyNode.type === 'property_identifier') key = keyNode.text;
        else if (keyNode.type === 'string' || keyNode.type === 'number') key = keyNode.type === 'string' ? staticString(keyNode) : keyNode.text;
        else if (keyNode.type === 'computed_property_name') key = staticString(namedKids(keyNode)[0]);
        if (key === null) {
          emitUse(origin, steps, 'dynamic', `destructured with computed key ${keyNode.text}`, el, trail);
          continue;
        }
        const s = [...steps, { t: 'prop', name: key }];
        let value = el.childForFieldName('value');
        if (value && value.type === 'assignment_pattern') value = value.childForFieldName('left');
        if (value && value.type === 'identifier') {
          emitUse(origin, s, 'binding', `bound to ${value.text}`, el, trail);
          addBinding(value.text, origin, s, trail, el);
        } else if (value && value.type === 'object_pattern') {
          emitUse(origin, s, 'binding', 'destructured further', el, trail);
          bindPattern(value, origin, s, trail, el);
        } else {
          emitUse(origin, s, 'escape', 'destructured with an unsupported pattern', el, trail);
        }
      } else if (el.type === 'rest_pattern') {
        const id = namedKids(el)[0];
        if (id && id.type === 'identifier') addBinding(id.text, origin, steps, trail, el);
        else emitUse(origin, steps, 'escape', 'collected by a rest pattern', el, trail);
      } else {
        emitUse(origin, steps, 'escape', 'destructured with an unsupported pattern', el, trail);
      }
    }
  };

  /**
   * Walk upward from `start` (an expression whose value is the imported value,
   * or something reached from it by `steps`) and record what happens to it.
   */
  const follow = (start, origin, baseSteps, trail) => {
    const steps = [...baseSteps];
    let cur = start;
    for (;;) {
      const p = cur.parent;
      if (!p) return emitUse(origin, steps, 'harmless', 'end of program', cur, trail);
      if (TRANSPARENT.has(p.type)) { cur = p; continue; }
      if (TYPE_CONTEXTS.has(p.type)) return emitUse(origin, steps, 'harmless', 'type position', cur, trail);
      if (HARMLESS_STATEMENTS.has(p.type)) return emitUse(origin, steps, 'harmless', p.type, cur, trail);
      switch (p.type) {
        case 'member_expression': {
          if (!field(p, 'object', cur)) return emitUse(origin, steps, 'harmless', 'member', cur, trail);
          const prop = p.childForFieldName('property');
          steps.push({ t: 'prop', name: prop.text.replace(/^#/, '') });
          cur = p;
          continue;
        }
        case 'subscript_expression': {
          if (!field(p, 'object', cur)) return emitUse(origin, steps, 'harmless', 'used as a computed key', cur, trail);
          const key = staticString(p.childForFieldName('index'));
          if (key === null) {
            return emitUse(origin, steps, 'dynamic', `indexed with computed key [${p.childForFieldName('index').text}]`, p, trail);
          }
          steps.push({ t: 'prop', name: key });
          cur = p;
          continue;
        }
        case 'call_expression':
          if (field(p, 'function', cur)) { steps.push({ t: 'call' }); cur = p; continue; }
          return emitUse(origin, steps, 'escape', 'used in a call expression', cur, trail);
        case 'new_expression':
          if (field(p, 'constructor', cur)) { steps.push({ t: 'call' }); cur = p; continue; }
          return emitUse(origin, steps, 'escape', 'used in a new expression', cur, trail);
        case 'jsx_opening_element': case 'jsx_self_closing_element':
          if (field(p, 'name', cur)) { steps.push({ t: 'call' }); return emitUse(origin, steps, 'harmless', 'rendered as a JSX component', cur, trail); }
          return emitUse(origin, steps, 'escape', 'used in a JSX element', cur, trail);
        case 'arguments':
          return emitUse(origin, steps, 'escape', 'passed as an argument to a function', cur, trail);
        case 'variable_declarator': {
          const name = p.childForFieldName('name');
          if (!field(p, 'value', cur) || !name) return emitUse(origin, steps, 'escape', 'used in a declaration', cur, trail);
          if (name.type === 'identifier') {
            emitUse(origin, steps, 'alias', `assigned to ${name.text}`, cur, trail);
            addBinding(name.text, origin, steps, trail, p);
            return undefined;
          }
          emitUse(origin, steps, 'binding', 'destructured', cur, trail);
          return bindPattern(name, origin, steps, trail, p);
        }
        case 'assignment_expression': {
          const left = p.childForFieldName('left');
          if (field(p, 'left', cur)) return emitUse(origin, steps, 'harmless', 'assigned to', cur, trail);
          if (left.type === 'identifier') {
            emitUse(origin, steps, 'alias', `assigned to ${left.text}`, cur, trail);
            addBinding(left.text, origin, steps, trail, p);
            return undefined;
          }
          if (left.type === 'object_pattern') {
            emitUse(origin, steps, 'binding', 'destructured', cur, trail);
            return bindPattern(left, origin, steps, trail, p);
          }
          const lt = left.text.replace(/\s+/g, '');
          const desc = /^(module\.)?exports\b/.test(lt) ? `exported via ${lt}` : `assigned to ${lt}`;
          return emitUse(origin, steps, 'escape', desc, cur, trail);
        }
        case 'augmented_assignment_expression':
          if (field(p, 'left', cur)) return emitUse(origin, steps, 'harmless', 'assigned to', cur, trail);
          return emitUse(origin, steps, 'escape', 'combined into another variable', cur, trail);
        case 'binary_expression': {
          const op = p.childForFieldName('operator');
          if (op && LOGICAL_OPERATORS.has(op.type)) return emitUse(origin, steps, 'escape', `combined with ${op.type}`, cur, trail);
          return emitUse(origin, steps, 'harmless', 'compared or coerced', cur, trail);
        }
        case 'ternary_expression':
          if (field(p, 'condition', cur)) return emitUse(origin, steps, 'harmless', 'condition', cur, trail);
          return emitUse(origin, steps, 'escape', 'chosen by a conditional expression', cur, trail);
        case 'sequence_expression': {
          const kids = namedKids(p);
          if (kids[kids.length - 1].id !== cur.id) return emitUse(origin, steps, 'harmless', 'discarded', cur, trail);
          return emitUse(origin, steps, 'escape', 'value of a comma expression', cur, trail);
        }
        case 'for_in_statement':
          if (field(p, 'left', cur)) return emitUse(origin, steps, 'harmless', 'loop target', cur, trail);
          return emitUse(origin, steps, 'escape', 'iterated over', cur, trail);
        case 'return_statement': case 'arrow_function':
          return emitUse(origin, steps, 'escape', 'returned from a function', cur, trail);
        case 'pair': case 'object':
          return emitUse(origin, steps, 'escape', 'stored in an object literal', cur, trail);
        case 'array':
          return emitUse(origin, steps, 'escape', 'stored in an array', cur, trail);
        case 'spread_element':
          return emitUse(origin, steps, 'escape', 'spread into another value', cur, trail);
        case 'export_statement': case 'export_specifier': case 'export_clause':
          return emitUse(origin, steps, 'escape', 'exported from the module', cur, trail);
        case 'jsx_expression':
          return emitUse(origin, steps, 'escape', 'passed as a JSX prop or child', cur, trail);
        case 'class_heritage':
          return emitUse(origin, steps, 'escape', 'extended by a class', cur, trail);
        default:
          return emitUse(origin, steps, 'escape', `used as part of ${p.type.replace(/_/g, ' ')}`, cur, trail);
      }
    }
  };

  // ---- imports and re-exports
  for (const st of importStmts) {
    const typeOnly = hasAnonChild(st, 'type');
    let source = st.childForFieldName('source');
    const requireClause = namedKids(st).find((c) => c.type === 'import_require_clause');
    if (!source && requireClause) source = requireClause.childForFieldName('source') || namedKids(requireClause).find((c) => c.type === 'string');
    if (!source) continue;
    consumedStrings.add(source.id);
    const spec = staticString(source);
    if (spec === null || typeOnly) continue;
    const r = resolveSpecifier(spec, st);
    if (r && r.builtin === 'vm') flagGlobal('eval_present', st, 'imports the vm module, which can run code built from strings');
    if (!r || !r.pkg) continue;
    const origin = { pkg: r.pkg, subpath: r.subpath };
    const site = loc(st);
    result.imports.push({ ...origin, form: 'esm', ...site });

    if (requireClause) {
      const id = namedKids(requireClause).find((c) => c.type === 'identifier');
      if (id) addBinding(id.text, origin, [], [], st);
      continue;
    }
    const clause = namedKids(st).find((c) => c.type === 'import_clause');
    if (!clause) continue; // side-effect import: import 'pkg'
    for (const part of namedKids(clause)) {
      if (part.type === 'identifier') {
        addBinding(part.text, origin, [], [], st); // default import = the module's main export
      } else if (part.type === 'namespace_import') {
        const id = namedKids(part).find((c) => c.type === 'identifier');
        if (id) addBinding(id.text, origin, [], [], st);
      } else if (part.type === 'named_imports') {
        for (const spec2 of namedKids(part)) {
          if (spec2.type !== 'import_specifier' || hasAnonChild(spec2, 'type')) continue;
          const nameNode = spec2.childForFieldName('name');
          const aliasNode = spec2.childForFieldName('alias');
          const imported = nameNode.type === 'string' ? staticString(nameNode) : nameNode.text;
          const local = (aliasNode || nameNode).text;
          const steps = imported === 'default' ? [] : [{ t: 'prop', name: imported }];
          if (steps.length) emitUse(origin, steps, 'binding', `imported as ${local}`, spec2, []);
          addBinding(local, origin, steps, [], st);
        }
      }
    }
  }

  for (const st of exportStmts) {
    const source = st.childForFieldName('source');
    if (!source) continue;
    consumedStrings.add(source.id);
    if (hasAnonChild(st, 'type')) continue;
    const spec = staticString(source);
    if (spec === null) continue;
    const r = resolveSpecifier(spec, st);
    if (!r || !r.pkg) continue;
    const origin = { pkg: r.pkg, subpath: r.subpath };
    result.imports.push({ ...origin, form: 're-export', ...loc(st) });
    const ns = namedKids(st).find((c) => c.type === 'namespace_export');
    const clause = namedKids(st).find((c) => c.type === 'export_clause');
    if (ns) {
      emitUse(origin, [], 'escape', 're-exported as a namespace', st, []);
    } else if (clause) {
      for (const es of namedKids(clause)) {
        if (es.type !== 'export_specifier' || hasAnonChild(es, 'type')) continue;
        const nameNode = es.childForFieldName('name');
        const name = nameNode ? (nameNode.type === 'string' ? staticString(nameNode) : nameNode.text) : 'default';
        const steps = name === 'default' ? [] : [{ t: 'prop', name }];
        emitUse(origin, steps, 'escape', 're-exported', es, []);
      }
    } else {
      flagPkg(r.pkg, 'reexport_all', st, `export * from '${spec}'`);
    }
  }

  // ---- require(), import(), createRequire, eval-like calls
  const requireNames = new Set(['require']);
  for (const c of calls) {
    const fn = c.childForFieldName('function');
    const isCreateRequire = fn && ((fn.type === 'identifier' && fn.text === 'createRequire') ||
      (fn.type === 'member_expression' && fn.childForFieldName('property').text === 'createRequire'));
    if (!isCreateRequire) continue;
    let p = c.parent;
    while (p && TRANSPARENT.has(p.type)) p = p.parent;
    if (p && p.type === 'variable_declarator' && p.childForFieldName('name').type === 'identifier') {
      requireNames.add(p.childForFieldName('name').text);
    } else if (!(p && p.type === 'call_expression')) {
      flagGlobal('require_escapes', c, 'a require function made by createRequire is stored or passed in a way this analysis cannot follow');
    }
  }

  const isRequireCallee = (fn) => {
    if (!fn) return false;
    if (fn.type === 'identifier') return requireNames.has(fn.text);
    if (fn.type === 'member_expression') {
      const obj = fn.childForFieldName('object');
      return obj.type === 'identifier' && obj.text === 'module' && fn.childForFieldName('property').text === 'require';
    }
    if (fn.type === 'call_expression') {
      const inner = fn.childForFieldName('function');
      return Boolean(inner && ((inner.type === 'identifier' && inner.text === 'createRequire') ||
        (inner.type === 'member_expression' && inner.childForFieldName('property').text === 'createRequire')));
    }
    return false;
  };

  const handleLoad = (callNode, kind) => {
    const arg = namedKids(callNode.childForFieldName('arguments') || callNode)[0];
    const spec = staticString(arg);
    if (spec === null) {
      const prefix = staticPrefix(arg);
      const m = prefix && resolveSpecifier(prefix.replace(/\/[^/]*$/, '') || prefix, null);
      if (m && m.pkg && prefix.startsWith(m.pkg + '/')) {
        flagPkg(m.pkg, 'dynamic_subpath', callNode, `${kind}() loads a computed subpath of ${m.pkg}`);
      } else {
        flagGlobal(kind === 'require' ? 'dynamic_require' : 'dynamic_import', callNode,
          `${kind}() is called with a non-literal argument (${arg ? arg.text.slice(0, 60) : 'nothing'})`);
      }
      return;
    }
    consumedStrings.add(arg.id);
    const r = resolveSpecifier(spec, callNode);
    if (r && r.builtin === 'vm') flagGlobal('eval_present', callNode, 'loads the vm module, which can run code built from strings');
    if (!r || !r.pkg) return;
    const origin = { pkg: r.pkg, subpath: r.subpath };
    result.imports.push({ ...origin, form: kind, ...loc(callNode) });
    if (kind === 'require') {
      follow(callNode, origin, [], []);
      return;
    }
    // import(): the value is a promise of the module namespace.
    let p = callNode.parent;
    let top = callNode;
    while (p && p.type === 'parenthesized_expression') { top = p; p = p.parent; }
    if (p && p.type === 'await_expression') {
      follow(top, origin, [], []);
    } else {
      flagPkg(r.pkg, 'dynamic_import_promise', callNode, `import('${spec}') is not directly awaited`);
    }
  };

  for (const c of calls) {
    const fn = c.childForFieldName('function');
    if (!fn) continue;
    if (fn.type === 'import') { handleLoad(c, 'import'); continue; }
    if (isRequireCallee(fn)) { handleLoad(c, 'require'); continue; }
    if (fn.type === 'identifier' && fn.text === 'Function') flagGlobal('eval_present', c, 'Function(...) builds code from strings');
    if (fn.type === 'member_expression' && fn.childForFieldName('property').text === 'constructor') {
      flagGlobal('eval_present', c, '.constructor(...) call, which can be the Function constructor');
    }
    const timerName = fn.type === 'identifier' ? fn.text : fn.type === 'member_expression' ? fn.childForFieldName('property').text : null;
    if (timerName && TIMER_FUNCTIONS.has(timerName)) {
      const first = namedKids(c.childForFieldName('arguments'))[0];
      if (first && (first.type === 'string' || first.type === 'template_string' || first.type === 'binary_expression')) {
        flagGlobal('eval_present', c, `${timerName}() with a string argument evaluates that string as code`);
      }
    }
  }
  for (const n of news) {
    const ctor = n.childForFieldName('constructor');
    if (ctor && ctor.type === 'identifier' && ctor.text === 'Function') flagGlobal('eval_present', n, 'new Function(...) builds code from strings');
  }
  for (const id of identifiers.get('eval') || []) flagGlobal('eval_present', id, 'eval is used');
  for (const m of evalMembers) {
    const obj = m.childForFieldName('object');
    if (obj && obj.type === 'identifier' && GLOBAL_OBJECTS.has(obj.text)) flagGlobal('eval_present', m, `${obj.text}.eval is used`);
  }

  // `require` used as a value (aliased, passed around) hides loads from us.
  for (const name of requireNames) {
    for (const id of identifiers.get(name) || []) {
      const p = id.parent;
      if (p.type === 'call_expression' && field(p, 'function', id)) continue;
      if (p.type === 'member_expression' && field(p, 'object', id)) {
        const prop = p.childForFieldName('property').text;
        if (!['call', 'apply', 'bind'].includes(prop)) continue; // require.resolve / .cache / .main
      }
      if (p.type === 'unary_expression' || p.type === 'binary_expression') continue; // typeof require, require === x
      flagGlobal('require_escapes', id, `${name} is used as a value (${p.type.replace(/_/g, ' ')}), so some module loads may be hidden`);
    }
  }

  // ---- follow every binding (imports, aliases, destructured names)
  for (let i = 0; i < bindings.length; i++) {
    const b = bindings[i];
    for (const id of identifiers.get(b.name) || []) {
      follow(id, b.origin, b.steps, b.trail);
    }
    for (const sh of shorthands.get(b.name) || []) {
      emitUse(b.origin, b.steps, 'escape', 'stored in an object literal', sh, b.trail);
    }
  }

  // ---- package names that appear as plain strings (alias maps, plugin names, mocks, ...)
  for (const s of strings) {
    if (consumedStrings.has(s.id)) continue;
    if (s.parent && (s.parent.type === 'module' || s.parent.type === 'import_require_clause')) continue;
    const v = staticString(s);
    if (!v || v.length > 214) continue;
    const r = resolveSpecifier(v, null);
    if (r && r.pkg && (v === r.pkg || v.startsWith(r.pkg + '/'))) {
      flagPkg(r.pkg, 'name_as_string', s, `the string '${v}' appears outside an import`);
    }
  }

  return result;
}

// ---------------------------------------------------------------- project

function readJsonc(file) {
  const text = fs.readFileSync(file, 'utf8').replace(/^﻿/, '');
  // Strip comments outside strings, then trailing commas.
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j;
    } else if (ch === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
    } else if (ch === '/' && text[i + 1] === '*') {
      i = text.indexOf('*/', i + 2);
      if (i === -1) break;
      i++;
    } else {
      out += ch;
    }
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'));
}

function collectStrings(value, out) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => collectStrings(v, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => collectStrings(v, out));
  return out;
}

/** Alias configuration that can map an import specifier onto a dependency. */
function scanAliasConfigs(root, packageJson, tracked, warnings) {
  const flags = [];
  const sources = [];
  for (const name of ['tsconfig.json', 'jsconfig.json']) {
    const file = path.join(root, name);
    if (!fs.existsSync(file)) continue;
    try {
      const cfg = readJsonc(file);
      const paths = cfg && cfg.compilerOptions && cfg.compilerOptions.paths;
      if (paths) sources.push({ file: name, targets: collectStrings(paths, []) });
      if (cfg && cfg.extends) warnings.push(`${name} extends another config; path aliases defined there were not checked`);
    } catch (err) {
      warnings.push(`could not parse ${name} (${err.message}); path aliases in it were not checked`);
    }
  }
  if (packageJson && packageJson.imports) sources.push({ file: 'package.json#imports', targets: collectStrings(packageJson.imports, []) });
  for (const src of sources) {
    for (const t of src.targets) {
      for (const pkg of tracked) {
        if (t === pkg || t.startsWith(pkg + '/') || t.includes(`node_modules/${pkg}`)) {
          flags.push({ pkg, code: 'alias_config', detail: `${src.file} maps an alias to '${t}'`, file: src.file, line: null, text: t });
        }
      }
    }
  }
  return flags;
}

/**
 * Scan a whole project.
 * @returns {{ filesScanned, imports, uses, unresolved, global, parseErrors, fileErrors, unknownImports, warnings }}
 */
export async function extractUsage(root, { tracked, packageJson } = {}) {
  const parse = await createParser();
  const { files, skippedLinks } = listSourceFiles(root);
  const out = {
    filesScanned: 0, files: [], imports: [], uses: [], unresolved: [], global: [], parseErrors: [], tolerated: [], fileErrors: [], unknownImports: [], warnings: [],
  };
  if (skippedLinks.length) out.warnings.push(`symbolic links were not followed: ${skippedLinks.slice(0, 5).join(', ')}${skippedLinks.length > 5 ? ', ...' : ''}`);

  for (const { file, error } of files) {
    const rel = path.relative(root, file).split(path.sep).join('/');
    if (error) { out.fileErrors.push({ file: rel, message: error }); continue; }
    let source;
    try {
      source = fs.readFileSync(file, 'utf8');
    } catch (err) {
      out.fileErrors.push({ file: rel, message: `cannot read: ${err.code || err.message}` });
      continue;
    }
    let tree;
    try {
      tree = parse(source, file);
    } catch (err) {
      out.parseErrors.push({ file: rel, line: null, text: '', message: err.message });
      continue;
    }
    try {
      const r = analyzeTree(tree, source, rel, tracked);
      out.filesScanned++;
      out.files.push(rel);
      for (const k of ['imports', 'uses', 'unresolved', 'global', 'parseErrors', 'tolerated', 'unknownImports']) out[k].push(...r[k]);
    } finally {
      tree.delete();
    }
  }
  if (out.tolerated.length) {
    const where = out.tolerated.slice(0, 5).map((t) => `${t.file}:${t.line}`).join(', ');
    out.warnings.push(`${out.tolerated.length} tree-sitter error(s) inside JSX attribute strings were tolerated (a bare '&' in a quoted string, e.g. a URL query; the string holds no code): ${where}${out.tolerated.length > 5 ? ', ...' : ''}`);
  }
  out.unresolved.push(...scanAliasConfigs(root, packageJson, tracked, out.warnings));
  return out;
}
