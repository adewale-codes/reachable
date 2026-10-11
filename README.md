# reachable

A local CLI that takes a JavaScript/TypeScript npm project and tells you which of
its dependency vulnerability alerts your code can actually trigger. Every alert
gets one of three verdicts, always with evidence:

| verdict       | meaning |
|---------------|---------|
| `reachable`   | Your source contains a reference to a function the advisory names. Evidence: the `file:line` chain from the import to the use. |
| `unreachable` | Proven: the package is imported, every import and use was resolved statically, nothing escaped the analysis, and no affected function is referenced. Evidence: the import sites and how many uses were checked. |
| `cant_tell`   | Anything else. Always with a machine-readable reason code and a plain-English explanation. |

**The rule the design follows:** a false `unreachable` tells a developer a real
vulnerability is safe to ignore, so it is the worst possible output.
`unreachable` is never a default. It is returned only when the list of reasons
to doubt it is empty. When part of a scan cannot run, the tool exits 2 and says
so; it never prints a clean report over a partial scan.

Phase 1 status: CLI and library. No LLM, no GitHub Action, no web UI, no MCP.

## Usage

```sh
npm install
node bin/reachable.js scan path/to/project            # readable report
node bin/reachable.js scan path/to/project --json     # machine-readable
```

| option | effect |
|---|---|
| `--json` | JSON report on stdout (shape below) |
| `--strict` | `cant_tell` also makes the exit code 1 |
| `--offline` | use only cached OSV data; fail (exit 2) if anything is missing |
| `--cache-dir <dir>` | OSV cache location (default `%LOCALAPPDATA%\reachable\cache`, `$XDG_CACHE_HOME/reachable` or `~/.cache/reachable`; or `$REACHABLE_CACHE_DIR`) |
| `--verbose` | more evidence lines per alert |

Exit codes: **0** nothing reachable · **1** at least one alert reachable (or
`cant_tell` with `--strict`) · **2** the scan could not complete.

Exit 2 cases: missing or invalid `package.json` / `package-lock.json`, a
lockfileVersion other than 2 or 3, a declared dependency missing from the
lockfile, OSV unreachable with nothing cached, a source file that does not
parse, an unreadable source file. Fatal errors print `SCAN FAILED` and no
report. Parse and read errors still print the report, framed by a
`SCAN INCOMPLETE` banner, with every would-be `unreachable` downgraded to
`cant_tell / parse_error`.

`REACHABLE_OSV_URL` overrides the OSV endpoint. It exists for testing outage
handling.

Library: `import { scan, exitCodeFor, formatText } from 'reachable'`.

## Scope (Phase 1)

- Source: `.js .mjs .cjs .jsx .ts .mts .cts .tsx` (`.d.ts` skipped; it has no
  runtime code). Every directory except `node_modules` and VCS folders is scanned.
- Projects: npm with `package.json` + `package-lock.json` (lockfileVersion 2 or 3).
- Direct dependencies (declared in `dependencies`, `devDependencies`,
  `optionalDependencies` or `peerDependencies` and installed at the top level)
  are analysed. Every other installed instance is listed as `cant_tell` /
  `transitive_not_analysed`, with the packages that require it.
- Advisories come from OSV.dev (`/v1/querybatch`, then `/v1/vulns/{id}`), cached
  on disk. Online scans query OSV first and fall back to the cache with a
  warning if OSV is down. Advisory details are reused from the cache while
  their `modified` timestamp is unchanged.
- Affected-function data is hand-curated (`data/advisories.json`). No LLM reads
  advisory text, so the accuracy measured below is the analysis itself.

## How it works

```
package-lock.json ──► inventory.js ──► instances (name@version, direct?)
                                            │
source files ──► usage.js (tree-sitter) ──► facts: imports, uses, unresolved, global flags
                                            │
OSV.dev / cache ──► osv.js ──► advisory ids + records
                                            │
data/advisories.json ──► verdict.js ──► one verdict per (advisory, installed instance)
                                            │
                                     format.js / bin/reachable.js
```

**Usage extraction** (`src/usage.js`) finds every import site of a tracked
package: `import x / {a, b as c} / * as ns`, `import x = require()` (TS),
`require()`, `module.require()`, `createRequire()` results, awaited `import()`,
and `export … from`. It then follows each imported value upward through the
expression that contains it: member access (`x.a`, `x['a']`, `` x[`a`] ``,
`x?.a`, statically concatenated keys), calls, `new`, TS wrappers (`as`, `!`,
`satisfies`, `<T>x`), `await`, aliases (`const y = x`), and object
destructuring including renames, nested patterns and rest. Matching is by name
within a file. There is no scope analysis, so shadowed names are
over-approximated: this can only add facts, never hide one. Type-only imports
are ignored because they are erased at compile time.

Anything the extractor cannot follow is recorded as a fact rather than dropped:
a computed key, the module object being passed / returned / exported / stored /
spread / combined with `||`, a dynamic `require`/`import`, `require` itself
being aliased, `export *`, eval-like code, or the package name appearing as a
plain string.

**Verdicts** (`src/verdict.js`) classify each use against the advisory's
affected symbols. Each use is walked step by step from the module's main export:

- the first property is an affected symbol → **reference** (reachable)
- calling the module itself → reference if the advisory's symbol is
  `(module)`, otherwise a **gateway** (its return value may expose everything)
- the first property is a curated gateway (`_.chain`, `_.runInContext`,
  `lodash/fp`, …) → reachable if a later property is affected, else `gateway_used`
- an affected name read off the return value of an unrelated export → `indirect_reference`
- the bare module object escaping → `module_escapes`; computed key on it → `dynamic_member_access`

`unreachable` requires all of: direct dependency, curated symbol data, at least
one import site, every deep import mapped, no escapes, no dynamic access, no
gateway use, no project-wide dynamic loading / eval / `require` aliasing, every
file parsed, and no reference to any affected symbol.

### Reason codes

| code | meaning |
|---|---|
| `transitive_not_analysed` | only a transitive dependency; Phase 1 does not follow code paths through other packages |
| `no_symbol_data` | no curated affected-function data for this advisory (or it was excluded on purpose) |
| `parse_error` / `file_unreadable` | some source could not be analysed (also makes the scan exit 2) |
| `no_import_found` | direct dependency that no scanned file imports (see open questions) |
| `module_escapes` | the module object is passed, returned, exported, stored or spread somewhere |
| `dynamic_member_access` | the module is indexed with a computed key, like `lib[name]` |
| `gateway_used` | a call returning an object that exposes the package's functions (e.g. `_.chain`, `_()`) |
| `indirect_reference` | an affected name is read from a value obtained through the package |
| `unmapped_subpath` | a deep import (`pkg/x`) with no mapping to exports |
| `dynamic_subpath` | a computed deep import (`require('pkg/' + x)`) |
| `dynamic_import_promise` | `import('pkg')` not directly awaited |
| `reexport_all` | `export * from 'pkg'` |
| `alias_config` | tsconfig/jsconfig `paths` or package.json `imports` map onto the package |
| `name_as_string` | the package name appears as a string outside an import (bundler alias, plugin name, `jest.mock`, …) |
| `dynamic_require` / `dynamic_import` | non-literal `require()` / `import()` anywhere in the project |
| `require_escapes` | `require` itself is aliased or passed around |
| `eval_present` | `eval`, `Function`, `.constructor(...)`, string timers or the `vm` module anywhere in the project |

### Curated advisory data

`data/advisories.json` holds 15 advisories across 6 packages: lodash (8),
minimist (2), jsonwebtoken (2), json5, underscore, trim-newlines. Each entry
quotes the advisory text it was based on and links its source. `(module)` means
"calling the package's main export". Advisories whose text names a function, but
where other public exports reach the same vulnerable code, were deliberately
**excluded** and are listed with the reason. Example: lodash's ReDoS advisory
names `toNumber`/`trim`/`trimEnd`, but `toNumber` is called internally by
`toInteger`/`toFinite` and by `debounce`, among many others. A three-name list
would have turned real uses into false `unreachable`.

The data also records per-package facts: lodash and underscore **gateways**, and
the lodash deep-import layout (`lodash/<name>` = `_.<name>`, `_`-prefixed files
are internal and never mapped).

## Ground-truth benchmark

```sh
npm run bench     # offline, deterministic: uses recorded OSV responses in bench/osv-cache
npm test          # 90 tests: 79 analyser tests (72 adversarial source snippets) + 11 CLI exit-code tests
npm run bench:record   # re-record OSV responses (network); re-label if the advisory list changed
```

`bench/fixtures/` has 22 small projects, each with a `package.json`, a real
npm-generated `package-lock.json`, source files and a hand-written
`expected.json`. Each advisory carries two labels:

- **`expected`**: the verdict the tool must give (pass/fail)
- **`truth`**: whether the fixture code can actually trigger the advisory,
  judged by reading it. This separates "the tool followed its rules" from "the
  tool was right", and shows what `cant_tell` costs.

The fixtures cover: named import, default import with member call, aliased
import, destructured require, namespace import (TS), unaffected function of a
vulnerable package, dynamic require, computed member access, module object
escaping to another file, `export *`, named re-export, transitive-only package,
advisory with no symbol data, calling the module itself (minimist), never
imported, eval present, TS `import = require` + type-only import + TSX, chain
gateways, lodash deep imports, underscore, trim-newlines.

Result (2026-10-11):

```
22 fixtures, 95 labelled advisory alerts, 95 match expected verdict

Confusion matrix: ground truth (rows) vs tool verdict (columns)
  truth           →reachable →unreachable   →cant_tell   total
  reachable               18            0           14      32
  unreachable              0           27           35      62
  unknown                  0            0            1       1

False "unreachable" (tool said unreachable, truth is not): 0
False "reachable" (tool said reachable, truth is unreachable): 0
```

How to read this honestly: the fixtures were written by the same author as the
analyser, so passing them shows the rules behave as designed on these
patterns. It does not establish a real-world accuracy rate. The 35
"truly unreachable → cant_tell" cells are the price of the conservative rules
(no symbol data, no import found, eval elsewhere, gateways, transitive).

## Real-project check (2026-10-11)

Three small public projects, chosen because they pin affected versions of
curated packages, were scanned live against OSV. Every `reachable` and
`unreachable` verdict was then checked by reading the code. This is a sample of
3 projects and 8 such verdicts, so it supports statements about those verdicts,
not an accuracy percentage.

| project (commit) | verdicts checked | manual reading |
|---|---|---|
| [desirekaleba/node-mysql-jwt-auth](https://github.com/desirekaleba/node-mysql-jwt-auth) (`23bccd6`) | 2 × `reachable`: jsonwebtoken 8.5.1 `verify` (GHSA-hjrf-2m68-5959, GHSA-qwph-4952-7xr6) | Correct per definition: `jwt.verify(token, JWT_SECRET_KEY)` at `src/utils/token.js:9`. **But** it sits inside the exported `decode()`, which nothing in the repo imports. So it is referenced, not invoked by any route. Phase 1 has no call graph, so a reference in dead code counts as reachable. |
| [odynvolk/omit-deep-lodash](https://github.com/odynvolk/omit-deep-lodash) (`3d4c5ef`) | 2 × `reachable`: lodash 4.17.21 `omit` (GHSA-xxjr-mmjv-4gpg, GHSA-f23m-r3pf-42rh); 1 × `unreachable`: `template` (GHSA-r5fr-rjxr-66jc) | Correct. `require("lodash/omit")` then `omit(o, props)` with caller-supplied keys (`src/index.js:22`). `lodash/omit` is the only lodash import, and its own requires (checked in lodash 4.17.21) never load `template`. |
| [SashenJayathilaka/Spotify-Clone](https://github.com/SashenJayathilaka/Spotify-Clone) (`02cd054`) | 3 × `unreachable`: lodash 4.17.21 template, unset/omit (×2) | Correct. The only lodash uses are `import { shuffle }` (`components/Center.js:3`) and `import { debounce }` (`components/Player.js:4`); neither reaches `template`, `unset` or `omit`. |

Everything else in these projects was `cant_tell`, mostly
`transitive_not_analysed` (193 alerts) and `no_symbol_data` (38: express, joi,
morgan, next, next-auth, postcss, jsonwebtoken's uncurated advisory).

The Spotify-Clone scan first exited 2. tree-sitter-javascript rejects a bare `&`
inside a JSX attribute string (`href="…?rik=…&pid=ImgRaw&r=0"`), which Babel
and TypeScript accept. That case alone is now tolerated, and only when the error
lies entirely inside one properly delimited string literal (which cannot
contain code). It is reported as a warning naming each location. All other
parse errors remain fatal.

## Network failure check

- **No network, no cache:** simulated two ways: (a) DNS resolution failing
  for the whole process (`EAI_AGAIN`, as on an offline machine), and (b) OSV
  pointed at a closed local port (`ECONNREFUSED`). Both printed
  `SCAN FAILED [osv_unavailable] … no cached OSV result …`, produced no report,
  and exited 2. This was a simulation; the machine's network adapter was not
  disabled.
- **No network, warm cache:** the report runs and its header says
  `advisories from local cache (OSV unreachable: …)`, plus a warning that
  advisories published since the cache was filled are missing.
- **Live path + cache:** a scan of `bench/fixtures/05-namespace-import` against
  api.osv.dev with an empty cache fetched 15 package queries and 3 advisory
  records. A second online run reused all 3 records from cache (unchanged
  `modified`), and an `--offline` run produced identical verdicts.

## Dependencies

Runtime dependencies are exactly tree-sitter and its two grammars:

| package | why |
|---|---|
| `web-tree-sitter` | The tree-sitter parser runtime, compiled to WebAssembly. Chosen over the native `tree-sitter` binding because it needs no C++ toolchain on any platform. The native JS (0.25) and TS (0.23) grammar bindings also require incompatible native `tree-sitter` peer versions. |
| `tree-sitter-javascript` | JavaScript + JSX grammar; its shipped `.wasm` file is loaded. |
| `tree-sitter-typescript` | TypeScript and TSX grammars; its shipped `.wasm` files are loaded. |

Note: the two grammar packages declare `node-addon-api` and `node-gyp-build`
(for their own native bindings, with prebuilt binaries) and run a small install
script. `reachable` never loads those bindings. Everything else uses Node
built-ins (`fetch`, `fs`, `node:test`). Node ≥ 18.17.

## npm name

`reachable` is **taken** on npm (v0.1.5 by another author, last modified 2022).
`package.json` is marked `"private": true` so it cannot be published by
accident. Alternatives:

- scoped: `@<your-npm-user>/reachable` (e.g. `@adewale-codes/reachable` if that is your npm username), or `@reachable/cli` (needs creating an npm org named `reachable`)
- unscoped and currently unregistered: `reachable-cli`, `vuln-reachable`, `js-reachable`, `reachable-vulns`

## Limitations

- No call graph: a reference to an affected function in dead code counts as
  reachable (see the jsonwebtoken example above). Reachable means "referenced",
  not "proven executed" or "exploitable"; advisory preconditions (e.g. "a falsy
  secret") are not checked.
- No cross-module data flow inside the project: when the module object leaves
  a file the result is `cant_tell`, not a deeper analysis.
- Return values of non-gateway exports are not tracked. Soundness for those
  depends on the curated gateway list being complete for the package.
- The curated data is only as complete as the curator's reading of the
  advisory and package source; each entry records its evidence for review.
- Bundler aliases defined in JS config files are caught only through the
  `name_as_string` rule (the config contains the package name as a string).
  `tsconfig` `extends` chains are not followed (a warning says so).
- Deliberately obfuscated loading (e.g. a computed `require` reached through
  `globalThis[...]` with a computed name) is out of scope.
- Workspaces: only the root `package.json` defines direct dependencies.

## Open questions for Phase 2

- **Never-imported direct dependencies.** Phase 1 answers `cant_tell` /
  `no_import_found`, because the package may be used by its CLI binary, an npm
  script, a config file or a file that was not scanned. Phase 2 could inspect
  `scripts`, known config files and `bin` usage to prove more of these
  `unreachable`.
- **Transitive dependencies.** Following paths through direct dependencies
  needs curated (or analysed) knowledge of which of the direct dependency's
  exports reach the transitive one.
- **Dead code.** A project-level call graph would separate "referenced" from
  "called from an entry point".
- **Scaling symbol data.** Curating by hand does not scale. Any automated
  source must keep the "excluded unless the full entry-point set is known" rule
  that this phase applies.
