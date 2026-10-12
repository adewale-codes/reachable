# reachable

A local CLI that takes a JavaScript/TypeScript npm project and tells you which of
its dependency vulnerability alerts your code can actually trigger. Every alert
gets one of three verdicts, always with evidence:

| verdict       | meaning |
|---------------|---------|
| `reachable`   | Your own source code contains a reference to a function the advisory names. Evidence: the `file:line` chain from the import to the use. |
| `unreachable` | Proven: every piece of code that can load the vulnerable package (your code, and every installed package that loads it) was resolved statically, nothing escaped the analysis, and no affected function is referenced. Evidence: import sites, loaders checked, dependency paths. |
| `cant_tell`   | Anything else. Always with machine-readable reason codes and a plain-English explanation. |

Every alert is also tagged `scope: prod | dev`. That tag is a fact, not a verdict.

**The rule the design follows:** a false `unreachable` tells a developer a real
vulnerability is safe to ignore, so it is the worst possible output.
`unreachable` is never a default. It is returned only when the list of reasons
to doubt it is empty. When part of a scan cannot run, the tool exits 2 and says
so; it never prints a clean report over a partial scan. When an optional Phase 2
step cannot run (no `node_modules`, no API key, LLM output rejected), the
affected alerts stay `cant_tell` with a reason code and the report says so once.

Status: Phase 2. CLI and library. No GitHub Action, web UI or MCP.

## Usage

```sh
npm install
node bin/reachable.js scan path/to/project            # readable report
node bin/reachable.js scan path/to/project --json     # machine-readable
```

| option | effect |
|---|---|
| `--json` | JSON report on stdout |
| `--strict` | `cant_tell` also makes the exit code 1 |
| `--offline` | use only cached OSV data (and only recorded LLM answers); fail (exit 2) if OSV data is missing |
| `--cache-dir <dir>` | cache location (default `%LOCALAPPDATA%\reachable\cache`, `$XDG_CACHE_HOME/reachable` or `~/.cache/reachable`; or `$REACHABLE_CACHE_DIR`). LLM answers go in `<dir>/llm`. |
| `--prod-only` | hide alerts on packages reachable only from `devDependencies`. Hides; never changes a verdict. The report says how many were hidden. |
| `--no-llm` | never use LLM symbol extraction, even with a key |
| `--llm-cache-only` | use recorded LLM answers only, no API calls |
| `--no-transitive` | do not analyse packages in `node_modules` |
| `--verbose` | more evidence lines per alert |

| environment | effect |
|---|---|
| `ANTHROPIC_API_KEY` | optional. Enables LLM extraction for advisories with no curated data. Without it the tool behaves like Phase 1 for those advisories and says so once. |
| `REACHABLE_LLM_MODEL` | extraction model (default `claude-opus-5`) |
| `REACHABLE_OSV_URL`, `REACHABLE_LLM_URL` | endpoint overrides, for testing outage handling |

Exit codes are unchanged from Phase 1: **0** nothing reachable · **1** at least
one alert reachable (or `cant_tell` with `--strict`) · **2** the scan could not
complete (bad lockfile, OSV unavailable with no cache, unparseable or unreadable
project source). A missing `node_modules`, a missing API key, an LLM failure, or
an unparseable file inside `node_modules` are not scan failures. They leave the
affected alerts at `cant_tell` with a reason code.

Library: `import { scan, exitCodeFor, formatText } from 'reachable'`.

## How it works

```
package-lock.json ─► inventory.js ─► installed instances, dependency graph, scope (prod/dev)
project source ────► usage.js (tree-sitter) ─► how the project's code uses each package
OSV.dev / cache ───► osv.js ─► advisories per instance
data/advisories.json ─────────────► curated affected symbols          (tier: curated)
advisory text ──► llm.js ─► guard ─► LLM-extracted affected symbols   (tier: llm)
node_modules ──► transitive.js / packages.js ─► how every installed loader uses the instance
                         └──────────────► verdict.js ─► one verdict per (advisory, instance)
```

### The loader model (Phase 2)

An installed instance (say `node_modules/lodash@4.17.20`) can be loaded by:

- **the project's own code**, which is analysed exactly as in Phase 1;
- **every installed package that loads it**: its declared dependents in the
  lockfile, plus packages that `require` it *without declaring it* (which
  works through hoisting). The second group is found by a text search of
  `node_modules` for the quoted name. A candidate is kept only when the parser
  finds the name in its code, since a comment loads nothing, and only when
  Node resolution from that package actually lands on this instance.

For each loader package, `reachable` parses the files that can run when the
package is loaded:

- with an `exports` map: the static closure of the exported entry points
  (plus `main`/`module`/`browser`);
- without one: every file, because consumers may deep-import any of them;
- in both cases, files reachable only from the package's `bin` are left out
  unless a project npm script runs that bin;
- if the closure cannot be computed reliably (wildcard exports, an `imports`
  map, an unresolvable relative import), every file.

It then applies the same strict Phase 1 test to that code.

`unreachable` requires the project edge (if the project loads it) **and every
loader edge** to pass. If any loader references an affected symbol, the alert
is `cant_tell / transitive_parent_uses_symbol`, never `reachable`: whether your
code reaches that part of the dependency is a call-graph question for Phase 3.
The developer's own code is different. If your code calls the function of a
package you only get transitively (an undeclared "phantom" dependency), that
is `reachable`, because the reference is in your source.

**This closes a Phase 1 blind spot.** Phase 1 judged a *direct* dependency only
by your code. But npm dedupes, so other installed packages usually share the
same copy. Fixture 35 shows the failure: the project uses `_.get`, an installed
package calls `lodash/template` on the same copy, and Phase 1 rules say
`unreachable`. Phase 2 says `cant_tell / transitive_parent_uses_symbol`. With
`node_modules` present, direct dependencies now get loader analysis too.
Without it, a direct dependency that other packages declare as a dependency is
`cant_tell / node_modules_missing`. A direct dependency with no declared
dependents falls back to Phase 1 behaviour (undeclared loaders cannot be
searched for without `node_modules`).

### Symbol data and trust tiers

| tier | source | may produce |
|---|---|---|
| `curated` | `data/advisories.json`: 15 hand-checked advisories (unchanged from Phase 1) | `reachable`, `unreachable`, `cant_tell` |
| `llm` | the Anthropic API reading the advisory text, then the code guard below | `reachable`, `cant_tell`, **never `unreachable`** |

The tier rule is enforced at the end of `decideAlert` in `src/verdict.js`, after
every other rule. An LLM that misses one affected function would otherwise
create a false `unreachable`. LLM-derived `reachable` evidence is labelled
`source: llm`, with the model name and the advisory quote.

**LLM extraction** (`src/llm.js`) runs only for alerts with no curated entry
whose package the project actually imports. Otherwise its answer could not
change the verdict.

- The call goes through plain `fetch` to the Messages API: no SDK, no new
  dependency. It requests JSON-schema structured output. For Claude Opus 5 / Opus 5.5 / Fable 5.1 it enables server-side
  refusal fallback (`fallbacks: "default"`), so a policy decline is retried on
  another model instead of failing. Set `REACHABLE_LLM_FALLBACKS=0` to turn
  that off.
- Output schema: `{ names_specific_api: boolean, symbols: [{ symbol, quote }] }`.
  Anything that does not parse is rejected (`llm_invalid_output`).
- Every response is cached on disk, keyed by advisory id + package + a SHA-256
  of the advisory text, the prompt and the schema. Reruns are offline, and an
  edited advisory is a cache miss.
- **The guard (code, not LLM)** drops any symbol whose `quote` is not verbatim
  in the advisory text (whitespace runs compared as single spaces), whose quote
  does not contain the symbol name, that is not an identifier (or `(module)`),
  or that is certainly not an export of the installed package. Exports are read
  statically from the entry file (`src/packages.js#readExports`). When they
  cannot be determined (UMD bundles such as lodash and underscore), the symbol
  is kept with `exportCheck: unknown`. That is safe because LLM data can only
  produce `reachable`. Dropped symbols are counted and reported per alert.

### Reason codes

| code | meaning |
|---|---|
| `transitive_parent_uses_symbol` | an installed package that loads the instance references an affected symbol (never promoted to `reachable`) |
| `no_symbol_data` | no curated data; with an LLM note when extraction was off, skipped or failed |
| `llm_unavailable` / `llm_invalid_output` / `llm_no_specific_api` / `llm_no_valid_symbols` | extraction did not run, its output was rejected, it found no specific function, or the guard dropped every symbol |
| `llm_tier_cannot_prove_unreachable` | analysis was clean but the symbols are LLM-sourced |
| `node_modules_missing` | loaders could not be inspected; the report prints one `npm ci` hint |
| `parent_not_installed` / `node_modules_out_of_sync` | a loader is in the lockfile but not installed, or installed at a different version |
| `parent_unparseable` | a loader's code did not parse (minified, bundled, >3 MB, Flow, ...). A warning tied to the alert, not a scan failure |
| `used_by_script` | the package (or its bin) is named in an npm script, the project's `bin`, or a root config file (eslint, jest, babel, webpack, vite, tsconfig, prettier) |
| `declared_unused` | a direct dependency found nowhere: code, scripts, configs |
| `transitive_not_analysed` | only with `--no-transitive` |
| `parse_error`, `file_unreadable`, `module_escapes`, `dynamic_member_access`, `gateway_used`, `indirect_reference`, `unmapped_subpath`, `dynamic_subpath`, `dynamic_import_promise`, `reexport_all`, `alias_config`, `name_as_string`, `dynamic_require`, `dynamic_import`, `require_escapes`, `eval_present` | as in Phase 1. Inside a loader package, the message names the package. |

### Why `used_by_script` and `declared_unused` are not `unreachable`

`used_by_script` means tooling loads and runs the package (`json5 -c file`
parses a file with the vulnerable `parse`), so it is plainly not safe to
ignore. `declared_unused` is a negative claim about everything that was *not*
scanned: JSON/YAML configs we do not read, other file types, tools invoked from
CI rather than npm scripts, packages loaded by name from user config. The tool
can show where a package is used; it cannot prove that nothing else uses it.
Both stay `cant_tell` until Phase 3 can model entry points.

## Scope (Phase 2)

- Source: `.js .mjs .cjs .jsx .ts .mts .cts .tsx` (`.d.ts` skipped).
- Projects: npm with `package.json` + `package-lock.json` (lockfileVersion 2 or 3).
  Transitive and loader analysis needs `node_modules` (`npm ci`).
- `scope` is `dev` only when npm marks the lockfile entry `"dev": true` (every
  path starts at a devDependency). `devOptional`/optional packages are tagged
  `prod`, because hiding them under `--prod-only` would be the unsafe direction.

## Ground-truth benchmark

```sh
npm run bench          # offline, deterministic (recorded OSV + LLM answers)
npm test               # 111 unit / adversarial / CLI tests
npm run bench:setup    # once: installs the curated packages for the extraction eval's export check
npm run bench:eval     # LLM extraction eval + promotion experiment
npm run bench:record   # re-record OSV (network);  node bench/record.js --llm  re-records LLM answers (API key)
```

36 fixtures (22 from Phase 1, 14 new), each with a `package.json`, a real or
hand-written `package-lock.json`, sources, and a hand-written `expected.json`.
Each advisory carries `expected` (the verdict the tool must give) and `truth`
(whether the code can actually trigger it, judged by reading it).

The new fixtures:

- transitive with an unused edge (real mkdirp@0.5.1 → minimist@0.0.8);
- the same with an npm script that runs mkdirp's CLI;
- a parent that calls the affected function;
- a diamond where one path uses it and one does not;
- missing `node_modules`;
- an unparseable (Flow-annotated) parent;
- an LLM-extracted symbol that is called;
- an LLM quote not in the advisory text;
- an LLM symbol that is not an export;
- prod vs dev scope;
- `used_by_script` and `declared_unused`;
- a direct dependency shared with a parent that uses the symbol (the Phase 1 blind spot);
- an undeclared loader.

Packages named `fx-*` are fictional, hand-written to create situations npm
cannot produce on demand. Real packages in fixture `node_modules` are unmodified
npm tarball contents. The two "guard" fixtures use hand-written LLM answers
stored in the fixture's own `llm-cache/`, marked `"synthetic": true`. All other
LLM answers are real recorded responses in `bench/llm-cache/`.

Results: see **Phase 2 results** below.

## Phase 2 results

PENDING: filled in after the LLM answers are recorded.

## Dependencies

No new runtime dependencies in Phase 2. The Anthropic API is called with
Node's built-in `fetch` (Node ≥ 18.17), so the runtime dependencies are still
only tree-sitter and its two grammars:

| package | why |
|---|---|
| `web-tree-sitter` | The tree-sitter parser runtime, compiled to WebAssembly: no C++ toolchain on any platform. The native JS (0.25) and TS (0.23) grammar bindings also require incompatible native `tree-sitter` versions. |
| `tree-sitter-javascript` | JavaScript + JSX grammar (its shipped `.wasm` file is loaded). |
| `tree-sitter-typescript` | TypeScript and TSX grammars (shipped `.wasm` files). |

The grammar packages declare `node-addon-api` and `node-gyp-build` for their own
native bindings, which `reachable` never loads.

## npm name

`reachable` is taken on npm (by another author, last modified 2022).
`package.json` is `"private": true`. Unregistered alternatives (checked
2026-10-11): `reachable-cli`, `vuln-reachable`, `js-reachable`,
`reachable-vulns`, or a scope you own (`@<npm-user>/reachable`).

## Limitations

- No call graph. `reachable` means "your code references it", not "proven
  executed" or "exploitable"; advisory preconditions are not checked. A
  dependency using the function is `cant_tell`, not `reachable`.
- Loader analysis covers packages that declare the instance or name it in their
  code. A package that loads it by a fully computed name, without ever writing
  the name, is not found (the same boundary as Phase 1's computed `require`).
- Curated symbol sets assume the named exports are the only entry points to the
  vulnerable code; each entry records the evidence for that.
- `unreachable` for transitive packages depends on the installed code matching
  the lockfile. Version mismatches are detected (`node_modules_out_of_sync`);
  hand-edited installed files are not.
- Speed: loader analysis parses every file in scope of every loader package.
  On a real babel 6 dev tree this took about 4 minutes on a OneDrive-synced
  disk. Parsed packages are cached per scan only.

## Open questions for Phase 3

- Call graphs and entry points: turn `transitive_parent_uses_symbol` into
  `reachable` or `unreachable`, and separate "referenced" from "called".
- Never-imported dependencies: model npm scripts, CI and config loading well
  enough to prove `declared_unused` safe.
- LLM promotion: whether LLM symbol data could ever be trusted for
  `unreachable`. The extraction eval's experiment measures this; Phase 2 does
  not act on it.
