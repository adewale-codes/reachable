# reachable: design, reason codes and phase history

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
| `REACHABLE_LLM_MODEL` | extraction model (default `claude-sonnet-5-5`) |
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
| `other_entry_point` | the symbol data ties the affected function to a specific module path (e.g. `nanoid/non-secure`), and the code loads the package through a different entry point. Never reachable, never unreachable. |
| `parse_error`, `file_unreadable`, `module_escapes`, `dynamic_member_access`, `gateway_used`, `indirect_reference`, `unmapped_subpath`, `dynamic_subpath`, `dynamic_import_promise`, `reexport_all`, `alias_config`, `name_as_string`, `dynamic_require`, `dynamic_import`, `require_escapes`, `eval_present` | as in Phase 1. Inside a loader package, the message names the package. |

### Why `used_by_script` and `declared_unused` are not `unreachable`

`used_by_script` means tooling loads and runs the package (`json5 -c file`
parses a file with the vulnerable `parse`), so it is plainly not safe to
ignore. `declared_unused` is a negative claim about everything that was *not*
scanned: JSON/YAML configs we do not read, other file types, tools invoked from
CI rather than npm scripts, packages loaded by name from user config. The tool
can show where a package is used; it cannot prove that nothing else uses it.
Both stay `cant_tell` until Phase 3 can model entry points.

## Pre-publish fixes (ANALYZER_VERSION 3.1.0)

Three precision fixes found during the Phase 3 real-repo verification. Each may
only move a verdict in the safe direction: out of a wrong `reachable`, or out of
`cant_tell` when the existing rules then prove it.

**1. Subpath-aware symbols.** A symbol may carry the module path it lives in:
`{ symbol: 'nanoid', module: 'nanoid/non-secure' }` in curated data, or
`module` in the LLM answer (the v2 prompt asks for it only when the advisory
names a path).

- A use matches a qualified symbol only when its import specifier is exactly
  that module (after dropping `/index` and `.js`).
- A use of the same name through any other entry point, and any import of
  another entry point at all, is `cant_tell / other_entry_point`. Other entry
  points may share the vulnerable code, so qualified data can remove a wrong
  `reachable` but can never produce `unreachable`.
- Bare symbols (the default) still apply to every entry point.
- The LLM guard keeps a module only if it starts with `<package>/` and is
  written verbatim in the advisory. Otherwise the symbol stays unqualified,
  which is the conservative reading.
- Cached v1 answers (asked before the prompt mentioned modules) are reused only
  when the advisory text names no deep path of the package
  (`namesDeepPath`: a `<package>/…` token that is not part of a URL, `@scope/`
  or `_next/`). Otherwise the answer is re-asked.

**2. Babel interop wrappers.** `var _x = _interopRequireDefault(require('pkg'))`
and `_interopRequireWildcard(require('pkg'))` are treated as the plain
`require`, so `_x.default.fn(...)`, `_x.fn(...)` and Babel's call idiom
`(0, _x.default)(...)` are followed like any import. This applies only when all
of these hold:

- the helper is defined in the same file with a body that exactly matches one
  of the genuine Babel helper bodies in `src/babel-helpers.js` (harvested from
  real Babel output; the cached wildcard form also needs a genuine
  `_getRequireWildcardCache`), or is bound from
  `@babel/runtime/helpers/interopRequire{Default,Wildcard}`;
- the helper is declared once and never reassigned;
- the `require` call is its only argument.

A look-alike or redefined helper, or any other call shape, stays
`module_escapes`. Passing the wrapped binding anywhere other than a member
access still escapes. The `(0, x)(...)` idiom is only transparent for interop
bindings; on a plain `require` binding it is still an escape. The core-js
runtime helper variants (which call `_typeof` / `_Object$defineProperty`) are
not whitelisted.

**3. Bundler `external` lists.** In a root-level `rollup.config.*`,
`vite.config.*` or `esbuild.config.*`, a plain string literal that is a direct
element of an array literal that is the value of an `external` property is not
a load, so it no longer raises `name_as_string`. The same applies to
`externals` in `webpack.config.*`. The same entries are blanked from the
root-config mention check (`used_by_script`). Anything else stays
conservative: spread or concatenated arrays, the function form, webpack's object
form, aliases, `jest.mock`, other config files, or a config not at the root.
Once the string is gone, the normal Phase 1 and 2 rules decide the verdict.

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

37 fixtures (22 from Phase 1, 15 new), each with a `package.json`, a real or
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
- an undeclared loader;
- the trim-newlines main export (added after the extraction eval to measure an LLM miss).

Packages named `fx-*` are fictional, hand-written to create situations npm
cannot produce on demand. Real packages in fixture `node_modules` are unmodified
npm tarball contents. The two "guard" fixtures use hand-written LLM answers
stored in the fixture's own `llm-cache/`, marked `"synthetic": true`. All other
LLM answers are real recorded responses in `bench/llm-cache/`.

Results: see **Phase 2 results** below.

## Phase 2 results (2026-10-12)

LLM extraction model: `claude-sonnet-5-5` (ID verified against the Models API
before any paid call). Recorded answers: 6 for the benchmark, 15 for the eval.

### Benchmark

```
37 fixtures, 131 labelled advisory alerts, 131 match expected verdict

Phase 2: ground truth (rows) vs tool verdict (columns)
  truth           →reachable →unreachable   →cant_tell   total
  reachable               29            0           27      56
  unreachable              0           33           41      74
  unknown                  0            0            1       1

Phase 1 rules on the same fixtures
  reachable               24            2           30      56
  unreachable              0           29           45      74
  unknown                  0            0            1       1

cant_tell rate                     Phase 1 baseline    Phase 2
  original 22 fixtures            50/95 (52.6%)       48/95 (50.5%)
  all 37 fixtures                 76/131 (58.0%)      69/131 (52.7%)

False "unreachable": Phase 2: 0.  Phase 1 rules: 2 (fixture 35).
```

What Phase 2 bought on these fixtures:

- **Five alerts became correctly `reachable` from LLM data:** jsonwebtoken
  `verify` (GHSA-8cf7, fixtures 05 and 29) and `ms` main-export calls
  (GHSA-3fx5, fixtures 13, 30 and 31).
- **Four transitive alerts became correctly `unreachable`:** fixture 23, and
  the unset/omit pair in the diamond, fixture 26.
- **Two Phase 1 false `unreachable` verdicts were removed** (fixture 35).

The rate on the original 22 fixtures barely moves (52.6% → 50.5%). Most of
their `cant_tell` alerts are uncurated advisories whose functions the project
does not call (LLM data can show `reachable`, never `unreachable`), plus
fixture 12, which has no `node_modules`. The 41 "truly unreachable →
cant_tell" alerts are still the main cost of the conservative rules.

### Extraction eval (`npm run bench:eval`)

The 15 curated advisories were extracted as if they had no entry. The guard
ran with each package's installed exports (`bench/eval-packages`).

| result | count |
|---|---|
| curated symbols found | 24 of 27 |
| exact symbol-set match | 12 of 15 advisories |
| missed | 3: minimist `(module)` ×2, trim-newlines `(module)` |
| extra symbols | 0 |
| guard rejections | 0 |

The misses:

- **minimist (×2):** the model answered `names_specific_api: false`. The text
  names the internal `setKey()` and "the arguments passed to minimist", so this
  is a defensible reading. It is also harmless: no symbol data means
  `cant_tell`.
- **trim-newlines:** the model returned exactly what the text says (`.end()`).
  The curated `(module)` came from reading the package source, which no model
  can get from the advisory text. **This is the dangerous kind of miss.**

Sonnet 5.5 was kept. Its misses follow the advisory text faithfully, and a
larger model reading the same text cannot recover what the text does not say.

In the benchmark fixtures, a real-model mistake also showed up and was caught.
For ms GHSA-w9mr, the model proposed `parse`, an internal function. In fixture
31 (package installed) the guard dropped it as `not_an_export`. In fixture 13
(no `node_modules`, exports unknown) it was kept, but it cannot cause harm
there: the code calls `ms(...)` itself, so the verdict is `cant_tell /
gateway_used`.

### Promotion experiment (measured only, not acted on)

If LLM data were allowed to prove `unreachable`:

- (a) curated advisories, with LLM symbols substituted: 31 of 56
  truth-unreachable alerts would be `unreachable`; 0 false `unreachable`;
- (b) uncurated advisories, with the LLM tier promoted: 9 of 18; 0 false
  `unreachable`.

**This does not justify promotion.** Fixture 37 was added to exercise the
trim-newlines miss: it calls `trimNewlines(text)`. With the LLM's `[end]` the
result is `cant_tell / gateway_used`. It was saved only because calling a
module's main export is treated as a gateway when `(module)` is not an
affected symbol. A missed *named* export (say `mergeWith` dropped from the
merge advisories) has no such backstop and would be a false `unreachable` in
any project that calls only that function. The sample has no fixture for that
case, so its 0 is a property of the sample, not evidence of safety. Phase 2
keeps the rule: LLM data never proves `unreachable`.

### Real repositories

The three public projects from Phase 1 were installed with
`npm ci --ignore-scripts` and scanned. Every `unreachable` produced by the new
loader analysis, and every LLM-sourced `reachable`, was checked by reading the
code. This is a sample of 3 projects, so it supports statements about these
verdicts, not an accuracy rate.

| project | what changed in Phase 2 | checked by hand |
|---|---|---|
| odynvolk/omit-deep-lodash | 24 transitive alerts `cant_tell` → `unreachable`: 4 lodash advisories × 6 babel 6 packages, each with its own nested lodash@4.17.20. The direct lodash `template` alert went **`unreachable` → `cant_tell`**: babel-core shares the project's lodash@4.17.21 and uses eval and dynamic `require`. | Each of the six loaders imports only per-method lodash files for unrelated functions (has, pull, values, extend, cloneDeep, assign, includes, repeat, defaults, clone, isPlainObject, isRegExp, uniq). None of them loads template, unset or omit. Their only grep hits for `Function(` are visitor methods named `Function`, not the constructor. The nested copies under babel-cli and babel-register stayed `cant_tell` (dynamic `require` / escape). |
| SashenJayathilaka/Spotify-Clone | lodash@4.17.21 (direct): still `unreachable` (3 alerts), now including loader analysis. json5@1.0.1 (transitive): `transitive_parent_uses_symbol`. | The only other file in `node_modules` naming lodash is `lodash.merge/index.js`, in comments only, so it is correctly ignored as a loader. tsconfig-paths calls `JSON5.parse(cleanedJson)` at `lib/tsconfig-loader.js:85`. |
| desirekaleba/node-mysql-jwt-auth | **Live end-to-end scan with the API key** (live OSV, 11 live LLM calls, 0 failures, exit 1). jsonwebtoken GHSA-8cf7 went `cant_tell` → `reachable` (source: llm; symbols `sign` and `verify`, both confirmed exports). Seven express and joi advisories got LLM symbols but stay `cant_tell`; four joi and morgan advisories got "no specific API". | `jwt.sign` at `src/utils/token.js:5` runs through `generate()`, called from `auth.controller.js:18` and `:49`. `jwt.verify` at line 9 is referenced, but its `decode()` has no caller. The quote ("...in the `sign()` and/or `verify()` functions") is verbatim in the advisory. The app signs with an HMAC string secret, while this advisory concerns asymmetric key types. So the function runs, but this use is likely not exploitable. Reachable means referenced, not exploitable. |

Two bugs were found and fixed during this check:

- Undeclared loaders of a *direct* dependency were found but then ignored by
  the verdict. This was a soundness bug; a regression test now covers it.
- Parent evidence pointed at later uses of a call's result instead of at the
  call.

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

## Results after the pre-publish fixes (2026-10-12)

- **Fixtures:** 47 fixtures, 178 labelled alerts, all matching. 0 false
  `unreachable`, 0 false `reachable`. `cant_tell` 53.4% (Phase 1 rules on the
  same fixtures: 60.1%). The 10 new fixtures (38-47) cover each fix and its
  conservative edges.
- **Real repos** (15, `bench/real/verified.json`): every `reachable` and
  `unreachable` verdict was read by hand.
  - 31 `unreachable`: all correct.
  - 25 `reachable`: 2 correct, 23 correct but not exploitable as written, 0
    wrong.
  - `cant_tell` is 96.4% of 1,556 alerts. A spot check of 314 found every
    reason code truthful.
  - Re-running with the fixes changed 2 verdicts, both `reachable` →
    `cant_tell`. The nanoid false positive is gone (`other_entry_point`), and
    one axios advisory was lost because the re-asked LLM answer said "no
    specific API". No verdict moved to `unreachable`.
- **LLM re-recording:** the v2 prompt changed the answers' cache keys. Of the
  121 LLM extractions in the benchmark and corpus, the 12 whose advisory text
  names a deep path of the package were re-asked (nanoid 28wg; axios 62hf,
  hfxv, jr5f, mmx7, pf86, pjwm; next 3x4c; next-auth 5jpx, v64w, xmf8;
  follow-redirects cxjh). The other 109 reuse their v1 answers.

## Limitations

- Symbols tied to a module path never say anything about other entry points:
  imports elsewhere in the package are `cant_tell` (`other_entry_point`).
  Without a module path, a symbol applies to every entry point, and a deep
  import of a package without a curated subpath mapping is `unmapped_subpath`.
- LLM answers are not stable across re-asks (one axios answer changed from
  `get` to "no specific API"). Recorded answers make runs reproducible, but a
  new recording can move a `reachable` to `cant_tell` (never to `unreachable`).
- Babel interop wrappers are followed only for byte-exact genuine helper bodies
  (`src/babel-helpers.js`) or `@babel/runtime/helpers` imports. Other compilers'
  interop helpers, and the core-js runtime variants, still count as escapes.
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
