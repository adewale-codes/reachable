# reachable

`npm audit` tells you which of your dependencies have known vulnerabilities.
`reachable` tells you which of those alerts **your code can actually
trigger**. It reads your source and every installed package that loads the
vulnerable dependency, and gives each alert one of three verdicts with
evidence: `reachable` (here is the line that calls it), `unreachable` (proven:
nothing that can load it references the affected function), or `cant_tell`
(with the exact reason). It never guesses `unreachable`: anything it cannot
prove stays `cant_tell`.

Expect a lot of `cant_tell`: on 15 real projects it was 96.4% of alerts, mostly
transitive packages for which there is no affected-function data at all.

```
$ reachable scan csgo-tradeup-cli --offline --llm-cache-only   # real corpus repo, abridged; cached OSV + LLM data from the live corpus run
reachable 0.1.0  csgo-tradeup-cli
  18 source files · 6 direct / 135 transitive packages · advisories from local cache (--offline)
  note: LLM symbol extraction uses recorded responses only (no API calls).

39 advisory alerts: 0 reachable · 3 unreachable · 36 can't tell

CAN'T TELL (36)
  GHSA-cxjh-pqwp-8mfp  follow-redirects@1.15.3  (direct, prod)  follow-redirects' Proxy-Authorization header kept across hosts
    no_symbol_data: There is no curated record of which follow-redirects functions this advisory affects,
    so usage cannot be matched against it. LLM: the LLM found no specific function named.
  ...

UNREACHABLE (3)
  GHSA-r5fr-rjxr-66jc  lodash@4.17.21  (transitive, prod)  lodash vulnerable to Code Injection via `_.template` imports key names
    affected: template; none referenced. Not imported by the project; every installed package that loads it was checked:
    loader whatwg-url@8.7.0: imports lodash at node_modules/whatwg-url/dist/URLSearchParams-impl.js:2; 2 uses checked, none affected
    2 dependency path(s), e.g. jsdom@16.7.0 > data-urls@2.0.0 > whatwg-url@8.7.0 > lodash@4.17.21
  ...
```

## Install and use

> Not yet published to npm. Until it is, run it from a checkout:
> `npm install && node bin/reachable.js scan <path>`. See `PUBLISHING.md`.

```sh
npm ci                                   # in your project: reachable needs node_modules for transitive analysis
npx @codesham/reachable scan .           # readable report
npx @codesham/reachable scan . --format markdown   # compact report for a PR comment
npx @codesham/reachable scan . --json    # machine-readable (schema below)
```

Requirements: Node ≥ 18.17; an npm project with `package.json` and
`package-lock.json` (lockfileVersion 2 or 3); JavaScript/TypeScript source.

| option | effect |
|---|---|
| `--format text\|json\|markdown` | output format (`--json` = `--format json`) |
| `--json-file <path>` | also write the JSON report to a file (written even when the scan fails) |
| `--strict` | `cant_tell` also makes the exit code 1 |
| `--prod-only` | hide alerts on packages reachable only from devDependencies (hides; never changes a verdict) |
| `--offline` | OSV and LLM data from cache only; fail if OSV data is missing |
| `--no-llm`, `--llm-cache-only` | turn the LLM tier off, or use recorded answers only |
| `--no-transitive` | skip the analysis of installed packages |
| `--cache-dir <dir>`, `--pkg-cache-dir <dir>`, `--no-pkg-cache` | cache locations (default: your user cache dir, never the project) |

`ANTHROPIC_API_KEY` (optional) turns on the LLM tier; `REACHABLE_LLM_MODEL`
picks the model (default `claude-sonnet-5-5`).

**Exit codes:** `0` nothing reachable · `1` something reachable (or
`cant_tell` with `--strict`) · `2` the scan could not complete (bad lockfile,
OSV unavailable with no cache, unparseable project source). A failed scan never
prints a clean report.

A GitHub Action that posts the Markdown report on pull requests lives in the
sibling `reachable-action` folder.

## The three verdicts

| verdict | what it means | evidence |
|---|---|---|
| `reachable` | your code references a function the advisory names | the `file:line` chain from the import to the use |
| `unreachable` | **proven**: your code and every installed package that loads the vulnerable copy were analysed statically, nothing escaped the analysis, and no affected function is referenced | import sites, every loader checked, dependency paths |
| `cant_tell` | anything not proven | machine-readable reason codes with plain-English messages and locations |

**`unreachable` needs proof.** A false `unreachable` tells you a real
vulnerability is safe to ignore, which is the worst thing this tool could do.
So `unreachable` is only returned when the list of reasons to doubt it is
empty. Doubts include: the module object being passed around, `lib[name]`
lookups, `eval`, dynamic `require`, a wrapper like `_.chain()`, an unparseable
file, an installed package that loads it and uses the function, or a missing
`node_modules`. Every one of them yields `cant_tell` with its reason.

Every alert is also tagged `scope: prod | dev`, a fact from the lockfile and not
a verdict.

## Where "affected function" data comes from: trust tiers

| tier | source | may produce |
|---|---|---|
| `curated` | `data/advisories.json`: 15 advisories checked by hand against the advisory text and package source | all three verdicts |
| `llm` | an LLM reads the advisory text; a code guard drops any symbol whose quote is not verbatim in the advisory or that is not an export of the installed package | `reachable` or `cant_tell`, **never `unreachable`** |

The LLM tier can miss a function (the evaluation found 3 misses in 27 symbols),
and a miss would turn into a false `unreachable`. So LLM data can only show that
something is called, never that it is not. LLM-sourced `reachable` verdicts are
labelled `source: llm` with the quote they rest on. Without an API key, the
tier is off and the report says so.

## Limitations

- **No call graph.** A reference in dead code counts as reachable, and a
  dependency that calls the vulnerable function is `cant_tell`
  (`transitive_parent_uses_symbol`), not reachable.
- **Reachable is not exploitable.** It means your code can call the affected
  function. Advisory preconditions (an attacker-controlled argument, a proxy
  configuration, prior prototype pollution) are not checked. In the real-repo
  check, most correct `reachable` verdicts were not exploitable as written.
- **JavaScript/TypeScript and npm only**, with `package-lock.json` v2/v3.
- **The LLM tier cannot prove `unreachable`.** Its answers can also vary when
  re-asked: one axios advisory went from `get` to "no specific API" after a
  prompt change, turning a correct `reachable` into `cant_tell`.
- **Sub-module advisories never prove anything about other entry points.**
  When the data says a function lives in e.g. `nanoid/non-secure`, an import
  of the main `nanoid` is `cant_tell` (`other_entry_point`), not reachable and
  not unreachable.
- **`cant_tell` is common.** Most alerts in real projects are transitive
  packages with no curated or LLM symbol data. See the rates below.
- Loaders that load a package by a fully computed name, without ever writing
  the name, are not found. Babel interop wrappers are followed only when the
  helper is byte-for-byte a genuine Babel helper (or comes from
  `@babel/runtime/helpers`); anything else still counts as the module escaping.

## Results

The fixture benchmark and the real-repository check are separate and measure
different things. Neither is an accuracy rate.

### Fixture benchmark (`npm run bench`)

47 small labelled projects. Each advisory has a hand-written expected verdict
and a separate "truth" (can the code really trigger it). Offline and
deterministic (recorded OSV and LLM answers).

```
47 fixtures, 178 labelled alerts, 178 match the expected verdict
                truth →  reachable  unreachable  cant_tell
  reachable               38          0           32
  unreachable              0         45           62
  unknown                  0          0            1
False "unreachable": 0   False "reachable": 0   cant_tell rate: 53.4% (Phase 1 rules on the same fixtures: 60.1%)
```

The fixtures were written by the same author as the analyser. Passing them
shows the rules behave as designed on these patterns.

### Real repositories (`bench/real/`)

15 public npm projects, each pinned to a commit SHA in `bench/real/corpus.json`:
4 Express APIs, 2 CLIs (one TypeScript), 2 React apps (Next.js, CRA), 5
libraries (4 TypeScript), and 2 monorepo-style projects. They were cloned
into a temp folder, installed with `npm ci --ignore-scripts`, and scanned on
2026-10-12 with live OSV data and the LLM tier on (Claude Sonnet 5.5). The
saved reports in `bench/real/results/` are an offline replay of exactly that
OSV and LLM data with the final code.

**Every `reachable` and `unreachable` verdict was checked by reading the code**
(`bench/real/verified.json`: file:line read, judgement, one-line reason). This
is what was checked, not an accuracy rate:

| | verdicts | judged correct | correct, not exploitable as written | wrong |
|---|---|---|---|---|
| `unreachable` | 31 | 31 | (n/a) | **0** |
| `reachable` | 25 | 2 | 23 | 0 |

- **No false `unreachable`** was found. The 31 are lodash and underscore
  advisories, where the installed packages that load the vulnerable copy were
  read one by one (e.g. whatwg-url only calls `lodash/sortBy`; six babel 6
  packages only use per-method imports like `has` and `clone`).
- **Most `reachable` verdicts are real calls that are not exploitable as
  written.** Examples: axios advisories that need prior prototype pollution or
  a proxy configuration; `nanoid(6)` with a constant size; `jwt.sign` with an
  HMAC secret; a `_.omit` call in a dev-only benchmark. Reachable means "your
  code calls it", nothing more.
- **0 wrong `reachable` after the pre-publish fixes** (was 1). The one wrong
  verdict was a nanoid advisory that affects only `nanoid/non-secure`, matched
  by name against the app's main `nanoid` import. Symbols can now carry their
  module path, and that alert is `cant_tell` (`other_entry_point`).
- **What changed when the corpus was re-run with the fixes** (every changed
  verdict was read by hand and is recorded in `verified.json`):

  | repo | advisory | old | new | why | judgement |
  |---|---|---|---|---|---|
  | bluuweb/api-rest-twitch… | GHSA-28wg (nanoid) | reachable | cant_tell | the advisory names `nanoid/non-secure`; the app imports main `nanoid` | correct: the wrong reachable is gone |
  | bluuweb/api-rest-twitch… | GHSA-pf86 (axios) | reachable | cant_tell | re-asked LLM said the advisory names no specific API (prototype-pollution gadgets) | truthful, but a correct (not exploitable) reachable was lost |

  No other verdict changed in the 15 repos. Babel interop and bundler
  `external` handling changed the reasons on 10 more alerts (e.g. microhook's
  `external: ['lodash']` no longer counts as a load, so the reason is now
  `declared_unused`; in express-js-api-rbac the Babel escape no longer hides a
  dependency that really calls `template`). Re-asked LLM answers that tie
  symbols to module paths changed the reasons on 6 (axios, next-auth). All 16
  were `cant_tell` before and after.
- **`cant_tell` rate on real repos: 96.4%** (1,500 of 1,556 alerts), against
  53.4% on the fixtures. Most real alerts are transitive packages with no
  curated or LLM symbol data. A spot check of 314 of the 1,500 `cant_tell`
  verdicts (≥ 20 % per repo) found every reason code truthful.
- One repo first failed with exit 2 on valid JSX (`<h1>React & Tailwind</h1>`,
  a tree-sitter grammar limitation). That case is now tolerated, only when the
  error is plain JSX text.

### Speed

Per-package results are cached in your user cache dir (never the project). The
cache is keyed by `name@version`, the lockfile integrity hash and the
analyzer version. Packages are read and analysed in parallel. Warm scans of the
corpus, after an empty-cache (cold) scan:

| repo | cold | warm |
|---|---|---|
| adiun/vite-monorepo (384 alerts) | 456 s | 7.3 s |
| arizonatribe/vanillas | 219 s | 9.2 s |
| thepranaygupta/react-tailwind-css-starter-pack | 173 s | 3.8 s |
| odynvolk/omit-deep-lodash | 56 s | 2.5 s |

Cold times include a partly warm OS file cache from earlier runs. A truly
cold first read of `node_modules` on Windows was about 4 minutes for
omit-deep-lodash in Phase 2. The cache never changes a result: the fixture
benchmark and the whole corpus were run cold and then warm, and the JSON
reports are identical (`bench/real/diff-results.js`).

## JSON output (`--json`, `--json-file`)

```jsonc
{
  "tool": { "name": "reachable", "version": "0.1.0" },
  "project": { "path": "...", "name": "..." },
  "complete": true,                 // false = the scan did not fully run; never treat as clean
  "errors": [{ "code": "parse_error", "message": "..." }],
  "warnings": ["..."], "notices": ["..."],
  "summary": { "alerts": 39, "reachable": 0, "unreachable": 3, "cant_tell": 36 },
  "scopeCounts": { "prod": 39, "dev": 0 }, "prodOnly": false, "hiddenDevAlerts": 0,
  "inventory": { "lockfileVersion": 2, "installed": 141, "direct": 6, "transitive": 135, "nodeModules": true },
  "source": { "filesScanned": 18, "parseErrors": 0 },
  "osv": { "mode": "online", "queriesFromNetwork": 141, "networkError": null, ... },
  "llm": { "mode": "live", "model": "claude-sonnet-5-5", "calls": 3, "cacheHits": 0, "failures": 0 },
  "transitiveAnalysis": { "packagesAnalysed": 1, "nodeModules": true, "cache": { "hits": 0, "misses": 2, ... } },
  "analyzerVersion": "3.0.1",
  "unresolvedImports": [{ "specifier": "...", "file": "...", "line": 1 }],
  "withdrawn": [],
  "results": [{
    "id": "GHSA-...", "aliases": ["CVE-..."], "summary": "...", "severity": "HIGH", "url": "https://osv.dev/vulnerability/GHSA-...",
    "package": "lodash", "installName": "lodash", "version": "4.17.21", "lockfilePath": "node_modules/lodash",
    "direct": false, "scope": "prod", "dev": false,
    "symbolTier": "curated",        // "curated" | "llm" | null
    "affectedSymbols": ["template"], "symbolSource": "https://github.com/advisories/...",
    "llm": null,                    // for LLM-tier alerts: { status, model, kept: [{symbol, quote, exportCheck}], dropped: [{symbol, quote, why}] }
    "verdict": "unreachable",       // "reachable" | "unreachable" | "cant_tell"
    "reason": null,                 // primary reason code for cant_tell
    "reasons": [{ "code": "...", "message": "...", "count": 1, "locations": [{ "file": "...", "line": 1, "text": "...", "detail": "..." }] }],
    "evidence": {
      // reachable:   { tier, references: [{ symbol, via, source, quote, chain: [{file, line, text}] }], referenceCount, model? }
      // unreachable: { tier, symbols, importSites, importCount, usesChecked, loaders: [{ loader, declared, result }], paths: { total, complete, sample } }
    }
  }]
}
```

Reason codes and the full design (the loader model, package file scoping, the
LLM guard, caching) are documented in [`docs/DESIGN.md`](docs/DESIGN.md).

## Development

```sh
npm test                 # unit, adversarial and CLI tests
npm run bench            # fixture benchmark (offline)
npm run bench:eval       # LLM extraction eval + promotion experiment (needs npm run bench:setup once)
node bench/real/run-corpus.js        # real-repo corpus (network; clones into a temp dir)
```

The per-package cache is keyed by `name@version`, the lockfile integrity hash
and `ANALYZER_VERSION` (`src/pkgcache.js`). Bump it in any change that alters
analysis behaviour.

## License

MIT
