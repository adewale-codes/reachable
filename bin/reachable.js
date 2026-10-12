#!/usr/bin/env node
// reachable scan <path> [--json] [--strict] [--offline] [--cache-dir <dir>] [--verbose]

import { scan, exitCodeFor, VERSION } from '../src/scan.js';
import { formatText, formatJson } from '../src/format.js';

const HELP = `reachable ${VERSION}
Tells you which dependency vulnerability alerts your JavaScript code can actually trigger.

Usage:
  reachable scan <path> [options]

Options:
  --json             machine-readable output on stdout
  --strict           exit 1 when any alert is cant_tell (not only reachable)
  --offline          use only cached OSV data; fail if anything is missing
  --cache-dir <dir>  OSV cache directory (default: per-user cache dir, or $REACHABLE_CACHE_DIR)
  --verbose          show more evidence per alert
  --prod-only        hide alerts on packages reachable only from devDependencies (never changes a verdict)
  --no-llm           do not use LLM symbol extraction even if ANTHROPIC_API_KEY is set
  --llm-cache-only   use recorded LLM responses only (no API calls)
  --no-transitive    do not analyse packages in node_modules (Phase 1 behaviour for dependents)
  -h, --help         show this help
  -v, --version      print the version

Environment:
  ANTHROPIC_API_KEY    enables LLM symbol extraction for advisories without curated data (optional)
  REACHABLE_LLM_MODEL  model for extraction (default claude-opus-5)

Exit codes:
  0  nothing reachable
  1  at least one alert is reachable (or cant_tell, with --strict)
  2  the scan could not complete (bad input, OSV unavailable, unparseable source, ...)
`;

function fail(message) {
  process.stderr.write(`reachable: error: ${message}\n`);
  process.exitCode = 2;
}

async function main(argv) {
  const opts = { json: false, strict: false, offline: false, verbose: false, cacheDir: undefined, prodOnly: false, llm: 'auto', transitive: true };
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') { process.stdout.write(HELP); return; }
    if (a === '-v' || a === '--version') { process.stdout.write(`${VERSION}\n`); return; }
    if (a === '--json') opts.json = true;
    else if (a === '--strict') opts.strict = true;
    else if (a === '--offline') opts.offline = true;
    else if (a === '--verbose') opts.verbose = true;
    else if (a === '--prod-only') opts.prodOnly = true;
    else if (a === '--no-llm') opts.llm = 'off';
    else if (a === '--llm-cache-only') opts.llm = 'cache';
    else if (a === '--no-transitive') opts.transitive = false;
    else if (a === '--cache-dir') {
      if (!argv[i + 1]) return fail('--cache-dir needs a directory');
      opts.cacheDir = argv[++i];
    } else if (a.startsWith('--cache-dir=')) opts.cacheDir = a.slice('--cache-dir='.length);
    else if (a.startsWith('-')) return fail(`unknown option ${a}\n\n${HELP}`);
    else positional.push(a);
  }
  if (positional[0] !== 'scan' || positional.length !== 2) {
    return fail(`expected: reachable scan <path>\n\n${HELP}`);
  }

  let report;
  try {
    report = await scan(positional[1], { offline: opts.offline, cacheDir: opts.cacheDir, prodOnly: opts.prodOnly, llm: opts.llm, transitive: opts.transitive });
  } catch (err) {
    if (err && err.name === 'ScanError') {
      if (opts.json) {
        process.stdout.write(JSON.stringify({ tool: { name: 'reachable', version: VERSION }, complete: false, errors: [{ code: err.code, message: err.message }], results: [] }, null, 2) + '\n');
      }
      process.stderr.write(`\nreachable: SCAN FAILED [${err.code}]\n  ${err.message}\nNo results were produced. Exit code 2.\n`);
      process.exitCode = 2;
      return;
    }
    throw err;
  }

  if (opts.json) {
    process.stdout.write(formatJson(report));
  } else {
    const color = process.stdout.isTTY && !process.env.NO_COLOR;
    process.stdout.write(formatText(report, { color, verbose: opts.verbose }));
  }
  if (!report.complete) process.stderr.write('reachable: scan incomplete; exit code 2\n');
  process.exitCode = exitCodeFor(report, { strict: opts.strict });
}

main(process.argv.slice(2)).catch((err) => {
  process.stderr.write(`reachable: internal error: ${err && err.stack ? err.stack : err}\n`);
  process.exitCode = 2;
});
