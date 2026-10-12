#!/usr/bin/env node
// Runs the real-repo corpus (bench/real/corpus.json). For each repo: clone into
// a temp folder (never into this project), check out the pinned SHA, run
// `npm ci --ignore-scripts` (no install scripts run), then scan with live OSV
// and the LLM tier (when ANTHROPIC_API_KEY is set). Full JSON reports are
// saved to bench/real/results/<slug>.json for manual verification.
//
// Usage: node bench/real/run-corpus.js [--only <slug>] [--workdir <dir>] [--no-install] [--cold]
//                                      [--pkg-cache-dir <dir>] [--offline] [--out-dir <dir>]
//   --cold           use a fresh, empty per-package cache for this run (for timing)
//   --pkg-cache-dir  use (and keep) this per-package cache dir, e.g. for a cold-then-warm comparison
//   --offline        OSV and LLM answers from cache only (a rerun sees exactly the same advisory data)
//   --out-dir        where to write results (default bench/real/results)

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scan, exitCodeFor } from '../../src/scan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const arg = (f) => { const i = process.argv.indexOf(f); return i > 0 ? process.argv[i + 1] : undefined; };
const workdir = arg('--workdir') || path.join(os.tmpdir(), 'reachable-corpus');
const only = arg('--only');
const corpus = JSON.parse(fs.readFileSync(path.join(here, 'corpus.json'), 'utf8')).repos;
const outDir = arg('--out-dir') || path.join(here, 'results');
fs.mkdirSync(outDir, { recursive: true });
fs.mkdirSync(workdir, { recursive: true });
const pkgCacheDir = arg('--pkg-cache-dir') || (process.argv.includes('--cold') ? fs.mkdtempSync(path.join(os.tmpdir(), 'reachable-pkgcache-')) : undefined);
const offline = process.argv.includes('--offline');

const sh = (cmd, args, cwd) => spawnSync(cmd, args, { cwd, encoding: 'utf8', shell: process.platform === 'win32', maxBuffer: 64 * 1024 * 1024 });
const slugOf = (repo) => repo.replace('/', '__');

const summary = [];
for (const r of corpus) {
  const slug = slugOf(r.repo);
  if (only && only !== slug && only !== r.repo) continue;
  const dir = path.join(workdir, slug);
  const meta = { repo: r.repo, sha: r.sha, style: r.style };
  if (!fs.existsSync(path.join(dir, '.git'))) {
    const c = sh('git', ['clone', '--quiet', '--no-checkout', r.url, dir]);
    if (c.status !== 0) { console.log(`${slug}: clone failed: ${c.stderr.trim()}`); continue; }
  }
  const co = sh('git', ['-C', dir, 'checkout', '--quiet', '--force', r.sha]);
  if (co.status !== 0) { console.log(`${slug}: checkout ${r.sha} failed: ${co.stderr.trim()}`); continue; }
  if (!process.argv.includes('--no-install') || !fs.existsSync(path.join(dir, 'node_modules'))) {
    const t0 = Date.now();
    const ci = sh('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund', '--loglevel=error'], dir);
    meta.npmCi = { ok: ci.status === 0, ms: Date.now() - t0, error: ci.status === 0 ? null : (ci.stderr || ci.stdout).trim().split('\n').slice(-3).join(' | ') };
  }
  const t1 = Date.now();
  let report;
  try {
    // --offline: OSV from cache. The LLM tier still answers cache misses live when a key is set
    // (e.g. after a prompt change), otherwise it uses recorded answers only.
    report = await scan(dir, { pkgCacheDir, offline, llm: offline ? (process.env.ANTHROPIC_API_KEY ? 'live' : 'cache') : 'auto' });
  } catch (err) {
    meta.scanError = `${err.code || err.name}: ${err.message}`;
    console.log(`${slug}: SCAN FAILED ${meta.scanError}`);
    summary.push(meta);
    continue;
  }
  meta.scanMs = Date.now() - t1;
  meta.exitCode = exitCodeFor(report);
  meta.summary = report.summary;
  fs.writeFileSync(path.join(outDir, `${slug}.json`), JSON.stringify({ meta, report }, null, 2) + '\n');
  summary.push(meta);
  console.log(`${slug.padEnd(52)} ${JSON.stringify(report.summary)} exit=${meta.exitCode} scan=${(meta.scanMs / 1000).toFixed(1)}s npm-ci=${meta.npmCi ? (meta.npmCi.ok ? 'ok' : 'FAILED') : 'skipped'} llm=${report.llm.mode}/${report.llm.calls || 0} calls`);
}
if (!only) fs.writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
