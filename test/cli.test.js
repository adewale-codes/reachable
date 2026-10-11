// End-to-end CLI behaviour: exit codes, and failing loudly when part of the
// scan cannot run. Uses the recorded OSV data in bench/osv-cache (offline),
// plus an unroutable OSV URL to simulate the network being down.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'reachable.js');
const fixtures = path.join(root, 'bench', 'fixtures');
const benchCache = path.join(root, 'bench', 'osv-cache');
const DEAD_OSV = 'http://127.0.0.1:59999'; // nothing listens here: connection refused

function run(args, env = {}) {
  const r = spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', ...env } });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

function tempCopy(fixture) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'reachable-test-'));
  fs.cpSync(path.join(fixtures, fixture), dir, { recursive: true });
  return dir;
}

function emptyDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'reachable-cache-'));
}

test('exit 1 when an alert is reachable; JSON output parses', () => {
  const r = run(['scan', path.join(fixtures, '01-named-import'), '--offline', '--cache-dir', benchCache, '--json']);
  assert.equal(r.code, 1, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.complete, true);
  assert.equal(report.summary.reachable, 2);
  const tpl = report.results.find((x) => x.id === 'GHSA-35jh-r3h4-6jhm');
  assert.equal(tpl.verdict, 'reachable');
  assert.deepEqual(tpl.evidence.references[0].chain.map((s) => `${s.file}:${s.line}`), ['src/render.js:1', 'src/render.js:4', 'src/render.js:5']);
});

test('exit 0 when nothing is reachable', () => {
  const r = run(['scan', path.join(fixtures, '18-unaffected-json5'), '--offline', '--cache-dir', benchCache]);
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /UNREACHABLE \(1\)/);
});

test('--strict turns cant_tell into exit 1', () => {
  const dir = path.join(fixtures, '15-never-imported');
  assert.equal(run(['scan', dir, '--offline', '--cache-dir', benchCache]).code, 0);
  assert.equal(run(['scan', dir, '--offline', '--cache-dir', benchCache, '--strict']).code, 1);
});

test('a source file that fails to parse: exit 2, loud banner, no unreachable verdicts', () => {
  const dir = tempCopy('06-unaffected-function');
  fs.writeFileSync(path.join(dir, 'src', 'broken.js'), "const _ = require('lodash');\n_.template(;\n");
  const r = run(['scan', dir, '--offline', '--cache-dir', benchCache, '--json']);
  assert.equal(r.code, 2);
  const report = JSON.parse(r.stdout);
  assert.equal(report.complete, false);
  assert.ok(report.errors.some((e) => e.code === 'parse_error'));
  assert.equal(report.summary.unreachable, 0);
  const text = run(['scan', dir, '--offline', '--cache-dir', benchCache]);
  assert.match(text.stdout, /SCAN INCOMPLETE/);
});

test('unsupported lockfileVersion: exit 2', () => {
  const dir = tempCopy('01-named-import');
  const lockPath = path.join(dir, 'package-lock.json');
  const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
  lock.lockfileVersion = 1;
  fs.writeFileSync(lockPath, JSON.stringify(lock));
  const r = run(['scan', dir, '--offline', '--cache-dir', benchCache]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /SCAN FAILED \[unsupported_lockfile\]/);
});

test('missing or corrupt lockfile: exit 2', () => {
  const dir = tempCopy('01-named-import');
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{ not json');
  assert.equal(run(['scan', dir, '--offline', '--cache-dir', benchCache]).code, 2);
  fs.rmSync(path.join(dir, 'package-lock.json'));
  assert.equal(run(['scan', dir, '--offline', '--cache-dir', benchCache]).code, 2);
});

test('direct dependency missing from lockfile: exit 2', () => {
  const dir = tempCopy('01-named-import');
  const pj = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  pj.dependencies['left-pad'] = '1.3.0';
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pj));
  const r = run(['scan', dir, '--offline', '--cache-dir', benchCache, '--json']);
  assert.equal(r.code, 2);
  assert.ok(JSON.parse(r.stdout).errors.some((e) => e.code === 'lockfile_missing_dependency'));
});

test('OSV unreachable and no cache: exit 2, no report', () => {
  const r = run(['scan', path.join(fixtures, '01-named-import'), '--cache-dir', emptyDir()], { REACHABLE_OSV_URL: DEAD_OSV });
  assert.equal(r.code, 2);
  assert.match(r.stderr, /SCAN FAILED \[osv_unavailable\]/);
  assert.doesNotMatch(r.stdout, /REACHABLE|UNREACHABLE/);
});

test('--offline with an empty cache: exit 2', () => {
  const r = run(['scan', path.join(fixtures, '01-named-import'), '--offline', '--cache-dir', emptyDir()]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /--offline was given/);
});

test('OSV unreachable but cache present: report runs from cache and says so', () => {
  const r = run(['scan', path.join(fixtures, '18-unaffected-json5'), '--cache-dir', benchCache, '--json'], { REACHABLE_OSV_URL: DEAD_OSV });
  assert.equal(r.code, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.ok(report.osv.networkError);
  assert.ok(report.warnings.some((w) => /advisory data came from the local cache/.test(w)));
});

test('bad arguments: exit 2', () => {
  assert.equal(run(['scan']).code, 2);
  assert.equal(run(['scan', '.', '--bogus']).code, 2);
  assert.equal(run(['scan', path.join(root, 'does-not-exist'), '--offline']).code, 2);
});
