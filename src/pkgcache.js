// On-disk cache for per-package analysis results (Phase 3).
//
// Entries are keyed by package name@version + the lockfile integrity hash +
// ANALYZER_VERSION + any extra key parts (e.g. which names were tracked).
// Bump ANALYZER_VERSION in any change that alters analysis behaviour, so a
// result computed by older code can never be reused.
//
// The cache lives in a user cache directory, never inside the scanned project.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/** Bump on ANY change to usage extraction, package scoping or mention indexing. */
export const ANALYZER_VERSION = '3.1.0'; // 3.0.1: location-independent paths; 3.0.2: '&' in JSX text; 3.1.0: Babel interop wrappers, bundler external lists

export class PackageCache {
  constructor(dir) {
    this.dir = dir;
    this.stats = { hits: 0, misses: 0, writes: 0, uncacheable: 0 };
  }

  keyFor(parts) {
    return crypto.createHash('sha256').update(JSON.stringify([ANALYZER_VERSION, ...parts])).digest('hex');
  }

  file(kind, key) {
    return path.join(this.dir, kind, key.slice(0, 2), `${key}.json`);
  }

  get(kind, parts) {
    const f = this.file(kind, this.keyFor(parts));
    try {
      const v = JSON.parse(fs.readFileSync(f, 'utf8'));
      this.stats.hits++;
      return v.value;
    } catch {
      this.stats.misses++;
      return undefined;
    }
  }

  set(kind, parts, value) {
    const f = this.file(kind, this.keyFor(parts));
    try {
      fs.mkdirSync(path.dirname(f), { recursive: true });
      const tmp = `${f}.${process.pid}.${Date.now()}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({ analyzer: ANALYZER_VERSION, parts, value }));
      fs.renameSync(tmp, f);
      this.stats.writes++;
    } catch {
      // A cache that cannot be written only costs speed.
    }
  }
}

/** Run async tasks with at most `limit` in flight. */
export async function pool(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return out;
}
