// OSV.dev advisory lookup with an on-disk cache.
//
// Policy:
//   - Online (default): ask OSV first. If OSV cannot be reached, fall back to
//     the cache and say so in the report. If something is missing from the
//     cache too, throw a ScanError (exit 2). Never return partial results.
//   - Offline (--offline): use only the cache; anything missing is a ScanError.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ScanError } from './errors.js';

export const DEFAULT_OSV_URL = 'https://api.osv.dev';
const BATCH_LIMIT = 1000;
const DETAIL_CONCURRENCY = 8;

export function defaultCacheDir() {
  if (process.env.REACHABLE_CACHE_DIR) return process.env.REACHABLE_CACHE_DIR;
  if (process.platform === 'win32' && process.env.LOCALAPPDATA) {
    return path.join(process.env.LOCALAPPDATA, 'reachable', 'cache');
  }
  const xdg = process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
  return path.join(xdg, 'reachable');
}

function safeName(s) {
  return s.replace(/[^A-Za-z0-9._@-]/g, (c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

function writeJsonAtomic(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n');
  fs.renameSync(tmp, file);
}

function readJsonOrNull(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function describeFetchError(err) {
  let cause = err && err.cause;
  if (cause && Array.isArray(cause.errors) && cause.errors.length) cause = cause.errors[0]; // AggregateError (IPv4 + IPv6 attempts)
  const code = (cause && (cause.code || cause.message || cause.name)) || err.name;
  return `${err.message}${code && !String(err.message).includes(code) ? ` (${code})` : ''}`;
}

export class OsvClient {
  constructor({ cacheDir = defaultCacheDir(), offline = false, baseUrl, timeoutMs = 30000, fetchImpl } = {}) {
    this.cacheDir = cacheDir;
    this.offline = offline;
    this.baseUrl = (baseUrl || process.env.REACHABLE_OSV_URL || DEFAULT_OSV_URL).replace(/\/+$/, '');
    this.timeoutMs = timeoutMs;
    this.fetch = fetchImpl || globalThis.fetch;
    this.stats = { mode: offline ? 'offline' : 'online', queriesFromNetwork: 0, queriesFromCache: 0, vulnsFromNetwork: 0, vulnsFromCache: 0, networkError: null };
  }

  queryCacheFile(name, version) {
    return path.join(this.cacheDir, 'query', 'npm', `${safeName(name)}@${safeName(version)}.json`);
  }

  vulnCacheFile(id) {
    return path.join(this.cacheDir, 'vulns', `${safeName(id)}.json`);
  }

  async request(method, urlPath, body) {
    const attempts = 3;
    let lastErr;
    for (let i = 0; i < attempts; i++) {
      try {
        const res = await this.fetch(this.baseUrl + urlPath, {
          method,
          headers: body ? { 'content-type': 'application/json' } : undefined,
          body: body ? JSON.stringify(body) : undefined,
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        if (res.status >= 500 || res.status === 429) {
          lastErr = new Error(`OSV returned HTTP ${res.status} for ${method} ${urlPath}`);
        } else if (!res.ok) {
          throw Object.assign(new Error(`OSV returned HTTP ${res.status} for ${method} ${urlPath}`), { fatal: true });
        } else {
          return await res.json();
        }
      } catch (err) {
        if (err.fatal) throw err;
        lastErr = new Error(describeFetchError(err));
      }
      if (i < attempts - 1) await new Promise((r) => setTimeout(r, 400 * (i + 1)));
    }
    throw lastErr;
  }

  /**
   * @param {{name: string, version: string}[]} pkgs
   * @returns {Promise<Map<string, {id: string, modified: string}[]>>} keyed by "name@version"
   */
  async queryPackages(pkgs) {
    const unique = [...new Map(pkgs.map((p) => [`${p.name}@${p.version}`, p])).values()];
    const out = new Map();

    if (!this.offline && unique.length) {
      try {
        const fresh = await this.queryNetwork(unique);
        for (const p of unique) {
          const key = `${p.name}@${p.version}`;
          const vulns = fresh.get(key);
          writeJsonAtomic(this.queryCacheFile(p.name, p.version), {
            package: p.name, ecosystem: 'npm', version: p.version, fetchedAt: new Date().toISOString(), vulns,
          });
          out.set(key, vulns);
        }
        this.stats.queriesFromNetwork += unique.length;
        return out;
      } catch (err) {
        if (err.fatal) throw new ScanError(`OSV query failed: ${err.message}`, 'osv_failed');
        this.stats.networkError = err.message;
      }
    }

    const missing = [];
    for (const p of unique) {
      const cached = readJsonOrNull(this.queryCacheFile(p.name, p.version));
      if (cached && Array.isArray(cached.vulns)) {
        out.set(`${p.name}@${p.version}`, cached.vulns);
        this.stats.queriesFromCache++;
        this.stats.oldestCacheEntry = minDate(this.stats.oldestCacheEntry, cached.fetchedAt);
      } else {
        missing.push(`${p.name}@${p.version}`);
      }
    }
    if (missing.length) {
      const why = this.offline ? '--offline was given' : `OSV could not be reached (${this.stats.networkError})`;
      throw new ScanError(
        `Advisory lookup failed: ${why}, and there is no cached OSV result for ${missing.length} of ${unique.length} packages ` +
        `(e.g. ${missing.slice(0, 5).join(', ')}). Cache directory: ${this.cacheDir}`,
        'osv_unavailable');
    }
    return out;
  }

  async queryNetwork(unique) {
    const out = new Map();
    for (let start = 0; start < unique.length; start += BATCH_LIMIT) {
      const chunk = unique.slice(start, start + BATCH_LIMIT);
      const body = { queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })) };
      const res = await this.request('POST', '/v1/querybatch', body);
      if (!res || !Array.isArray(res.results) || res.results.length !== chunk.length) {
        throw new Error('OSV querybatch returned an unexpected response shape');
      }
      for (let i = 0; i < chunk.length; i++) {
        const p = chunk[i];
        const vulns = [...(res.results[i].vulns || [])];
        let token = res.results[i].next_page_token;
        while (token) {
          const page = await this.request('POST', '/v1/querybatch', {
            queries: [{ package: { name: p.name, ecosystem: 'npm' }, version: p.version, page_token: token }],
          });
          vulns.push(...(page.results[0].vulns || []));
          token = page.results[0].next_page_token;
        }
        out.set(`${p.name}@${p.version}`, vulns.map((v) => ({ id: v.id, modified: v.modified })));
      }
    }
    return out;
  }

  /**
   * @param {{id: string, modified?: string}[]} refs
   * @returns {Promise<Map<string, object>>} id -> OSV vulnerability record
   */
  async getVulns(refs) {
    const unique = [...new Map(refs.map((r) => [r.id, r])).values()];
    const out = new Map();
    const toFetch = [];
    for (const ref of unique) {
      const cached = readJsonOrNull(this.vulnCacheFile(ref.id));
      const fresh = cached && cached.vuln && (!ref.modified || sameInstant(cached.vuln.modified, ref.modified));
      if (cached && cached.vuln && (fresh || this.offline || this.stats.networkError)) {
        out.set(ref.id, cached.vuln);
        this.stats.vulnsFromCache++;
      } else {
        toFetch.push(ref);
      }
    }

    const failures = [];
    let next = 0;
    const worker = async () => {
      while (next < toFetch.length) {
        const ref = toFetch[next++];
        try {
          if (this.offline) throw new Error('--offline was given');
          const vuln = await this.request('GET', `/v1/vulns/${encodeURIComponent(ref.id)}`);
          writeJsonAtomic(this.vulnCacheFile(ref.id), { fetchedAt: new Date().toISOString(), vuln });
          out.set(ref.id, vuln);
          this.stats.vulnsFromNetwork++;
        } catch (err) {
          const cached = readJsonOrNull(this.vulnCacheFile(ref.id));
          if (cached && cached.vuln) {
            out.set(ref.id, cached.vuln);
            this.stats.vulnsFromCache++;
            this.stats.networkError = this.stats.networkError || err.message;
          } else {
            failures.push(`${ref.id} (${err.message})`);
          }
        }
      }
    };
    await Promise.all(Array.from({ length: DETAIL_CONCURRENCY }, worker));
    if (failures.length) {
      throw new ScanError(
        `Could not fetch advisory details for ${failures.length} advisories and they are not cached: ${failures.slice(0, 5).join('; ')}`,
        'osv_unavailable');
    }
    return out;
  }
}

// querybatch reports `modified` in microseconds, /v1/vulns in nanoseconds.
function sameInstant(a, b) {
  if (!a || !b) return false;
  return Date.parse(a) === Date.parse(b);
}

function minDate(a, b) {
  if (!a) return b;
  if (!b) return a;
  return a < b ? a : b;
}
