// LLM affected-symbol extraction (Phase 2) for advisories with no curated
// entry. Calls the Anthropic Messages API with plain fetch (no SDK, no new
// runtime dependency). Every response is cached on disk, keyed by advisory
// id + package + a hash of the advisory text and the full prompt, so reruns
// and the benchmark are offline and deterministic.
//
// The LLM's answer is untrusted. A code guard (applyGuard) drops any symbol
// whose quote is not verbatim in the advisory text, that is not an
// identifier, whose quote does not mention it, or that is certainly not an
// export of the installed package. verdict.js then enforces the trust tier:
// LLM data can produce reachable or cant_tell, never unreachable.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const DEFAULT_LLM_MODEL = 'claude-sonnet-5-5';
const API_URL = 'https://api.anthropic.com/v1/messages';
const FALLBACK_MODELS = new Set(['claude-opus-5', 'claude-opus-5-5', 'claude-fable-5-1']);

// v1 prompt and schema are kept verbatim: their cache keys are still computed so
// v1 answers can be reused where the v2 change cannot matter (see extract()).
export const SYSTEM_PROMPT_V1 = `You read npm security advisories and identify which exported functions of the affected package a program must call (or reference) to be exposed to the vulnerability.

Rules:
- Use only the advisory text you are given. Do not use outside knowledge of the package.
- A symbol is the name as user code reaches it from the package's main export: \`_.template(...)\` -> "template"; \`jwt.verify()\` -> "verify"; \`JSON5.parse\` -> "parse"; \`trimNewlines.end()\` -> "end".
- If the advisory says the vulnerability is triggered by calling the package's main export itself (for example \`ms(str)\` or \`minimist(args)\`), use the symbol "(module)".
- Do not list internal helpers or files (for example "setKey() in index.js") unless the text says they are exported; describe the exported entry point instead only if the text names it.
- For every symbol give "quote": a span copied character for character from the advisory text that supports it and that contains the symbol's name (for "(module)", a span describing the call).
- If the advisory does not name any specific function, method or entry point, set "names_specific_api" to false and return an empty "symbols" list.
- Answer with JSON only, matching the schema.`;

const SCHEMA_V1 = {
  type: 'object',
  properties: {
    names_specific_api: { type: 'boolean' },
    symbols: {
      type: 'array',
      items: {
        type: 'object',
        properties: { symbol: { type: 'string' }, quote: { type: 'string' } },
        required: ['symbol', 'quote'],
        additionalProperties: false,
      },
    },
  },
  required: ['names_specific_api', 'symbols'],
  additionalProperties: false,
};

// v2 (pre-publish fix): the model may say which module path a symbol lives in.
export const SYSTEM_PROMPT = SYSTEM_PROMPT_V1.replace(
  '- If the advisory does not name any specific function',
  '- If the advisory says the affected function lives only in a specific module path of the package (for example "some-lib/legacy" or "some-lib/dist/parser.js"), set "module" to that exact path, written as it appears in the advisory text. If the advisory does not name a module path, or the function is exported from the main package, omit "module".\n- If the advisory does not name any specific function',
);
const SCHEMA = {
  ...SCHEMA_V1,
  properties: {
    ...SCHEMA_V1.properties,
    symbols: {
      type: 'array',
      items: {
        type: 'object',
        properties: { symbol: { type: 'string' }, quote: { type: 'string' }, module: { type: 'string' } },
        required: ['symbol', 'quote'],
        additionalProperties: false,
      },
    },
  },
};

/**
 * Does the advisory text name a deep module path of the package, written as a
 * specifier ('nanoid/non-secure', `axios/lib/x.js`)? URLs (github.com/axios/axios),
 * '_next/...' and '@scope/pkg' do not count: the path must start a token.
 */
export function namesDeepPath(text, pkg) {
  const esc = pkg.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  return new RegExp('(^|[\\s\'"`(\\[])' + esc + '/[\\w.-]').test(text);
}

/** The advisory text given to the LLM and used by the verbatim-quote guard. */
export function advisoryText(vuln) {
  return [vuln.summary || '', vuln.details || ''].filter(Boolean).join('\n\n');
}

export function userPrompt({ advisoryId, pkg, text }) {
  return `Advisory ${advisoryId} for the npm package "${pkg}".\n\nAdvisory text:\n<<<\n${text}\n>>>\n\nWhich exported symbols of "${pkg}" are affected?`;
}

export function cacheKey({ advisoryId, pkg, text, version = 2 }) {
  const [prompt, schema] = version === 1 ? [SYSTEM_PROMPT_V1, SCHEMA_V1] : [SYSTEM_PROMPT, SCHEMA];
  const h = crypto.createHash('sha256').update(text).update('\u0000').update(prompt).update('\u0000')
    .update(userPrompt({ advisoryId, pkg, text })).update('\u0000').update(JSON.stringify(schema)).digest('hex').slice(0, 16);
  return `${advisoryId}__${pkg.replace(/[^\w.-]/g, '_')}__${h}.json`;
}

/** Strict parse of the model's answer. Returns { ok, value } or { ok: false, why }. */
export function parseAnswer(text) {
  let s = String(text || '').trim();
  const fence = s.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/);
  if (fence) s = fence[1];
  let v;
  try { v = JSON.parse(s); } catch (err) { return { ok: false, why: `not JSON (${err.message})` }; }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return { ok: false, why: 'not a JSON object' };
  if (typeof v.names_specific_api !== 'boolean') return { ok: false, why: 'names_specific_api is not a boolean' };
  if (!Array.isArray(v.symbols)) return { ok: false, why: 'symbols is not an array' };
  for (const [i, x] of v.symbols.entries()) {
    if (!x || typeof x !== 'object' || typeof x.symbol !== 'string' || typeof x.quote !== 'string' || !x.symbol.trim() || !x.quote.trim()) {
      return { ok: false, why: `symbols[${i}] is not {symbol: string, quote: string}` };
    }
    if (x.module !== undefined && typeof x.module !== 'string') return { ok: false, why: `symbols[${i}].module is not a string` };
  }
  return { ok: true, value: { names_specific_api: v.names_specific_api, symbols: v.symbols.map((x) => ({ symbol: x.symbol.trim(), quote: x.quote, ...(x.module && x.module.trim() ? { module: x.module.trim() } : {}) })) } };
}

const squash = (s) => s.replace(/\s+/g, ' ').trim();

/**
 * Code guard over a parsed answer. Quotes must appear verbatim in the advisory
 * text (whitespace runs are compared as single spaces). Exports are checked
 * when they could be determined; otherwise a symbol is kept with
 * exportCheck "unknown" (LLM symbols can only ever lead to reachable).
 * A module path (e.g. 'nanoid/non-secure') is kept only if it names a deep path
 * of this package and appears verbatim in the advisory text; otherwise the
 * symbol is kept UNqualified (it then applies to every entry point, the
 * conservative reading) and the dropped qualification is reported.
 * @param exportsInfo { determined: true, names: Set, callable } | { determined: false, why }
 * @param pkg the package name (needed to validate module paths)
 */
export function applyGuard(answer, text, exportsInfo, pkg = null) {
  const hay = squash(text);
  const kept = [];
  const dropped = [];
  const unqualified = [];
  const seen = new Set();
  for (const { symbol, quote, module: moduleIn } of answer.symbols) {
    const drop = (why) => dropped.push({ symbol, quote, why });
    if (symbol !== '(module)' && !/^[A-Za-z_$][\w$]*$/.test(symbol)) { drop('not_an_identifier'); continue; }
    if (!hay.includes(squash(quote))) { drop('quote_not_in_advisory'); continue; }
    if (symbol !== '(module)' && !quote.includes(symbol)) { drop('quote_lacks_symbol'); continue; }
    let module = null;
    if (moduleIn && moduleIn !== pkg) {
      if (pkg && moduleIn.startsWith(`${pkg}/`) && hay.includes(moduleIn)) module = moduleIn;
      else unqualified.push({ symbol, module: moduleIn, why: !pkg || !moduleIn.startsWith(`${pkg}/`) ? 'module_not_a_deep_path_of_package' : 'module_not_in_advisory' });
    }
    if (seen.has(`${symbol}|${module || ''}`)) continue;
    let exportCheck = 'unknown';
    // The main entry's exports say nothing about a deep module: not checked there.
    if (!module && exportsInfo && exportsInfo.determined) {
      const ok = symbol === '(module)' ? exportsInfo.callable : exportsInfo.names.has(symbol);
      if (!ok) { drop('not_an_export'); continue; }
      exportCheck = 'confirmed';
    }
    seen.add(`${symbol}|${module || ''}`);
    kept.push({ symbol, quote, exportCheck, ...(module ? { module } : {}) });
  }
  return { kept, dropped, unqualified };
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

export class LlmExtractor {
  /**
   * @param mode      'live' (call the API on a cache miss), 'cache' (recorded responses only), 'off'
   * @param readDirs  cache directories searched in order
   * @param writeDir  where live responses are stored (default readDirs[readDirs.length - 1])
   */
  constructor({ mode, apiKey = null, model = DEFAULT_LLM_MODEL, readDirs = [], writeDir = null, fetchImpl, apiUrl } = {}) {
    this.mode = mode;
    this.apiKey = apiKey;
    this.model = model;
    this.readDirs = readDirs;
    this.writeDir = writeDir || readDirs[readDirs.length - 1];
    this.fetch = fetchImpl || globalThis.fetch;
    this.apiUrl = apiUrl || process.env.REACHABLE_LLM_URL || API_URL;
    this.stats = { calls: 0, cacheHits: 0, failures: 0 };
  }

  /** @returns {{ status: 'ok', answer, model, record } | { status: 'unavailable'|'invalid', detail, model? }} */
  async extract({ advisoryId, pkg, vuln }) {
    const text = advisoryText(vuln);
    const key = cacheKey({ advisoryId, pkg, text });
    // A v1 answer (asked before the prompt could report module paths) is reused
    // only when the advisory text names no deep path of the package at all: then
    // the v2 rule has nothing to apply to and the answer would be the same.
    const keys = [key, ...(namesDeepPath(text, pkg) ? [] : [cacheKey({ advisoryId, pkg, text, version: 1 })])];
    for (const k of keys) {
      for (const d of this.readDirs) {
        const rec = readJson(path.join(d, k));
        if (rec && typeof rec.responseText === 'string') {
          this.stats.cacheHits++;
          const parsed = parseAnswer(rec.responseText);
          if (!parsed.ok) return { status: 'invalid', detail: parsed.why, model: rec.model, record: rec };
          return { status: 'ok', answer: parsed.value, model: rec.model, record: rec, text, promptVersion: k === key ? 2 : 1 };
        }
      }
    }
    if (this.mode !== 'live') return { status: 'unavailable', detail: 'no recorded LLM response and live calls are off' };
    if (!this.apiKey) return { status: 'unavailable', detail: 'ANTHROPIC_API_KEY is not set' };

    this.stats.calls++;
    let res;
    try {
      res = await this.call(advisoryId, pkg, text);
    } catch (err) {
      this.stats.failures++;
      return { status: 'unavailable', detail: err.message };
    }
    const rec = {
      advisoryId, package: pkg, model: res.model, requestedModel: this.model, createdAt: new Date().toISOString(),
      stopReason: res.stop_reason, responseText: res.text,
    };
    if (this.writeDir) {
      fs.mkdirSync(this.writeDir, { recursive: true });
      fs.writeFileSync(path.join(this.writeDir, key), JSON.stringify(rec, null, 2) + '\n');
    }
    const parsed = parseAnswer(res.text);
    if (!parsed.ok) return { status: 'invalid', detail: parsed.why, model: res.model, record: rec };
    return { status: 'ok', answer: parsed.value, model: res.model, record: rec, text };
  }

  async call(advisoryId, pkg, text) {
    const body = {
      model: this.model,
      max_tokens: 16000,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: userPrompt({ advisoryId, pkg, text }) }],
      output_config: { format: { type: 'json_schema', schema: SCHEMA } },
    };
    const headers = { 'content-type': 'application/json', 'x-api-key': this.apiKey, 'anthropic-version': '2023-06-01' };
    if (FALLBACK_MODELS.has(this.model) && process.env.REACHABLE_LLM_FALLBACKS !== '0') {
      // Server-side refusal fallback: a policy decline is re-run on Anthropic's
      // recommended fallback model instead of failing the extraction.
      body.fallbacks = 'default';
      headers['anthropic-beta'] = 'server-side-fallback-2026-07-01';
    }
    let lastErr;
    for (let attempt = 0; attempt < 3; attempt++) {
      let r;
      try {
        r = await this.fetch(this.apiUrl, { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(180000) });
      } catch (err) {
        lastErr = new Error(`request failed: ${err.message}${err.cause && err.cause.code ? ` (${err.cause.code})` : ''}`);
        continue;
      }
      if (r.status === 429 || r.status >= 500) {
        lastErr = new Error(`Anthropic API returned HTTP ${r.status}`);
        await new Promise((ok) => setTimeout(ok, 1000 * (attempt + 1)));
        continue;
      }
      const json = await r.json().catch(() => null);
      if (!r.ok) throw new Error(`Anthropic API returned HTTP ${r.status}${json && json.error ? `: ${json.error.type}: ${json.error.message}` : ''}`);
      if (json.stop_reason === 'refusal') {
        const cat = json.stop_details && json.stop_details.category;
        throw new Error(`the model declined the request${cat ? ` (${cat})` : ''}`);
      }
      if (json.stop_reason === 'max_tokens') throw new Error('response hit max_tokens');
      const t = (json.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('');
      return { text: t, model: json.model, stop_reason: json.stop_reason };
    }
    throw lastErr;
  }
}

/**
 * Turn an extraction result + guard into the symbolInfo verdict.js expects.
 */
export function toSymbolInfo(result, exportsInfo, pkg = null) {
  if (result.status === 'unavailable') {
    return { tier: null, reasons: [{ code: 'no_symbol_data', llmNote: `LLM extraction did not run: ${result.detail}` }, { code: 'llm_unavailable', detail: result.detail }], llm: { status: 'unavailable', detail: result.detail } };
  }
  if (result.status === 'invalid') {
    return { tier: null, reasons: [{ code: 'no_symbol_data', llmNote: 'the LLM answer was rejected' }, { code: 'llm_invalid_output', detail: result.detail }], llm: { status: 'invalid', detail: result.detail, model: result.model } };
  }
  const { answer } = result;
  if (!answer.names_specific_api || !answer.symbols.length) {
    return { tier: null, reasons: [{ code: 'no_symbol_data', llmNote: 'the LLM found no specific function named' }, { code: 'llm_no_specific_api' }], llm: { status: 'no_specific_api', model: result.model } };
  }
  const g = applyGuard(answer, result.text, exportsInfo, pkg);
  const llm = { status: 'ok', model: result.model, proposed: answer.symbols.length, kept: g.kept, dropped: g.dropped, unqualified: g.unqualified, promptVersion: result.promptVersion || 2, exportsDetermined: Boolean(exportsInfo && exportsInfo.determined), synthetic: Boolean(result.record && result.record.synthetic) };
  if (!g.kept.length) {
    const detail = g.dropped.map((d) => `${d.symbol}: ${d.why}`).join('; ');
    return { tier: null, reasons: [{ code: 'no_symbol_data', llmNote: 'every LLM-proposed symbol was rejected by the guard' }, { code: 'llm_no_valid_symbols', detail }], llm };
  }
  return { tier: 'llm', symbols: g.kept, model: result.model, llm };
}
