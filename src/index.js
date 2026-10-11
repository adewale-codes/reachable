// Library entry point.
export { scan, exitCodeFor, VERSION } from './scan.js';
export { formatText, formatJson } from './format.js';
export { readInventory } from './inventory.js';
export { OsvClient, defaultCacheDir } from './osv.js';
export { extractUsage, analyzeTree } from './usage.js';
export { computeVerdicts, decide, classify, loadAdvisoryData, REASONS } from './verdict.js';
export { ScanError } from './errors.js';
