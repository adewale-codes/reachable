// Library entry point.
export { scan, exitCodeFor, VERSION } from './scan.js';
export { formatText, formatJson, formatMarkdown } from './format.js';
export { readInventory } from './inventory.js';
export { OsvClient, defaultCacheDir } from './osv.js';
export { extractUsage, analyzeTree } from './usage.js';
export { decideAlert, decide, analyzeUse, classify, loadAdvisoryData, REASONS } from './verdict.js';
export { PackageCache, ANALYZER_VERSION } from './pkgcache.js';
export { ScanError } from './errors.js';
