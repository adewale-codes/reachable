const lodashWhatwg = (advisory, symbols) => ({
  repo: 'StiliyanKushev/csgo-tradeup-cli', advisory, package: 'lodash@4.17.21', verdict: 'unreachable', tier: 'curated',
  read: ['node_modules/whatwg-url/dist/URLSearchParams-impl.js:2', 'node_modules/whatwg-url/dist/URLSearchParams-impl.js:111', 'package-lock.json (dependents of node_modules/lodash)'], judgement: 'correct',
  why: `the only package that loads this lodash is whatwg-url, which requires lodash/sortBy and calls it once; sortBy does not reach ${symbols}; no other file in node_modules or the project names lodash.`,
});
export const entries = [
  lodashWhatwg('GHSA-f23m-r3pf-42rh', 'unset/omit'),
  lodashWhatwg('GHSA-r5fr-rjxr-66jc', 'template'),
  lodashWhatwg('GHSA-xxjr-mmjv-4gpg', 'unset/omit'),
];
export const spotChecks = [
  { repo: 'StiliyanKushev/csgo-tradeup-cli', checked: 8, of: 36, untruthful: 0,
    note: 'mongoose dynamic_import truthful (prediction/worker.js:10 import(path.join(...))); transitive no_symbol_data truthful.' },
  { repo: 'web3-storage/w3up-cli', checked: 38, of: 188, untruthful: 0,
    note: 'all 38 sampled are transitive no_symbol_data (vite, undici, protobufjs, npm-bundled tar/minimatch...): truthful, none curated and none imported by the project.' },
];
