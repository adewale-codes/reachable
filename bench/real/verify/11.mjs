export const entries = ['GHSA-f23m-r3pf-42rh', 'GHSA-xxjr-mmjv-4gpg'].map((advisory) => ({
  repo: 'arizonatribe/vanillas', advisory, package: 'lodash@4.17.21', verdict: 'reachable', tier: 'curated',
  read: ['test/benchmarks/omit.js:2', 'test/benchmarks/omit.js:14', 'package.json (lodash in devDependencies; "benchmark" script)'], judgement: 'correct-but-not-exploitable',
  why: '_.omit is really called, in a dev-only benchmark (scope: dev) with the constant key list ["Jupiter","Saturn","Neptune"]; no attacker-controlled path reaches it.',
}));
export const spotChecks = [
  { repo: 'arizonatribe/vanillas', checked: 16, of: 78, untruthful: 0,
    note: 'all 16 sampled are no_symbol_data: 15 transitive and rollup (direct, but not imported by the project, so not sent to the LLM). Truthful.' },
];
