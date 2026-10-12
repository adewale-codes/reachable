export const entries = [];
export const spotChecks = [
  { repo: 'adiun/vite-monorepo', checked: 77, of: 384, untruthful: 0,
    note: 'all 77 sampled are cant_tell with truthful reasons: vite is "transitive" because it is declared by workspace members, not the root package.json (documented limitation), but the LLM still ran because project files import it; vite dev-server advisories llm_no_specific_api match the recorded answers; GHSA-c27g (LLM symbol launchEditor, not referenced) correctly stays cant_tell by the tier rule; the rest are transitive no_symbol_data.' },
  { repo: 'davestewart/spaceman', checked: 3, of: 11, untruthful: 0,
    note: 'all 3 sampled are transitive no_symbol_data: truthful.' },
];
