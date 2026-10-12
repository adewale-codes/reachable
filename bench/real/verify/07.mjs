const lodash = (advisory, symbols) => ({
  repo: 'SashenJayathilaka/Spotify-Clone', advisory, package: 'lodash@4.17.21', verdict: 'unreachable', tier: 'curated',
  read: ['components/Center.js:3', 'components/Center.js:30', 'components/Player.js:4', 'components/Player.js:73', 'node_modules/lodash.merge/index.js:3,255 (comments only)'], judgement: 'correct',
  why: `the project uses only shuffle and debounce from lodash; neither reaches ${symbols}; the only other file naming lodash (lodash.merge) does so in comments, and no installed package declares lodash.`,
});
export const entries = [
  lodash('GHSA-f23m-r3pf-42rh', 'unset/omit'),
  lodash('GHSA-r5fr-rjxr-66jc', 'template'),
  lodash('GHSA-xxjr-mmjv-4gpg', 'unset/omit'),
];
export const spotChecks = [
  { repo: 'SashenJayathilaka/Spotify-Clone', checked: 17, of: 82, untruthful: 0,
    note: 'json5 transitive_parent_uses_symbol truthful (tsconfig-paths lib/tsconfig-loader.js:85 calls JSON5.parse); next llm_no_specific_api match the recorded answers; transitive no_symbol_data truthful.' },
];
