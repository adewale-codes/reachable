export const entries = [];
export const spotChecks = [
  { repo: 'Ruimve/microhook', checked: 18, of: 75, untruthful: 0,
    note: '15 sampled (14 transitive no_symbol_data, rollup direct but not imported) truthful; additionally checked the 3 direct lodash alerts: template transitive_parent_uses_symbol truthful (node_modules/git-raw-commits/index.js:27 calls template); unset/omit were name_as_string (rollup.config.js:14,32 lists "lodash" in rollup\'s external array); after the pre-publish Fix 3 the external entries are exempt and the reason is declared_unused, which is truthful: lodash is declared in package.json but no scanned file imports it (grep of the repo outside node_modules). Verdicts unchanged (cant_tell).' },
];
