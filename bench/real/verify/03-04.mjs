export const entries = [
  { repo: 'IBM-Cloud/get-started-node', advisory: 'GHSA-cf4h-3jhx-xvhq', package: 'underscore@1.9.2', verdict: 'unreachable', tier: 'curated',
    read: ['node_modules/cfenv/lib/cfenv.js:11', 'node_modules/cfenv/lib/cfenv.js (all _ uses)', 'node_modules/lodash/lodash.js:17193', 'node_modules/lodash/core.js:3861'], judgement: 'correct',
    why: 'cfenv is the only loader of underscore and uses only _.clone, _.isEmpty and _.isRegExp; the two other files naming "underscore" (lodash.js, core.js) mention it in comments only; the project never imports it.' },
];
export const spotChecks = [
  { repo: 'IBM-Cloud/get-started-node', checked: 9, of: 42, untruthful: 0,
    note: 'lodash unmapped_subpath + eval_present truthful (async requires lodash/_baseRest, an internal helper); transitive no_symbol_data entries truthful.' },
  { repo: 'richienabuk/express-js-api-rbac', checked: 17, of: 82, untruthful: 0,
    note: 'sequelize llm_no_valid_symbols truthful (LLM proposed findAll, a Model method, not a module export; the guard dropped it); transitive no_symbol_data entries truthful.' },
];
