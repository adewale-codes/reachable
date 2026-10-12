const R = 'odynvolk/omit-deep-lodash';
const loaders = {
  'babel-helper-define-map': ['lib/index.js:19', 'has'],
  'babel-helper-regex': ['lib/index.js:7', 'pull'],
  'babel-plugin-transform-es2015-block-scoping': ['lib/index.js:87,91', 'values, extend'],
  'babel-template': ['lib/index.js:57,61,65', 'cloneDeep, assign, has'],
  'babel-traverse': ['lib/index.js:50, lib/path/index.js:29, lib/scope/index.js:25-41, lib/visitors.js:33', 'includes, assign, repeat, defaults, clone'],
  'babel-types': ['lib/converters.js:27,31, lib/index.js:321,325', 'isPlainObject, isRegExp, clone, uniq'],
};
const advisories = [['GHSA-35jh-r3h4-6jhm', 'template'], ['GHSA-r5fr-rjxr-66jc', 'template'], ['GHSA-xxjr-mmjv-4gpg', 'unset/omit'], ['GHSA-f23m-r3pf-42rh', 'unset/omit']];
export const entries = [
  ...['GHSA-f23m-r3pf-42rh', 'GHSA-xxjr-mmjv-4gpg'].map((advisory) => ({
    repo: R, advisory, package: 'lodash@4.17.21', verdict: 'reachable', tier: 'curated',
    read: ['src/index.js:1', 'src/index.js:22'], judgement: 'correct',
    why: 'require("lodash/omit") then omit(o, props) with caller-supplied keys: the library\'s whole purpose; the advisories concern crafted omit paths.',
  })),
  ...Object.entries(loaders).flatMap(([pkg, [where, fns]]) => advisories.map(([advisory, sym]) => ({
    repo: R, advisory, package: 'lodash@4.17.20', verdict: 'unreachable', tier: 'curated', instance: `node_modules/${pkg}/node_modules/lodash`,
    read: [`node_modules/${pkg}/${where}`, `grep of every require of lodash and every _x2 binding use in node_modules/${pkg}`], judgement: 'correct',
    why: `this nested copy is loaded only by ${pkg}, which uses per-method imports of ${fns}; none reaches ${sym}; no dynamic require/eval in the package (the only "Function(" hits are visitor methods named Function).`,
  }))),
];
export const spotChecks = [
  { repo: R, checked: 16, of: 77, untruthful: 0,
    note: 'babel-cli / babel-register nested lodash dynamic_require + eval_present truthful: their loaders include a nested babel-core with require(parser) (lib/transformation/file/index.js:500), require(generator) (:699) and new Function (lib/api/browser.js:115), and babel-cli requires "vm" (lib/_babel-node.js:29); transitive no_symbol_data truthful.' },
];
