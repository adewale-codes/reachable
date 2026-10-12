export const entries = [];
export const spotChecks = [
  { repo: 'thepranaygupta/react-tailwind-css-starter-pack', checked: 37, of: 168, untruthful: 0,
    note: 'The first (live) scan exited 2: tree-sitter rejected a bare "&" in JSX text at src/App.jsx:6-7 ("React & Tailwind CSS"), valid JSX. Fixed in ANALYZER_VERSION 3.0.2 (tolerated only when the error is plain JSX text); the final offline replay completes with the same 168 cant_tell verdicts. 34 sampled transitive no_symbol_data truthful; additionally checked all 3 non-trivial ones: lodash template transitive_parent_uses_symbol truthful (html-webpack-plugin lib/loader.js:32 and workbox-build call template); lodash unset/omit module_escapes truthful by the rules (eslint-plugin-flowtype passes require("lodash") into Babel\'s _interopRequireDefault helper), a precision cost: compiled Babel output is common in node_modules.' },
];
