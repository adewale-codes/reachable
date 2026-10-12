// Hand verification, repos 1-2. judgement: correct | wrong | correct-but-not-exploitable
const CBNE = 'correct-but-not-exploitable';
export const entries = [
  // ---- desirekaleba/node-mysql-jwt-auth
  { repo: 'desirekaleba/node-mysql-jwt-auth', advisory: 'GHSA-8cf7-32gw-wr33', package: 'jsonwebtoken@8.5.1', verdict: 'reachable', tier: 'llm',
    read: ['src/utils/token.js:5', 'src/utils/token.js:9', 'src/controllers/auth.controller.js:18', 'src/controllers/auth.controller.js:49'], judgement: CBNE,
    why: 'jwt.sign runs on signup/signin via generate(); the advisory concerns asymmetric key types, but the app signs with an HMAC string secret.' },
  { repo: 'desirekaleba/node-mysql-jwt-auth', advisory: 'GHSA-hjrf-2m68-5959', package: 'jsonwebtoken@8.5.1', verdict: 'reachable', tier: 'curated',
    read: ['src/utils/token.js:9'], judgement: CBNE,
    why: 'jwt.verify is referenced inside decode(), which nothing in the repo calls (dead code), and the key is a string, not a key-retrieval function.' },
  { repo: 'desirekaleba/node-mysql-jwt-auth', advisory: 'GHSA-qwph-4952-7xr6', package: 'jsonwebtoken@8.5.1', verdict: 'reachable', tier: 'curated',
    read: ['src/utils/token.js:9'], judgement: CBNE,
    why: 'jwt.verify is referenced inside decode(), which is never called; it would only matter with a falsy JWT_SECRET_KEY.' },
  // ---- bluuweb/api-rest-twitch-2022-mongo-express-node-jwt
  ...[
    ['GHSA-3g43-6gmg-66jw', 'prototype-pollution gadget in config merge; needs Object.prototype polluted by another bug'],
    ['GHSA-43fc-jf86-j433', 'mergeConfig crash on an own __proto__ key; the app passes no attacker-built config object'],
    ['GHSA-7q8q-rj6j-mhjq', 'nested option objects read polluted prototype values; needs prior prototype pollution and auth/paramsSerializer placeholders, neither present'],
    ['GHSA-898c-q2cr-xwhg', 'read-side prototype-pollution gadgets; needs prior prototype pollution'],
    ['GHSA-fvcv-3m26-pcqx', 'header injection chain needs prototype pollution elsewhere first'],
    ['GHSA-j5f8-grm9-p9fc', 'Proxy-Authorization leak on redirect; needs an authenticated proxy, none configured'],
    ['GHSA-jr5f-v2jv-69x6', 'absolute URL overrides baseURL; no baseURL is set (the route fetches a user URL by design)'],
    ['GHSA-m7pr-hjqh-92cm', 'no_proxy bypass via IP alias; needs proxy + NO_PROXY env configuration'],
    ['GHSA-mmx7-hfxf-jppx', 'axios.get reads inherited data; needs prior prototype pollution'],
    ['GHSA-p92q-9vqr-4j8v', 'Proxy-Authorization leak across HTTP-to-HTTPS redirect; needs an authenticated proxy'],
    ['GHSA-pmwg-cvhr-8vh7', 'NO_PROXY loopback-subnet bypass; needs proxy configuration'],
    ['GHSA-w9j2-pvgh-6h63', 'validateStatus pollution gadget; needs prior pollution'],
    ['GHSA-xx6v-rp6x-q39c', 'withXSRFToken pollution gadget (browser XSRF); server-side use, needs prior pollution'],
  ].map(([advisory, pre]) => ({
    repo: 'bluuweb/api-rest-twitch-2022-mongo-express-node-jwt', advisory, package: 'axios@0.27.2', verdict: 'reachable', tier: 'llm',
    read: ['middlewares/validatorManager.js:31', 'routes/link.route.js:24'], judgement: CBNE,
    why: `axios.get(value) runs in bodyLinkValidator on POST /links with a user-supplied URL, so axios's shared request path is reached; ${pre}.`,
  })),
  { repo: 'bluuweb/api-rest-twitch-2022-mongo-express-node-jwt', advisory: 'GHSA-8cf7-32gw-wr33', package: 'jsonwebtoken@8.5.1', verdict: 'reachable', tier: 'llm',
    read: ['utils/tokenManager.js:6', 'utils/tokenManager.js:16', 'middlewares/requireToken.js:11', 'middlewares/requireRefreshToken.js:9'], judgement: CBNE,
    why: 'sign and verify both run on auth routes; the advisory concerns asymmetric key types and the app uses HMAC secrets from env.' },
  { repo: 'bluuweb/api-rest-twitch-2022-mongo-express-node-jwt', advisory: 'GHSA-hjrf-2m68-5959', package: 'jsonwebtoken@8.5.1', verdict: 'reachable', tier: 'curated',
    read: ['middlewares/requireToken.js:11', 'middlewares/requireRefreshToken.js:9'], judgement: CBNE,
    why: 'verify runs on every protected route; the key is an env string, not a key-retrieval function mixing key types.' },
  { repo: 'bluuweb/api-rest-twitch-2022-mongo-express-node-jwt', advisory: 'GHSA-qwph-4952-7xr6', package: 'jsonwebtoken@8.5.1', verdict: 'reachable', tier: 'curated',
    read: ['middlewares/requireToken.js:11', 'middlewares/requireRefreshToken.js:9'], judgement: CBNE,
    why: 'verify runs with no algorithms option; exploitable only if JWT_SECRET / JWT_REFRESH are unset (falsy secret), which is a deployment question.' },
  { repo: 'bluuweb/api-rest-twitch-2022-mongo-express-node-jwt', advisory: 'GHSA-mwcw-c2x4-8c55', package: 'nanoid@3.3.4', verdict: 'reachable', tier: 'llm',
    read: ['controllers/link.controller.js:59'], judgement: CBNE,
    why: 'main nanoid() is affected for fractional sizes in Node; it is called with the constant 6.' },
  { repo: 'bluuweb/api-rest-twitch-2022-mongo-express-node-jwt', advisory: 'GHSA-xwg4-73v4-xw9w', package: 'nanoid@3.3.4', verdict: 'reachable', tier: 'llm',
    read: ['controllers/link.controller.js:59'], judgement: CBNE,
    why: 'integer overflow needs a user-influenced size; it is called with the constant 6.' },
];
export const spotChecks = [
  { repo: 'desirekaleba/node-mysql-jwt-auth', checked: 10, of: 48, untruthful: 0,
    note: 'transitive no_symbol_data (minimatch, qs, path-to-regexp, semver, brace-expansion, send, braces) correct: not curated and not sent to the LLM because the project does not import them; joi llm_tier_cannot_prove_unreachable correct: LLM symbols (messages, link, validate...) not referenced in src.' },
  { repo: 'bluuweb/api-rest-twitch-2022-mongo-express-node-jwt', checked: 16, of: 72, untruthful: 0,
    note: 'axios/mongoose llm_no_specific_api match the recorded answers; express gateway_used is truthful (express() called, LLM symbol redirect is a response method); transitive no_symbol_data entries are truthful. After the pre-publish fixes, also checked the 2 new cant_tell (nanoid 28wg other_entry_point, axios pf86 llm_no_specific_api; see changes).' },
];

// Verdicts that changed with the pre-publish fixes (ANALYZER_VERSION 3.1.0), checked by hand.
export const changes = [
  { repo: 'bluuweb/api-rest-twitch-2022-mongo-express-node-jwt', advisory: 'GHSA-28wg-ghj8-5hjv', package: 'nanoid@3.3.4', old: 'reachable', new: 'cant_tell',
    newReasons: ['other_entry_point', 'llm_tier_cannot_prove_unreachable'], cause: 'Fix 1 (subpath-aware symbols)',
    read: ['controllers/link.controller.js:1', 'controllers/link.controller.js:59', 'advisory text: "...customAlphabet and nanoid functions of its non-secure module (nanoid/non-secure)"'],
    judgement: 'correct', why: 'The re-asked LLM answer ties customAlphabet and nanoid to nanoid/non-secure (written verbatim in the advisory); the app imports the main nanoid, so the wrong reachable is gone. It is cant_tell, not unreachable, by design: subpath data never proves unreachable.' },
  { repo: 'bluuweb/api-rest-twitch-2022-mongo-express-node-jwt', advisory: 'GHSA-pf86-5x62-jrwf', package: 'axios@0.27.2', old: 'reachable', new: 'cant_tell',
    newReasons: ['no_symbol_data', 'llm_no_specific_api'], cause: 'LLM re-ask (the advisory text contains an axios/... path, so the v1 answer could not be reused)',
    read: ['middlewares/validatorManager.js:31', 'recorded v1 answer (get, from a PoC line) and v2 answer (names_specific_api: false)'],
    judgement: 'truthful but a loss', why: 'Not caused by the subpath logic: asked again, the model said the advisory names no specific API (it describes prototype-pollution gadgets read during any request). cant_tell is truthful; the earlier reachable (axios.get reaches the shared request path, not exploitable as written) is lost. Safe direction.' },
];
