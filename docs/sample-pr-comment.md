### reachable: dependency advisories your code can trigger

**20 reachable** · **0 unreachable** · **70 can't tell** · 90 alerts in `backend-twitch`
<sub>LLM symbol extraction uses recorded responses only (no API calls).</sub>

| Advisory | Package | Scope | Affected | Evidence |
|---|---|---|---|---|
| [GHSA-3g43-6gmg-66jw](https://osv.dev/vulnerability/GHSA-3g43-6gmg-66jw) | `axios@0.27.2` | prod | get _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-43fc-jf86-j433](https://osv.dev/vulnerability/GHSA-43fc-jf86-j433) | `axios@0.27.2` | prod | mergeConfig, get, post, getUri _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-7q8q-rj6j-mhjq](https://osv.dev/vulnerability/GHSA-7q8q-rj6j-mhjq) | `axios@0.27.2` | prod | getUri, get _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-898c-q2cr-xwhg](https://osv.dev/vulnerability/GHSA-898c-q2cr-xwhg) | `axios@0.27.2` | prod | get, request _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-fvcv-3m26-pcqx](https://osv.dev/vulnerability/GHSA-fvcv-3m26-pcqx) | `axios@0.27.2` | prod | get _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-j5f8-grm9-p9fc](https://osv.dev/vulnerability/GHSA-j5f8-grm9-p9fc) | `axios@0.27.2` | prod | get _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-jr5f-v2jv-69x6](https://osv.dev/vulnerability/GHSA-jr5f-v2jv-69x6) | `axios@0.27.2` | prod | create, get _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-m7pr-hjqh-92cm](https://osv.dev/vulnerability/GHSA-m7pr-hjqh-92cm) | `axios@0.27.2` | prod | get _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-mmx7-hfxf-jppx](https://osv.dev/vulnerability/GHSA-mmx7-hfxf-jppx) | `axios@0.27.2` | prod | get, delete, head, options _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-p92q-9vqr-4j8v](https://osv.dev/vulnerability/GHSA-p92q-9vqr-4j8v) | `axios@0.27.2` | prod | get _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-pf86-5x62-jrwf](https://osv.dev/vulnerability/GHSA-pf86-5x62-jrwf) | `axios@0.27.2` | prod | get _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-pmwg-cvhr-8vh7](https://osv.dev/vulnerability/GHSA-pmwg-cvhr-8vh7) | `axios@0.27.2` | prod | get _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-w9j2-pvgh-6h63](https://osv.dev/vulnerability/GHSA-w9j2-pvgh-6h63) | `axios@0.27.2` | prod | get _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-xx6v-rp6x-q39c](https://osv.dev/vulnerability/GHSA-xx6v-rp6x-q39c) | `axios@0.27.2` | prod | get _(LLM-extracted)_ | `middlewares/validatorManager.js:31` `await axios.get(value);` |
| [GHSA-8cf7-32gw-wr33](https://osv.dev/vulnerability/GHSA-8cf7-32gw-wr33) | `jsonwebtoken@8.5.1` | prod | sign, verify _(LLM-extracted)_ | `middlewares/requireRefreshToken.js:11` `req.uid = uid;` (+3 more) |
| [GHSA-hjrf-2m68-5959](https://osv.dev/vulnerability/GHSA-hjrf-2m68-5959) | `jsonwebtoken@8.5.1` | prod | verify | `middlewares/requireRefreshToken.js:11` `req.uid = uid;` (+1 more) |
| [GHSA-qwph-4952-7xr6](https://osv.dev/vulnerability/GHSA-qwph-4952-7xr6) | `jsonwebtoken@8.5.1` | prod | verify | `middlewares/requireRefreshToken.js:11` `req.uid = uid;` (+1 more) |
| [GHSA-28wg-ghj8-5hjv](https://osv.dev/vulnerability/GHSA-28wg-ghj8-5hjv) | `nanoid@3.3.4` | prod | customAlphabet, nanoid _(LLM-extracted)_ | `controllers/link.controller.js:59` `const link = new Link({ longLink, nanoLink: nanoid(6), uid: req.uid });` |
| [GHSA-mwcw-c2x4-8c55](https://osv.dev/vulnerability/GHSA-mwcw-c2x4-8c55) | `nanoid@3.3.4` | prod | nanoid _(LLM-extracted)_ | `controllers/link.controller.js:59` `const link = new Link({ longLink, nanoLink: nanoid(6), uid: req.uid });` |
| [GHSA-xwg4-73v4-xw9w](https://osv.dev/vulnerability/GHSA-xwg4-73v4-xw9w) | `nanoid@3.3.4` | prod | nanoid _(LLM-extracted)_ | `controllers/link.controller.js:59` `const link = new Link({ longLink, nanoLink: nanoid(6), uid: req.uid });` |

<details><summary>Can't tell (70), by reason</summary>

**`no_symbol_data`** (57): There is no curated record of which axios functions this advisory affects, so usage cannot be matched against it. LLM: the LLM found no specific function named.
<sub>axios@0.27.2, body-parser@1.20.0, brace-expansion@1.1.11, braces@3.0.2, cookie@0.4.1, cookie@0.5.0, follow-redirects@1.15.0, form-data@4.0.0, got@9.6.0, http-cache-semantics@4.1.0, ip@1.1.5, jws@3.2.2, minimatch@3.1.2, mongodb@4.5.0, mongoose@6.3.1, +10 more</sub>

**`llm_tier_cannot_prove_unreachable`** (8): The affected functions come from LLM extraction, which may have missed one. LLM-sourced data can show a call is reachable but is never allowed to prove unreachable.
<sub>axios@0.27.2, mongoose@6.3.1, nanoid@3.3.4</sub>

**`gateway_used`** (5): In the project, a express call that returns an object exposing the package's other functions is used (for example a chain wrapper), so later calls on it could reach redirect.
<sub>express@4.18.0, lodash@4.17.21</sub>

</details>

---
<sub><b>reachable</b> means your code references a function the advisory names; it is not the same as exploitable. <b>unreachable</b> is only reported with proof; anything unproven is <b>can't tell</b>. Generated by reachable 0.1.0.</sub>
