# Publishing `@codesham/reachable`

The package is ready to publish but deliberately blocked by `"private": true`
in `package.json`. Nothing has been published.

## Checked already (2026-10-12)

- `npm pack --dry-run` contains only `bin/`, `src/`, `data/`, `README.md`,
  `LICENSE` and `package.json`: 19 files, about 58 kB. No bench fixtures, tests
  or caches.
- The packed tarball was installed into an empty scratch project.
  `npx reachable --version` and `npx reachable scan <project>` both work from
  the installed copy, including the WebAssembly grammars (JS, TS and TSX
  parsed). `import('@codesham/reachable')` works too.

## To publish

1. Make sure you own the `codesham` scope on npm (`npm whoami`, and that
   `codesham` is your user or an org you can publish to).
2. In `package.json`, delete the line:

   ```diff
   -  "private": true,
   ```

   `publishConfig.access` is already `"public"`, which scoped packages need.
3. Bump `version` if 0.1.0 is not what you want.
4. Run `npm publish`. `prepublishOnly` runs the test suite and the offline
   fixture benchmark first, and aborts the publish if either fails.
5. Then the Action (`../reachable-action`) works as-is. Set its
   `reachable-version` default to the published version if you want it
   pinned rather than `latest`.

## Before every release that changes analysis behaviour

Bump `ANALYZER_VERSION` in `src/pkgcache.js`. The per-package cache is keyed on
it, so results computed by older analysis code are never reused.
