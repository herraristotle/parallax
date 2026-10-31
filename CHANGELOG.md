# Changelog

## [Unreleased]

## [1.0.2]

### Fixed
- **Stage 8 (`--execute`) browser confirmation was dead in every release.** `confirmInBrowser`
  lazy-loads `playwright`, but the release asset was a `@yao-pkg/pkg` single-file snapshot.
  Playwright cannot run from a snapshot (no `browsers.json`, no inspector), so the import
  threw, `.catch(() => undefined)` swallowed it, and `alertFired` stayed `undefined` with no
  warning — the scan reported a cache poison it never confirmed in a browser.
- A failed browser confirmation is now reported (`ExploitResult.browserError`) and logged
  once per run as "cache poisons below are HTTP-confirmed only", instead of being
  indistinguishable from "browser ran and no alert fired".

### Changed
- Releases are now one architecture-independent npm tarball, `mastermind-parallax-<ver>.tgz`,
  instead of four pkg executables (Windows/Linux/macOS x64 + macOS arm64). Install with
  `npm install -g <tarball>`; Node.js 22+. This also removes the platform-asset class of
  bugs (a single x64 asset installed on arm64, `exec format error` at runtime).
- `playwright` is pinned to one exact version instead of a caret range, so the browser
  revision this package asks for matches the one Artex installs once into a shared
  `PLAYWRIGHT_BROWSERS_PATH`. A range could resolve to a different revision and fail at
  launch.
- `package.json`: `pkg.assets` removed (dead — there is no pkg build), replaced by a `files`
  allowlist for the tarball.

### Added
- CI gates the release on what previously broke silently: Playwright launches a real browser
  and fires an alert, the compiled CLI runs with its runtime assets, and a global install of
  the packed tarball both runs by name and launches a browser from the installed tree.
  A release now fails in CI instead of at the target.
- `src/__tests__/release-assets.test.ts` asserts the `files` allowlist still covers every
  runtime asset and that `playwright` stays a runtime dependency.
