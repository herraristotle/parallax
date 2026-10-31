# Parallax Cache Toolkit

Differential cache analysis for web cache poisoning (WCP) and web cache deception (WCD). Six-stage pipeline: probe → harvest → timing → discover → diff → poison → weaponize.

## Install

```bash
npm install
npm run build        # emits dist/, including dist/cli.js
```

## Release tarball

Each tagged release publishes one asset, `mastermind-parallax-<version>.tgz` — an npm
package carrying the compiled `dist/`, the bundled `wordlists/` and `src/vendor/`. Install
it globally; npm pulls its dependencies and links the `parallax` bin:

```bash
npm install -g ./mastermind-parallax-1.0.2.tgz
parallax --help
```

It is not a single-file executable: Stage 8 (`--execute`) drives Playwright, which resolves
JS by runtime path and needs `browsers.json`. A pkg snapshot cannot host that (no
`browsers.json`, no inspector) and a bun `--compile` bundle only finds playwright when
`node_modules` sits beside the binary. That is why the previous platform executables shipped
with browser confirmation silently dead. The browser itself lives outside the package, so
install it once with this package's own playwright (revision must match):

```bash
"$(npm root -g)/@mastermind/parallax/node_modules/.bin/playwright" install --with-deps chromium
```

Push a version tag such as `v1.0.2` to build and publish it:

```bash
git tag v1.0.2
git push origin v1.0.2
```

CI gates the release on the three things that previously broke silently: Playwright launches
a real browser and fires an alert, the compiled CLI runs with its runtime assets, and a
global install of the packed tarball both runs by name and launches a browser from the
installed tree.

## Usage

```bash
# Scan a target (you are authorized to test)
node dist/cli.js scan https://target.example --profile fast

# Multi-target: one URL per line, # for comments
node dist/cli.js batch targets.txt --output ./output

# Endpoint discovery only
node dist/cli.js discover https://target.example

# NDJSON trace: one record per request + stage events + run summary
node dist/cli.js scan https://target.example --trace output/run.jsonl
```

Key flags: `--no-timing`, `--no-diff`, `--no-poison`, `--no-deception`, `--no-weaponize`, `--http2`, `--wordlist fast|all`, `--log-level debug`, `--bigquery-project <id>` (Stage-2 HTTP Archive harvest; costs money, needs GCP creds).

### `--external` — katana + GAU endpoint discovery

Opt-in merge of ProjectDiscovery `katana` (deep crawl) and `gau` (historical URLs) into stage-4 discovery. Binaries must already be on PATH — Parallax never auto-installs anything:

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc525/gau/v2/cmd/gau@latest
node dist/cli.js scan https://target.example --external
```

Missing binaries degrade gracefully: the scan continues wordlist-only and logs a warning naming each missing tool.

### Tracing (`--trace`)

Every line is independently parseable NDJSON:

```json
{"ts":"...","runId":"<uuid>","event":"probe","stage":"discover","method":"GET","url":"...","status":200,"latencyMs":42}
{"ts":"...","runId":"<uuid>","event":"run.summary","durationMs":1234,"requests":87,"errors":1,"findings":3}
```

Events: `run.start`, `stage.start`, `probe`, `run.summary`. Probe records carry stage, URL, method, status, latency, body hash, and error reason — enough to replay what the scanner saw when a result looks wrong.

## Tests

```bash
npm test             # vitest, full suite
npx tsc --noEmit     # typecheck
```

## Safety

Only scan targets you are authorized to test. BigQuery harvest queries real HTTP Archive data (billable; ToS applies). No auto-install of external tools, ever.

## Credits

Methodology follows research by Kettle (cache entanglement, cracking the lens), Omer Gil (web cache deception, 2017), Orange Tsai (Black Hat 2017), Tsai et al. (Practical Web Cache Poisoning), Liang et al. (HCache, CCS '24), Mirheidari et al. (USENIX '20/'22), Golinelli et al. (Hidden Web Caches, RAID '24), and Heyes (JavaScript for Hackers).
