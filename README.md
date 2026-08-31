# StealthAudit

Open-source browser fingerprinting and anti-detection audit engine. Launches
headless (or headed) browser sessions across multiple automation drivers,
captures low-level browser/device/network fingerprints, checks for session
isolation leaks, and produces a normalized Stealth Score with a category
breakdown and an HTML dashboard.

This is a fingerprinting/detection tool (comparable in spirit to
FingerprintJS) — it does **not** provide anti-detection or evasion
capabilities itself.

## Status

Working end-to-end: `run`, `leaktest`, `compare`, and `serve` all produce
real output against Playwright, Puppeteer, and Selenium on Chromium (and,
untested but wired up, Firefox/WebKit). No automated test suite yet.

## Layout

```
cmd/stealthaudit/     CLI entrypoint (run, leaktest, compare, serve, list-drivers)
pkg/orchestrator/      BrowserAdapter interface + driver adapters (Playwright/Puppeteer/Selenium)
pkg/collector/         Fingerprint schema + in-browser audit script (audit.js) collection
pkg/network/           TLS (JA3/JA4) and HTTP/2 fingerprint capture via a local probe server
pkg/leakdetector/       Cross-context/session isolation leak tests
pkg/analyzer/           Stealth Score computation (rule-based scorer)
pkg/mlmodel/            Logistic-regression classifier: P(automated) from fingerprint signals
pkg/report/             JSON report envelopes + loading, shared by run/leaktest/compare/serve
pkg/comparer/           Baseline-vs-target diffing for `compare`
pkg/dashboard/          Self-contained HTML dashboard rendering (run + compare)
pkg/config/             Run configuration types
runners/                Node (Playwright/Puppeteer) and Python (Selenium) runner scripts,
                          spawned by the Go orchestrator and driven over stdin/stdout JSON-RPC
tools/trainml/          Trains pkg/mlmodel's weights (`go run ./tools/trainml`)
```

## Requirements

- Go 1.22+
- Node.js + `npm install` in `runners/playwright` and `runners/puppeteer` (for those drivers)
- Python 3 + `pip3 install -r runners/selenium/requirements.txt` (for the Selenium driver)

## Build

```
go build ./...
```

Run the CLI from the repository root (or set `STEALTHAUDIT_PLAYWRIGHT_DIR` /
`STEALTHAUDIT_PUPPETEER_DIR`) so the Node runners can find their
`node_modules`.

## Usage

```
# Fingerprint one session and score it.
stealthaudit run --driver=playwright --browser=chromium --out-json=report.json --out-html=report.html

# Launch two isolated sessions and check for cross-session state leaks.
stealthaudit leaktest --driver=playwright --browser=chromium

# Diff two `run` reports (e.g. a real-browser baseline vs. a stealth-plugin target).
stealthaudit compare --baseline=chrome_real.json --target=playwright_stealth.json --out-html=diff.html

# Serve a local page that runs the audit script in *your* real browser, so you
# can see what a genuine, non-automated session looks like and sanity-check
# the collector against it.
stealthaudit serve --port=8765

stealthaudit list-drivers
```

Every subcommand supports `-h` for the full flag list.

### `run`

Launches one browser session, navigates it, collects the in-browser
fingerprint (canvas/WebGL/audio hashes, `navigator.webdriver`, device
metrics, fonts, etc. — see `pkg/collector/audit.js`), then makes one extra
navigation to a local self-signed TLS probe to capture the raw
ClientHello (JA3/JA4) and, over h2, the HTTP/2 SETTINGS frame and header
order. `pkg/analyzer` scores all of it into a 0–100 Stealth Score across
four categories (`js_runtime_integrity`, `hardware_consistency`,
`tls_network_alignment`, `session_isolation` — the last always scores 100
here since `run` is a single session; use `leaktest` for that category).
`--out-json` writes the full report; `--out-html` writes a standalone
dashboard.

### `leaktest`

Launches two independent sessions with identical launch options and runs
five isolation checks (cookies, localStorage, IndexedDB, SharedWorker,
ServiceWorker) between them via a local plain-HTTP origin. Any leak points
at a driver/profile configuration bug, since two sessions from one
`Launch()` call are expected to be fully isolated.

### `compare`

Loads two JSON reports written by `run --out-json` and diffs them:
Stealth Score and per-category deltas, flags unique to each side (added =
regressions in the target, removed = things the target fixed relative to
baseline), and a field-by-field diff of the underlying fingerprint/network
data (User-Agent, canvas/audio hashes, WebGL renderer, JA3/JA4, HTTP/2
header order, etc.). `--out-html` writes a standalone diff dashboard.

### `serve`

Starts a local HTTP server (default port 8765) plus the same TLS probe
`run` uses. Open `http://127.0.0.1:<port>/` in an actual desktop browser
(not through an automation driver) and it runs `audit.js` client-side,
POSTs the result back, and scores it — letting you see a genuine baseline
fingerprint, or sanity-check the collector script itself, without needing
a driver/runner installed. Visiting the printed TLS probe URL first (in a
new tab, accepting the self-signed cert warning) also fills in the
TLS/HTTP2 category.

It's built as a fingerprint.com-style live demo: returning visitors are
recognized from stable fingerprint signals alone (canvas/audio hashes,
WebGL renderer, fonts, screen/CPU — no cookies), with visit counts and a
timestamped history of the last 25 visits persisted to
`~/.stealthaudit/visitors.json` across restarts and rendered as a visit
timeline on the page. Every result
also runs through `pkg/mlmodel`'s classifier, surfaced as an immediate
banner at the top of the page ("ML model flagged this fingerprint as
suspicious — 96%") with the top contributing signals, before you even see
the rule-based breakdown below it.

### ML scoring (`pkg/mlmodel`)

Alongside the rule-based analyzer, every report also gets a logistic
regression score: P(automated) computed from 13 fingerprint/network
features, with per-feature contributions for explainability. It's a
deliberately different technique from the rule engine — rules apply fixed
thresholds, the model combines every signal into one weighted probability,
so it can still flag a fingerprint that's individually patched around one
or two rule checks (e.g. `navigator.webdriver` spoofed away) but still
looks statistically off on everything else. There's no large labeled
corpus of real fingerprints available to this project, so the weights
(`pkg/mlmodel/model.go`) are fit against a synthetic dataset built from the
same domain knowledge `pkg/analyzer/baseline.go` encodes as rules — see
`tools/trainml/main.go` for the full methodology, and run
`go run ./tools/trainml` to regenerate.

## Known gaps

- No automated test suite (`*_test.go`) yet — the analyzer rules,
  fingerprint parsing, and comparer logic are all currently only manually
  verified.
- Firefox/WebKit are wired into the orchestrator and adapters but have only
  been exercised on Chromium so far.
- The rule-based scorer (`pkg/analyzer/rules.go`) intentionally avoids
  hardcoding per-version JA3/JA4 baselines (they go stale on every browser
  release); it favors structural signals instead. A per-version baseline
  database is a possible future addition but isn't implemented.
