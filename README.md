# StealthAudit

Open-source browser fingerprinting and anti-detection audit engine. Launches
headless browser sessions across multiple automation drivers, captures
low-level browser/device/network fingerprints, checks for session isolation
leaks, and produces a normalized Stealth Score with a category breakdown.

This is a fingerprinting/detection tool (comparable in spirit to
FingerprintJS) — it does **not** provide anti-detection or evasion
capabilities itself.

## Status

Phase 0 (scaffolding) — interfaces and CLI stubs only, no working
orchestration yet. See `docs/PLAN.md` (or project notes) for the phased
roadmap.

## Layout

```
cmd/stealthaudit/     CLI entrypoint
pkg/orchestrator/      BrowserAdapter interface + driver adapters (Playwright/Puppeteer/Selenium)
pkg/collector/         Fingerprint schema + in-browser audit script collection
pkg/network/           TLS (JA3/JA4) and HTTP/2 fingerprint capture
pkg/leakdetector/       Cross-context isolation leak tests
pkg/analyzer/           Stealth Score computation
pkg/config/             Run/compare configuration types
```

## Requirements

- Go 1.22+
- Node.js (for Playwright/Puppeteer runner scripts, added in later phases)
- Python 3 (for Selenium runner script, added in later phases)

## Build

```
go build ./...
```

## Usage (stubbed)

```
stealthaudit run --driver=playwright --browser=chromium --proxy=http://127.0.0.1:8080 --stealth-plugin
stealthaudit compare --baseline=chrome_real.json --target=playwright_stealth.json
stealthaudit list-drivers
```
