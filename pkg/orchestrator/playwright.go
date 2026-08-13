package orchestrator

import (
	"context"

	pwrunner "github.com/Aymaancoderji/StealthAudit/runners/playwright"
)

// PlaywrightAdapter launches sessions by spawning a Node.js process running
// the embedded Playwright runner script (runners/playwright/session.js) and
// speaking newline-delimited JSON over its stdin/stdout.
type PlaywrightAdapter struct {
	// NodeBin overrides the "node" executable used to run the runner
	// script. Defaults to looking up "node" on PATH.
	NodeBin string
}

func (a *PlaywrightAdapter) Name() Driver { return DriverPlaywright }

func (a *PlaywrightAdapter) SupportedBrowsers() []Browser {
	return []Browser{BrowserChromium, BrowserFirefox, BrowserWebkit}
}

func (a *PlaywrightAdapter) Launch(ctx context.Context, opts LaunchOptions) (Session, error) {
	launchParams := map[string]any{
		"browser":           string(opts.Browser),
		"headless":          opts.Headless,
		"proxyURL":          opts.ProxyURL,
		"userAgent":         opts.UserAgent,
		"stealthPlugin":     opts.StealthPlugin,
		"extraArgs":         opts.ExtraArgs,
		"ignoreHTTPSErrors": opts.IgnoreHTTPSErrors,
	}
	return launchNodeSession(ctx, "playwright adapter", a.NodeBin, pwrunner.Script, "pw", "playwright", "playwright", launchParams)
}

var _ BrowserAdapter = (*PlaywrightAdapter)(nil)
