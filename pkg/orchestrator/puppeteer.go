package orchestrator

import (
	"context"
	"fmt"

	pprunner "github.com/Aymaancoderji/StealthAudit/runners/puppeteer"
)

// PuppeteerAdapter launches sessions by spawning a Node.js process running
// the embedded Puppeteer runner script (runners/puppeteer/session.js) and
// speaking newline-delimited JSON over its stdin/stdout. Only Chromium is
// supported — puppeteer-extra-plugin-stealth targets Chromium specifically.
type PuppeteerAdapter struct {
	// NodeBin overrides the "node" executable used to run the runner
	// script. Defaults to looking up "node" on PATH.
	NodeBin string
}

func (a *PuppeteerAdapter) Name() Driver { return DriverPuppeteer }

func (a *PuppeteerAdapter) SupportedBrowsers() []Browser {
	return []Browser{BrowserChromium}
}

func (a *PuppeteerAdapter) Launch(ctx context.Context, opts LaunchOptions) (Session, error) {
	if opts.Browser != "" && opts.Browser != BrowserChromium {
		return nil, fmt.Errorf("puppeteer adapter: only chromium is supported, got %q", opts.Browser)
	}

	launchParams := map[string]any{
		"browser":           string(opts.Browser),
		"headless":          opts.Headless,
		"proxyURL":          opts.ProxyURL,
		"userAgent":         opts.UserAgent,
		"stealthPlugin":     opts.StealthPlugin,
		"extraArgs":         opts.ExtraArgs,
		"ignoreHTTPSErrors": opts.IgnoreHTTPSErrors,
	}
	return launchNodeSession(ctx, "puppeteer adapter", a.NodeBin, pprunner.Script, "pp", "puppeteer", "puppeteer", launchParams)
}

var _ BrowserAdapter = (*PuppeteerAdapter)(nil)
