// Package orchestrator defines the driver-agnostic contract for launching
// and controlling headless browser sessions (Playwright, Puppeteer, Selenium).
package orchestrator

import "context"

// Driver identifies which automation backend a session runs on.
type Driver string

const (
	DriverPlaywright Driver = "playwright"
	DriverPuppeteer  Driver = "puppeteer"
	DriverSelenium   Driver = "selenium"
)

// Browser identifies which browser engine to launch.
type Browser string

const (
	BrowserChromium Browser = "chromium"
	BrowserFirefox  Browser = "firefox"
	BrowserWebkit   Browser = "webkit"
)

// LaunchOptions configures a single browser session.
type LaunchOptions struct {
	Driver        Driver
	Browser       Browser
	Headless      bool
	ProxyURL      string // e.g. http://127.0.0.1:8080 or socks5://...
	UserAgent     string // overrides the default UA when non-empty
	StealthPlugin bool   // enable stealth-plugin style patches, where the driver supports it
	ExtraArgs     []string

	// IgnoreHTTPSErrors disables certificate validation for the whole
	// session. Needed to reach pkg/network's self-signed local TLS probe;
	// leave false for any session where real certificate validation
	// matters.
	IgnoreHTTPSErrors bool
}

// Session represents a live, controllable browser instance.
type Session interface {
	// Navigate loads the given URL and waits for the page to settle.
	Navigate(ctx context.Context, url string) error

	// Evaluate runs JavaScript in the page context and unmarshals the
	// JSON-serializable result into out.
	Evaluate(ctx context.Context, script string, out any) error

	// Close tears down the browser process and releases resources.
	Close(ctx context.Context) error
}

// BrowserAdapter launches sessions for a specific automation driver.
// Each supported driver (Playwright, Puppeteer, Selenium) implements this
// interface, typically by shelling out to a Node.js/Python runner process.
type BrowserAdapter interface {
	// Name returns the driver this adapter implements.
	Name() Driver

	// SupportedBrowsers lists the browser engines this adapter can launch.
	SupportedBrowsers() []Browser

	// Launch starts a new browser session with the given options.
	Launch(ctx context.Context, opts LaunchOptions) (Session, error)
}
