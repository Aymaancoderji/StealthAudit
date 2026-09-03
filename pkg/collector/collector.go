// Package collector defines the fingerprint telemetry schema and the
// interface for gathering it from a live browser session.
package collector

import (
	"context"

	"github.com/Aymaancoderji/StealthAudit/pkg/orchestrator"
)

// SchemaVersion is bumped whenever the Fingerprint struct's shape changes
// in a way that breaks older JSON reports or baseline files.
const SchemaVersion = "0.3.0"

// Fingerprint is the normalized set of telemetry collected from one
// browser session. Fields are filled in incrementally as collection
// sub-modules (canvas, audio, runtime, device) are implemented.
type Fingerprint struct {
	SchemaVersion string `json:"schemaVersion"`

	// UserAgent is the browser's claimed identity (navigator.userAgent).
	// The analyzer cross-references it against evidence that can't be
	// spoofed by a one-line JS override — WebGL renderer, TLS/HTTP2
	// behavior — to catch claim/evidence mismatches.
	UserAgent string `json:"userAgent"`

	Canvas  *CanvasFingerprint  `json:"canvas,omitempty"`
	WebGL   *WebGLFingerprint   `json:"webgl,omitempty"`
	Audio   *AudioFingerprint   `json:"audio,omitempty"`
	Runtime *RuntimeFingerprint `json:"runtime,omitempty"`
	Device  *DeviceFingerprint  `json:"device,omitempty"`
}

// CanvasFingerprint captures 2D canvas rendering output.
// Hash is a SHA-256 hex digest of the rendered canvas's data URL (browsers
// don't expose MD5 natively; uniqueness, not cryptographic strength, is
// what matters here).
type CanvasFingerprint struct {
	Hash string `json:"hash"`
}

// WebGLFingerprint captures WebGL vendor/renderer and capability data.
type WebGLFingerprint struct {
	Vendor            string   `json:"vendor"`
	Renderer          string   `json:"renderer"`
	UnmaskedVendor    string   `json:"unmaskedVendor"`
	UnmaskedRenderer  string   `json:"unmaskedRenderer"`
	SupportedExtensions []string `json:"supportedExtensions"`
	ShaderPrecision   map[string]string `json:"shaderPrecision"`
}

// AudioFingerprint captures Web Audio API oscillator/analyser output.
type AudioFingerprint struct {
	Hash string `json:"hash"`
}

// RuntimeFingerprint captures JS engine / browser-internals signals.
type RuntimeFingerprint struct {
	WebdriverFlag       bool     `json:"webdriverFlag"`
	FunctionToStringOK  bool     `json:"functionToStringOk"`
	HasChromeRuntime    bool     `json:"hasChromeRuntime"`
	PermissionsAnomaly  bool     `json:"permissionsAnomaly"`
	WorkerSupport       bool     `json:"workerSupport"`

	// AutomationArtifacts lists any WebDriver/automation-shim global
	// property names (ChromeDriver's cdc_ variables, Selenium/PhantomJS
	// markers, etc.) found on window/document. A non-empty list is an
	// unambiguous automation signal.
	AutomationArtifacts []string `json:"automationArtifacts,omitempty"`

	// ChromeLoadTimesPresent/ChromeCsiPresent/ChromeAppPresent describe
	// the shape of window.chrome when present. A genuine Chrome runtime
	// has all three; stealth patches that reconstruct window.chrome to
	// hide headless mode often ship an incomplete shim.
	ChromeLoadTimesPresent bool `json:"chromeLoadTimesPresent"`
	ChromeCsiPresent       bool `json:"chromeCsiPresent"`
	ChromeAppPresent       bool `json:"chromeAppPresent"`

	// WebdriverDescriptorAnomaly reports whether navigator.webdriver's
	// property descriptor doesn't match a native browser implementation
	// (deleted from Navigator.prototype, or replaced with a plain value
	// instead of a getter) — a tell distinct from the flag's value.
	WebdriverDescriptorAnomaly bool `json:"webdriverDescriptorAnomaly"`

	// CDPRuntimeDomainSuspected is a best-effort signal that the Chrome
	// DevTools Protocol Runtime domain is enabled (as Puppeteer/Playwright
	// do by default), detected via console.debug object-preview timing.
	CDPRuntimeDomainSuspected bool `json:"cdpRuntimeDomainSuspected"`
}

// DeviceFingerprint captures hardware/device metrics.
type DeviceFingerprint struct {
	ScreenWidth       int      `json:"screenWidth"`
	ScreenHeight      int      `json:"screenHeight"`
	ColorDepth        int      `json:"colorDepth"`
	DeviceMemory      float64  `json:"deviceMemory"`
	HardwareConcurrency int    `json:"hardwareConcurrency"`
	TouchPoints       int      `json:"touchPoints"`
	Fonts             []string `json:"fonts"`
}

// Collector gathers a Fingerprint from a live browser session by injecting
// the standardized audit script and reading back its result.
type Collector interface {
	Collect(ctx context.Context, session orchestrator.Session) (*Fingerprint, error)
}
