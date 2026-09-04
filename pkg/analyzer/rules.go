package analyzer

import (
	"fmt"
	"strings"
)

// RuleScorer is the default Scorer: a fixed set of heuristic checks against
// the baseline knowledge in baseline.go. Each triggered check produces a
// Flag and deducts points from its Category; the overall StealthScore is
// the average of the four category scores. The rule set favors signals
// that are either unambiguous (navigator.webdriver, an active leak) or
// structural and version-independent (renderer type, HTTP/2 pseudo-header
// order) over anything that would need a per-browser-version baseline
// database that goes stale on every release.
type RuleScorer struct{}

// pointsPerSeverity converts a Flag's 1-5 severity into a category score
// deduction. Linear and out of 100 so severity 5 alone can zero out a
// category; multiple lower-severity flags in the same category stack.
const pointsPerSeverity = 10.0

func (RuleScorer) Score(in Input) (*Report, error) {
	deductions := map[Category]float64{
		CategoryJSRuntimeIntegrity:  0,
		CategoryHardwareConsistency: 0,
		CategoryTLSNetworkAlignment: 0,
		CategorySessionIsolation:    0,
	}
	var flags []Flag

	add := func(category Category, code string, severity int, format string, args ...any) {
		flags = append(flags, Flag{
			Category:    category,
			Code:        code,
			Description: fmt.Sprintf(format, args...),
			Severity:    severity,
		})
		deductions[category] += float64(severity) * pointsPerSeverity
	}

	fp := in.Fingerprint
	family := familyUnknown
	if fp != nil {
		family = detectBrowserFamily(fp.UserAgent)
	}

	if fp != nil && fp.Runtime != nil {
		rt := fp.Runtime
		if rt.WebdriverFlag {
			add(CategoryJSRuntimeIntegrity, "webdriver_flag_true", 5,
				"navigator.webdriver is true, an unambiguous automation signal real browsers never expose")
		}
		if !rt.FunctionToStringOK {
			add(CategoryJSRuntimeIntegrity, "function_tostring_tampered", 4,
				"Function.prototype.toString has been overridden, indicating an attempt to hide patched native functions")
		}
		if rt.PermissionsAnomaly {
			add(CategoryJSRuntimeIntegrity, "permissions_api_anomaly", 3,
				"Notification.permission and the Permissions API disagree, a known headless Chrome tell")
		}
		if !rt.WorkerSupport {
			add(CategoryJSRuntimeIntegrity, "worker_unsupported", 2,
				"Web Worker support is unexpectedly unavailable")
		}

		if len(rt.AutomationArtifacts) > 0 {
			add(CategoryJSRuntimeIntegrity, "automation_artifacts_detected", 5,
				"WebDriver/automation-framework artifacts found on window/document (%s), an unambiguous signal of a controlled session",
				strings.Join(rt.AutomationArtifacts, ", "))
		}
		if rt.WebdriverDescriptorAnomaly {
			add(CategoryJSRuntimeIntegrity, "webdriver_descriptor_anomaly", 4,
				"navigator.webdriver's property descriptor doesn't match a native browser implementation, indicating it was patched or deleted to hide automation")
		}
		if rt.CDPRuntimeDomainSuspected {
			add(CategoryJSRuntimeIntegrity, "cdp_runtime_domain_suspected", 3,
				"a getter on an object logged via console.debug fired without being read in-page, consistent with the Chrome DevTools Protocol Runtime domain being enabled (used by Puppeteer/Playwright by default) to generate console object previews")
		}
		if rt.HasChromeRuntime && family == familyChromium && (!rt.ChromeLoadTimesPresent || !rt.ChromeCsiPresent) {
			add(CategoryJSRuntimeIntegrity, "chrome_object_shape_incomplete", 3,
				"window.chrome is present but missing loadTimes/csi, consistent with a stealth patch reconstructing a partial window.chrome object rather than a genuine Chrome runtime")
		}
		if family == familyChromium && !rt.HasChromeRuntime {
			add(CategoryJSRuntimeIntegrity, "chrome_object_missing", 3,
				"User-Agent claims a Chromium-based browser but window.chrome.runtime is absent, as commonly seen in headless/automated Chrome without the window.chrome shim")
		}
		if rt.WorkerWebdriverLeak {
			add(CategoryJSRuntimeIntegrity, "worker_webdriver_leak", 5,
				"navigator.webdriver is true in an isolated Web Worker despite being masked on window")
		}
		if rt.WorkerUserAgentMismatch || rt.WorkerConcurrencyMismatch || rt.WorkerPlatformMismatch {
			add(CategoryJSRuntimeIntegrity, "worker_environment_mismatch", 4,
				"Web Worker environment signals contradict window scope (workerUserAgent=%q, workerPlatform=%q)",
				rt.WorkerUserAgent, rt.WorkerPlatform)
		}
		if rt.ErrorStackAutomationLeak {
			add(CategoryJSRuntimeIntegrity, "error_stack_automation_leak", 5,
				"Error stack trace exposed automation runner frames or evaluation scripts (%s)",
				strings.Join(rt.ErrorStackArtifacts, ", "))
		}
		if rt.ToStringDescriptorAnomaly || !rt.ToStringOfToStringOK {
			add(CategoryJSRuntimeIntegrity, "function_tostring_deep_tamper", 4,
				"Function.prototype.toString failed deep integrity or descriptor checks, indicating function tampering")
		}
	}

	if fp != nil && fp.WebGL != nil {
		if isSoftwareRenderer(fp.WebGL.UnmaskedRenderer) {
			add(CategoryHardwareConsistency, "software_gpu_renderer", 5,
				"WebGL reports a software rasterizer (%q) instead of real GPU hardware — the default in most headless/CI environments",
				fp.WebGL.UnmaskedRenderer)
		}
		if family != familyUnknown && !fp.WebGL.WebGL2Supported {
			add(CategoryHardwareConsistency, "webgl2_unsupported", 2,
				"WebGL2 context unavailable on modern browser engine")
		}
	}
	if fp != nil && fp.Canvas != nil && fp.Canvas.Hash == "" {
		add(CategoryHardwareConsistency, "canvas_fingerprint_blocked", 3,
			"Canvas rendering produced no usable output, consistent with fingerprint-blocking or a broken rendering pipeline")
	}
	if fp != nil && fp.Audio != nil && fp.Audio.Hash == "" {
		add(CategoryHardwareConsistency, "audio_fingerprint_blocked", 3,
			"Web Audio rendering produced no usable output, consistent with fingerprint-blocking or a broken audio pipeline")
	}
	if fp != nil && fp.Device != nil {
		dev := fp.Device
		if dev.HardwareConcurrency <= 1 {
			add(CategoryHardwareConsistency, "low_core_count", 2,
				"hardwareConcurrency of %d is unusually low for a desktop machine", dev.HardwareConcurrency)
		}
		if len(dev.Fonts) < 3 {
			add(CategoryHardwareConsistency, "minimal_font_set", 2,
				"Only %d system fonts detected, far fewer than a typical desktop install", len(dev.Fonts))
		}
		if family == familyChromium && dev.DeviceMemory == 0 {
			add(CategoryHardwareConsistency, "device_memory_missing_on_chromium", 2,
				"Chrome always implements navigator.deviceMemory; a value of 0 suggests a non-standard or stripped-down runtime")
		}
		if (dev.OuterWidth == 0 && dev.OuterHeight == 0) || (dev.OuterWidth > 0 && dev.InnerWidth > dev.OuterWidth) {
			add(CategoryHardwareConsistency, "headless_screen_geometry", 4,
				"Window geometry reports outer dimensions outerWidth=%d, outerHeight=%d, indicating a headless browser window",
				dev.OuterWidth, dev.OuterHeight)
		}
		if dev.UserAgentData != nil && !ClientHintsPlatformMatches(fp.UserAgent, dev.UserAgentData.Platform) {
			add(CategoryHardwareConsistency, "client_hints_platform_mismatch", 4,
				"navigator.userAgentData.platform (%q) contradicts claimed User-Agent platform",
				dev.UserAgentData.Platform)
		}
		if family == familyChromium && dev.SpeechVoiceCount == 0 && (strings.Contains(strings.ToLower(fp.UserAgent), "windows") || strings.Contains(strings.ToLower(fp.UserAgent), "macintosh")) {
			add(CategoryHardwareConsistency, "speech_voices_empty", 2,
				"Desktop Chromium environment reports 0 SpeechSynthesis voices, typical of automated/headless environments")
		}
	}

	if in.Network != nil {
		if in.Network.HTTP2 == nil {
			if family != familyUnknown {
				add(CategoryTLSNetworkAlignment, "http2_not_negotiated", 3,
					"Browser did not negotiate HTTP/2 over TLS, unusual for a modern browser and often seen in scripted/non-browser TLS stacks")
			}
		} else if !pseudoHeaderOrderMatches(family, in.Network.HTTP2.PseudoHeaders) {
			add(CategoryTLSNetworkAlignment, "http2_pseudo_header_order_mismatch", 4,
				"HTTP/2 pseudo-header order %v doesn't match what a real %s engine sends, suggesting a mismatched or spoofed TLS/HTTP stack",
				in.Network.HTTP2.PseudoHeaders, family)
		}
	}

	for _, finding := range in.LeakFindings {
		if !finding.Leaked {
			continue
		}
		detail := finding.Detail
		if detail == "" {
			detail = "state set in one session was observable from a second, supposedly isolated session"
		}
		add(CategorySessionIsolation, "leak_"+string(finding.Kind), 4, "%s", detail)
	}

	categoryScores := map[Category]float64{}
	var total float64
	for _, category := range []Category{
		CategoryJSRuntimeIntegrity,
		CategoryHardwareConsistency,
		CategoryTLSNetworkAlignment,
		CategorySessionIsolation,
	} {
		score := 100.0 - deductions[category]
		if score < 0 {
			score = 0
		}
		categoryScores[category] = score
		total += score
	}

	return &Report{
		StealthScore:   total / 4,
		CategoryScores: categoryScores,
		Flags:          flags,
	}, nil
}

var _ Scorer = RuleScorer{}
