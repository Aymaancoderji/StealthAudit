package analyzer

import "fmt"

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
	}

	if fp != nil && fp.WebGL != nil && isSoftwareRenderer(fp.WebGL.UnmaskedRenderer) {
		add(CategoryHardwareConsistency, "software_gpu_renderer", 5,
			"WebGL reports a software rasterizer (%q) instead of real GPU hardware — the default in most headless/CI environments",
			fp.WebGL.UnmaskedRenderer)
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
