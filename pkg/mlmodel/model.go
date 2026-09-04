// Package mlmodel is a small logistic-regression classifier that scores a
// fingerprint's probability of belonging to an automated/headless browser
// rather than a genuine one.
//
// It's a deliberately different technique from pkg/analyzer's RuleScorer:
// the rule engine applies fixed thresholds ("webdriver is true -> flag"),
// while this model combines every signal into a single weighted
// probability, so ambiguous or partial evidence (a couple of soft signals,
// none individually damning) can still push the score up. The two are
// meant to be read together, not as replacements for each other.
//
// Weights were fit by tools/trainml (batch gradient descent, L2-regularized
// logistic regression) against a synthetic dataset built from the same
// domain knowledge pkg/analyzer/baseline.go encodes as rules — real labeled
// fingerprint corpora aren't available to this project. See
// tools/trainml/main.go for the full generation/training methodology and to
// regenerate the weights below.
package mlmodel

import (
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/Aymaancoderji/StealthAudit/pkg/collector"
	"github.com/Aymaancoderji/StealthAudit/pkg/network"
)

// FeatureNames is the ordered list of inputs the model expects; Weights[i]
// corresponds to FeatureNames[i]. Exported so the trainer and any
// explainability output stay aligned with the runtime feature extraction.
var FeatureNames = []string{
	"webdriver_flag",
	"function_tostring_tampered",
	"permissions_api_anomaly",
	"missing_chrome_runtime",
	"worker_unsupported",
	"software_gpu_renderer",
	"canvas_fingerprint_blocked",
	"audio_fingerprint_blocked",
	"hardware_concurrency_norm", // higher = more genuine; weight expected negative
	"font_count_norm",           // higher = more genuine; weight expected negative
	"device_memory_missing",
	"tls_ja3_missing",
	"http2_not_negotiated",
	"automation_artifacts_detected",
	"worker_context_leak",
	"error_stack_automation_leak",
	"headless_screen_geometry",
	"client_hints_platform_mismatch",
}

// softwareRendererPatterns duplicates pkg/analyzer's list deliberately: the
// ML model is meant to stand on its own domain reasoning rather than import
// the rule engine's internals.
var softwareRendererPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)swiftshader`),
	regexp.MustCompile(`(?i)llvmpipe`),
	regexp.MustCompile(`(?i)software rasterizer`),
	regexp.MustCompile(`(?i)apple software renderer`),
	regexp.MustCompile(`(?i)mesa.*(?:softpipe|llvmpipe)`),
}

func isSoftwareRenderer(renderer string) bool {
	for _, p := range softwareRendererPatterns {
		if p.MatchString(renderer) {
			return true
		}
	}
	return false
}

func clientHintsPlatformMatches(ua, uadPlatform string) bool {
	if uadPlatform == "" || ua == "" {
		return true
	}
	uaLower := strings.ToLower(ua)
	platLower := strings.ToLower(uadPlatform)
	switch platLower {
	case "windows":
		return strings.Contains(uaLower, "windows")
	case "macos", "mac os x":
		return strings.Contains(uaLower, "macintosh") || strings.Contains(uaLower, "mac os x")
	case "linux":
		return strings.Contains(uaLower, "linux") && !strings.Contains(uaLower, "android")
	case "android":
		return strings.Contains(uaLower, "android")
	default:
		return true
	}
}

func b01(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func clip01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// FeatureVector extracts the model's input features from a fingerprint and
// optional network capture, in FeatureNames order.
func FeatureVector(fp *collector.Fingerprint, net *network.Capture) []float64 {
	f := make([]float64, len(FeatureNames))
	if fp == nil {
		return f
	}

	if rt := fp.Runtime; rt != nil {
		f[0] = b01(rt.WebdriverFlag)
		f[1] = b01(!rt.FunctionToStringOK || !rt.ToStringOfToStringOK || rt.ToStringDescriptorAnomaly)
		f[2] = b01(rt.PermissionsAnomaly)
		f[3] = b01(!rt.HasChromeRuntime)
		f[4] = b01(!rt.WorkerSupport)
		f[13] = b01(len(rt.AutomationArtifacts) > 0)
		f[14] = b01(rt.WorkerWebdriverLeak || rt.WorkerUserAgentMismatch || rt.WorkerPlatformMismatch)
		f[15] = b01(rt.ErrorStackAutomationLeak)
	}

	if gl := fp.WebGL; gl != nil {
		f[5] = b01(isSoftwareRenderer(gl.UnmaskedRenderer))
	}

	f[6] = b01(fp.Canvas == nil || fp.Canvas.Hash == "")
	f[7] = b01(fp.Audio == nil || fp.Audio.Hash == "")

	if dev := fp.Device; dev != nil {
		f[8] = clip01(float64(dev.HardwareConcurrency) / 16.0)
		f[9] = clip01(float64(len(dev.Fonts)) / 30.0)
		f[10] = b01(dev.DeviceMemory == 0)
		f[16] = b01((dev.OuterWidth == 0 && dev.OuterHeight == 0) || (dev.OuterWidth > 0 && dev.InnerWidth > dev.OuterWidth))
		f[17] = b01(dev.UserAgentData != nil && !clientHintsPlatformMatches(fp.UserAgent, dev.UserAgentData.Platform))
	}

	f[11] = b01(net == nil || net.TLS == nil || net.TLS.JA3 == "")
	f[12] = b01(net == nil || net.HTTP2 == nil)

	return f
}

// Contribution is one feature's push toward or away from "automated", for
// explaining a Result rather than leaving it a black box.
type Contribution struct {
	Feature string  `json:"feature"`
	Value   float64 `json:"value"`
	Weight  float64 `json:"weight"`
	Impact  float64 `json:"impact"` // Value * Weight; positive pushes toward "automated"
}

// Result is the model's verdict for one fingerprint.
type Result struct {
	Probability   float64        `json:"probability"`   // 0-1, P(automated)
	Verdict       string         `json:"verdict"`       // "likely_automated" | "uncertain" | "likely_genuine"
	Contributions []Contribution `json:"contributions"` // sorted by |impact| descending
}

const (
	automatedThreshold = 0.65
	genuineThreshold   = 0.35
)

// Weights and Bias are the fitted logistic regression parameters, in
// FeatureNames order. Generated by tools/trainml — see that file's doc
// comment for the training methodology, and run `go run ./tools/trainml`
// to regenerate.
var Weights = []float64{
	2.7489, // webdriver_flag
	0.4858, // function_tostring_tampered
	1.1101, // permissions_api_anomaly
	0.8172, // missing_chrome_runtime
	0.2208, // worker_unsupported
	2.1468, // software_gpu_renderer
	0.5642, // canvas_fingerprint_blocked
	0.5067, // audio_fingerprint_blocked
	-2.1014, // hardware_concurrency_norm
	-2.8281, // font_count_norm
	0.8848, // device_memory_missing
	0.8708, // tls_ja3_missing
	0.6217, // http2_not_negotiated
	0.8757, // automation_artifacts_detected
	1.3449, // worker_context_leak
	1.0286, // error_stack_automation_leak
	1.6515, // headless_screen_geometry
	0.8999, // client_hints_platform_mismatch
}

// training accuracy on the synthetic dataset: 99.5% (8000 samples)
var Bias = -1.4007

func sigmoid(x float64) float64 {
	return 1 / (1 + math.Exp(-x))
}

// Predict returns the raw P(automated) for a feature vector.
func Predict(features []float64) float64 {
	sum := Bias
	for i, w := range Weights {
		if i < len(features) {
			sum += w * features[i]
		}
	}
	return sigmoid(sum)
}

// Classify scores a fingerprint end-to-end and explains the result.
func Classify(fp *collector.Fingerprint, net *network.Capture) *Result {
	features := FeatureVector(fp, net)
	prob := Predict(features)

	contributions := make([]Contribution, 0, len(FeatureNames))
	for i, name := range FeatureNames {
		if i >= len(Weights) || i >= len(features) {
			continue
		}
		contributions = append(contributions, Contribution{
			Feature: name,
			Value:   features[i],
			Weight:  Weights[i],
			Impact:  features[i] * Weights[i],
		})
	}
	sort.Slice(contributions, func(i, j int) bool {
		return math.Abs(contributions[i].Impact) > math.Abs(contributions[j].Impact)
	})

	verdict := "uncertain"
	switch {
	case prob >= automatedThreshold:
		verdict = "likely_automated"
	case prob <= genuineThreshold:
		verdict = "likely_genuine"
	}

	return &Result{
		Probability:   prob,
		Verdict:       verdict,
		Contributions: contributions,
	}
}
