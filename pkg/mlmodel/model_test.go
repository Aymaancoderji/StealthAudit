package mlmodel

import (
	"testing"

	"github.com/Aymaancoderji/StealthAudit/pkg/collector"
	"github.com/Aymaancoderji/StealthAudit/pkg/network"
)

func TestModelClassifyGenuine(t *testing.T) {
	fp := &collector.Fingerprint{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		Canvas:    &collector.CanvasFingerprint{Hash: "abc"},
		WebGL: &collector.WebGLFingerprint{
			UnmaskedRenderer: "ANGLE (NVIDIA RTX 3080)",
			WebGL2Supported:  true,
		},
		Audio: &collector.AudioFingerprint{Hash: "def"},
		Runtime: &collector.RuntimeFingerprint{
			WebdriverFlag:        false,
			FunctionToStringOK:   true,
			ToStringOfToStringOK: true,
			HasChromeRuntime:     true,
			WorkerSupport:        true,
		},
		Device: &collector.DeviceFingerprint{
			HardwareConcurrency: 16,
			Fonts:               make([]string, 25),
			DeviceMemory:        16,
			OuterWidth:          1920,
			OuterHeight:         1080,
			UserAgentData: &collector.UserAgentDataFingerprint{
				Platform: "Windows",
			},
		},
	}
	net := &network.Capture{
		TLS:   &network.TLSFingerprint{JA3: "771,4865-4866"},
		HTTP2: &network.HTTP2Fingerprint{PseudoHeaders: []string{":method", ":authority", ":scheme", ":path"}},
	}

	res := Classify(fp, net)
	if res.Verdict != "likely_genuine" {
		t.Errorf("expected likely_genuine, got %s (p=%.2f)", res.Verdict, res.Probability)
	}
	if res.Probability > 0.35 {
		t.Errorf("expected probability <= 0.35, got %.2f", res.Probability)
	}
}

func TestModelClassifyAutomated(t *testing.T) {
	fp := &collector.Fingerprint{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		Canvas:    &collector.CanvasFingerprint{Hash: "abc"},
		WebGL: &collector.WebGLFingerprint{
			UnmaskedRenderer: "Google SwiftShader",
		},
		Runtime: &collector.RuntimeFingerprint{
			WebdriverFlag:            false,
			WorkerWebdriverLeak:      true, // Phase 2 leak
			ErrorStackAutomationLeak: true, // Phase 2 leak
			AutomationArtifacts:      []string{"$cdc_asdjflas_"},
		},
		Device: &collector.DeviceFingerprint{
			HardwareConcurrency: 2,
			Fonts:               []string{"Arial"},
			OuterWidth:          0, // Phase 2 headless geometry
			OuterHeight:         0,
			UserAgentData: &collector.UserAgentDataFingerprint{
				Platform: "Linux", // Phase 2 mismatch
			},
		},
	}

	res := Classify(fp, nil)
	if res.Verdict != "likely_automated" {
		t.Errorf("expected likely_automated, got %s (p=%.2f)", res.Verdict, res.Probability)
	}
	if res.Probability < 0.80 {
		t.Errorf("expected probability >= 0.80, got %.2f", res.Probability)
	}
}

func TestFeatureVectorLength(t *testing.T) {
	fp := &collector.Fingerprint{}
	vec := FeatureVector(fp, nil)
	if len(vec) != len(FeatureNames) {
		t.Errorf("FeatureVector length %d != FeatureNames length %d", len(vec), len(FeatureNames))
	}
	if len(Weights) != len(FeatureNames) {
		t.Errorf("Weights length %d != FeatureNames length %d", len(Weights), len(FeatureNames))
	}
}
