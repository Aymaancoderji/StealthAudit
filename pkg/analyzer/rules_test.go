package analyzer

import (
	"testing"

	"github.com/Aymaancoderji/StealthAudit/pkg/collector"
)

func TestRuleScorerGenuine(t *testing.T) {
	scorer := RuleScorer{}
	fp := &collector.Fingerprint{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		Canvas:    &collector.CanvasFingerprint{Hash: "abc123hash"},
		WebGL: &collector.WebGLFingerprint{
			UnmaskedRenderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)",
			WebGL2Supported:  true,
		},
		Audio: &collector.AudioFingerprint{Hash: "audio123hash"},
		Runtime: &collector.RuntimeFingerprint{
			WebdriverFlag:          false,
			FunctionToStringOK:     true,
			ToStringOfToStringOK:   true,
			HasChromeRuntime:       true,
			ChromeLoadTimesPresent: true,
			ChromeCsiPresent:       true,
			ChromeAppPresent:       true,
			WorkerSupport:          true,
			WorkerExecutionOK:      true,
		},
		Device: &collector.DeviceFingerprint{
			HardwareConcurrency: 8,
			Fonts:               []string{"Arial", "Helvetica", "Times New Roman", "Consolas"},
			DeviceMemory:        16,
			OuterWidth:          1920,
			OuterHeight:         1080,
			InnerWidth:          1920,
			InnerHeight:         1000,
			SpeechVoiceCount:    10,
			UserAgentData: &collector.UserAgentDataFingerprint{
				Platform: "Windows",
			},
		},
	}

	rep, err := scorer.Score(Input{Fingerprint: fp})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.StealthScore < 100 {
		t.Errorf("expected genuine score 100, got %.1f with flags: %v", rep.StealthScore, rep.Flags)
	}
	if len(rep.Flags) != 0 {
		t.Errorf("expected 0 flags, got %d: %v", len(rep.Flags), rep.Flags)
	}
}

func TestRuleScorerPhase2Traps(t *testing.T) {
	scorer := RuleScorer{}
	fp := &collector.Fingerprint{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		Canvas:    &collector.CanvasFingerprint{Hash: "abc123hash"},
		WebGL: &collector.WebGLFingerprint{
			UnmaskedRenderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)",
			WebGL2Supported:  false,
		},
		Audio: &collector.AudioFingerprint{Hash: "audio123hash"},
		Runtime: &collector.RuntimeFingerprint{
			WebdriverFlag:            false,
			WorkerWebdriverLeak:      true,
			WorkerExecutionOK:        true,
			ErrorStackAutomationLeak: true,
			ErrorStackArtifacts:      []string{"__puppeteer_evaluation_script__"},
			ToStringOfToStringOK:     false,
			FunctionToStringOK:       true,
			HasChromeRuntime:         true,
			ChromeLoadTimesPresent:   true,
			ChromeCsiPresent:         true,
			WorkerSupport:            true,
		},
		Device: &collector.DeviceFingerprint{
			HardwareConcurrency: 8,
			Fonts:               []string{"Arial", "Helvetica", "Times New Roman"},
			DeviceMemory:        8,
			OuterWidth:          0,
			OuterHeight:         0,
			UserAgentData: &collector.UserAgentDataFingerprint{
				Platform: "Linux",
			},
		},
	}

	rep, err := scorer.Score(Input{Fingerprint: fp})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasCode := func(code string) bool {
		for _, f := range rep.Flags {
			if f.Code == code {
				return true
			}
		}
		return false
	}

	expectedCodes := []string{
		"worker_webdriver_leak",
		"error_stack_automation_leak",
		"function_tostring_deep_tamper",
		"headless_screen_geometry",
		"client_hints_platform_mismatch",
		"webgl2_unsupported",
	}

	for _, code := range expectedCodes {
		if !hasCode(code) {
			t.Errorf("expected flag %s to be triggered, but was missing", code)
		}
	}
}

func TestClientHintsPlatformMatches(t *testing.T) {
	tests := []struct {
		ua       string
		platform string
		want     bool
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0", "Windows", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0", "Linux", false},
		{"Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0", "Linux", true},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36", "macOS", true},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0", "Windows", false},
		{"", "Windows", true},
		{"Mozilla/5.0 (Windows NT 10.0) Chrome/120.0", "", true},
	}

	for _, tt := range tests {
		got := ClientHintsPlatformMatches(tt.ua, tt.platform)
		if got != tt.want {
			t.Errorf("ClientHintsPlatformMatches(%q, %q) = %v; want %v", tt.ua, tt.platform, got, tt.want)
		}
	}
}
