package comparer

import (
	"testing"

	"github.com/Aymaancoderji/StealthAudit/pkg/analyzer"
	"github.com/Aymaancoderji/StealthAudit/pkg/collector"
	"github.com/Aymaancoderji/StealthAudit/pkg/report"
)

func TestComparerDiff(t *testing.T) {
	baseline := &report.Run{
		Fingerprint: &collector.Fingerprint{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
			Device: &collector.DeviceFingerprint{
				OuterWidth:  1920,
				OuterHeight: 1080,
				UserAgentData: &collector.UserAgentDataFingerprint{
					Platform: "Windows",
				},
			},
			Runtime: &collector.RuntimeFingerprint{
				WorkerWebdriverLeak: false,
			},
			WebGL: &collector.WebGLFingerprint{
				WebGL2Supported: true,
			},
		},
		Analysis: &analyzer.Report{
			StealthScore: 100,
			CategoryScores: map[analyzer.Category]float64{
				analyzer.CategoryJSRuntimeIntegrity:  100,
				analyzer.CategoryHardwareConsistency: 100,
				analyzer.CategoryTLSNetworkAlignment: 100,
				analyzer.CategorySessionIsolation:    100,
			},
		},
	}

	target := &report.Run{
		Fingerprint: &collector.Fingerprint{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
			Device: &collector.DeviceFingerprint{
				OuterWidth:  0,
				OuterHeight: 0,
				UserAgentData: &collector.UserAgentDataFingerprint{
					Platform: "Linux",
				},
			},
			Runtime: &collector.RuntimeFingerprint{
				WorkerWebdriverLeak: true,
			},
			WebGL: &collector.WebGLFingerprint{
				WebGL2Supported: false,
			},
		},
		Analysis: &analyzer.Report{
			StealthScore: 60,
			CategoryScores: map[analyzer.Category]float64{
				analyzer.CategoryJSRuntimeIntegrity:  50,
				analyzer.CategoryHardwareConsistency: 50,
				analyzer.CategoryTLSNetworkAlignment: 100,
				analyzer.CategorySessionIsolation:    100,
			},
			Flags: []analyzer.Flag{
				{Category: analyzer.CategoryJSRuntimeIntegrity, Code: "worker_webdriver_leak"},
			},
		},
	}

	diff := Compare(baseline, target)
	if diff.BaselineScore != 100 || diff.TargetScore != 60 {
		t.Errorf("expected scores 100 and 60, got %.1f and %.1f", diff.BaselineScore, diff.TargetScore)
	}
	if diff.ScoreDelta != -40 {
		t.Errorf("expected delta -40, got %.1f", diff.ScoreDelta)
	}
	if len(diff.FlagsAdded) != 1 || diff.FlagsAdded[0].Code != "worker_webdriver_leak" {
		t.Errorf("expected worker_webdriver_leak flag added, got %v", diff.FlagsAdded)
	}

	fieldMap := map[string]FieldDiff{}
	for _, f := range diff.Fields {
		fieldMap[f.Field] = f
	}

	if f, ok := fieldMap["Worker webdriver leak"]; !ok || !f.Changed {
		t.Errorf("expected 'Worker webdriver leak' field to change, got %v", f)
	}
	if f, ok := fieldMap["Window outer size"]; !ok || !f.Changed {
		t.Errorf("expected 'Window outer size' field to change, got %v", f)
	}
	if f, ok := fieldMap["Client hints platform"]; !ok || !f.Changed {
		t.Errorf("expected 'Client hints platform' field to change, got %v", f)
	}
}
