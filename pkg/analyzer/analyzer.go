// Package analyzer scores collected telemetry against baseline data and
// produces the normalized Stealth Score.
package analyzer

import (
	"github.com/stealthaudit/stealthaudit/pkg/collector"
	"github.com/stealthaudit/stealthaudit/pkg/leakdetector"
	"github.com/stealthaudit/stealthaudit/pkg/network"
)

// Category is one of the four sub-scores that make up the Stealth Score.
type Category string

const (
	CategoryJSRuntimeIntegrity  Category = "js_runtime_integrity"
	CategoryHardwareConsistency Category = "hardware_consistency"
	CategoryTLSNetworkAlignment Category = "tls_network_alignment"
	CategorySessionIsolation    Category = "session_isolation"
)

// Flag is a single high-risk indicator found during analysis.
type Flag struct {
	Category    Category `json:"category"`
	Code        string   `json:"code"`        // stable identifier, e.g. "webdriver_true"
	Description string   `json:"description"`
	Severity    int      `json:"severity"` // 1 (low) - 5 (critical)
}

// Report is the full analysis output for one session.
type Report struct {
	StealthScore   float64             `json:"stealthScore"` // 0-100
	CategoryScores map[Category]float64 `json:"categoryScores"`
	Flags          []Flag              `json:"flags"`
}

// Input bundles everything the analyzer needs for one session.
type Input struct {
	Fingerprint *collector.Fingerprint
	Network     *network.Capture
	LeakFindings []leakdetector.Finding
}

// Scorer produces a Report from collected telemetry, evaluated against a
// baseline database of authentic browser fingerprints.
type Scorer interface {
	Score(in Input) (*Report, error)
}
