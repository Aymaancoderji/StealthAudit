// Package report defines the JSON envelopes written by `stealthaudit run`
// and `stealthaudit leaktest`, and loads them back in for `compare`.
package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Aymaancoderji/StealthAudit/pkg/analyzer"
	"github.com/Aymaancoderji/StealthAudit/pkg/collector"
	"github.com/Aymaancoderji/StealthAudit/pkg/leakdetector"
	"github.com/Aymaancoderji/StealthAudit/pkg/network"
)

// Run is the JSON envelope for `run`'s output: the in-browser fingerprint,
// the network-level (TLS/HTTP2) capture, and the resulting Stealth
// Score/flags. Embedding *collector.Fingerprint promotes its fields to the
// top level so the schema stays flat.
type Run struct {
	*collector.Fingerprint
	Network     *network.Capture `json:"network,omitempty"`
	Analysis    *analyzer.Report `json:"analysis,omitempty"`
	GeneratedAt string           `json:"generatedAt,omitempty"`
}

// Leak is the JSON envelope for `leaktest`'s output.
type Leak struct {
	Findings []leakdetector.Finding `json:"findings"`
	Analysis *analyzer.Report       `json:"analysis"`
}

// LoadRun reads and parses a JSON report previously written by `run`.
func LoadRun(path string) (*Run, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	r := &Run{Fingerprint: &collector.Fingerprint{}}
	if err := json.Unmarshal(data, r); err != nil {
		return nil, fmt.Errorf("parsing %s as a stealthaudit run report: %w", path, err)
	}
	return r, nil
}
