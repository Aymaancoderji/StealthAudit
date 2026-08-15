// Package comparer diffs two `stealthaudit run` reports (e.g. a real
// browser baseline against an automated/stealth-plugin target) for the
// `compare` command.
package comparer

import (
	"fmt"
	"strings"

	"github.com/Aymaancoderji/StealthAudit/pkg/analyzer"
	"github.com/Aymaancoderji/StealthAudit/pkg/collector"
	"github.com/Aymaancoderji/StealthAudit/pkg/report"
)

// FieldDiff is one fingerprint/network attribute compared between the two
// reports.
type FieldDiff struct {
	Field    string
	Baseline string
	Target   string
	Changed  bool
}

// CategoryDiff is one analyzer category's score in both reports.
type CategoryDiff struct {
	Category analyzer.Category
	Baseline float64
	Target   float64
	Delta    float64
}

// Diff is the full baseline-vs-target comparison.
type Diff struct {
	BaselineScore float64
	TargetScore   float64
	ScoreDelta    float64
	Categories    []CategoryDiff
	FlagsAdded    []analyzer.Flag // present in target, not baseline
	FlagsRemoved  []analyzer.Flag // present in baseline, not target
	Fields        []FieldDiff
}

var categoryOrder = []analyzer.Category{
	analyzer.CategoryJSRuntimeIntegrity,
	analyzer.CategoryHardwareConsistency,
	analyzer.CategoryTLSNetworkAlignment,
	analyzer.CategorySessionIsolation,
}

// Compare produces a Diff between two `stealthaudit run` reports.
func Compare(baseline, target *report.Run) *Diff {
	d := &Diff{}

	if baseline.Analysis != nil {
		d.BaselineScore = baseline.Analysis.StealthScore
	}
	if target.Analysis != nil {
		d.TargetScore = target.Analysis.StealthScore
	}
	d.ScoreDelta = d.TargetScore - d.BaselineScore

	for _, cat := range categoryOrder {
		var b, t float64
		if baseline.Analysis != nil {
			b = baseline.Analysis.CategoryScores[cat]
		}
		if target.Analysis != nil {
			t = target.Analysis.CategoryScores[cat]
		}
		d.Categories = append(d.Categories, CategoryDiff{Category: cat, Baseline: b, Target: t, Delta: t - b})
	}

	d.FlagsAdded, d.FlagsRemoved = diffFlags(flagsOf(baseline), flagsOf(target))
	d.Fields = diffFields(baseline, target)

	return d
}

func flagsOf(r *report.Run) []analyzer.Flag {
	if r.Analysis == nil {
		return nil
	}
	return r.Analysis.Flags
}

// diffFlags splits by stable Flag.Code: codes only in target are
// regressions (added), codes only in baseline are fixes (removed).
func diffFlags(baseline, target []analyzer.Flag) (added, removed []analyzer.Flag) {
	baseCodes := map[string]bool{}
	for _, f := range baseline {
		baseCodes[f.Code] = true
	}
	targetCodes := map[string]bool{}
	for _, f := range target {
		targetCodes[f.Code] = true
	}
	for _, f := range target {
		if !baseCodes[f.Code] {
			added = append(added, f)
		}
	}
	for _, f := range baseline {
		if !targetCodes[f.Code] {
			removed = append(removed, f)
		}
	}
	return added, removed
}

func safeFP(r *report.Run) *collector.Fingerprint {
	if r.Fingerprint != nil {
		return r.Fingerprint
	}
	return &collector.Fingerprint{}
}

func diffFields(baseline, target *report.Run) []FieldDiff {
	b, t := safeFP(baseline), safeFP(target)
	var fields []FieldDiff
	str := func(name, bVal, tVal string) {
		fields = append(fields, FieldDiff{Field: name, Baseline: bVal, Target: tVal, Changed: bVal != tVal})
	}

	str("User-Agent", b.UserAgent, t.UserAgent)

	var bWD, tWD string
	if b.Runtime != nil {
		bWD = fmt.Sprintf("%v", b.Runtime.WebdriverFlag)
	}
	if t.Runtime != nil {
		tWD = fmt.Sprintf("%v", t.Runtime.WebdriverFlag)
	}
	str("navigator.webdriver", bWD, tWD)

	var bWG, tWG string
	if b.WebGL != nil {
		bWG = b.WebGL.UnmaskedRenderer
	}
	if t.WebGL != nil {
		tWG = t.WebGL.UnmaskedRenderer
	}
	str("WebGL unmasked renderer", bWG, tWG)

	var bCanvas, tCanvas string
	if b.Canvas != nil {
		bCanvas = b.Canvas.Hash
	}
	if t.Canvas != nil {
		tCanvas = t.Canvas.Hash
	}
	str("Canvas hash", bCanvas, tCanvas)

	var bAudio, tAudio string
	if b.Audio != nil {
		bAudio = b.Audio.Hash
	}
	if t.Audio != nil {
		tAudio = t.Audio.Hash
	}
	str("Audio hash", bAudio, tAudio)

	var bHC, tHC string
	if b.Device != nil {
		bHC = fmt.Sprintf("%d", b.Device.HardwareConcurrency)
	}
	if t.Device != nil {
		tHC = fmt.Sprintf("%d", t.Device.HardwareConcurrency)
	}
	str("hardwareConcurrency", bHC, tHC)

	var bFonts, tFonts string
	if b.Device != nil {
		bFonts = fmt.Sprintf("%d fonts", len(b.Device.Fonts))
	}
	if t.Device != nil {
		tFonts = fmt.Sprintf("%d fonts", len(t.Device.Fonts))
	}
	str("Detected fonts", bFonts, tFonts)

	var bJA3, tJA3 string
	if baseline.Network != nil && baseline.Network.TLS != nil {
		bJA3 = baseline.Network.TLS.JA3
	}
	if target.Network != nil && target.Network.TLS != nil {
		tJA3 = target.Network.TLS.JA3
	}
	str("TLS JA3", bJA3, tJA3)

	var bJA4, tJA4 string
	if baseline.Network != nil && baseline.Network.TLS != nil {
		bJA4 = baseline.Network.TLS.JA4
	}
	if target.Network != nil && target.Network.TLS != nil {
		tJA4 = target.Network.TLS.JA4
	}
	str("TLS JA4", bJA4, tJA4)

	var bPH, tPH string
	if baseline.Network != nil && baseline.Network.HTTP2 != nil {
		bPH = strings.Join(baseline.Network.HTTP2.PseudoHeaders, ",")
	}
	if target.Network != nil && target.Network.HTTP2 != nil {
		tPH = strings.Join(target.Network.HTTP2.PseudoHeaders, ",")
	}
	str("HTTP/2 pseudo-header order", bPH, tPH)

	return fields
}
