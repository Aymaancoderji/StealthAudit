// Package dashboard renders self-contained HTML dashboards for a single
// `run` report and for a `compare` diff, with no external CSS/JS
// dependencies so the output file works standalone.
package dashboard

import (
	"bytes"
	_ "embed"
	"html/template"
	"strconv"

	"github.com/Aymaancoderji/StealthAudit/pkg/comparer"
	"github.com/Aymaancoderji/StealthAudit/pkg/report"
)

//go:embed run.html.tmpl
var runTmplSrc string

//go:embed compare.html.tmpl
var compareTmplSrc string

var funcMap = template.FuncMap{
	"scoreColor": scoreColor,
	"sevColor":   sevColor,
	"signed": func(f float64) string {
		if f > 0 {
			return "+" + trimFloat(f)
		}
		return trimFloat(f)
	},
	"round1":     trimFloat,
	"mulHundred": func(f float64) float64 { return f * 100 },
}

var runTmpl = template.Must(template.New("run").Funcs(funcMap).Parse(runTmplSrc))
var compareTmpl = template.Must(template.New("compare").Funcs(funcMap).Parse(compareTmplSrc))

// scoreColor grades a 0-100 score into a stoplight color used for score
// text, bars, and badges throughout both dashboards.
func scoreColor(score float64) string {
	switch {
	case score >= 80:
		return "#3fb950"
	case score >= 50:
		return "#d29922"
	default:
		return "#f85149"
	}
}

func trimFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}

// sevColor grades a Flag's 1-5 severity into the same stoplight palette as
// scoreColor.
func sevColor(severity int) string {
	switch {
	case severity >= 4:
		return "#f85149"
	case severity >= 2:
		return "#d29922"
	default:
		return "#3fb950"
	}
}

// RenderRun renders the single-report HTML dashboard for `stealthaudit run`.
func RenderRun(r *report.Run) ([]byte, error) {
	var buf bytes.Buffer
	if err := runTmpl.Execute(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RenderCompare renders the baseline-vs-target diff HTML dashboard for
// `stealthaudit compare`.
func RenderCompare(d *comparer.Diff) ([]byte, error) {
	var buf bytes.Buffer
	if err := compareTmpl.Execute(&buf, d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
