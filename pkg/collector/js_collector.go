package collector

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/stealthaudit/stealthaudit/pkg/orchestrator"
)

//go:embed audit.js
var auditScript string

// JSCollector gathers a Fingerprint by evaluating the standardized audit
// script (audit.js) in the target page.
type JSCollector struct{}

func (c *JSCollector) Collect(ctx context.Context, session orchestrator.Session) (*Fingerprint, error) {
	var fp Fingerprint
	if err := session.Evaluate(ctx, auditScript, &fp); err != nil {
		return nil, fmt.Errorf("collector: evaluating audit script: %w", err)
	}
	if fp.SchemaVersion == "" {
		fp.SchemaVersion = SchemaVersion
	}
	return &fp, nil
}

var _ Collector = (*JSCollector)(nil)
