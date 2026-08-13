// Package config defines the RunConfig used by the `stealthaudit run`
// command, shared across the orchestrator, collector, and analyzer.
package config

import "github.com/stealthaudit/stealthaudit/pkg/orchestrator"

// RunConfig is the fully resolved configuration for one audit run,
// built from CLI flags and/or a config file.
type RunConfig struct {
	Driver        orchestrator.Driver
	Browser       orchestrator.Browser
	Headless      bool
	ProxyURL      string
	UserAgent     string
	StealthPlugin bool

	OutputJSON string // path to write the JSON report; empty = skip
	OutputHTML string // path to write the HTML dashboard; empty = skip
}

// CompareConfig is the resolved configuration for `stealthaudit compare`.
type CompareConfig struct {
	BaselinePath string
	TargetPath   string
	OutputHTML   string
}
