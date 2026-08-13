// Package leakdetector tests whether isolated browser contexts actually
// stay isolated (cookies, storage, workers) rather than leaking state
// across supposedly separate sessions/profiles.
package leakdetector

import (
	"context"

	"github.com/stealthaudit/stealthaudit/pkg/orchestrator"
)

// LeakKind identifies the isolation boundary being tested.
type LeakKind string

const (
	LeakCookie        LeakKind = "cookie"
	LeakLocalStorage  LeakKind = "localStorage"
	LeakIndexedDB     LeakKind = "indexedDB"
	LeakSharedWorker  LeakKind = "sharedWorker"
	LeakServiceWorker LeakKind = "serviceWorker"
)

// Finding describes one detected (or ruled-out) leak between two sessions.
type Finding struct {
	Kind    LeakKind `json:"kind"`
	Leaked  bool     `json:"leaked"`
	Detail  string   `json:"detail,omitempty"`
}

// LeakTest checks one isolation boundary across a set of concurrently
// running sessions that are expected to be isolated from one another.
type LeakTest interface {
	Kind() LeakKind
	Run(ctx context.Context, sessions []orchestrator.Session) (*Finding, error)
}
