package leakdetector

import (
	"crypto/rand"
	"encoding/hex"
)

// randomMarker returns a fresh random hex string used as a unique value to
// plant in one session and check for in another; a fresh value per test
// run rules out stale state from a previous run being mistaken for a leak.
func randomMarker() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
