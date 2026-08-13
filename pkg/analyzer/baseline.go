package analyzer

import (
	"regexp"
	"strings"
)

// This file holds the analyzer's baseline knowledge of what an authentic
// desktop browser looks like: known software/headless GPU renderer
// strings, and the real HTTP/2 pseudo-header orders each browser engine
// family sends (verified empirically against Playwright/Puppeteer/Selenium
// across Chromium, Firefox, and WebKit — see the project's phase 4 work).
// Exact per-version JA3/JA4 baselines are deliberately not hardcoded here:
// they drift with every browser release and would silently go stale,
// producing false confidence instead of a real signal. The checks below
// favor structural properties that stay true across versions.

// softwareRendererPatterns matches WebGL unmasked-renderer strings that
// indicate a software (non-GPU) rasterizer — the norm for headless/CI
// browser automation, essentially never seen on a real user's desktop.
var softwareRendererPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)swiftshader`),
	regexp.MustCompile(`(?i)llvmpipe`),
	regexp.MustCompile(`(?i)software rasterizer`),
	regexp.MustCompile(`(?i)apple software renderer`),
	regexp.MustCompile(`(?i)mesa.*(?:softpipe|llvmpipe)`),
}

func isSoftwareRenderer(renderer string) bool {
	for _, p := range softwareRendererPatterns {
		if p.MatchString(renderer) {
			return true
		}
	}
	return false
}

// browserFamily is which rendering engine a User-Agent claims to be.
type browserFamily string

const (
	familyChromium browserFamily = "chromium"
	familyFirefox  browserFamily = "firefox"
	familyWebKit   browserFamily = "webkit"
	familyUnknown  browserFamily = "unknown"
)

// detectBrowserFamily classifies a User-Agent string. Order matters:
// Chrome's UA also contains "Safari", and real Safari's UA doesn't
// contain "Chrome", so Chrome must be checked first.
func detectBrowserFamily(userAgent string) browserFamily {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "firefox"):
		return familyFirefox
	case strings.Contains(ua, "chrome") || strings.Contains(ua, "chromium") || strings.Contains(ua, "headlesschrome"):
		return familyChromium
	case strings.Contains(ua, "safari") && strings.Contains(ua, "applewebkit"):
		return familyWebKit
	default:
		return familyUnknown
	}
}

// expectedPseudoHeaderOrder is the HTTP/2 pseudo-header sequence each
// engine family actually sends, confirmed against real captures in this
// project (see pkg/network). A mismatch means the claimed User-Agent and
// the actual TLS-stack behavior don't come from the same browser engine —
// e.g. a Chrome UA string paired with a non-Chromium HTTP/2 stack.
var expectedPseudoHeaderOrder = map[browserFamily][]string{
	familyChromium: {":method", ":authority", ":scheme", ":path"},
	familyFirefox:  {":method", ":path", ":authority", ":scheme"},
	familyWebKit:   {":method", ":scheme", ":authority", ":path"},
}

func pseudoHeaderOrderMatches(family browserFamily, observed []string) bool {
	want, ok := expectedPseudoHeaderOrder[family]
	if !ok || len(observed) == 0 {
		return true // nothing to compare against; don't flag on absence
	}
	if len(observed) != len(want) {
		return false
	}
	for i := range want {
		if observed[i] != want[i] {
			return false
		}
	}
	return true
}
