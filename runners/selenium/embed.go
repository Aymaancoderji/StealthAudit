// Package selenium embeds the Python runner script so the compiled
// stealthaudit binary stays self-contained (no separate .py file to ship).
package selenium

import _ "embed"

//go:embed session.py
var Script string
