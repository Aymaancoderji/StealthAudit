// Package playwright embeds the Node runner script so the compiled
// stealthaudit binary stays self-contained (no separate JS file to ship).
package playwright

import _ "embed"

//go:embed session.js
var Script string
