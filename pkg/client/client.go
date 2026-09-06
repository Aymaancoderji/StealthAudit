package client

import (
	_ "embed"
	"net/http"
)

//go:embed stealthaudit.js
var scriptContent string

// Script returns the embedded client SDK JavaScript content.
func Script() string {
	return scriptContent
}

// Handler returns an http.Handler that serves the client SDK script.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(scriptContent))
	})
}
