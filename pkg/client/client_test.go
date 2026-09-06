package client

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientScriptAndHandler(t *testing.T) {
	script := Script()
	if len(script) == 0 {
		t.Fatalf("expected non-empty client script")
	}
	if !strings.Contains(script, "StealthAudit") {
		t.Errorf("expected script to define StealthAudit")
	}

	handler := Handler()
	req := httptest.NewRequest("GET", "/stealthaudit.js", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/javascript") {
		t.Errorf("content-type = %q, want application/javascript", ct)
	}
	if rec.Body.Len() == 0 {
		t.Errorf("expected non-empty response body")
	}
}
