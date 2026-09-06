package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Aymaancoderji/StealthAudit/pkg/token"
)

func TestMiddlewareFlows(t *testing.T) {
	secret := []byte("middleware-test-secret-key-123456")
	signer, _ := token.NewSigner(secret)
	verifier, _ := token.NewVerifier(secret)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := FromContext(r.Context())
		if !ok || claims == nil {
			http.Error(w, "missing context claims", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("welcome " + claims.VisitorID))
	})

	protected := Protect(verifier)(dummyHandler)

	// 1. Missing token -> 403
	reqNoToken := httptest.NewRequest("GET", "/api/data", nil)
	recNoToken := httptest.NewRecorder()
	protected.ServeHTTP(recNoToken, reqNoToken)
	if recNoToken.Code != http.StatusForbidden {
		t.Errorf("expected 403 on missing token, got %d", recNoToken.Code)
	}

	// 2. Allowed token via header -> 200
	validToken, err := signer.IssueToken(token.Claims{
		VisitorID:      "human_123",
		Score:          90.0,
		BotProbability: 0.05,
		Decision:       token.DecisionAllow,
		ExpiresAt:      time.Now().Unix() + 100,
	})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	reqValid := httptest.NewRequest("GET", "/api/data", nil)
	reqValid.Header.Set("X-StealthAudit-Token", validToken)
	recValid := httptest.NewRecorder()
	protected.ServeHTTP(recValid, reqValid)

	if recValid.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", recValid.Code)
	}
	if !strings.Contains(recValid.Body.String(), "welcome human_123") {
		t.Errorf("expected welcome human_123, got %q", recValid.Body.String())
	}

	// 3. Blocked token -> 403
	blockToken, _ := signer.IssueToken(token.Claims{
		VisitorID:      "bot_456",
		Score:          10.0,
		BotProbability: 0.98,
		Decision:       token.DecisionBlock,
		ExpiresAt:      time.Now().Unix() + 100,
	})
	reqBlock := httptest.NewRequest("GET", "/api/data", nil)
	reqBlock.Header.Set("X-StealthAudit-Token", blockToken)
	recBlock := httptest.NewRecorder()
	protected.ServeHTTP(recBlock, reqBlock)

	if recBlock.Code != http.StatusForbidden {
		t.Errorf("expected 403 for blocked token, got %d", recBlock.Code)
	}

	// 4. Form value token
	form := url.Values{}
	form.Set("_stealthaudit_token", validToken)
	reqForm := httptest.NewRequest("POST", "/api/data", strings.NewReader(form.Encode()))
	reqForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recForm := httptest.NewRecorder()
	protected.ServeHTTP(recForm, reqForm)

	if recForm.Code != http.StatusOK {
		t.Errorf("expected 200 for form token, got %d", recForm.Code)
	}
}
