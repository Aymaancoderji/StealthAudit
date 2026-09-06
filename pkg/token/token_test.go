package token

import (
	"strings"
	"testing"
	"time"
)

func TestTokenSignAndVerify(t *testing.T) {
	secret := []byte("super-secret-key-1234567890123456")
	signer, err := NewSigner(secret)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	verifier, err := NewVerifier(secret)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	now := time.Now().Unix()
	claims := Claims{
		VisitorID:      "test-visitor-abc-123",
		Score:          95.5,
		BotProbability: 0.05,
		Decision:       DecisionAllow,
		Flags:          []string{"minor_inconsistency"},
		IssuedAt:       now,
		ExpiresAt:      now + 60,
	}

	rawToken, err := signer.IssueToken(claims)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	verified, err := verifier.VerifyToken(rawToken)
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}

	if verified.VisitorID != claims.VisitorID {
		t.Errorf("VisitorID = %q, want %q", verified.VisitorID, claims.VisitorID)
	}
	if verified.Decision != DecisionAllow {
		t.Errorf("Decision = %q, want %q", verified.Decision, DecisionAllow)
	}
	if verified.Score != claims.Score {
		t.Errorf("Score = %v, want %v", verified.Score, claims.Score)
	}
	if verified.Nonce == "" {
		t.Errorf("expected generated nonce, got empty")
	}
}

func TestTokenTampering(t *testing.T) {
	secret := []byte("secret-key")
	signer, _ := NewSigner(secret)
	verifier, _ := NewVerifier(secret)

	rawToken, err := signer.IssueToken(Claims{
		VisitorID: "user1",
		Decision:  DecisionBlock,
		ExpiresAt: time.Now().Unix() + 60,
	})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	// Tamper with signature
	tampered := rawToken + "corrupt"
	_, err = verifier.VerifyToken(tampered)
	if err == nil {
		t.Fatalf("expected error verifying tampered token")
	}

	// Wrong key
	otherVerifier, _ := NewVerifier([]byte("wrong-key"))
	_, err = otherVerifier.VerifyToken(rawToken)
	if err != ErrSignatureMismatch {
		t.Errorf("expected ErrSignatureMismatch, got %v", err)
	}

	// Malformed structure
	parts := strings.Split(rawToken, ".")
	_, err = verifier.VerifyToken(parts[0] + "." + parts[1])
	if err != ErrInvalidToken {
		t.Errorf("expected ErrInvalidToken for 2 parts, got %v", err)
	}
}

func TestTokenExpiration(t *testing.T) {
	secret := []byte("secret-key")
	signer, _ := NewSigner(secret)
	verifier, _ := NewVerifier(secret, WithClockSkew(0))

	past := time.Now().Add(-10 * time.Second).Unix()
	rawToken, err := signer.IssueToken(Claims{
		VisitorID: "user1",
		Decision:  DecisionAllow,
		IssuedAt:  past - 60,
		ExpiresAt: past,
	})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	_, err = verifier.VerifyToken(rawToken)
	if err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}
