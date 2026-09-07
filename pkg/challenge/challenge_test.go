package challenge

import (
	"testing"
	"time"
)

func TestChallengeCreationAndVerification(t *testing.T) {
	secret := []byte("challenge-secret-key-123456789012")
	mgr, err := NewManager(secret, 30*time.Second)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	difficulty := 2 // 2 leading zeros for fast test execution
	ch, err := mgr.CreateChallenge(difficulty)
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}

	if ch.ID == "" || ch.Prefix == "" || ch.Signature == "" {
		t.Fatalf("invalid challenge generated: %+v", ch)
	}

	nonce, ok := Solve(ch.Prefix, ch.Difficulty, 500000)
	if !ok {
		t.Fatalf("reference solver failed to find solution")
	}

	sol := &Solution{
		ID:    ch.ID,
		Nonce: nonce,
	}

	valid, err := mgr.Verify(ch, sol)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Errorf("expected valid solution, got invalid")
	}

	// Test replay protection
	_, err = mgr.Verify(ch, sol)
	if err != ErrSolutionReplayed {
		t.Errorf("expected ErrSolutionReplayed, got %v", err)
	}
}

func TestChallengeInvalidNonce(t *testing.T) {
	secret := []byte("challenge-secret-key")
	mgr, _ := NewManager(secret, 30*time.Second)

	ch, _ := mgr.CreateChallenge(3)
	sol := &Solution{
		ID:    ch.ID,
		Nonce: "obviously-invalid-nonce-that-fails",
	}

	valid, err := mgr.Verify(ch, sol)
	if valid || err != ErrInvalidSolution {
		t.Errorf("expected ErrInvalidSolution, got valid=%v, err=%v", valid, err)
	}
}

func TestChallengeTamperedSignature(t *testing.T) {
	secret := []byte("challenge-secret-key")
	mgr, _ := NewManager(secret, 30*time.Second)

	ch, _ := mgr.CreateChallenge(2)
	ch.Signature = "corrupted-signature"

	sol := &Solution{
		ID:    ch.ID,
		Nonce: "0",
	}

	_, err := mgr.Verify(ch, sol)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}
