package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidToken      = errors.New("stealthaudit: invalid token format")
	ErrSignatureMismatch = errors.New("stealthaudit: token signature mismatch")
	ErrTokenExpired      = errors.New("stealthaudit: token has expired")
	ErrTokenPremature    = errors.New("stealthaudit: token used before issue date")
	ErrMissingSecretKey  = errors.New("stealthaudit: secret key cannot be empty")
)

// Decision defines the assessment outcome.
type Decision string

const (
	DecisionAllow     Decision = "allow"
	DecisionChallenge Decision = "challenge"
	DecisionBlock     Decision = "block"
)

// Header represents the token envelope header.
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

// Claims represents the verified payload embedded within a StealthAudit token.
type Claims struct {
	VisitorID      string   `json:"vid"`
	Score          float64  `json:"scr"`
	BotProbability float64  `json:"bp"`
	Decision       Decision `json:"dec"`
	Flags          []string `json:"flg,omitempty"`
	IssuedAt       int64    `json:"iat"`
	ExpiresAt      int64    `json:"exp"`
	Nonce          string   `json:"nonce"`
}

// Signer generates signed StealthAudit tokens.
type Signer struct {
	secretKey []byte
}

// NewSigner creates a new Signer with the provided secret key.
func NewSigner(secretKey []byte) (*Signer, error) {
	if len(secretKey) == 0 {
		return nil, ErrMissingSecretKey
	}
	return &Signer{secretKey: secretKey}, nil
}

// IssueToken signs the given claims and returns a base64url-encoded token string.
func (s *Signer) IssueToken(claims Claims) (string, error) {
	if claims.Nonce == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("generating nonce: %w", err)
		}
		claims.Nonce = hex.EncodeToString(b)
	}

	header := Header{
		Algorithm: "HS256",
		Type:      "SAT", // StealthAudit Token
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	b64Header := base64.RawURLEncoding.EncodeToString(headerJSON)
	b64Claims := base64.RawURLEncoding.EncodeToString(claimsJSON)

	payload := b64Header + "." + b64Claims
	mac := hmac.New(sha256.New, s.secretKey)
	mac.Write([]byte(payload))
	signature := mac.Sum(nil)
	b64Sig := base64.RawURLEncoding.EncodeToString(signature)

	return payload + "." + b64Sig, nil
}

// Verifier checks and validates StealthAudit tokens.
type Verifier struct {
	secretKey []byte
	clockSkew time.Duration
}

// VerifierOption configures verification rules.
type VerifierOption func(*Verifier)

// WithClockSkew allows a leeway duration for clock differences.
func WithClockSkew(d time.Duration) VerifierOption {
	return func(v *Verifier) {
		v.clockSkew = d
	}
}

// NewVerifier creates a new token Verifier.
func NewVerifier(secretKey []byte, opts ...VerifierOption) (*Verifier, error) {
	if len(secretKey) == 0 {
		return nil, ErrMissingSecretKey
	}
	v := &Verifier{
		secretKey: secretKey,
		clockSkew: 5 * time.Second,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

// VerifyToken parses, validates the signature, and checks temporal validity of the raw token.
func (v *Verifier) VerifyToken(rawToken string) (*Claims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	b64Header, b64Claims, b64Sig := parts[0], parts[1], parts[2]

	expectedSigBytes, err := base64.RawURLEncoding.DecodeString(b64Sig)
	if err != nil {
		return nil, ErrInvalidToken
	}

	payload := b64Header + "." + b64Claims
	mac := hmac.New(sha256.New, v.secretKey)
	mac.Write([]byte(payload))
	computedSig := mac.Sum(nil)

	if subtle.ConstantTimeCompare(expectedSigBytes, computedSig) != 1 {
		return nil, ErrSignatureMismatch
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(b64Claims)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	now := time.Now().Unix()
	skewSec := int64(v.clockSkew.Seconds())

	if claims.ExpiresAt > 0 && now-skewSec > claims.ExpiresAt {
		return nil, ErrTokenExpired
	}
	if claims.IssuedAt > 0 && now+skewSec < claims.IssuedAt {
		return nil, ErrTokenPremature
	}

	return &claims, nil
}
