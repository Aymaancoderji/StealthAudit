package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrChallengeExpired  = errors.New("stealthaudit: challenge has expired")
	ErrInvalidSignature = errors.New("stealthaudit: challenge signature invalid")
	ErrInvalidSolution  = errors.New("stealthaudit: proof-of-work solution invalid")
	ErrSolutionReplayed  = errors.New("stealthaudit: challenge solution already used")
	ErrMissingSecretKey = errors.New("stealthaudit: challenge secret key cannot be empty")
)

// Challenge represents a cryptographic Proof-of-Work challenge puzzle.
type Challenge struct {
	ID         string `json:"id"`
	Algorithm  string `json:"algorithm"`
	Prefix     string `json:"prefix"`
	Difficulty int    `json:"difficulty"` // Number of leading zero hex characters required
	ExpiresAt  int64  `json:"expiresAt"`
	Signature  string `json:"signature"`
}

// Solution represents the client's computed answer to a challenge.
type Solution struct {
	ID    string `json:"id"`
	Nonce string `json:"nonce"`
}

// Manager handles issuing and validating dynamic proof-of-work challenges.
type Manager struct {
	secretKey []byte
	ttl       time.Duration

	mu         sync.Mutex
	usedNonces map[string]int64 // id -> expiry timestamp for replay protection
}

// NewManager creates a challenge manager with HMAC authentication.
func NewManager(secretKey []byte, ttl time.Duration) (*Manager, error) {
	if len(secretKey) == 0 {
		return nil, ErrMissingSecretKey
	}
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &Manager{
		secretKey:  secretKey,
		ttl:        ttl,
		usedNonces: make(map[string]int64),
	}, nil
}

// CreateChallenge generates a new cryptographic puzzle.
// Difficulty indicates number of leading '0' hex digits in sha256(prefix + nonce).
func (m *Manager) CreateChallenge(difficulty int) (*Challenge, error) {
	if difficulty <= 0 {
		difficulty = 3 // default 3 hex zeros = ~4096 hashes (~5-15ms in JS)
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generating challenge id: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	prefixBytes := make([]byte, 16)
	if _, err := rand.Read(prefixBytes); err != nil {
		return nil, fmt.Errorf("generating challenge prefix: %w", err)
	}
	prefix := hex.EncodeToString(prefixBytes)

	expiresAt := time.Now().Add(m.ttl).Unix()

	ch := &Challenge{
		ID:         id,
		Algorithm:  "sha256-hashcash",
		Prefix:     prefix,
		Difficulty: difficulty,
		ExpiresAt:  expiresAt,
	}

	ch.Signature = m.signChallenge(ch)
	return ch, nil
}

func (m *Manager) signChallenge(ch *Challenge) string {
	payload := fmt.Sprintf("%s:%s:%d:%d", ch.ID, ch.Prefix, ch.Difficulty, ch.ExpiresAt)
	mac := hmac.New(sha256.New, m.secretKey)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify verifies that the client's solution satisfies the challenge.
func (m *Manager) Verify(ch *Challenge, sol *Solution) (bool, error) {
	if ch == nil || sol == nil {
		return false, ErrInvalidSolution
	}
	if ch.ID != sol.ID {
		return false, ErrInvalidSolution
	}

	// 1. Check expiration
	now := time.Now().Unix()
	if now > ch.ExpiresAt {
		return false, ErrChallengeExpired
	}

	// 2. Verify signature integrity
	expectedSig := m.signChallenge(ch)
	if !hmac.Equal([]byte(ch.Signature), []byte(expectedSig)) {
		return false, ErrInvalidSignature
	}

	// 3. Replay prevention
	m.mu.Lock()
	m.cleanupExpired(now)
	if _, used := m.usedNonces[ch.ID]; used {
		m.mu.Unlock()
		return false, ErrSolutionReplayed
	}
	m.usedNonces[ch.ID] = ch.ExpiresAt
	m.mu.Unlock()

	// 4. Validate Proof-of-Work: sha256(prefix + nonce) must have difficulty leading hex zeros
	hashInput := ch.Prefix + sol.Nonce
	sum := sha256.Sum256([]byte(hashInput))
	hexDigest := hex.EncodeToString(sum[:])

	prefixZeros := strings.Repeat("0", ch.Difficulty)
	if !strings.HasPrefix(hexDigest, prefixZeros) {
		return false, ErrInvalidSolution
	}

	return true, nil
}

// Solve is a reference solver (used for testing or client verification).
func Solve(prefix string, difficulty int, maxIterations int) (string, bool) {
	target := strings.Repeat("0", difficulty)
	if maxIterations <= 0 {
		maxIterations = 5_000_000
	}

	for i := 0; i < maxIterations; i++ {
		nonce := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(prefix + nonce))
		hexDigest := hex.EncodeToString(sum[:])
		if strings.HasPrefix(hexDigest, target) {
			return nonce, true
		}
	}
	return "", false
}

func (m *Manager) cleanupExpired(now int64) {
	for id, exp := range m.usedNonces {
		if now > exp {
			delete(m.usedNonces, id)
		}
	}
}
