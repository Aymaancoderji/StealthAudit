package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Aymaancoderji/StealthAudit/pkg/token"
)

type contextKey struct{}

var claimsContextKey = &contextKey{}

// Policy defines decision thresholds.
type Policy struct {
	MaxBotProbability float64
	MinScore          float64
}

// Config defines options for the protection middleware.
type Config struct {
	Policy            Policy
	HeaderName        string
	FormField         string
	OnMissingToken    func(http.ResponseWriter, *http.Request)
	OnInvalidToken    func(http.ResponseWriter, *http.Request, error)
	OnChallenge       func(http.ResponseWriter, *http.Request, *token.Claims)
	OnBlock           func(http.ResponseWriter, *http.Request, *token.Claims)
}

// DefaultConfig provides recommended defaults.
var DefaultConfig = Config{
	Policy: Policy{
		MaxBotProbability: 0.85,
		MinScore:          40.0,
	},
	HeaderName: "X-StealthAudit-Token",
	FormField:  "_stealthaudit_token",
}

// Protect returns an HTTP middleware enforcing StealthAudit token verification.
func Protect(verifier *token.Verifier, configs ...Config) func(http.Handler) http.Handler {
	cfg := DefaultConfig
	if len(configs) > 0 {
		c := configs[0]
		if c.Policy.MaxBotProbability > 0 {
			cfg.Policy.MaxBotProbability = c.Policy.MaxBotProbability
		}
		if c.Policy.MinScore > 0 {
			cfg.Policy.MinScore = c.Policy.MinScore
		}
		if c.HeaderName != "" {
			cfg.HeaderName = c.HeaderName
		}
		if c.FormField != "" {
			cfg.FormField = c.FormField
		}
		if c.OnMissingToken != nil {
			cfg.OnMissingToken = c.OnMissingToken
		}
		if c.OnInvalidToken != nil {
			cfg.OnInvalidToken = c.OnInvalidToken
		}
		if c.OnChallenge != nil {
			cfg.OnChallenge = c.OnChallenge
		}
		if c.OnBlock != nil {
			cfg.OnBlock = c.OnBlock
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawToken := extractToken(r, cfg)
			if rawToken == "" {
				if cfg.OnMissingToken != nil {
					cfg.OnMissingToken(w, r)
				} else {
					writeJSONError(w, http.StatusForbidden, "stealthaudit: missing assessment token")
				}
				return
			}

			claims, err := verifier.VerifyToken(rawToken)
			if err != nil {
				if cfg.OnInvalidToken != nil {
					cfg.OnInvalidToken(w, r, err)
				} else {
					writeJSONError(w, http.StatusForbidden, "stealthaudit: invalid or expired token")
				}
				return
			}

			// Check block conditions
			if claims.Decision == token.DecisionBlock ||
				(cfg.Policy.MaxBotProbability > 0 && claims.BotProbability > cfg.Policy.MaxBotProbability) ||
				(cfg.Policy.MinScore > 0 && claims.Score < cfg.Policy.MinScore) {
				if cfg.OnBlock != nil {
					cfg.OnBlock(w, r, claims)
				} else {
					writeJSONError(w, http.StatusForbidden, "stealthaudit: request blocked due to automated bot detection")
				}
				return
			}

			// Check challenge conditions
			if claims.Decision == token.DecisionChallenge {
				if cfg.OnChallenge != nil {
					cfg.OnChallenge(w, r, claims)
				} else {
					writeJSONError(w, http.StatusPreconditionRequired, "stealthaudit: security verification challenge required")
				}
				return
			}

			// Passed: inject claims into context
			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromContext extracts verified StealthAudit claims from request context if present.
func FromContext(ctx context.Context) (*token.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*token.Claims)
	return claims, ok
}

func extractToken(r *http.Request, cfg Config) string {
	// 1. Configured header
	if val := r.Header.Get(cfg.HeaderName); val != "" {
		return val
	}

	// 2. Authorization: Bearer <token>
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// 3. Form field or query parameter
	if r.Method == http.MethodPost {
		if val := r.PostFormValue(cfg.FormField); val != "" {
			return val
		}
	}
	if val := r.URL.Query().Get(cfg.FormField); val != "" {
		return val
	}
	if val := r.URL.Query().Get("_sat"); val != "" {
		return val
	}

	return ""
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":  message,
		"status": status,
	})
}
