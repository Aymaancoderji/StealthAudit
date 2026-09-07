package gateway

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/Aymaancoderji/StealthAudit/pkg/analyzer"
	"github.com/Aymaancoderji/StealthAudit/pkg/challenge"
	"github.com/Aymaancoderji/StealthAudit/pkg/client"
	"github.com/Aymaancoderji/StealthAudit/pkg/collector"
	"github.com/Aymaancoderji/StealthAudit/pkg/mlmodel"
	"github.com/Aymaancoderji/StealthAudit/pkg/network"
	"github.com/Aymaancoderji/StealthAudit/pkg/token"
)

// Config configures the Ingestion and Scoring Gateway.
type Config struct {
	SecretKey           []byte
	MinAllowScore       float64
	MaxAllowBotProb     float64
	TokenTTL            time.Duration
	ChallengeDifficulty int
	NetCaptureProvider  func() *network.Capture
	Scorer              analyzer.Scorer
}

// DefaultConfig returns standard gateway defaults.
func DefaultConfig(secretKey []byte) Config {
	return Config{
		SecretKey:           secretKey,
		MinAllowScore:       40.0,
		MaxAllowBotProb:     0.85,
		TokenTTL:            120 * time.Second,
		ChallengeDifficulty: 3,
		Scorer:              analyzer.RuleScorer{},
	}
}

// Gateway handles in-browser telemetry ingestion, scoring, and token issuance.
type Gateway struct {
	cfg          Config
	signer       *token.Signer
	verifier     *token.Verifier
	challengeMgr *challenge.Manager
	mux          *http.ServeMux

	mu       sync.Mutex
	demoLogs []map[string]any
}

// TelemetryRequest is the payload sent from stealthaudit.js.
type TelemetryRequest struct {
	Fingerprint       *collector.Fingerprint `json:"fingerprint"`
	Challenge         *challenge.Challenge   `json:"challenge,omitempty"`
	ChallengeSolution *challenge.Solution    `json:"challengeSolution,omitempty"`
}

// TelemetryResponse is returned to the client SDK with the assessment token.
type TelemetryResponse struct {
	Token             string               `json:"token"`
	Decision          token.Decision       `json:"decision"`
	Score             float64              `json:"score"`
	BotProbability    float64              `json:"botProbability"`
	Verdict           string               `json:"verdict"`
	VisitorID         string               `json:"visitorId"`
	Flags             []string             `json:"flags,omitempty"`
	Challenge         *challenge.Challenge `json:"challenge,omitempty"`
	ChallengeVerified bool                 `json:"challengeVerified,omitempty"`
}

// VerifyRequest is submitted by customer backend APIs verifying a token.
type VerifyRequest struct {
	Token string `json:"token"`
}

// VerifyResponse is returned by /v1/verify.
type VerifyResponse struct {
	Valid  bool          `json:"valid"`
	Claims *token.Claims `json:"claims,omitempty"`
	Error  string        `json:"error,omitempty"`
}

// New creates a new Gateway instance.
func New(cfg Config) (*Gateway, error) {
	if len(cfg.SecretKey) == 0 {
		return nil, token.ErrMissingSecretKey
	}
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = 120 * time.Second
	}
	if cfg.Scorer == nil {
		cfg.Scorer = analyzer.RuleScorer{}
	}

	signer, err := token.NewSigner(cfg.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("initializing token signer: %w", err)
	}

	verifier, err := token.NewVerifier(cfg.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("initializing token verifier: %w", err)
	}

	challengeMgr, err := challenge.NewManager(cfg.SecretKey, 60*time.Second)
	if err != nil {
		return nil, fmt.Errorf("initializing challenge manager: %w", err)
	}

	gw := &Gateway{
		cfg:          cfg,
		signer:       signer,
		verifier:     verifier,
		challengeMgr: challengeMgr,
		mux:          http.NewServeMux(),
		demoLogs:     make([]map[string]any, 0),
	}

	gw.routes()
	return gw, nil
}

// Handler returns the Gateway's http.Handler.
func (g *Gateway) Handler() http.Handler {
	return g.mux
}

// Verifier returns the gateway's token verifier.
func (g *Gateway) Verifier() *token.Verifier {
	return g.verifier
}

// ChallengeManager returns the gateway's challenge manager.
func (g *Gateway) ChallengeManager() *challenge.Manager {
	return g.challengeMgr
}

func (g *Gateway) routes() {
	// 1. Client SDK bundle
	g.mux.Handle("/stealthaudit.js", client.Handler())

	// 2. Telemetry ingestion
	g.mux.HandleFunc("/v1/telemetry", g.handleTelemetry)

	// 3. Token verification API
	g.mux.HandleFunc("/v1/verify", g.handleVerify)

	// 4. Dynamic Proof-of-Work challenge API
	g.mux.HandleFunc("/v1/challenge", g.handleChallenge)

	// 5. Healthcheck
	g.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"version": "1.0.0",
		})
	})

	// 6. Interactive Demo Page & Protected Form
	g.mux.HandleFunc("/", g.handleDemo)
	g.mux.HandleFunc("/api/demo-action", g.handleDemoAction)
}

func (g *Gateway) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TelemetryRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB limit
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid payload: %v", err), http.StatusBadRequest)
		return
	}

	if req.Fingerprint == nil {
		http.Error(w, "missing fingerprint data", http.StatusBadRequest)
		return
	}

	var netCapture *network.Capture
	if g.cfg.NetCaptureProvider != nil {
		netCapture = g.cfg.NetCaptureProvider()
	}

	analysis, err := g.cfg.Scorer.Score(analyzer.Input{
		Fingerprint: req.Fingerprint,
		Network:     netCapture,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("scoring failed: %v", err), http.StatusInternalServerError)
		return
	}

	mlResult := mlmodel.Classify(req.Fingerprint, netCapture)
	visitorID := collector.ComputeVisitorID(req.Fingerprint)

	flagCodes := make([]string, 0, len(analysis.Flags))
	for _, f := range analysis.Flags {
		flagCodes = append(flagCodes, f.Code)
	}

	// Policy Decision
	decision := token.DecisionAllow
	isHardAutomation := false

	if req.Fingerprint.Runtime != nil {
		rt := req.Fingerprint.Runtime
		if rt.WebdriverFlag || len(rt.AutomationArtifacts) > 0 || rt.WorkerWebdriverLeak || rt.ErrorStackAutomationLeak || rt.ProxyTrapDetected {
			isHardAutomation = true
		}
	}
	if req.Fingerprint.Behavioral != nil {
		if req.Fingerprint.Behavioral.HasUntrustedEvents {
			isHardAutomation = true
		}
	}

	var issuedChallenge *challenge.Challenge
	challengeVerified := false

	if isHardAutomation || mlResult.Probability >= g.cfg.MaxAllowBotProb {
		decision = token.DecisionBlock
	} else if mlResult.Probability >= 0.40 || (g.cfg.MinAllowScore > 0 && analysis.StealthScore < g.cfg.MinAllowScore) {
		// If client provided a valid challenge solution, upgrade challenge to allow!
		if req.Challenge != nil && req.ChallengeSolution != nil {
			valid, err := g.challengeMgr.Verify(req.Challenge, req.ChallengeSolution)
			if err == nil && valid {
				decision = token.DecisionAllow
				challengeVerified = true
			} else {
				decision = token.DecisionChallenge
				ch, _ := g.challengeMgr.CreateChallenge(g.cfg.ChallengeDifficulty)
				issuedChallenge = ch
			}
		} else {
			decision = token.DecisionChallenge
			ch, _ := g.challengeMgr.CreateChallenge(g.cfg.ChallengeDifficulty)
			issuedChallenge = ch
		}
	}

	now := time.Now()
	claims := token.Claims{
		VisitorID:         visitorID,
		Score:             analysis.StealthScore,
		BotProbability:    mlResult.Probability,
		Decision:          decision,
		Flags:             flagCodes,
		ChallengeVerified: challengeVerified,
		IssuedAt:          now.Unix(),
		ExpiresAt:         now.Add(g.cfg.TokenTTL).Unix(),
	}

	signedToken, err := g.signer.IssueToken(claims)
	if err != nil {
		http.Error(w, fmt.Sprintf("token issuance: %v", err), http.StatusInternalServerError)
		return
	}

	resp := TelemetryResponse{
		Token:             signedToken,
		Decision:          decision,
		Score:             analysis.StealthScore,
		BotProbability:    mlResult.Probability,
		Verdict:           mlResult.Verdict,
		VisitorID:         visitorID,
		Flags:             flagCodes,
		Challenge:         issuedChallenge,
		ChallengeVerified: challengeVerified,
	}

	// Record for demo log
	g.mu.Lock()
	g.demoLogs = append(g.demoLogs, map[string]any{
		"time":      now.Format("15:04:05"),
		"visitorId": visitorID[:8],
		"score":     analysis.StealthScore,
		"botProb":   mlResult.Probability,
		"decision":  decision,
	})
	if len(g.demoLogs) > 20 {
		g.demoLogs = g.demoLogs[len(g.demoLogs)-20:]
	}
	g.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	claims, err := g.verifier.VerifyToken(req.Token)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(VerifyResponse{
			Valid: false,
			Error: err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(VerifyResponse{
		Valid:  true,
		Claims: claims,
	})
}

func (g *Gateway) handleChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		ch, err := g.challengeMgr.CreateChallenge(g.cfg.ChallengeDifficulty)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(ch)
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			Challenge *challenge.Challenge `json:"challenge"`
			Solution  *challenge.Solution  `json:"solution"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		valid, err := g.challengeMgr.Verify(req.Challenge, req.Solution)
		if err != nil || !valid {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"valid": false,
				"error": "challenge verification failed",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"valid":    true,
			"verified": true,
		})
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (g *Gateway) handleDemo(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/demo" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = demoTemplate.Execute(w, nil)
}

func (g *Gateway) handleDemoAction(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("X-StealthAudit-Token")
	if tok == "" {
		tok = r.PostFormValue("_stealthaudit_token")
	}

	w.Header().Set("Content-Type", "application/json")
	if tok == "" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "blocked",
			"message": "Access Denied: Missing StealthAudit security token.",
		})
		return
	}

	claims, err := g.verifier.VerifyToken(tok)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "blocked",
			"message": fmt.Sprintf("Access Denied: Token verification failed (%v).", err),
		})
		return
	}

	if claims.Decision == token.DecisionBlock {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "blocked",
			"message": "Access Denied: Automated bot detected. Request rejected.",
			"claims":  claims,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "success",
		"message": fmt.Sprintf("Request Approved! Verified human visitor %s (Stealth Score: %.1f, Bot Prob: %.0f%%)", claims.VisitorID[:8], claims.Score, claims.BotProbability*100),
		"claims":  claims,
	})
}

var demoTemplate = template.Must(template.New("demo").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>StealthAudit Protection Gateway</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-bright: #f0f6fc;
      --accent: #58a6ff;
      --green: #3fb950;
      --red: #f85149;
      --yellow: #d29922;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      line-height: 1.5;
      padding: 2rem 1rem;
    }
    .container { max-width: 860px; margin: 0 auto; }
    header { margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }
    h1 { color: var(--text-bright); font-size: 1.8rem; margin-bottom: 0.25rem; }
    .subtitle { color: #8b949e; font-size: 0.95rem; }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    h2 { color: var(--text-bright); font-size: 1.2rem; margin-bottom: 1rem; }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      border-radius: 9999px;
      font-weight: 600;
      font-size: 0.85rem;
      margin-bottom: 1rem;
    }
    .status-badge.allow { background: rgba(63, 185, 80, 0.15); color: var(--green); border: 1px solid var(--green); }
    .status-badge.block { background: rgba(248, 81, 73, 0.15); color: var(--red); border: 1px solid var(--red); }
    .status-badge.challenge { background: rgba(210, 153, 34, 0.15); color: var(--yellow); border: 1px solid var(--yellow); }
    .status-badge.loading { background: rgba(88, 166, 255, 0.15); color: var(--accent); border: 1px solid var(--accent); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1rem; }
    .stat-box { background: var(--bg); padding: 1rem; border-radius: 6px; border: 1px solid var(--border); }
    .stat-label { font-size: 0.75rem; text-transform: uppercase; color: #8b949e; letter-spacing: 0.05em; }
    .stat-val { font-size: 1.3rem; font-weight: 700; color: var(--text-bright); margin-top: 0.25rem; }
    pre {
      background: var(--bg);
      border: 1px solid var(--border);
      padding: 1rem;
      border-radius: 6px;
      font-size: 0.82rem;
      overflow-x: auto;
      color: #79c0ff;
    }
    button {
      background: #238636;
      color: white;
      border: 1px solid rgba(240, 246, 252, 0.1);
      padding: 8px 16px;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      font-size: 0.9rem;
    }
    button:hover { background: #2ea043; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .result-box {
      margin-top: 1rem;
      padding: 1rem;
      border-radius: 6px;
      display: none;
    }
  </style>
  <script src="/stealthaudit.js"></script>
</head>
<body>
  <div class="container">
    <header>
      <h1>StealthAudit Ingestion Gateway</h1>
      <p class="subtitle">Live real-time client SDK telemetry assessment & token issuance</p>
    </header>

    <div class="card">
      <h2>1. Live Client Assessment</h2>
      <div id="statusBadge" class="status-badge loading">Auditing browser environment...</div>
      <div class="grid">
        <div class="stat-box">
          <div class="stat-label">Decision</div>
          <div id="statDecision" class="stat-val">-</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Stealth Score</div>
          <div id="statScore" class="stat-val">-</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Bot Probability</div>
          <div id="statBotProb" class="stat-val">-</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Visitor ID</div>
          <div id="statVisitorId" class="stat-val" style="font-size:1rem;word-break:break-all;">-</div>
        </div>
      </div>
      <p style="font-size:0.85rem;color:#8b949e;margin-bottom:0.5rem;">Signed StealthAudit Token (SAT):</p>
      <pre id="tokenDisplay">Waiting for telemetry...</pre>
    </div>

    <div class="card">
      <h2>2. Behavioral Biometrics & Kinematics</h2>
      <p style="font-size:0.9rem;margin-bottom:1rem;">Real humans exhibit non-linear cursor curvature and variable keystroke flight times. Automated bots teleport or follow rigid linear paths.</p>
      <div class="grid">
        <div class="stat-box">
          <div class="stat-label">Mouse Movements</div>
          <div id="statMouseCount" class="stat-val">0</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Straight-Line Ratio</div>
          <div id="statStraightRatio" class="stat-val">0.00</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Keystroke Flight Variance</div>
          <div id="statKeyVariance" class="stat-val">0.00 ms</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Event Integrity</div>
          <div id="statEventTrust" class="stat-val" style="color:var(--green);">Trusted</div>
        </div>
      </div>
      <input type="text" id="demoInput" placeholder="Type inside this box to test keystroke flight variance..." style="width:100%;padding:10px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text-bright);font-size:0.9rem;">
    </div>

    <div class="card">
      <h2>3. Dynamic Proof-of-Work (PoW) Challenge Engine</h2>
      <p style="font-size:0.9rem;margin-bottom:1rem;">When traffic is suspicious, the gateway issues a cryptographic puzzle solved silently by a background Web Worker.</p>
      <div id="powStatus" style="font-size:0.9rem;color:#8b949e;margin-bottom:1rem;">Worker Solver: <strong style="color:var(--green);">Active & Ready</strong></div>
      <button onclick="testPoWChallenge()" style="background:#1f6feb;">Solve Test Challenge (Web Worker)</button>
      <div id="powResult" class="result-box"></div>
    </div>

    <div class="card">
      <h2>4. Test Protected API Endpoint</h2>
      <p style="font-size:0.9rem;margin-bottom:1rem;">Submit a request to <code>POST /api/demo-action</code>. The server-side middleware will verify the token's cryptographic signature and bot score before allowing access.</p>
      <button id="testBtn" onclick="submitProtectedAction()">Submit Protected Request</button>
      <div id="actionResult" class="result-box"></div>
    </div>
  </div>

  <script>
    window.addEventListener('stealthaudit:ready', function(e) {
      const data = e.detail;
      const badge = document.getElementById('statusBadge');
      badge.className = 'status-badge ' + data.decision;
      badge.textContent = 'Decision: ' + data.decision.toUpperCase();

      document.getElementById('statDecision').textContent = data.decision.toUpperCase();
      document.getElementById('statScore').textContent = data.score.toFixed(1) + '/100';
      document.getElementById('statBotProb').textContent = (data.botProbability * 100).toFixed(0) + '%';
      document.getElementById('statVisitorId').textContent = data.visitorId.substring(0, 12) + '...';
      document.getElementById('tokenDisplay').textContent = data.token;
    });

    setInterval(() => {
      if (window.StealthAudit && window.StealthAudit.getBehavioral) {
        const beh = window.StealthAudit.getBehavioral();
        document.getElementById('statMouseCount').textContent = beh.mouseMovementCount;
        document.getElementById('statStraightRatio').textContent = beh.mouseStraightLineRatio.toFixed(2);
        document.getElementById('statKeyVariance').textContent = beh.keyFlightVariance.toFixed(2) + ' ms';
        const trustEl = document.getElementById('statEventTrust');
        if (beh.hasUntrustedEvents) {
          trustEl.textContent = 'Untrusted';
          trustEl.style.color = 'var(--red)';
        } else {
          trustEl.textContent = 'Trusted';
          trustEl.style.color = 'var(--green)';
        }
      }
    }, 250);

    async function testPoWChallenge() {
      const resBox = document.getElementById('powResult');
      resBox.style.display = 'block';
      resBox.style.background = 'var(--surface)';
      resBox.style.border = '1px solid var(--border)';
      resBox.style.color = 'var(--text-bright)';
      resBox.textContent = 'Requesting challenge from gateway...';

      try {
        const start = performance.now();
        const chRes = await fetch('/v1/challenge');
        const ch = await chRes.json();
        resBox.textContent = 'Solving Proof-of-Work challenge in Web Worker (Difficulty: ' + ch.difficulty + ')...';
        const sol = await window.StealthAudit.solveChallenge(ch);
        const elapsed = (performance.now() - start).toFixed(0);

        if (!sol) {
          throw new Error('Solver returned empty solution');
        }

        const verifyRes = await fetch('/v1/challenge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ challenge: ch, solution: sol })
        });
        const vData = await verifyRes.json();

        if (verifyRes.ok && vData.valid) {
          resBox.style.background = 'rgba(63, 185, 80, 0.15)';
          resBox.style.border = '1px solid var(--green)';
          resBox.textContent = 'Challenge verified! Solved in ' + elapsed + 'ms via Web Worker. Nonce: ' + sol.nonce;
        } else {
          resBox.style.background = 'rgba(248, 81, 73, 0.15)';
          resBox.style.border = '1px solid var(--red)';
          resBox.textContent = 'Challenge verification failed: ' + JSON.stringify(vData);
        }
      } catch (err) {
        resBox.style.background = 'rgba(248, 81, 73, 0.15)';
        resBox.style.border = '1px solid var(--red)';
        resBox.textContent = 'Error: ' + err.message;
      }
    }

    async function submitProtectedAction() {
      const btn = document.getElementById('testBtn');
      const box = document.getElementById('actionResult');
      btn.disabled = true;
      box.style.display = 'block';
      box.style.background = 'var(--surface)';
      box.style.border = '1px solid var(--border)';
      box.textContent = 'Sending request with StealthAudit token...';

      try {
        const token = await window.StealthAudit.getToken();
        const res = await fetch('/api/demo-action', {
          method: 'POST',
          headers: {
            'X-StealthAudit-Token': token
          }
        });
        const data = await res.json();
        if (res.ok) {
          box.style.background = 'rgba(63, 185, 80, 0.15)';
          box.style.border = '1px solid var(--green)';
          box.style.color = 'var(--text-bright)';
          box.textContent = data.message;
        } else {
          box.style.background = 'rgba(248, 81, 73, 0.15)';
          box.style.border = '1px solid var(--red)';
          box.style.color = '#ff7b72';
          box.textContent = data.message || data.error;
        }
      } catch (err) {
        box.textContent = 'Error: ' + err.message;
      } finally {
        btn.disabled = false;
      }
    }
  </script>
</body>
</html>`))
