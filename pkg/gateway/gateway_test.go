package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Aymaancoderji/StealthAudit/pkg/challenge"
	"github.com/Aymaancoderji/StealthAudit/pkg/collector"
	"github.com/Aymaancoderji/StealthAudit/pkg/token"
)

func TestGatewayEndpoints(t *testing.T) {
	secret := []byte("test-gateway-secret-32bytes-123456")
	gw, err := New(DefaultConfig(secret))
	if err != nil {
		t.Fatalf("New gateway: %v", err)
	}

	handler := gw.Handler()

	// 1. GET /stealthaudit.js
	reqJS := httptest.NewRequest("GET", "/stealthaudit.js", nil)
	recJS := httptest.NewRecorder()
	handler.ServeHTTP(recJS, reqJS)

	if recJS.Code != http.StatusOK {
		t.Errorf("GET /stealthaudit.js code = %d, want 200", recJS.Code)
	}
	if !strings.Contains(recJS.Body.String(), "StealthAudit") {
		t.Errorf("expected script in response")
	}

	// 2. POST /v1/telemetry (normal human fingerprint)
	humanFP := &collector.Fingerprint{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		Canvas:    &collector.CanvasFingerprint{Hash: "canvas_hash_123"},
		WebGL: &collector.WebGLFingerprint{
			Vendor:           "Google Inc. (NVIDIA)",
			Renderer:         "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)",
			UnmaskedVendor:   "NVIDIA",
			UnmaskedRenderer: "NVIDIA GeForce RTX 3080",
			WebGL2Supported:  true,
		},
		Audio: &collector.AudioFingerprint{Hash: "audio_hash_123"},
		Runtime: &collector.RuntimeFingerprint{
			WebdriverFlag:          false,
			FunctionToStringOK:     true,
			ToStringOfToStringOK:   true,
			HasChromeRuntime:       true,
			ChromeLoadTimesPresent: true,
			ChromeCsiPresent:       true,
			ChromeAppPresent:       true,
			WorkerSupport:          true,
			WorkerExecutionOK:      true,
		},
		Device: &collector.DeviceFingerprint{
			ScreenWidth:         1920,
			ScreenHeight:        1080,
			OuterWidth:          1920,
			OuterHeight:         1080,
			InnerWidth:          1920,
			InnerHeight:         1000,
			HardwareConcurrency: 8,
			DeviceMemory:        16,
			Fonts:               []string{"Arial", "Helvetica", "Times New Roman"},
			SpeechVoiceCount:    10,
			UserAgentData: &collector.UserAgentDataFingerprint{
				Platform: "Windows",
			},
		},
	}

	telemetryReq := TelemetryRequest{Fingerprint: humanFP}
	body, _ := json.Marshal(telemetryReq)

	reqTel := httptest.NewRequest("POST", "/v1/telemetry", bytes.NewReader(body))
	recTel := httptest.NewRecorder()
	handler.ServeHTTP(recTel, reqTel)

	if recTel.Code != http.StatusOK {
		t.Fatalf("POST /v1/telemetry status = %d: %s", recTel.Code, recTel.Body.String())
	}

	var telResp TelemetryResponse
	if err := json.NewDecoder(recTel.Body).Decode(&telResp); err != nil {
		t.Fatalf("decode telemetry response: %v", err)
	}

	if telResp.Token == "" {
		t.Fatalf("expected token in response")
	}
	if telResp.Decision != token.DecisionAllow {
		t.Errorf("decision = %q, want allow", telResp.Decision)
	}

	// 3. POST /v1/verify
	verifyReq := VerifyRequest{Token: telResp.Token}
	vBody, _ := json.Marshal(verifyReq)

	reqVer := httptest.NewRequest("POST", "/v1/verify", bytes.NewReader(vBody))
	recVer := httptest.NewRecorder()
	handler.ServeHTTP(recVer, reqVer)

	if recVer.Code != http.StatusOK {
		t.Fatalf("POST /v1/verify status = %d", recVer.Code)
	}

	var verResp VerifyResponse
	if err := json.NewDecoder(recVer.Body).Decode(&verResp); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if !verResp.Valid || verResp.Claims == nil {
		t.Fatalf("expected valid claims in verify response")
	}
	if verResp.Claims.VisitorID != telResp.VisitorID {
		t.Errorf("verified visitorID = %q, want %q", verResp.Claims.VisitorID, telResp.VisitorID)
	}

	// 4. POST /api/demo-action with verified token
	reqAction := httptest.NewRequest("POST", "/api/demo-action", nil)
	reqAction.Header.Set("X-StealthAudit-Token", telResp.Token)
	recAction := httptest.NewRecorder()
	handler.ServeHTTP(recAction, reqAction)

	if recAction.Code != http.StatusOK {
		t.Errorf("demo-action status = %d, want 200", recAction.Code)
	}

	// 5. Automated bot telemetry -> DecisionBlock
	botFP := &collector.Fingerprint{
		UserAgent: "Mozilla/5.0 HeadlessChrome/128.0.0.0",
		Runtime: &collector.RuntimeFingerprint{
			WebdriverFlag:       true,
			AutomationArtifacts: []string{"__webdriver_evaluate"},
		},
	}
	botBody, _ := json.Marshal(TelemetryRequest{Fingerprint: botFP})
	reqBot := httptest.NewRequest("POST", "/v1/telemetry", bytes.NewReader(botBody))
	recBot := httptest.NewRecorder()
	handler.ServeHTTP(recBot, reqBot)

	var botResp TelemetryResponse
	_ = json.NewDecoder(recBot.Body).Decode(&botResp)
	if botResp.Decision != token.DecisionBlock {
		t.Errorf("bot decision = %q, want block", botResp.Decision)
	}

	// Attempt demo-action with blocked bot token
	reqBotAction := httptest.NewRequest("POST", "/api/demo-action", nil)
	reqBotAction.Header.Set("X-StealthAudit-Token", botResp.Token)
	recBotAction := httptest.NewRecorder()
	handler.ServeHTTP(recBotAction, reqBotAction)

	if recBotAction.Code != http.StatusForbidden {
		t.Errorf("demo-action with bot token = %d, want 403", recBotAction.Code)
	}
}

func TestGatewayProofOfWorkChallenge(t *testing.T) {
	secret := []byte("test-gateway-secret-32bytes-123456")
	cfg := DefaultConfig(secret)
	cfg.ChallengeDifficulty = 2 // Fast for testing
	cfg.MinAllowScore = 95.0    // Threshold above humanFP without TLS (~87.5) to trigger challenge

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("New gateway: %v", err)
	}

	handler := gw.Handler()

	// Fingerprint with score ~87.5 (below 95.0 threshold -> DecisionChallenge)
	borderlineFP := &collector.Fingerprint{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36",
		Canvas:    &collector.CanvasFingerprint{Hash: "canvas_hash_123"},
		WebGL: &collector.WebGLFingerprint{
			UnmaskedVendor:   "NVIDIA",
			UnmaskedRenderer: "NVIDIA GeForce RTX 3080",
			WebGL2Supported:  true,
		},
		Audio: &collector.AudioFingerprint{Hash: "audio_hash_123"},
		Runtime: &collector.RuntimeFingerprint{
			WebdriverFlag:        false,
			FunctionToStringOK:   true,
			ToStringOfToStringOK: true,
			HasChromeRuntime:     true,
			WorkerSupport:        true,
			WorkerExecutionOK:    true,
		},
		Device: &collector.DeviceFingerprint{
			ScreenWidth:         1920,
			ScreenHeight:        1080,
			HardwareConcurrency: 8,
			DeviceMemory:        16,
			Fonts:               []string{"Arial", "Helvetica", "Times New Roman"},
			SpeechVoiceCount:    10,
			UserAgentData: &collector.UserAgentDataFingerprint{
				Platform: "Windows",
			},
		},
	}

	body, _ := json.Marshal(TelemetryRequest{Fingerprint: borderlineFP})
	req := httptest.NewRequest("POST", "/v1/telemetry", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	var resp TelemetryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Decision != token.DecisionChallenge {
		t.Fatalf("expected decision 'challenge', got %s", resp.Decision)
	}
	if resp.Challenge == nil {
		t.Fatalf("expected challenge object in response, got nil")
	}

	// Solve the challenge
	nonce, ok := challenge.Solve(resp.Challenge.Prefix, resp.Challenge.Difficulty, 100000)
	if !ok {
		t.Fatalf("failed to solve challenge")
	}

	// Resubmit with solution
	solveReq := TelemetryRequest{
		Fingerprint: borderlineFP,
		Challenge:   resp.Challenge,
		ChallengeSolution: &challenge.Solution{
			ID:    resp.Challenge.ID,
			Nonce: nonce,
		},
	}
	solveBody, _ := json.Marshal(solveReq)
	req2 := httptest.NewRequest("POST", "/v1/telemetry", bytes.NewReader(solveBody))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	var resp2 TelemetryResponse
	if err := json.NewDecoder(rec2.Body).Decode(&resp2); err != nil {
		t.Fatalf("decode solved response: %v", err)
	}

	if resp2.Decision != token.DecisionAllow {
		t.Errorf("expected decision 'allow' after solving challenge, got %s", resp2.Decision)
	}
	if !resp2.ChallengeVerified {
		t.Errorf("expected ChallengeVerified = true")
	}

	// Test ProxyTrap hard automation block
	proxyFP := &collector.Fingerprint{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
		Runtime: &collector.RuntimeFingerprint{
			ProxyTrapDetected: true,
		},
	}
	proxyBody, _ := json.Marshal(TelemetryRequest{Fingerprint: proxyFP})
	reqProxy := httptest.NewRequest("POST", "/v1/telemetry", bytes.NewReader(proxyBody))
	recProxy := httptest.NewRecorder()
	handler.ServeHTTP(recProxy, reqProxy)

	var respProxy TelemetryResponse
	_ = json.NewDecoder(recProxy.Body).Decode(&respProxy)
	if respProxy.Decision != token.DecisionBlock {
		t.Errorf("expected block on proxy trap, got %s", respProxy.Decision)
	}
}

