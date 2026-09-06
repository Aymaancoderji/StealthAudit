package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
