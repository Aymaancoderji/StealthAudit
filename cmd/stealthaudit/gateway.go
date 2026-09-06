package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Aymaancoderji/StealthAudit/pkg/gateway"
	"github.com/Aymaancoderji/StealthAudit/pkg/network"
)

func cmdGateway(args []string) {
	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	port := fs.Int("port", 8080, "HTTP port for the telemetry ingestion & evaluation gateway")
	secret := fs.String("secret", "", "secret key for signing StealthAudit tokens (defaults to random 32-byte key or STEALTHAUDIT_SECRET_KEY)")
	minScore := fs.Float64("min-score", 40.0, "minimum stealth score to allow without security challenge")
	maxBotProb := fs.Float64("max-bot-prob", 0.85, "maximum ML bot probability before blocking access")
	tokenTTLSec := fs.Int("token-ttl", 120, "validity duration of issued assessment tokens in seconds")
	withProbe := fs.Bool("with-probe", true, "start local TLS/HTTP2 network probe server alongside gateway")
	fs.Parse(args)

	secretKeyStr := *secret
	if secretKeyStr == "" {
		secretKeyStr = os.Getenv("STEALTHAUDIT_SECRET_KEY")
	}
	if secretKeyStr == "" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		secretKeyStr = hex.EncodeToString(b)
		fmt.Printf("[gateway] No secret key provided. Generated ephemeral 32-byte key: %s\n", secretKeyStr)
	}

	cfg := gateway.Config{
		SecretKey:       []byte(secretKeyStr),
		MinAllowScore:   *minScore,
		MaxAllowBotProb: *maxBotProb,
		TokenTTL:        time.Duration(*tokenTTLSec) * time.Second,
	}

	var netServer *network.Server
	if *withProbe {
		netServer = network.NewServer()
		probeURL, err := netServer.Start()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: starting network probe: %v\n", err)
		} else {
			cfg.NetCaptureProvider = netServer.Latest
			fmt.Printf("[gateway] Local TLS/HTTP2 probe listening at %s\n", probeURL)
			defer netServer.Stop()
		}
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize gateway: %v\n", err)
		os.Exit(1)
	}

	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	fmt.Println("==================================================================")
	fmt.Printf(" StealthAudit Real-Time Ingestion Gateway running on http://%s\n", addr)
	fmt.Println("==================================================================")
	fmt.Printf(" Client SDK Tag:\n   <script src=\"http://localhost:%d/stealthaudit.js\"></script>\n\n", *port)
	fmt.Println(" Gateway Endpoints:")
	fmt.Printf("   - Telemetry Ingestion: POST http://localhost:%d/v1/telemetry\n", *port)
	fmt.Printf("   - Token Verification:  POST http://localhost:%d/v1/verify\n", *port)
	fmt.Printf("   - Interactive Demo:    GET  http://localhost:%d/\n", *port)
	fmt.Printf("   - Health Check:        GET  http://localhost:%d/healthz\n", *port)
	fmt.Println("==================================================================")

	srv := &http.Server{
		Addr:              addr,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "gateway server error: %v\n", err)
		os.Exit(1)
	}
}
