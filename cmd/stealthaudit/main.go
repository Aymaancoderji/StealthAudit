// Command stealthaudit is the CLI entrypoint. Subcommands are stubbed in
// Phase 0 and wired to real functionality in later phases.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Aymaancoderji/StealthAudit/pkg/analyzer"
	"github.com/Aymaancoderji/StealthAudit/pkg/collector"
	"github.com/Aymaancoderji/StealthAudit/pkg/comparer"
	"github.com/Aymaancoderji/StealthAudit/pkg/config"
	"github.com/Aymaancoderji/StealthAudit/pkg/dashboard"
	"github.com/Aymaancoderji/StealthAudit/pkg/leakdetector"
	"github.com/Aymaancoderji/StealthAudit/pkg/mlmodel"
	"github.com/Aymaancoderji/StealthAudit/pkg/network"
	"github.com/Aymaancoderji/StealthAudit/pkg/orchestrator"
	"github.com/Aymaancoderji/StealthAudit/pkg/report"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		cmdRun(os.Args[2:])
	case "leaktest":
		cmdLeakTest(os.Args[2:])
	case "compare":
		cmdCompare(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "gateway":
		cmdGateway(os.Args[2:])
	case "list-drivers":
		cmdListDrivers()
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `stealthaudit - browser fingerprint & anti-detection audit engine

Usage:
  stealthaudit run [flags]
  stealthaudit leaktest [flags]
  stealthaudit compare --baseline=<file> --target=<file> [--out-html=<file>]
  stealthaudit serve [--port=<n>]
  stealthaudit gateway [--port=<n>] [--secret=<key>]
  stealthaudit list-drivers

Run "stealthaudit <command> -h" for flag details.
`)
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	driver := fs.String("driver", "playwright", "automation driver: playwright|puppeteer|selenium")
	browser := fs.String("browser", "chromium", "browser engine: chromium|firefox|webkit")
	proxy := fs.String("proxy", "", "proxy URL, e.g. http://127.0.0.1:8080")
	stealthPlugin := fs.Bool("stealth-plugin", false, "enable stealth-plugin style patches where supported")
	outJSON := fs.String("out-json", "", "path to write JSON report")
	outHTML := fs.String("out-html", "", "path to write HTML dashboard")
	timeoutSec := fs.Int("timeout", 60, "seconds to allow for the whole run before aborting")
	fs.Parse(args)

	cfg := config.RunConfig{
		Driver:        orchestrator.Driver(*driver),
		Browser:       orchestrator.Browser(*browser),
		Headless:      true,
		ProxyURL:      *proxy,
		StealthPlugin: *stealthPlugin,
		OutputJSON:    *outJSON,
		OutputHTML:    *outHTML,
	}

	if err := runCollect(cfg, time.Duration(*timeoutSec)*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "run failed: %v\n", err)
		os.Exit(1)
	}
}

func newAdapter(driver orchestrator.Driver) (orchestrator.BrowserAdapter, error) {
	switch driver {
	case orchestrator.DriverPlaywright:
		return &orchestrator.PlaywrightAdapter{}, nil
	case orchestrator.DriverPuppeteer:
		return &orchestrator.PuppeteerAdapter{}, nil
	case orchestrator.DriverSelenium:
		return &orchestrator.SeleniumAdapter{}, nil
	default:
		return nil, fmt.Errorf("unknown driver %q (want playwright|puppeteer|selenium)", driver)
	}
}

func runCollect(cfg config.RunConfig, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	adapter, err := newAdapter(cfg.Driver)
	if err != nil {
		return err
	}

	netServer := network.NewServer()
	probeURL, err := netServer.Start()
	if err != nil {
		return fmt.Errorf("starting network probe server: %w", err)
	}
	defer netServer.Stop()

	fmt.Printf("launching %s/%s (headless=%v, proxy=%q, stealth-plugin=%v)...\n",
		cfg.Driver, cfg.Browser, cfg.Headless, cfg.ProxyURL, cfg.StealthPlugin)

	session, err := adapter.Launch(ctx, orchestrator.LaunchOptions{
		Driver:        cfg.Driver,
		Browser:       cfg.Browser,
		Headless:      cfg.Headless,
		ProxyURL:      cfg.ProxyURL,
		UserAgent:     cfg.UserAgent,
		StealthPlugin: cfg.StealthPlugin,
		// The network probe below is a self-signed local endpoint, not a
		// real site, so certificate errors are expected and ignored for
		// this session only.
		IgnoreHTTPSErrors: true,
	})
	if err != nil {
		return fmt.Errorf("launch: %w", err)
	}
	defer session.Close(ctx)

	if err := session.Navigate(ctx, "https://example.org"); err != nil {
		return fmt.Errorf("navigate: %w", err)
	}
	fmt.Println("navigated to https://example.org")

	fp, err := (&collector.JSCollector{}).Collect(ctx, session)
	if err != nil {
		return fmt.Errorf("collect: %w", err)
	}

	if err := session.Navigate(ctx, probeURL); err != nil {
		fmt.Fprintf(os.Stderr, "network probe navigation failed (continuing without it): %v\n", err)
	}
	netCapture := netServer.Latest()

	analysis, err := (analyzer.RuleScorer{}).Score(analyzer.Input{Fingerprint: fp, Network: netCapture})
	if err != nil {
		return fmt.Errorf("analyze: %w", err)
	}
	fmt.Printf("stealth score: %.1f/100\n", analysis.StealthScore)
	for _, flag := range analysis.Flags {
		fmt.Printf("  [%s] %s: %s\n", flag.Category, flag.Code, flag.Description)
	}

	mlResult := mlmodel.Classify(fp, netCapture)
	fmt.Printf("ML automation probability: %.0f%% (%s)\n", mlResult.Probability*100, mlResult.Verdict)

	rep := &report.Run{
		Fingerprint: fp,
		Network:     netCapture,
		Analysis:    analysis,
		ML:          mlResult,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	if cfg.OutputJSON != "" {
		if err := os.WriteFile(cfg.OutputJSON, out, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", cfg.OutputJSON, err)
		}
		fmt.Printf("wrote fingerprint report to %s\n", cfg.OutputJSON)
	} else {
		fmt.Println(string(out))
	}

	if cfg.OutputHTML != "" {
		html, err := dashboard.RenderRun(rep)
		if err != nil {
			return fmt.Errorf("rendering dashboard: %w", err)
		}
		if err := os.WriteFile(cfg.OutputHTML, html, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", cfg.OutputHTML, err)
		}
		fmt.Printf("wrote HTML dashboard to %s\n", cfg.OutputHTML)
	}

	return nil
}

func cmdLeakTest(args []string) {
	fs := flag.NewFlagSet("leaktest", flag.ExitOnError)
	driver := fs.String("driver", "playwright", "automation driver: playwright|puppeteer|selenium")
	browser := fs.String("browser", "chromium", "browser engine: chromium|firefox|webkit")
	stealthPlugin := fs.Bool("stealth-plugin", false, "enable stealth-plugin style patches where supported")
	outJSON := fs.String("out-json", "", "path to write JSON report")
	timeoutSec := fs.Int("timeout", 90, "seconds to allow for the whole run before aborting")
	fs.Parse(args)

	cfg := config.RunConfig{
		Driver:        orchestrator.Driver(*driver),
		Browser:       orchestrator.Browser(*browser),
		Headless:      true,
		StealthPlugin: *stealthPlugin,
		OutputJSON:    *outJSON,
	}

	if err := runLeakTest(cfg, time.Duration(*timeoutSec)*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "leaktest failed: %v\n", err)
		os.Exit(1)
	}
}

// runLeakTest launches two independent sessions with identical launch
// options (same driver, browser, and profile-affecting flags) and checks
// whether state set in one is visible from the other. Two sessions from
// the same Launch() call are expected to be fully isolated from each
// other — any observed leak points at a driver/profile configuration bug
// rather than an inherent browser behavior.
func runLeakTest(cfg config.RunConfig, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	adapter, err := newAdapter(cfg.Driver)
	if err != nil {
		return err
	}

	originServer := &leakdetector.Server{}
	baseURL, err := originServer.Start()
	if err != nil {
		return fmt.Errorf("starting leak test origin server: %w", err)
	}
	defer originServer.Stop()

	launchOpts := orchestrator.LaunchOptions{
		Driver:        cfg.Driver,
		Browser:       cfg.Browser,
		Headless:      cfg.Headless,
		StealthPlugin: cfg.StealthPlugin,
	}

	fmt.Printf("launching two independent %s/%s sessions...\n", cfg.Driver, cfg.Browser)

	sessionA, err := adapter.Launch(ctx, launchOpts)
	if err != nil {
		return fmt.Errorf("launching session A: %w", err)
	}
	defer sessionA.Close(ctx)

	sessionB, err := adapter.Launch(ctx, launchOpts)
	if err != nil {
		return fmt.Errorf("launching session B: %w", err)
	}
	defer sessionB.Close(ctx)

	sessions := []orchestrator.Session{sessionA, sessionB}

	var findings []leakdetector.Finding
	for _, test := range leakdetector.AllTests(baseURL) {
		finding, err := test.Run(ctx, sessions)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s test error (skipped): %v\n", test.Kind(), err)
			continue
		}
		findings = append(findings, *finding)
		status := "ok"
		if finding.Leaked {
			status = "LEAK"
		}
		fmt.Printf("  [%s] %s%s\n", status, finding.Kind, detailSuffix(finding.Detail))
	}

	// Only the SessionIsolation category is meaningful here — no
	// fingerprint/network data was collected in this command, so the other
	// three categories score a default 100 (no evidence against them).
	analysis, err := (analyzer.RuleScorer{}).Score(analyzer.Input{LeakFindings: findings})
	if err != nil {
		return fmt.Errorf("analyze: %w", err)
	}
	fmt.Printf("session isolation score: %.1f/100\n", analysis.CategoryScores[analyzer.CategorySessionIsolation])

	leakReport := report.Leak{Findings: findings, Analysis: analysis}

	out, err := json.MarshalIndent(leakReport, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal findings: %w", err)
	}

	if cfg.OutputJSON != "" {
		if err := os.WriteFile(cfg.OutputJSON, out, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", cfg.OutputJSON, err)
		}
		fmt.Printf("wrote leak test report to %s\n", cfg.OutputJSON)
	} else {
		fmt.Println(string(out))
	}

	return nil
}

func detailSuffix(detail string) string {
	if detail == "" {
		return ""
	}
	return " (" + detail + ")"
}

func cmdCompare(args []string) {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	baseline := fs.String("baseline", "", "path to baseline JSON report (from `run --out-json`)")
	target := fs.String("target", "", "path to target JSON report (from `run --out-json`)")
	outHTML := fs.String("out-html", "", "path to write diff HTML dashboard")
	fs.Parse(args)

	if *baseline == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "compare requires --baseline and --target")
		os.Exit(1)
	}

	if err := runCompare(*baseline, *target, *outHTML); err != nil {
		fmt.Fprintf(os.Stderr, "compare failed: %v\n", err)
		os.Exit(1)
	}
}

func runCompare(baselinePath, targetPath, outHTML string) error {
	baseline, err := report.LoadRun(baselinePath)
	if err != nil {
		return fmt.Errorf("loading baseline: %w", err)
	}
	target, err := report.LoadRun(targetPath)
	if err != nil {
		return fmt.Errorf("loading target: %w", err)
	}

	diff := comparer.Compare(baseline, target)

	fmt.Printf("baseline stealth score: %.1f/100\n", diff.BaselineScore)
	fmt.Printf("target stealth score:   %.1f/100\n", diff.TargetScore)
	fmt.Printf("delta: %+.1f\n", diff.ScoreDelta)
	for _, c := range diff.Categories {
		fmt.Printf("  %-22s baseline=%.1f target=%.1f delta=%+.1f\n", c.Category, c.Baseline, c.Target, c.Delta)
	}
	if len(diff.FlagsAdded) > 0 {
		fmt.Println("flags only in target (new/regressed):")
		for _, f := range diff.FlagsAdded {
			fmt.Printf("  [%s] %s: %s\n", f.Category, f.Code, f.Description)
		}
	}
	if len(diff.FlagsRemoved) > 0 {
		fmt.Println("flags only in baseline (fixed/improved):")
		for _, f := range diff.FlagsRemoved {
			fmt.Printf("  [%s] %s: %s\n", f.Category, f.Code, f.Description)
		}
	}

	if outHTML != "" {
		html, err := dashboard.RenderCompare(diff)
		if err != nil {
			return fmt.Errorf("rendering dashboard: %w", err)
		}
		if err := os.WriteFile(outHTML, html, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", outHTML, err)
		}
		fmt.Printf("wrote diff dashboard to %s\n", outHTML)
	}

	return nil
}

func cmdListDrivers() {
	fmt.Println("supported drivers (adapters land starting Phase 1-3):")
	fmt.Println("  -", orchestrator.DriverPlaywright)
	fmt.Println("  -", orchestrator.DriverPuppeteer)
	fmt.Println("  -", orchestrator.DriverSelenium)
}
