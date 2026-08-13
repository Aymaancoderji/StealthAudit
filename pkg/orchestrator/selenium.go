package orchestrator

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	selrunner "github.com/Aymaancoderji/StealthAudit/runners/selenium"
)

// SeleniumAdapter launches sessions by spawning a Python process running
// the embedded Selenium runner script (runners/selenium/session.py) and
// speaking newline-delimited JSON over its stdin/stdout, mirroring the
// protocol used by the Node-based adapters.
type SeleniumAdapter struct {
	// PythonBin overrides the Python executable used to run the runner
	// script. Defaults to looking up "python3" then "python" on PATH.
	PythonBin string
}

func (a *SeleniumAdapter) Name() Driver { return DriverSelenium }

func (a *SeleniumAdapter) SupportedBrowsers() []Browser {
	return []Browser{BrowserChromium, BrowserFirefox}
}

func (a *SeleniumAdapter) Launch(ctx context.Context, opts LaunchOptions) (Session, error) {
	const label = "selenium adapter"

	pythonBin := a.PythonBin
	if pythonBin == "" {
		var err error
		pythonBin, err = exec.LookPath("python3")
		if err != nil {
			pythonBin, err = exec.LookPath("python")
			if err != nil {
				return nil, fmt.Errorf("%s: no python3/python executable found on PATH: %w", label, err)
			}
		}
	}

	if err := checkPythonModule(pythonBin, "selenium"); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}

	scriptPath, err := writeEmbeddedScript("sel", selrunner.Script)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}

	cmd := exec.CommandContext(ctx, pythonBin, scriptPath)

	launchParams := map[string]any{
		"browser":           string(opts.Browser),
		"headless":          opts.Headless,
		"proxyURL":          opts.ProxyURL,
		"userAgent":         opts.UserAgent,
		"stealthPlugin":     opts.StealthPlugin,
		"extraArgs":         opts.ExtraArgs,
		"ignoreHTTPSErrors": opts.IgnoreHTTPSErrors,
	}

	// Prefer explicit, version-matched browser/driver binaries over
	// whatever's on PATH: system package managers install chromedriver and
	// Chrome independently, and a version skew between them makes the
	// driver fail to connect. Reuse the Chrome for Testing build Puppeteer
	// already downloaded (runners/puppeteer's chrome + a chromedriver
	// fetched to match it via `npx @puppeteer/browsers install chromedriver@<ver>`).
	if bin := os.Getenv("STEALTHAUDIT_CHROME_BIN"); bin != "" {
		launchParams["chromeBinary"] = bin
	} else if home, err := os.UserHomeDir(); err == nil {
		if matches, _ := filepath.Glob(filepath.Join(home, ".cache", "puppeteer", "chrome", "*", "chrome-linux64", "chrome")); len(matches) > 0 {
			launchParams["chromeBinary"] = matches[len(matches)-1]
		}
	}
	if bin := os.Getenv("STEALTHAUDIT_CHROMEDRIVER_BIN"); bin != "" {
		launchParams["chromedriverBinary"] = bin
	} else if bin := findLatestGlobMatch("puppeteer", filepath.Join("chromedriver", "*", "chromedriver-linux64", "chromedriver")); bin != "" {
		launchParams["chromedriverBinary"] = bin
	}

	// Prefer Playwright's downloaded Firefox + a standalone geckodriver
	// binary (runners/selenium/bin) over whatever's on PATH: on systems
	// where firefox/geckodriver are snap packages, invoking them repeatedly
	// spawns them under snap confinement, which can take far longer to
	// become connectable than Selenium's internal service-start timeout
	// allows — an environment quirk, not a version mismatch, but a
	// standalone binary sidesteps it entirely.
	if bin := os.Getenv("STEALTHAUDIT_FIREFOX_BIN"); bin != "" {
		launchParams["firefoxBinary"] = bin
	} else if home, err := os.UserHomeDir(); err == nil {
		if matches, _ := filepath.Glob(filepath.Join(home, ".cache", "ms-playwright", "firefox-*", "firefox", "firefox")); len(matches) > 0 {
			launchParams["firefoxBinary"] = matches[len(matches)-1]
		}
	}
	if bin := os.Getenv("STEALTHAUDIT_GECKODRIVER_BIN"); bin != "" {
		launchParams["geckodriverBinary"] = bin
	} else if bin := findLatestGlobMatch("selenium", filepath.Join("bin", "geckodriver")); bin != "" {
		launchParams["geckodriverBinary"] = bin
	} else if bin, err := exec.LookPath("geckodriver"); err == nil {
		launchParams["geckodriverBinary"] = bin
	}

	return startProcessSession(ctx, label, cmd, launchParams)
}

// checkPythonModule runs a quick `import <module>` to fail fast with a
// clear message rather than a confusing pipe-closed error from the runner.
func checkPythonModule(pythonBin, module string) error {
	cmd := exec.Command(pythonBin, "-c", "import "+module)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf(
			"python module %q not importable via %s (%v); install it with "+
				"`pip3 install -r runners/selenium/requirements.txt`\n%s",
			module, pythonBin, err, string(out))
	}
	return nil
}

var _ BrowserAdapter = (*SeleniumAdapter)(nil)
