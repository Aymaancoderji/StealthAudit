package orchestrator

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// rpcMessage is the newline-delimited JSON protocol spoken with the Node
// runner scripts under runners/playwright and runners/puppeteer.
type rpcMessage struct {
	ID     int64           `json:"id"`
	Method string          `json:"method,omitempty"`
	Params map[string]any  `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// nodeSession is a Session backed by a spawned Node runner process talking
// rpcMessage lines over stdin/stdout. Both PlaywrightAdapter and
// PuppeteerAdapter use it — the runner scripts differ, but the transport
// and request/response framing are identical.
type nodeSession struct {
	adapterLabel string // for error messages, e.g. "playwright adapter"
	cmd          *exec.Cmd
	stdin        io.WriteCloser
	scanner      *bufio.Scanner
	nextID       atomic.Int64
	mu           sync.Mutex // serializes calls; the runner handles one request at a time anyway
}

// launchNodeSession writes the embedded runner script to a temp file,
// resolves node_modules for the given npm package, spawns node, and
// performs the initial "launch" RPC call.
func launchNodeSession(
	ctx context.Context,
	adapterLabel string,
	nodeBin string,
	scriptContent string,
	scriptCacheKey string,
	npmPackageName string,
	runnerSubdir string,
	launchParams map[string]any,
) (*nodeSession, error) {
	if nodeBin == "" {
		var err error
		nodeBin, err = exec.LookPath("node")
		if err != nil {
			return nil, fmt.Errorf("%s: node executable not found on PATH: %w", adapterLabel, err)
		}
	}

	scriptPath, err := writeEmbeddedScript(scriptCacheKey, scriptContent)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", adapterLabel, err)
	}

	nodeModulesDir, err := findNodeModules(runnerSubdir, npmPackageName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", adapterLabel, err)
	}

	cmd := exec.CommandContext(ctx, nodeBin, scriptPath)
	cmd.Dir = filepath.Dir(scriptPath)
	cmd.Env = append(os.Environ(), "NODE_PATH="+nodeModulesDir)

	return startProcessSession(ctx, adapterLabel, cmd, launchParams)
}

// startProcessSession spawns cmd, wires up its stdin/stdout for the
// rpcMessage protocol, and performs the initial "launch" RPC call. Used by
// both the Node runners (Playwright/Puppeteer) and the Python/Selenium
// runner — the transport is identical regardless of which interpreter is
// on the other end.
func startProcessSession(ctx context.Context, adapterLabel string, cmd *exec.Cmd, launchParams map[string]any) (*nodeSession, error) {
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("%s: stdin pipe: %w", adapterLabel, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%s: stdout pipe: %w", adapterLabel, err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%s: starting runner process: %w", adapterLabel, err)
	}

	s := &nodeSession{
		adapterLabel: adapterLabel,
		cmd:          cmd,
		stdin:        stdin,
		scanner:      bufio.NewScanner(stdout),
	}
	s.scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	if _, err := s.call(ctx, "launch", launchParams, nil); err != nil {
		s.cmd.Process.Kill()
		return nil, fmt.Errorf("%s: launch failed: %w", adapterLabel, err)
	}

	return s, nil
}

// candidateRunnerDirs lists the directories that might hold
// "runners/<subdir>" of the repo/release layout, in priority order:
//  1. STEALTHAUDIT_<SUBDIR>_DIR env var, if set (see envOverrideVar)
//  2. "runners/<subdir>" relative to the current working directory
//     (repo checkout / `go run` from the module root)
//  3. "runners/<subdir>" next to the running executable
func candidateRunnerDirs(runnerSubdir string) []string {
	var candidates []string
	if dir := os.Getenv(envOverrideVar(runnerSubdir)); dir != "" {
		candidates = append(candidates, dir)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "runners", runnerSubdir))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "runners", runnerSubdir))
	}
	return candidates
}

// findNodeModules locates the node_modules directory containing the given
// npm-installed package (browser binaries are large and not embeddable, so
// this is expected to live outside the compiled binary).
func findNodeModules(runnerSubdir, npmPackageName string) (string, error) {
	candidates := candidateRunnerDirs(runnerSubdir)
	for _, dir := range candidates {
		nm := filepath.Join(dir, "node_modules")
		if info, err := os.Stat(filepath.Join(nm, npmPackageName)); err == nil && info.IsDir() {
			return nm, nil
		}
	}
	return "", fmt.Errorf(
		"could not find node_modules/%s (checked %v); run `npm install` in runners/%s, or set %s",
		npmPackageName, candidates, runnerSubdir, envOverrideVar(runnerSubdir))
}

// findLatestGlobMatch returns the lexicographically-greatest match of
// pattern under each of candidateRunnerDirs(runnerSubdir), which for
// version-numbered directory names (e.g. chrome-linux64 downloads) is also
// the newest version. Returns "" if nothing matches anywhere.
func findLatestGlobMatch(runnerSubdir, relGlobPattern string) string {
	var best string
	for _, dir := range candidateRunnerDirs(runnerSubdir) {
		matches, err := filepath.Glob(filepath.Join(dir, relGlobPattern))
		if err != nil {
			continue
		}
		for _, m := range matches {
			if m > best {
				best = m
			}
		}
	}
	return best
}

func envOverrideVar(runnerSubdir string) string {
	switch runnerSubdir {
	case "playwright":
		return "STEALTHAUDIT_PLAYWRIGHT_DIR"
	case "puppeteer":
		return "STEALTHAUDIT_PUPPETEER_DIR"
	default:
		return "STEALTHAUDIT_" + runnerSubdir + "_DIR"
	}
}

// writeEmbeddedScript writes an embedded runner script to a temp directory
// once per (process, cacheKey), so a single compiled stealthaudit binary
// needs no external JS files on disk besides the npm-installed packages.
var (
	scriptCacheMu sync.Mutex
	scriptCache   = map[string]string{} // cacheKey -> written file path
)

func writeEmbeddedScript(cacheKey, content string) (string, error) {
	scriptCacheMu.Lock()
	defer scriptCacheMu.Unlock()

	if path, ok := scriptCache[cacheKey]; ok {
		return path, nil
	}

	dir, err := os.MkdirTemp("", "stealthaudit-"+cacheKey+"-runner-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "session.js")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	scriptCache[cacheKey] = path
	return path, nil
}

// call sends a request and blocks for the matching response. Since the
// runner processes one message at a time and this adapter issues one call
// at a time per session, responses are read in request order without
// needing an ID-multiplexing dispatcher.
func (s *nodeSession) call(ctx context.Context, method string, params map[string]any, out any) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextID.Add(1)
	req := rpcMessage{ID: id, Method: method, Params: params}
	line, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	line = append(line, '\n')

	if _, err := s.stdin.Write(line); err != nil {
		return nil, fmt.Errorf("writing to runner stdin: %w", err)
	}

	if !s.scanner.Scan() {
		if err := s.scanner.Err(); err != nil {
			return nil, fmt.Errorf("reading runner stdout: %w", err)
		}
		return nil, fmt.Errorf("runner process closed stdout unexpectedly")
	}

	var resp rpcMessage
	if err := json.Unmarshal(s.scanner.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("decoding runner response: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("runner error: %s", resp.Error)
	}
	if out != nil && resp.Result != nil {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return nil, fmt.Errorf("decoding runner result: %w", err)
		}
	}
	return resp.Result, nil
}

func (s *nodeSession) Navigate(ctx context.Context, url string) error {
	_, err := s.call(ctx, "navigate", map[string]any{"url": url}, nil)
	return err
}

func (s *nodeSession) Evaluate(ctx context.Context, script string, out any) error {
	_, err := s.call(ctx, "evaluate", map[string]any{"script": script}, out)
	return err
}

func (s *nodeSession) Close(ctx context.Context) error {
	_, err := s.call(ctx, "close", nil, nil)
	s.stdin.Close()
	waitErr := s.cmd.Wait()
	if err != nil {
		return err
	}
	if waitErr != nil {
		// Process exit after "close" is expected (runner calls process.exit(0)
		// itself); only surface unexpected non-zero exits.
		if exitErr, ok := waitErr.(*exec.ExitError); ok && exitErr.ExitCode() != 0 {
			return fmt.Errorf("runner process exited with error: %w", waitErr)
		}
	}
	return nil
}

var _ Session = (*nodeSession)(nil)
