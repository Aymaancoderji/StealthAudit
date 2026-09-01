package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Aymaancoderji/StealthAudit/pkg/analyzer"
	"github.com/Aymaancoderji/StealthAudit/pkg/collector"
	"github.com/Aymaancoderji/StealthAudit/pkg/mlmodel"
	"github.com/Aymaancoderji/StealthAudit/pkg/network"
	"github.com/Aymaancoderji/StealthAudit/pkg/report"
)

// indexTmpl is a single-page, fingerprint.com-style demo: it runs audit.js
// directly in whatever real browser opens the page (no orchestrator/Session
// involved), then renders the scored result client-side. The point is to
// let you see what a genuine, non-automated browser's baseline looks like,
// and to sanity-check the collector script by hand.
var indexTmpl = template.Must(template.New("index").Parse(indexHTML))

// serveState holds the single most recently collected fingerprint. `serve`
// is a single-user local tool, so one slot (rather than per-session
// tracking) is enough.
type serveState struct {
	mu          sync.Mutex
	fingerprint *collector.Fingerprint
	collectedAt time.Time
}

// maxVisitHistory caps how many past-visit timestamps are kept per visitor,
// so the store doesn't grow unbounded for a visitor that reloads often.
const maxVisitHistory = 25

// maxCollectBodyBytes bounds how large a /api/collect request body can be,
// since it's decoded straight into memory as JSON.
const maxCollectBodyBytes = 1 << 20 // 1 MiB

// visitorRecord is what's persisted per stable visitor ID.
type visitorRecord struct {
	Count     int         `json:"count"`
	FirstSeen time.Time   `json:"firstSeen"`
	LastSeen  time.Time   `json:"lastSeen"`
	Visits    []time.Time `json:"visits,omitempty"`
}

// visitorStore recognizes returning visitors purely from stable fingerprint
// signals (no cookies), the same trick real fingerprinting vendors use, and
// persists counts to disk so "you've been here N times" survives restarts.
type visitorStore struct {
	mu      sync.Mutex
	path    string
	records map[string]*visitorRecord
}

func loadVisitorStore() *visitorStore {
	s := &visitorStore{records: map[string]*visitorRecord{}}
	if home, err := os.UserHomeDir(); err == nil {
		s.path = filepath.Join(home, ".stealthaudit", "visitors.json")
	}
	if s.path == "" {
		return s
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return s
	}
	_ = json.Unmarshal(data, &s.records)
	return s
}

// touch records a visit and reports whether this visitor ID has been seen
// before.
func (s *visitorStore) touch(visitorID string) (rec visitorRecord, isNew bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	r, ok := s.records[visitorID]
	if !ok {
		r = &visitorRecord{FirstSeen: now}
		s.records[visitorID] = r
	}
	r.Count++
	r.LastSeen = now
	r.Visits = append(r.Visits, now)
	if len(r.Visits) > maxVisitHistory {
		r.Visits = r.Visits[len(r.Visits)-maxVisitHistory:]
	}
	s.save()
	return *r, !ok
}

// peek reports a visitor's current record without incrementing the count,
// for re-fetching the report after the TLS probe step without inflating
// the visit count.
func (s *visitorStore) peek(visitorID string) (rec visitorRecord, found bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[visitorID]
	if !ok {
		return visitorRecord{}, false
	}
	return *r, true
}

// save writes the store to disk. Caller must hold s.mu. It writes to a
// temp file and renames into place so a crash or power loss mid-write
// can't leave visitors.json truncated or corrupted.
func (s *visitorStore) save() {
	if s.path == "" {
		return
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	data, err := json.MarshalIndent(s.records, "", "  ")
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".visitors-*.json.tmp")
	if err != nil {
		return
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
	}
}

// computeVisitorID derives a stable identifier from fingerprint signals
// that survive cookie/storage clearing and don't depend on IP: the same
// approach real fingerprinting products use to recognize returning
// visitors without any client-side state.
func computeVisitorID(fp *collector.Fingerprint) string {
	var parts []string
	parts = append(parts, fp.UserAgent)
	if fp.WebGL != nil {
		parts = append(parts, fp.WebGL.UnmaskedVendor, fp.WebGL.UnmaskedRenderer)
	}
	if fp.Canvas != nil {
		parts = append(parts, fp.Canvas.Hash)
	}
	if fp.Audio != nil {
		parts = append(parts, fp.Audio.Hash)
	}
	if fp.Device != nil {
		parts = append(parts,
			fmt.Sprint(fp.Device.ScreenWidth), fmt.Sprint(fp.Device.ScreenHeight),
			fmt.Sprint(fp.Device.ColorDepth), fmt.Sprint(fp.Device.HardwareConcurrency),
			fmt.Sprintf("%v", fp.Device.DeviceMemory), strings.Join(fp.Device.Fonts, ","))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", 8765, "port to serve the local fingerprint test page on")
	fs.Parse(args)

	if err := runServe(*port); err != nil {
		fmt.Fprintf(os.Stderr, "serve failed: %v\n", err)
		os.Exit(1)
	}
}

func runServe(port int) error {
	netServer := network.NewServer()
	probeURL, err := netServer.Start()
	if err != nil {
		return fmt.Errorf("starting network probe server: %w", err)
	}
	defer netServer.Stop()

	state := &serveState{}
	visitors := loadVisitorStore()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		indexTmpl.Execute(w, map[string]any{
			"ProbeURL":    probeURL,
			"AuditScript": template.JS(collector.AuditScript()),
		})
	})

	// buildReport assembles the combined {report, visitor} JSON payload the
	// front end renders. touchVisit controls whether this call counts as a
	// new visit (POST /api/collect) or just re-reads the current one (GET
	// /api/report, used to refresh in the TLS/HTTP2 data after the probe
	// step).
	buildReport := func(fp *collector.Fingerprint, collectedAt time.Time, touchVisit bool) (map[string]any, error) {
		netCapture := netServer.Latest()
		analysis, err := (analyzer.RuleScorer{}).Score(analyzer.Input{Fingerprint: fp, Network: netCapture})
		if err != nil {
			return nil, err
		}

		visitorID := computeVisitorID(fp)
		var rec visitorRecord
		var isNew bool
		if touchVisit {
			rec, isNew = visitors.touch(visitorID)
		} else {
			var found bool
			rec, found = visitors.peek(visitorID)
			if !found {
				rec, isNew = visitors.touch(visitorID)
			}
		}

		rep := &report.Run{
			Fingerprint: fp,
			Network:     netCapture,
			Analysis:    analysis,
			ML:          mlmodel.Classify(fp, netCapture),
			GeneratedAt: collectedAt.UTC().Format(time.RFC3339),
		}

		visits := make([]string, 0, len(rec.Visits))
		for _, t := range rec.Visits {
			visits = append(visits, t.UTC().Format(time.RFC3339))
		}

		return map[string]any{
			"report": rep,
			"visitor": map[string]any{
				"id":        visitorID,
				"shortId":   strings.ToUpper(visitorID[:8]),
				"count":     rec.Count,
				"isNew":     isNew,
				"firstSeen": rec.FirstSeen.UTC().Format(time.RFC3339),
				"lastSeen":  rec.LastSeen.UTC().Format(time.RFC3339),
				"visits":    visits,
			},
		}, nil
	}

	mux.HandleFunc("/api/collect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxCollectBodyBytes)
		var fp collector.Fingerprint
		if err := json.NewDecoder(r.Body).Decode(&fp); err != nil {
			http.Error(w, fmt.Sprintf("decoding fingerprint: %v", err), http.StatusBadRequest)
			return
		}
		now := time.Now()
		state.mu.Lock()
		state.fingerprint = &fp
		state.collectedAt = now
		state.mu.Unlock()

		payload, err := buildReport(&fp, now, true)
		if err != nil {
			http.Error(w, fmt.Sprintf("analyze: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
	})

	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		fp := state.fingerprint
		collectedAt := state.collectedAt
		state.mu.Unlock()

		if fp == nil {
			http.Error(w, "no fingerprint collected yet", http.StatusNotFound)
			return
		}

		payload, err := buildReport(fp, collectedAt, false)
		if err != nil {
			http.Error(w, fmt.Sprintf("analyze: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Printf("stealthaudit serve: open http://%s/ in a real browser to test its fingerprint\n", addr)
	fmt.Printf("  (TLS/HTTP2 probe listening separately at %s)\n", probeURL)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return srv.ListenAndServe()
}
