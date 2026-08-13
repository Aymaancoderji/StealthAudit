package network

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
)

// Server is the default Interceptor implementation: a local TLS server the
// audit flow points the browser at (as one deliberate extra navigation)
// to observe the raw TLS ClientHello and, when the browser negotiates h2
// via ALPN, the raw HTTP/2 SETTINGS frame and header order.
//
// It deliberately does not MITM-proxy arbitrary browser traffic to
// external sites: that would need a root CA generated and trusted inside
// the browser profile, and would show a TLS stack renegotiated through
// Go's crypto/tls rather than the browser's own — the opposite of what a
// TLS fingerprint audit wants to see. Pointing the browser at a
// self-issued probe endpoint (with certificate errors ignored for this
// audit session only) gets the real ClientHello with none of that.
type Server struct {
	listener net.Listener
	cert     tls.Certificate

	mu       sync.Mutex
	captures map[string]*Capture
	closed   chan struct{}
}

func NewServer() *Server {
	return &Server{
		captures: map[string]*Capture{},
		closed:   make(chan struct{}),
	}
}

// Start implements Interceptor. The returned address is an https:// URL
// suitable for a direct browser navigation.
func (s *Server) Start() (string, error) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return "", fmt.Errorf("network server: %w", err)
	}
	s.cert = cert

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("network server: listen: %w", err)
	}
	s.listener = ln

	go s.acceptLoop()

	return fmt.Sprintf("https://%s/probe", ln.Addr().String()), nil
}

func (s *Server) acceptLoop() {
	for {
		raw, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				continue
			}
		}
		go s.handleConn(raw)
	}
}

func (s *Server) handleConn(raw net.Conn) {
	defer raw.Close()

	sessionID := raw.RemoteAddr().String()
	capture := &Capture{SessionID: sessionID}

	cc := &captureConn{Conn: raw}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	tlsConn := tls.Server(cc, tlsConfig)

	if err := tlsConn.Handshake(); err != nil {
		// The ClientHello may still have been captured even if the
		// handshake itself didn't complete (e.g. the browser aborted on
		// seeing our untrusted cert before we finished); a partial
		// TLS-only capture is still useful.
		if ch, perr := parseClientHello(cc.recorded); perr == nil {
			capture.TLS = tlsFingerprintFrom(ch)
			s.store(sessionID, capture)
		}
		return
	}
	defer tlsConn.Close()

	if ch, err := parseClientHello(cc.recorded); err == nil {
		capture.TLS = tlsFingerprintFrom(ch)
	}

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		if res, err := probeHTTP2(tlsConn); err == nil {
			capture.HTTP2 = &HTTP2Fingerprint{
				SettingsFrame: res.Settings,
				HeaderOrder:   res.HeaderOrder,
				PseudoHeaders: res.PseudoHeaders,
			}
		}
	} else {
		serveHTTP1(tlsConn)
	}

	s.store(sessionID, capture)
}

func (s *Server) store(sessionID string, c *Capture) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.captures[sessionID] = c
}

// Captures implements Interceptor.
func (s *Server) Captures() map[string]*Capture {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]*Capture, len(s.captures))
	for k, v := range s.captures {
		out[k] = v
	}
	return out
}

// Latest returns the most recently stored capture, or nil if none yet.
// Convenience for the common single-session case; multi-session
// correlation is Phase 5's concern (leak detector needs real session
// identity, not just remote address).
func (s *Server) Latest() *Capture {
	s.mu.Lock()
	defer s.mu.Unlock()
	var latest *Capture
	for _, c := range s.captures {
		latest = c
	}
	return latest
}

// Stop implements Interceptor.
func (s *Server) Stop() error {
	close(s.closed)
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func tlsFingerprintFrom(ch *clientHello) *TLSFingerprint {
	_, ja3Hash := ja3(ch)
	return &TLSFingerprint{
		JA3: ja3Hash,
		JA4: ja4(ch),
	}
}

var _ Interceptor = (*Server)(nil)
