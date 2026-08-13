// Package network defines the TLS/HTTP2 fingerprint capture contract.
// A local server intercepts browser requests (via the session's configured
// proxy) and records low-level transport characteristics that JS cannot see.
package network

// TLSFingerprint captures ClientHello-derived identifiers.
type TLSFingerprint struct {
	JA3  string `json:"ja3"`
	JA4  string `json:"ja4"`
}

// HTTP2Fingerprint captures HTTP/2 framing and header-order characteristics.
type HTTP2Fingerprint struct {
	SettingsFrame  map[string]uint32 `json:"settingsFrame"`
	HeaderOrder    []string          `json:"headerOrder"`
	PseudoHeaders  []string          `json:"pseudoHeaders"` // e.g. :method, :path, :authority, :scheme
}

// Capture is one intercepted request's transport-level fingerprint,
// keyed by the session/request ID that produced it.
type Capture struct {
	SessionID string            `json:"sessionId"`
	TLS       *TLSFingerprint   `json:"tls,omitempty"`
	HTTP2     *HTTP2Fingerprint `json:"http2,omitempty"`
}

// Interceptor runs a local server that browser sessions route traffic
// through, and records transport-level fingerprints per session.
type Interceptor interface {
	// Start begins listening and returns the local proxy/server address
	// sessions should be configured to use.
	Start() (addr string, err error)

	// Captures returns fingerprints recorded so far, keyed by session ID.
	Captures() map[string]*Capture

	// Stop shuts down the listener.
	Stop() error
}
