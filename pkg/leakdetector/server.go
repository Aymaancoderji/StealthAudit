package leakdetector

import (
	"fmt"
	"net"
	"net/http"
)

// sharedWorkerScript keeps a single in-memory value shared by every port
// connected to this SharedWorker instance. Two pages that are supposed to
// be isolated (separate profiles/contexts) should each get their own
// worker instance; if they instead observe each other's value, that's a
// leak across the isolation boundary.
const sharedWorkerScript = `
let store = null;
onconnect = (e) => {
  const port = e.ports[0];
  port.onmessage = (ev) => {
    const msg = ev.data || {};
    if (msg.type === 'set') {
      store = msg.value;
      port.postMessage({ ok: true });
    } else if (msg.type === 'get') {
      port.postMessage({ value: store });
    }
  };
  port.start();
};
`

// serviceWorkerScript intercepts fetches to /sw-marker and answers with
// whatever value was last pushed to it via postMessage, instead of letting
// the request reach the server. A second, supposedly isolated context
// fetching /sw-marker and getting back the first context's value (instead
// of the server's own "server-default" response) means the two contexts
// share a service worker instance/registration.
const serviceWorkerScript = `
let marker = null;
self.addEventListener('install', () => { self.skipWaiting(); });
self.addEventListener('activate', (e) => { e.waitUntil(self.clients.claim()); });
self.addEventListener('message', (e) => {
  const msg = e.data || {};
  if (msg.type === 'set') {
    marker = msg.value;
    if (e.ports && e.ports[0]) e.ports[0].postMessage({ ok: true });
  }
});
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.pathname === '/sw-marker') {
    e.respondWith(new Response(marker !== null ? marker : 'server-default'));
  }
});
`

const indexPage = `<!doctype html>
<title>stealthaudit leak test origin</title>
<p>stealthaudit session isolation test page.</p>
`

// Server is a plain local HTTP origin that leak tests point sessions at.
// Service workers are permitted over plain HTTP on loopback addresses per
// the "potentially trustworthy origin" exception, so no TLS is needed here
// (unlike pkg/network's probe, which specifically needs a TLS handshake to
// inspect).
type Server struct {
	listener net.Listener
	server   *http.Server
}

// Start begins serving and returns the origin's base URL.
func (s *Server) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("leakdetector server: listen: %w", err)
	}
	s.listener = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(indexPage))
	})
	mux.HandleFunc("/shared-worker.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Write([]byte(sharedWorkerScript))
	})
	mux.HandleFunc("/service-worker.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Write([]byte(serviceWorkerScript))
	})
	mux.HandleFunc("/sw-marker", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("server-default"))
	})

	s.server = &http.Server{Handler: mux}
	go s.server.Serve(ln)

	return fmt.Sprintf("http://%s/", ln.Addr().String()), nil
}

// Stop shuts down the server.
func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}
