package network

import (
	"bufio"
	"fmt"
	"net"
	"time"
)

// serveHTTP1 handles the (uncommon, for modern browsers) case where TLS
// ALPN negotiated http/1.1 instead of h2. There's no HTTP/2 framing to
// capture here — the TLS ClientHello capture already happened regardless
// of ALPN outcome — this just answers the request so the browser's
// navigation completes instead of hanging.
func serveHTTP1(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	// Drain the request line + headers without needing them for anything.
	for {
		line, err := r.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	body := "stealthaudit network probe\n"
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}
