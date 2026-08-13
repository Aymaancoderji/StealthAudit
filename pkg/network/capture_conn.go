package network

import "net"

// maxClientHelloCapture caps how many bytes captureConn will buffer while
// looking for a complete ClientHello record, guarding against a
// misbehaving/malicious client that never sends a well-formed TLS record.
const maxClientHelloCapture = 1 << 16

// captureConn wraps an accepted connection so the raw bytes of the first
// TLS record (the ClientHello) can be recovered after crypto/tls has
// consumed them from the stream. It's a transparent passthrough — reads
// are serviced normally: only the capturing bookkeeping is disabled once
// the record is complete.
//
// This assumes the ClientHello fits in a single TLS record, true for the
// overwhelming majority of real browsers; pathologically large
// ClientHellos spanning multiple records won't be captured.
type captureConn struct {
	net.Conn
	recorded []byte
	done     bool
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.done {
		c.recorded = append(c.recorded, p[:n]...)
		if len(c.recorded) >= 5 {
			recLen := int(c.recorded[3])<<8 | int(c.recorded[4])
			if len(c.recorded) >= 5+recLen {
				c.done = true
			}
		}
		if len(c.recorded) > maxClientHelloCapture {
			c.done = true
		}
	}
	return n, err
}
