package network

import (
	"crypto/tls"
	"fmt"
	"io"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// http2FramingResult is the raw framing-level data pulled off the wire —
// SETTINGS values and header order/pseudo-headers as the client actually
// sent them, which is exactly what net/http's Request abstraction throws
// away (it normalizes headers and synthesizes Method/URL/Host, discarding
// wire order). Pulling frames directly via http2.Framer/hpack.Decoder
// (the same low-level primitives net/http's own HTTP/2 transport is built
// on) is what lets this stay at the framing level instead.
type http2FramingResult struct {
	Settings      map[string]uint32
	HeaderOrder   []string
	PseudoHeaders []string
}

var http2SettingNames = map[http2.SettingID]string{
	http2.SettingHeaderTableSize:      "HEADER_TABLE_SIZE",
	http2.SettingEnablePush:           "ENABLE_PUSH",
	http2.SettingMaxConcurrentStreams: "MAX_CONCURRENT_STREAMS",
	http2.SettingInitialWindowSize:    "INITIAL_WINDOW_SIZE",
	http2.SettingMaxFrameSize:         "MAX_FRAME_SIZE",
	http2.SettingMaxHeaderListSize:    "MAX_HEADER_LIST_SIZE",
}

// probeHTTP2 speaks just enough of the HTTP/2 wire protocol, by hand, to
// capture the client's connection preface, its first SETTINGS frame, and
// the header block (in wire order) of its first HEADERS frame — then sends
// a minimal valid response so the browser's request/navigation completes
// normally instead of hanging. Only a single request/stream is handled,
// which is all the audit flow needs (the browser is pointed at this probe
// as one deliberate extra navigation, not general traffic).
func probeHTTP2(conn *tls.Conn) (*http2FramingResult, error) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return nil, fmt.Errorf("reading client preface: %w", err)
	}
	if string(preface) != http2.ClientPreface {
		return nil, fmt.Errorf("unexpected client preface: %q", preface)
	}

	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = nil // decode headers ourselves to preserve wire order

	// Per RFC 7540 §3.5, the client preface is immediately followed by a
	// SETTINGS frame from both sides.
	if err := framer.WriteSettings(); err != nil {
		return nil, fmt.Errorf("writing server settings: %w", err)
	}

	result := &http2FramingResult{Settings: map[string]uint32{}}
	var headerBlock []byte
	var streamID uint32

	decoder := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		result.HeaderOrder = append(result.HeaderOrder, f.Name)
		if len(f.Name) > 0 && f.Name[0] == ':' {
			result.PseudoHeaders = append(result.PseudoHeaders, f.Name)
		}
	})

	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return nil, fmt.Errorf("reading frame: %w", err)
		}

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			f.ForeachSetting(func(s http2.Setting) error {
				name := http2SettingNames[s.ID]
				if name == "" {
					name = fmt.Sprintf("UNKNOWN_%d", s.ID)
				}
				result.Settings[name] = s.Val
				return nil
			})
			if err := framer.WriteSettingsAck(); err != nil {
				return nil, fmt.Errorf("acking client settings: %w", err)
			}

		case *http2.HeadersFrame:
			streamID = f.StreamID
			headerBlock = append(headerBlock, f.HeaderBlockFragment()...)
			if f.HeadersEnded() {
				if _, err := decoder.Write(headerBlock); err != nil {
					return nil, fmt.Errorf("decoding headers: %w", err)
				}
				return result, respondHTTP2(framer, streamID)
			}

		case *http2.ContinuationFrame:
			headerBlock = append(headerBlock, f.HeaderBlockFragment()...)
			if f.HeadersEnded() {
				if _, err := decoder.Write(headerBlock); err != nil {
					return nil, fmt.Errorf("decoding headers: %w", err)
				}
				return result, respondHTTP2(framer, streamID)
			}

		case *http2.WindowUpdateFrame, *http2.PingFrame:
			// ignore; not relevant to fingerprinting

		default:
			// ignore other frame types (PRIORITY, etc.)
		}
	}
}

// respondHTTP2 sends a minimal valid 200 response so the browser's
// request/navigation completes instead of hanging waiting for a reply.
func respondHTTP2(framer *http2.Framer, streamID uint32) error {
	var hbuf []byte
	enc := hpack.NewEncoder(sliceWriter{&hbuf})
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "text/plain; charset=utf-8"})

	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: hbuf,
		EndHeaders:    true,
	}); err != nil {
		return err
	}
	body := []byte("stealthaudit network probe\n")
	return framer.WriteData(streamID, true, body)
}

type sliceWriter struct{ buf *[]byte }

func (w sliceWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}
