package network

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// clientHello holds the fields extracted from a raw TLS ClientHello record
// that JA3/JA4 fingerprinting needs. Parsed directly from the wire bytes
// (rather than via crypto/tls's ClientHelloInfo) because JA3/JA4 both
// depend on the *raw ordered* extension list, which crypto/tls does not
// expose — it only surfaces already-categorized fields.
type clientHello struct {
	Version          uint16
	CipherSuites     []uint16
	Extensions       []uint16 // in wire order, as sent by the client
	SupportedGroups  []uint16
	ECPointFormats   []uint8
	SignatureAlgos   []uint16
	ALPNProtocols    []string
	ServerName       string
	SupportedVersion uint16 // highest version from the supported_versions extension, if present (TLS 1.3 clients)
}

const (
	extServerName         = 0
	extSupportedGroups    = 10
	extECPointFormats     = 11
	extSignatureAlgorithms = 13
	extALPN               = 16
	extSupportedVersions   = 43
)

// isGREASE reports whether v is one of the reserved GREASE values (RFC
// 8701) that Chromium/BoringSSL-derived clients insert at random positions
// in cipher suites, extensions, and supported groups specifically to
// prevent ossification. Left in, they'd make the fingerprint of a single
// real browser look different on every connection, which defeats the
// point of JA3/JA4 as a stable identifier — so, matching common modern
// JA3/JA4 implementations, they're filtered out below.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// parseClientHello parses a raw TLS record containing a ClientHello
// handshake message (as captured by captureConn before the record reaches
// crypto/tls). Only extension types relevant to JA3/JA4 are decoded in
// detail; unrecognized extensions still contribute their type ID to the
// Extensions list.
func parseClientHello(raw []byte) (*clientHello, error) {
	if len(raw) < 5 || raw[0] != 0x16 {
		return nil, errors.New("not a TLS handshake record")
	}
	recLen := int(binary.BigEndian.Uint16(raw[3:5]))
	if len(raw) < 5+recLen {
		return nil, errors.New("truncated TLS record")
	}
	body := raw[5 : 5+recLen]

	if len(body) < 4 || body[0] != 0x01 {
		return nil, errors.New("not a ClientHello handshake message")
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if len(body) < 4+hsLen {
		return nil, errors.New("truncated handshake message")
	}
	p := body[4 : 4+hsLen]

	r := &reader{buf: p}
	ch := &clientHello{}

	ch.Version = r.u16()
	r.skip(32) // random
	sidLen := r.u8()
	r.skip(int(sidLen))

	csLen := r.u16()
	cs := r.bytes(int(csLen))
	for i := 0; i+1 < len(cs); i += 2 {
		ch.CipherSuites = append(ch.CipherSuites, binary.BigEndian.Uint16(cs[i:i+2]))
	}

	cmLen := r.u8()
	r.skip(int(cmLen))

	if r.remaining() < 2 {
		if r.err != nil {
			return nil, r.err
		}
		return ch, nil // no extensions block (very old/minimal ClientHello)
	}
	extTotalLen := r.u16()
	extData := r.bytes(int(extTotalLen))
	er := &reader{buf: extData}
	for er.remaining() >= 4 {
		extType := er.u16()
		extLen := er.u16()
		extBody := er.bytes(int(extLen))
		ch.Extensions = append(ch.Extensions, extType)

		switch extType {
		case extServerName:
			ch.ServerName = parseSNI(extBody)
		case extSupportedGroups:
			gr := &reader{buf: extBody}
			listLen := gr.u16()
			list := gr.bytes(int(listLen))
			for i := 0; i+1 < len(list); i += 2 {
				ch.SupportedGroups = append(ch.SupportedGroups, binary.BigEndian.Uint16(list[i:i+2]))
			}
		case extECPointFormats:
			pr := &reader{buf: extBody}
			listLen := pr.u8()
			ch.ECPointFormats = append(ch.ECPointFormats, pr.bytes(int(listLen))...)
		case extSignatureAlgorithms:
			sr := &reader{buf: extBody}
			listLen := sr.u16()
			list := sr.bytes(int(listLen))
			for i := 0; i+1 < len(list); i += 2 {
				ch.SignatureAlgos = append(ch.SignatureAlgos, binary.BigEndian.Uint16(list[i:i+2]))
			}
		case extALPN:
			ar := &reader{buf: extBody}
			listLen := ar.u16()
			list := ar.bytes(int(listLen))
			lr := &reader{buf: list}
			for lr.remaining() > 0 {
				n := lr.u8()
				ch.ALPNProtocols = append(ch.ALPNProtocols, string(lr.bytes(int(n))))
			}
		case extSupportedVersions:
			vr := &reader{buf: extBody}
			listLen := vr.u8()
			list := vr.bytes(int(listLen))
			for i := 0; i+1 < len(list); i += 2 {
				v := binary.BigEndian.Uint16(list[i : i+2])
				if !isGREASE(v) && v > ch.SupportedVersion {
					ch.SupportedVersion = v
				}
			}
		}
	}

	if r.err != nil {
		return nil, r.err
	}
	return ch, nil
}

func parseSNI(extBody []byte) string {
	r := &reader{buf: extBody}
	listLen := r.u16()
	list := r.bytes(int(listLen))
	lr := &reader{buf: list}
	for lr.remaining() >= 3 {
		nameType := lr.u8()
		nameLen := lr.u16()
		name := lr.bytes(int(nameLen))
		if nameType == 0 { // host_name
			return string(name)
		}
	}
	return ""
}

// reader is a minimal bounds-checked byte cursor; any read past the end
// sets err and returns zero values, so callers can ignore the panic-prone
// bookkeeping and check err once at the end.
type reader struct {
	buf []byte
	pos int
	err error
}

func (r *reader) remaining() int { return len(r.buf) - r.pos }

func (r *reader) need(n int) bool {
	if r.err != nil || r.pos+n > len(r.buf) {
		if r.err == nil {
			r.err = fmt.Errorf("clienthello: unexpected end of data (need %d, have %d)", n, r.remaining())
		}
		return false
	}
	return true
}

func (r *reader) u8() uint8 {
	if !r.need(1) {
		return 0
	}
	v := r.buf[r.pos]
	r.pos++
	return v
}

func (r *reader) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos : r.pos+2])
	r.pos += 2
	return v
}

func (r *reader) bytes(n int) []byte {
	if n < 0 || !r.need(n) {
		return nil
	}
	v := r.buf[r.pos : r.pos+n]
	r.pos += n
	return v
}

func (r *reader) skip(n int) {
	r.bytes(n)
}

// ja3 computes the JA3 fingerprint (https://github.com/salesforce/ja3):
// md5("Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats")
// with each list dash-joined. GREASE values are excluded (see isGREASE).
func ja3(ch *clientHello) (string, string) {
	str := strings.Join([]string{
		strconv.Itoa(int(ch.Version)),
		joinUint16(filterGREASE(ch.CipherSuites)),
		joinUint16(filterGREASE(ch.Extensions)),
		joinUint16(filterGREASE(ch.SupportedGroups)),
		joinUint8(ch.ECPointFormats),
	}, ",")
	sum := md5.Sum([]byte(str))
	return str, hex.EncodeToString(sum[:])
}

// ja4 computes a best-effort JA4 fingerprint per the public FoxIO spec
// (https://github.com/FoxIO-LLC/ja4): a human-readable prefix (protocol,
// TLS version, SNI presence, cipher/extension counts, first ALPN value)
// followed by truncated SHA-256 hashes of the sorted cipher list and the
// sorted extension+signature-algorithm list.
func ja4(ch *clientHello) string {
	version := ch.Version
	if ch.SupportedVersion != 0 {
		version = ch.SupportedVersion
	}
	versionCode := ja4VersionCode(version)

	sni := "i"
	if ch.ServerName != "" {
		sni = "d"
	}

	ciphers := filterGREASE(ch.CipherSuites)
	// Extensions minus SNI/ALPN, per spec, since those are already
	// reflected elsewhere in the fingerprint.
	var exts []uint16
	for _, e := range filterGREASE(ch.Extensions) {
		if e == extServerName || e == extALPN {
			continue
		}
		exts = append(exts, e)
	}

	alpn := "00"
	if len(ch.ALPNProtocols) > 0 {
		first := ch.ALPNProtocols[0]
		if len(first) >= 2 {
			alpn = first[:2]
		} else if len(first) == 1 {
			alpn = first + "0"
		}
	}

	a := fmt.Sprintf("t%s%s%02d%02d%s", versionCode, sni, min(len(ciphers), 99), min(len(exts), 99), alpn)

	sortedCiphers := append([]uint16(nil), ciphers...)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	b := truncatedSHA256(joinUint16Hex(sortedCiphers))

	sortedExts := append([]uint16(nil), exts...)
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })
	sigAlgos := append([]uint16(nil), ch.SignatureAlgos...)
	cPart := joinUint16Hex(sortedExts)
	if len(sigAlgos) > 0 {
		cPart += "_" + joinUint16Hex(sigAlgos)
	}
	c := truncatedSHA256(cPart)

	return a + "_" + b + "_" + c
}

func ja4VersionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return "00"
	}
}

func truncatedSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	full := hex.EncodeToString(sum[:])
	if len(full) > 12 {
		return full[:12]
	}
	return full
}

func filterGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinUint16(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func joinUint16Hex(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func joinUint8(vs []uint8) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}
