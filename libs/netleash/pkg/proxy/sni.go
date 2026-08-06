// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package proxy

import (
	"bufio"
	"errors"
	"strings"
)

// tlsHandshakeRecord is the TLS record content type for a handshake message
// (0x16). A transparently-redirected TLS connection begins with this byte,
// which is how the proxy tells a raw TLS client apart from an explicit HTTP
// proxy request (CONNECT / absolute-form GET) that begins with ASCII.
const tlsHandshakeRecord = 0x16

// maxClientHelloPeek bounds how many bytes the proxy will buffer to find the
// SNI in a ClientHello. A ClientHello almost always fits in a single TLS record
// (≤ 16 KiB); this covers the record header plus a full-size record with slack.
// The client's bufio.Reader is sized to this so Peek can return the whole
// ClientHello without consuming it (the bytes are replayed to the TLS server or
// the spliced upstream afterwards).
const maxClientHelloPeek = 18 * 1024

// errNoSNI is returned when a ClientHello carries no server_name extension (or
// could not be parsed). The proxy fails closed on it: without a hostname it
// cannot enforce the allow list on a transparently-redirected TLS connection.
var errNoSNI = errors.New("proxy: no SNI in ClientHello")

// sniffClientHelloSNI reads (via Peek, without consuming) the leading TLS
// handshake records from br and returns the server_name (SNI) from the
// ClientHello. The bytes stay buffered so the caller can either hand them to a
// tls.Server (MITM) or copy them to a spliced upstream unchanged. A ClientHello
// almost always fits in a single TLS record, but it may legally be fragmented
// across several; consecutive handshake records are reassembled (up to
// maxClientHelloPeek) so a spanning ClientHello still yields its SNI.
func sniffClientHelloSNI(br *bufio.Reader) (string, error) {
	// TLS record header: type(1) + version(2) + length(2).
	hdr, err := br.Peek(5)
	if err != nil {
		return "", err
	}
	if hdr[0] != tlsHandshakeRecord {
		return "", errNoSNI
	}

	var hs []byte // reassembled handshake payload (record bodies concatenated)
	off := 0      // bytes of the stream walked so far (record headers + bodies)
	for {
		// Peek the next record header at off.
		buf, err := br.Peek(off + 5)
		if len(buf) < off+5 {
			// Can't see another full record header (EOF, deadline, or the peek
			// buffer is exhausted): parse what has been assembled — the SNI sits
			// near the front of the ClientHello, so a truncated tail rarely
			// matters.
			if host, perr := parseSNIFromRecord(hs); perr == nil {
				return host, nil
			}
			if err == nil {
				err = errNoSNI
			}
			return "", err
		}
		if buf[off] != tlsHandshakeRecord {
			break // next record is not part of the handshake — stop reassembling
		}
		recordLen := int(buf[off+3])<<8 | int(buf[off+4])
		if recordLen == 0 {
			break
		}
		want := min(off+5+recordLen, maxClientHelloPeek)
		buf, err = br.Peek(want)
		if len(buf) > off+5 {
			hs = append(hs, buf[off+5:]...)
		}
		if err != nil || len(buf) < want || want >= maxClientHelloPeek {
			break // truncated record or peek budget exhausted — parse what we have
		}
		off = want

		// Stop once the ClientHello declared by the handshake header
		// (msg_type(1) + length(3)) is fully assembled. Peeking for another
		// record only happens while the handshake is still incomplete — the
		// client necessarily has more bytes in flight then, so the loop never
		// blocks waiting for data that will never arrive.
		if len(hs) >= 4 {
			hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if len(hs) >= 4+hsLen {
				break
			}
		}
	}
	return parseSNIFromRecord(hs)
}

// parseSNIFromRecord parses a TLS handshake payload (record bodies with the
// 5-byte record headers stripped and, if fragmented, concatenated) and extracts
// the SNI host_name from a ClientHello. It is deliberately strict about bounds
// and returns errNoSNI on any malformed or missing field rather than guessing.
func parseSNIFromRecord(b []byte) (string, error) {
	// Handshake header: msg_type(1) + length(3).
	if len(b) < 4 || b[0] != 0x01 { // 0x01 = ClientHello
		return "", errNoSNI
	}
	// The handshake body follows; its declared length may exceed what we buffered
	// (truncated tail) — parse against the bytes we actually have.
	body := b[4:]

	pos := 0
	// client_version(2) + random(32).
	if len(body) < 34 {
		return "", errNoSNI
	}
	pos += 34
	// session_id: 1-byte length + data.
	if pos >= len(body) {
		return "", errNoSNI
	}
	sidLen := int(body[pos])
	pos++
	pos += sidLen
	// cipher_suites: 2-byte length + data.
	if pos+2 > len(body) {
		return "", errNoSNI
	}
	csLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2 + csLen
	// compression_methods: 1-byte length + data.
	if pos+1 > len(body) {
		return "", errNoSNI
	}
	cmLen := int(body[pos])
	pos += 1 + cmLen
	// extensions: 2-byte length + data.
	if pos+2 > len(body) {
		return "", errNoSNI
	}
	extTotal := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	end := min(pos+extTotal, len(body)) // tolerate a truncated tail

	for pos+4 <= end {
		extType := int(body[pos])<<8 | int(body[pos+1])
		extLen := int(body[pos+2])<<8 | int(body[pos+3])
		pos += 4
		if pos+extLen > end {
			break
		}
		if extType == 0x0000 { // server_name
			return parseServerNameExtension(body[pos : pos+extLen])
		}
		pos += extLen
	}
	return "", errNoSNI
}

// parseServerNameExtension parses a server_name extension body and returns the
// first host_name (type 0). Structure: server_name_list length(2), then entries
// of name_type(1) + name length(2) + name.
func parseServerNameExtension(b []byte) (string, error) {
	if len(b) < 2 {
		return "", errNoSNI
	}
	listLen := int(b[0])<<8 | int(b[1])
	pos := 2
	end := min(pos+listLen, len(b))
	for pos+3 <= end {
		nameType := b[pos]
		nameLen := int(b[pos+1])<<8 | int(b[pos+2])
		pos += 3
		if pos+nameLen > end {
			break
		}
		if nameType == 0x00 { // host_name
			host := strings.ToLower(strings.TrimSuffix(string(b[pos:pos+nameLen]), "."))
			if host == "" {
				// A malformed empty host_name is unusable for allow-list
				// enforcement; fail closed instead of letting an allow-all
				// binding dial ":443" (i.e. the proxy host itself).
				return "", errNoSNI
			}
			return host, nil
		}
		pos += nameLen
	}
	return "", errNoSNI
}
