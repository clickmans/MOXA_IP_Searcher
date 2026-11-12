package discovery

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// portAXOM is the AXOM discovery port used by MXConfigCS for the WIFI6 /
// AWK-1161 product family (PROTOCOL_SPEC.md §1).
const portAXOM = 40404

// AXOM frame constants (PROTOCOL_SPEC.md §4).
const (
	// axomRequestLen is the fixed request length in bytes.
	axomRequestLen = 40
	// axomTLVOffset is where the TLV sequence starts in a reply. The 40 byte
	// prefix is magic(4) + len(1) + pad(3) + type(4) + bodyLen(4) + seq(4) +
	// nonceLen(4) + nonce(16).
	axomTLVOffset = 40
	// axomMaxTLVLen guards the parser against a corrupted length field.
	axomMaxTLVLen = 4096
)

// AXOM TLV type codes. The type field is big endian, the length field that
// follows it is LITTLE endian - verified against the capture fixture in
// _analysis/decode_fixtures.py where `20 00 00 00` means 32 bytes of host name.
// PROTOCOL_SPEC.md §4.2 labels both fields as BE32; the fixture contradicts
// that for the length field, so the fixture wins.
const (
	axomTypeName        = 0x34000001 // host name, NUL padded
	axomTypeIP          = 0x10000001 // device IPv4, 4 bytes
	axomTypeMAC         = 0x33000001 // device MAC, 6 bytes
	axomTypeSerial      = 0x32000001 // device serial number (plain ASCII)
	axomTypeFirmware    = 0x36001000 // firmware version text (see decodeAXOMHexText)
	axomTypeDescription = 0x37000001 // device description text
	axomTypeLocation    = 0x38000001 // device location text
)

// axomFirmwareMaxLen guards the hex decoder against an absurd payload.
const axomFirmwareMaxLen = 512

// axomNonceSeq makes every generated nonce unique inside one process run.
var axomNonceSeq uint64

// protocolAXOM describes the UDP/40404 AXOM discovery protocol.
func protocolAXOM() *protocolSpec {
	return &protocolSpec{
		Port:       portAXOM,
		Name:       ProtoNameAXOM,
		ListenPort: 0,
		Build:      buildAXOMRequests,
		Parse:      parseAXOMFallback,
	}
}

// axomRequestTypes holds the bytes at [8:12] of the request. Two dialects are in
// the field and MXConfigCS sends both (verified in _analysis/axom_request_types.py):
//
//	00 08 01 07 - WIFI 6 family (AWK-1161C, EOM-106); reply is 132 B and echoes 07
//	00 08 01 01 - EDS-G4012 and other newer switches; reply is 136 B and echoes 01
//
// A device only answers the dialect it implements: replaying the captured
// requests against a live EDS-G4012 gave 2 replies for ...01 and 0 replies for
// ...07, byte for byte otherwise identical (see _analysis/replay_g4000.py).
// Sending both costs 40 bytes per adapter and reply duplicates are merged by
// (MAC, IP) in the aggregator.
var axomRequestTypes = [][4]byte{
	{0x00, 0x08, 0x01, 0x07},
	{0x00, 0x08, 0x01, 0x01},
}

// buildAXOMRequests renders the 40 byte AXOM requests - one per dialect.
//
// Layout (PROTOCOL_SPEC.md §4.1):
//
//	[0:4]   = "AXOM"
//	[4]     = 0x20              total length - 8
//	[8:12]  = request type      see axomRequestTypes
//	[12:16] = 24 (LE32)         number of bytes starting at offset 16
//	[16:20] = sequence number   echoed by the device
//	[20:24] = 16 (LE32)         nonce length
//	[24:40] = 16 byte nonce     echoed by the device
func buildAXOMRequests(ac adapterCtx) [][]byte {
	nonce := axomNonce(ac)
	requests := make([][]byte, 0, len(axomRequestTypes))
	for _, requestType := range axomRequestTypes {
		req := make([]byte, axomRequestLen)
		copy(req[0:4], []byte("AXOM"))
		req[4] = axomRequestLen - 8
		copy(req[8:12], requestType[:])
		binary.LittleEndian.PutUint32(req[12:16], 24)
		copy(req[16:20], []byte{0x00, 0x00, 0x00, 0x01})
		binary.LittleEndian.PutUint32(req[20:24], 16)
		copy(req[24:40], nonce)
		requests = append(requests, req)
	}
	return requests
}

// axomNonce derives a 16 byte nonce that is unique per request.
func axomNonce(ac adapterCtx) []byte {
	nonce := make([]byte, 16)
	seq := atomic.AddUint64(&axomNonceSeq, 1)
	now := uint64(time.Now().UnixNano())
	binary.BigEndian.PutUint64(nonce[0:8], now)
	binary.BigEndian.PutUint64(nonce[8:16], seq<<16|uint64(len(ac.Name)))
	return nonce
}

// parseAXOMFallback adapts parseAXOM to the protocolSpec signature.
func parseAXOMFallback(payload []byte, _ net.IP) (*Device, bool) {
	return parseAXOM(payload)
}

// ParseAXOM decodes a 132 byte AXOM reply (exported for the unit tests).
func ParseAXOM(payload []byte) (*Device, bool) { return parseAXOM(payload) }

// parseAXOM walks the TLV sequence of an AXOM reply.
//
// Every TLV is `type(BE32) | len(LE32) | value(len)` and each TLV starts on a
// 4 byte boundary, therefore short values are padded (the 6 byte MAC is
// followed by two zero bytes). Fixed offsets are never used because the TLV
// order is not guaranteed across firmware versions.
func parseAXOM(payload []byte) (*Device, bool) {
	if len(payload) < axomTLVOffset+8 {
		return nil, false
	}
	if string(payload[0:4]) != "AXOM" {
		return nil, false
	}

	var (
		ipText      string
		macText     string
		hostName    string
		firmware    string
		serial      string
		description string
		location    string
	)
	off := axomTLVOffset
	for off+8 <= len(payload) {
		typ := binary.BigEndian.Uint32(payload[off : off+4])
		length := binary.LittleEndian.Uint32(payload[off+4 : off+8])
		if length > axomMaxTLVLen || int(length) > len(payload)-(off+8) {
			break // malformed frame, keep what we already decoded
		}
		value := payload[off+8 : off+8+int(length)]
		switch typ {
		case axomTypeName:
			hostName = fixedString(value)
		case axomTypeIP:
			if len(value) == 4 {
				if ip := net.IPv4(value[0], value[1], value[2], value[3]); ValidDeviceIP(ip) {
					ipText = ip.String()
				}
			}
		case axomTypeMAC:
			if len(value) >= 6 {
				macText = NormalizeMAC(value[:6])
			}
		case axomTypeFirmware:
			firmware = decodeAXOMHexText(value)
		case axomTypeSerial:
			// Kept for later use and never displayed. Plain ASCII on the models
			// seen so far; a binary serial degrades to its hex form.
			if text := axomTextValue(value); text != "" {
				serial = text
			} else {
				serial = hexUpper(value)
			}
		case axomTypeDescription:
			description = axomTextValue(value)
		case axomTypeLocation:
			location = axomTextValue(value)
		}
		next := off + 8 + int(length)
		if pad := length % 4; pad != 0 {
			next += int(4 - pad)
		}
		if next <= off {
			break
		}
		off = next
	}

	if ipText == "" {
		return nil, false
	}
	return &Device{
		IP:          ipText,
		MAC:         macText,
		Name:        hostName,
		Firmware:    firmware,
		Serial:      serial,
		Description: description,
		Location:    location,
		Protocol:    ProtoNameAXOM,
	}, true
}

// decodeAXOMHexText decodes a TLV value that carries a text string.
//
// Two encodings are accepted because both occur in the field:
//
//  1. HEX ENCODED ASCII - the form documented for 0x36001000, where
//     `56332e312e3130206275696c642032363130323931350a` is the string
//     "V3.1.10 build 26102915\n";
//  2. PLAIN ASCII - the form the EOM-106 firmware in the reference network
//     actually sends (verified with _analysis/ui_v11/probe_axom.py, where the
//     23 byte value literally reads "V3.1.10 build 26102915\n").
//
// The hex form is tried first and only accepted when it decodes to printable
// text, so a plain value that happens to look like hex ("abcd") is not mangled.
// Trailing CR/LF/blank characters are stripped; any other non printable byte
// makes the whole value unusable (returns ""): a half decoded string in the
// firmware column would be worse than an empty one.
func decodeAXOMHexText(value []byte) string {
	if len(value) == 0 || len(value) > axomFirmwareMaxLen {
		return ""
	}
	if text, ok := decodeAXOMHexPair(value); ok {
		return text
	}
	return strings.TrimSpace(plainAXOMText(value))
}

// decodeAXOMHexPair decodes a hex encoded ASCII value, reporting whether the
// value really was hex encoded printable text.
func decodeAXOMHexPair(value []byte) (string, bool) {
	if len(value) == 0 || len(value)%2 != 0 {
		return "", false
	}
	for _, c := range value {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			continue
		}
		return "", false
	}
	decoded := make([]byte, len(value)/2)
	if _, err := hex.Decode(decoded, value); err != nil {
		return "", false
	}
	for _, c := range decoded {
		if !isAXOMPrintable(c) {
			return "", false
		}
	}
	return strings.TrimSpace(string(decoded)), true
}

// plainAXOMText returns value as text up to the first NUL, or "" as soon as a
// non printable byte appears.
func plainAXOMText(value []byte) string {
	if idx := indexByte(value, 0); idx >= 0 {
		value = value[:idx]
	}
	for _, c := range value {
		if !isAXOMPrintable(c) {
			return ""
		}
	}
	return string(value)
}

// axomTextValue decodes a free text TLV (serial, description, location). Values
// with non printable bytes are cleaned instead of dropped, because these fields
// are only kept for later use and never displayed.
func axomTextValue(value []byte) string {
	if text := decodeAXOMHexText(value); text != "" {
		return text
	}
	return fixedString(value)
}

// isAXOMPrintable reports whether c may appear in a decoded text value:
// printable ASCII plus the whitespace that gets trimmed afterwards.
func isAXOMPrintable(c byte) bool {
	if c >= 0x20 && c <= 0x7e {
		return true
	}
	return c == '\t' || c == '\r' || c == '\n'
}

// hexUpper renders raw bytes as an upper case hex string.
func hexUpper(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const digits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0x0f]
	}
	return string(out)
}
