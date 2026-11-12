package discovery

import (
	"encoding/binary"
	"net"
)

// portWSU is the wireless discovery port used by the AWK WIFI4 family
// (PROTOCOL_SPEC.md §1 / §5).
const portWSU = 5800

// wsuListenPort is the local UDP port advertised inside the WSU request, the
// same port the official AWK tool binds. When it is already taken by another
// process the scanner falls back to an ephemeral port and advertises that one
// instead (PROTOCOL_SPEC.md §5.2).
const wsuListenPort = 15802

// WSU frame geometry (PROTOCOL_SPEC.md §5).
const (
	wsuRequestLen = 68
	// wsuReplyLen is the documented reply length of the AWK-1131A family.
	wsuReplyLen = 218
	// wsuReplyLenAWK1132C is the measured reply length of the AWK-1132C and of
	// the AWK-1137C: both frames are 16 bytes longer than the documented one
	// (234 bytes), and the extra bytes sit behind every field that is decoded
	// here (see _analysis/wifi4_frames.txt line 5 and _analysis/wifi_frames.txt
	// line 9). The length is deliberately NOT used as an acceptance criterion -
	// a reply of any length that passes the structural checks below is parsed.
	wsuReplyLenAWK1132C = 234
	// wsuMinReplyLen is the shortest frame that can still carry the decoded
	// fields; anything shorter cannot be a WSU reply.
	wsuMinReplyLen = 32
)

// Fixed offsets inside a WSU reply (PROTOCOL_SPEC.md §5.2, re-measured on the
// AWK-1131A and AWK-1132C captures).
const (
	// wsuFlagOffset is the BE16 marker at [2:4], always 0x0001 in a reply.
	wsuFlagOffset = 2
	// wsuLengthOffset is the BE32 sub frame length at [4:8].
	wsuLengthOffset = 4
	// wsuLengthBias is the constant distance between that field and the frame
	// end: [4:8] = len-36 (198 on the 234 byte AWK-1132C reply, 182 on a 218
	// byte reply).
	wsuLengthBias = 36
	// wsuBinaryMACOffset/wsuBinaryMACLen is the device MAC as 6 raw bytes.
	wsuBinaryMACOffset = 20
	wsuBinaryMACLen    = 6
	// wsuModelOffset/wsuModelLen is the model name as a 12 byte ASCII field
	// ("AWK-1131A-US", "AWK-1132C-US" are exactly 12 bytes).
	wsuModelOffset = 46
	wsuModelLen    = 12
	// wsuIPOffset/wsuIPLen is the device IPv4 address as ASCII.
	wsuIPOffset = 79
	wsuIPLen    = 16
	// wsuMACOffset/wsuMACLen is the device MAC as ASCII.
	wsuMACOffset = 95
	wsuMACLen    = 18
	// wsuMaskOffset/wsuMaskLen is the subnet mask as ASCII (not displayed).
	wsuMaskOffset = 113
	wsuMaskLen    = 14
)

// wsuReplyFlag is the value of the BE16 marker at [2:4] of every WSU reply.
const wsuReplyFlag = 0x0001

// WSU reply magic words: the first big endian word of the frame.
//
// Measured on hardware:
//
//	AWK-1131A  0x0DBD  (218 byte reply, _analysis/wifi_frames.txt line 6)
//	AWK-1132C  0x0DBF  (234 byte reply, _analysis/wifi4_frames.txt line 5)
//	AWK-1137C  0x1DBF  (234 byte reply, _analysis/wifi_frames.txt line 9)
//
// Two independent sources agree that the AWK-1137C starts with 0x1D instead of
// 0x0D: the vendor's own capture of the Wireless Search Utility
// (MAGIC_SEEN_FIRST_BYTES = (0x0D, 0x1D)) and the older WIFI4 tool. The high
// byte therefore identifies the frame *family* and the low byte the product,
// and the accepted set is a table instead of a single constant - both the
// AWK-1132C and the AWK-1137C were discarded silently by a strict == on
// 0x0DBD, which left the 产品型号 and 固件版本 columns empty.
const (
	// wsuMagicAWK1131A is the magic word of the 218 byte AWK-1131A reply.
	wsuMagicAWK1131A = 0x0DBD
	// wsuMagicAWK1132C is the magic word of the 234 byte AWK-1132C reply.
	wsuMagicAWK1132C = 0x0DBF
	// wsuMagicAWK1137C is the magic word of the 234 byte AWK-1137C reply.
	wsuMagicAWK1137C = 0x1DBF
	// wsuMagicAWK1137CBD is the second low byte of the 0x1D family. It was not
	// captured, but the low byte is what varies between firmware revisions of
	// the same family, so the whole low byte set is accepted for both high
	// bytes; the structural checks in parseWSU still gate the frame.
	wsuMagicAWK1137CBD = 0x1DBD
)

// wsuMagicHighBytes lists the accepted high bytes of a WSU reply magic: 0x0D
// for the older WIFI4 family, 0x1D for the AWK-1137C generation.
var wsuMagicHighBytes = [...]byte{
	wsuMagicAWK1131A >> 8,
	wsuMagicAWK1137C >> 8,
}

// wsuMagicLowBytes lists the accepted low bytes of a WSU reply magic.
var wsuMagicLowBytes = [...]byte{
	byte(wsuMagicAWK1131A & 0xFF),
	byte(wsuMagicAWK1132C & 0xFF),
}

// isWSUMagic reports whether v is a known WSU reply magic word.
//
// Both bytes are checked against the tables above, so neither "any high byte"
// nor "any low byte" can enter the parser by chance: 0x0DAA (unknown product),
// 0x2DBF (unknown family) and 0x0000 are rejected. A frame that passes this
// test still has to pass the structural checks in parseWSU.
func isWSUMagic(v uint16) bool {
	high, low := byte(v>>8), byte(v)
	knownHigh := false
	for _, candidate := range wsuMagicHighBytes {
		if high == candidate {
			knownHigh = true
			break
		}
	}
	if !knownHigh {
		return false
	}
	for _, candidate := range wsuMagicLowBytes {
		if low == candidate {
			return true
		}
	}
	return false
}

// protocolWSU describes the UDP/5800 WSU wireless discovery protocol.
func protocolWSU() *protocolSpec {
	return &protocolSpec{
		Port:       portWSU,
		Name:       ProtoNameWSU,
		ListenPort: wsuListenPort,
		Build:      buildWSURequests,
		Parse:      parseWSUFallback,
	}
}

// buildWSURequests renders the 68 byte WSU request.
//
// Layout (PROTOCOL_SPEC.md §5.1):
//
//	[0:2]   = 00 01
//	[2:4]   = 00 01
//	[4:8]   = BE32(68-36) = 32
//	[8:20]  = 0
//	[20:26] = local adapter MAC
//	[26:36] = 0
//	[36:38] = 00 01
//	[38:40] = BE16(68-40) = 28
//	[40:42] = 00 00
//	[42:44] = 00 01
//	[44:46] = BE16(68-46) = 22
//	[46:62] = local IP as ASCII, 16 bytes NUL padded
//	[62:68] = local listening port as ASCII, 6 bytes NUL padded
func buildWSURequests(ac adapterCtx) [][]byte {
	req := make([]byte, wsuRequestLen)
	req[1] = 0x01
	req[3] = 0x01
	binary.BigEndian.PutUint32(req[4:8], uint32(wsuRequestLen-36))
	if len(ac.MAC) >= 6 {
		copy(req[20:26], ac.MAC[:6])
	}
	req[36], req[37] = 0x00, 0x01
	binary.BigEndian.PutUint16(req[38:40], uint16(wsuRequestLen-40))
	req[40], req[41] = 0x00, 0x00
	req[42], req[43] = 0x00, 0x01
	binary.BigEndian.PutUint16(req[44:46], uint16(wsuRequestLen-46))
	copyFixedString(req[46:62], ac.IP.String())
	port := ac.ListenPort
	if port <= 0 {
		port = wsuListenPort
	}
	copyFixedString(req[62:68], itoa(port))
	return [][]byte{req}
}

// parseWSUFallback adapts parseWSU to the protocolSpec signature.
func parseWSUFallback(payload []byte, src net.IP) (*Device, bool) {
	return parseWSU(payload)
}

// ParseWSU decodes a WSU reply (exported for the unit tests).
func ParseWSU(payload []byte) (*Device, bool) { return parseWSU(payload) }

// parseWSU decodes a WSU reply (PROTOCOL_SPEC.md §5.2):
//
//	[0:2]     = magic, 0x0DBD (AWK-1131A), 0x0DBF (AWK-1132C) or 0x1DBF
//	            (AWK-1137C)
//	[2:4]     = 0x0001 reply marker
//	[4:8]     = BE32(len-36), zero on the firmware that does not fill it in
//	[20:26]   = device MAC (binary)
//	[26:32]   = requesting adapter MAC (echo)
//	[46:58]   = model ASCII, e.g. "AWK-1131A-EU" / "AWK-1137C-EU"
//	[79:95]   = device IP as ASCII
//	[95:113]  = device MAC as ASCII
//	[113:127] = subnet mask as ASCII
//	[177:193] = requester IP as ASCII
//
// The frame length is not fixed: 218 bytes for the AWK-1131A, 234 bytes for the
// AWK-1132C and the AWK-1137C. The three structural checks (minimum length,
// known magic, reply marker) are what separates a WSU reply from an unrelated
// datagram.
//
// If the frame disagrees with the length it declares ([4:8] present but not
// equal to len-36) the layout of that firmware revision is unknown, so the
// fixed offsets are not trusted and only the scan fallback is used. The same
// fallback recovers the IP and the MAC when a fixed field holds an implausible
// value.
func parseWSU(payload []byte) (*Device, bool) {
	if len(payload) < wsuMinReplyLen {
		return nil, false
	}
	if !isWSUMagic(binary.BigEndian.Uint16(payload[0:2])) {
		return nil, false
	}
	if binary.BigEndian.Uint16(payload[wsuFlagOffset:wsuFlagOffset+2]) != wsuReplyFlag {
		return nil, false
	}

	fixed := wsuLengthConsistent(payload)

	model := ""
	ipText := ""
	macText := ""
	if fixed {
		if len(payload) >= wsuModelOffset+wsuModelLen {
			model = fixedString(payload[wsuModelOffset : wsuModelOffset+wsuModelLen])
		}
		if len(payload) >= wsuIPOffset+wsuIPLen {
			ipText = fixedString(payload[wsuIPOffset : wsuIPOffset+wsuIPLen])
		}
		if len(payload) >= wsuMACOffset+wsuMACLen {
			macText = ParseMACString(fixedString(payload[wsuMACOffset : wsuMACOffset+wsuMACLen]))
		}
	}
	// An empty or unprintable model field simply leaves the column empty; the
	// discovery layer then derives the model from the device name.
	if !isDottedQuad(ipText) {
		ipText = scanIPString(payload)
	}
	if ipText == "" {
		return nil, false
	}
	if macText == "" {
		macText = scanMACString(payload)
	}
	if macText == "" && len(payload) >= wsuBinaryMACOffset+wsuBinaryMACLen {
		macText = NormalizeMAC(payload[wsuBinaryMACOffset : wsuBinaryMACOffset+wsuBinaryMACLen])
	}

	return &Device{
		IP:       ipText,
		MAC:      macText,
		Model:    model,
		Protocol: ProtoNameWSU,
		// WIFI4 devices do not carry a plain firmware field: the version is the
		// encrypted block in the tail of the reply (PROTOCOL_SPEC.md §5.3.1,
		// see DecodeWSUFirmware). It is decoded here so that every consumer of
		// the parser - the scan, the GUI, the JSON output and the tests - sees
		// the same value, and so that a frame without a decodable block simply
		// leaves the field empty.
		//
		// The value is marked provisional: it is a rendering by the vendor's
		// own utility ("1.27 Build 25092317"), and a device that answers a
		// version itself (4800 0x83 / 0x16) keeps the last word.
		Firmware:            DecodeWSUFirmware(payload),
		FirmwareProvisional: true,
	}, true
}

// wsuLengthConsistent reports whether the BE32 sub frame length at [4:8]
// agrees with the real frame length, i.e. equals len-36.
//
// The field may be zero ("not declared"), which is how some firmware revisions
// answer; in that case the fixed offsets are still used.
func wsuLengthConsistent(payload []byte) bool {
	if len(payload) < wsuLengthOffset+4 {
		return false
	}
	declared := binary.BigEndian.Uint32(payload[wsuLengthOffset : wsuLengthOffset+4])
	if declared == 0 {
		return true
	}
	return int64(declared) == int64(len(payload))-wsuLengthBias
}

// isDottedQuad reports whether s is a plain printable IPv4 address string.
func isDottedQuad(s string) bool {
	if s == "" {
		return false
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	return v4 != nil && ValidDeviceIP(v4)
}
