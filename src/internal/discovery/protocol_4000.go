package discovery

import (
	"net"
)

// port4000 is the EDS switch discovery port used by EDSConfig
// (PROTOCOL_SPEC.md §1).
const port4000 = 4000

// sessionID4000 is the session marker echoed back by the devices. The hardware
// does not validate it: a capture of EDSConfig used 0x7D48, and the measured
// replies arrive with 0x2627, 0x7D48 and 0x9A3C alike (all echoed verbatim).
const sessionID4000 = 0x2627

// command4000Discover is the request command that makes an EDS switch answer.
//
// ⚠️ Measured mistake, do not "fix" it back: the request used to carry 0x49
// (taken from an old capture header), and **no device ever answered it** -
// five EDS switches replied to 0x48 and stayed silent for 0x49, with all other
// bytes identical. EDSConfig sends `49 ...` and `48 ...` back to back, but only
// the 0x48 one is the discovery request; 0x49 is a companion frame without a
// reply. Keeping both keeps us byte-compatible with the official tool, so only
// 0x48 is expected to produce traffic.
const (
	command4000Companion = 0x49
	command4000Discover  = 0x48
)

// replyHeader4000 is the first byte of the 64 byte discovery answer
// (0x48 | 0x80).
const replyHeader4000 = 0xC9

// minLen4000 is the shortest reply that carries MAC + model.
const minLen4000 = 24

// modelFieldEnd4000 is the end offset of the 40 byte model field.
const modelFieldEnd4000 = 64

// replyIPOffset4000 / replyMACOffset4000 / replyModelOffset4000 locate the
// fields of the 64 byte answer.
//
// ⚠️ [14:18] is **not** the device address, although PROTOCOL_SPEC.md §3.2 said
// so and the unit test used to assert exactly that. In a capture of five
// switches every single answer carries the *requester* address there
// (192.168.100.100, the PC), while the actual device address is the UDP source
// address. That is also how EDSConfig labels the rows: the 64 byte frame has no
// room for the device address at all - it only appears in the 178 byte unicast
// detail answer, at [172:176], which is optional. The source address is
// therefore used first and the field only as a fallback.
const (
	replyIPOffset4000    = 14
	replyMACOffset4000   = 18
	replyModelOffset4000 = 24
)

// buildRequests4000 renders the two 6 byte broadcast frames per round:
// the companion 0x49 and the discovery 0x48.
func buildRequests4000(_ adapterCtx) [][]byte {
	frame := func(command byte) []byte {
		return []byte{command, 0x00, 0x00, 0x06,
			byte(sessionID4000 >> 8), byte(sessionID4000 & 0xFF)}
	}
	return [][]byte{frame(command4000Companion), frame(command4000Discover)}
}

// protocol4000 describes the UDP/4000 EDS discovery protocol.
func protocol4000() *protocolSpec {
	return &protocolSpec{
		Port:       port4000,
		Name:       ProtoName4000,
		ListenPort: 0,
		Build:      buildRequests4000,
		Parse:      parse4000Fallback,
	}
}

// parse4000Fallback adapts parse4000 to the protocolSpec signature.
func parse4000Fallback(payload []byte, src net.IP) (*Device, bool) {
	return parse4000(payload, src)
}

// Parse4000 decodes an EDS 0x48 reply (exported for the unit tests).
//
// src is the UDP source address of the datagram, i.e. the device address.
func Parse4000(payload []byte, src net.IP) (*Device, bool) { return parse4000(payload, src) }

// parse4000 decodes a 64 byte EDS reply (PROTOCOL_SPEC.md §3.2):
//
//	[0]     = 0xC9
//	[2:4]   = total length (BE16, 64)
//	[4:6]   = session id (echo of the request)
//	[6:14]  = 8 byte identifier (serial, ignored)
//	[14:18] = requester IPv4 (NOT the device address - see the constants above)
//	[18:24] = device MAC
//	[24:64] = model / name, ASCII, NUL padded
func parse4000(payload []byte, src net.IP) (*Device, bool) {
	if len(payload) < minLen4000 {
		return nil, false
	}
	if payload[0] != replyHeader4000 {
		return nil, false
	}
	// The source address is authoritative; the in-frame field is only used when
	// the caller has no address (unit tests, synthesized frames).
	ip := src
	if ip == nil || ip.To4() == nil {
		ip = net.IPv4(payload[replyIPOffset4000], payload[replyIPOffset4000+1],
			payload[replyIPOffset4000+2], payload[replyIPOffset4000+3])
	}
	if !ValidDeviceIP(ip) {
		return nil, false
	}
	end := modelFieldEnd4000
	if len(payload) < end {
		end = len(payload)
	}
	return &Device{
		IP:       ip.String(),
		MAC:      NormalizeMAC(payload[replyMACOffset4000 : replyMACOffset4000+6]),
		Model:    fixedString(payload[replyModelOffset4000:end]),
		Protocol: ProtoName4000,
	}, true
}
