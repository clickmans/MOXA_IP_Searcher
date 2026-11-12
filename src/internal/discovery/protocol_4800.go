package discovery

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// port4800 is the main MOXA device discovery port used by DSU, MXConfigCS,
// NPort Administrator and MGate Manager (PROTOCOL_SPEC.md §1).
const port4800 = 4800

// request4800 is the 8 byte discovery request that every official tool sends
// and that is proven to be answered (PROTOCOL_SPEC.md §2.1):
//
//	[0]    = 0x01 command (search)
//	[2:4]  = 0x0008 total length (BE16)
//	[4:8]  = 0
var request4800 = []byte{0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}

// Reply command bytes (0x80 | request command).
const (
	// replyHeader4800 is the discovery answer (0x80 | 0x01).
	replyHeader4800 = 0x81
	// replyHeader4800Model is the answer of the 0x03 property query.
	replyHeader4800Model = 0x83
	// replyHeader4800Name is the answer of the 0x10 name query.
	replyHeader4800Name = 0x90
	// replyHeader4800Version is the answer of the 0x16 version query.
	replyHeader4800Version = 0x96
)

// Request command bytes of the three detail queries (v1.2).
const (
	// cmd4800Model asks for the property list ("Model\t<value>\n", ...).
	cmd4800Model = 0x03
	// cmd4800Name asks for the plain device name, e.g. "NP6450_0001".
	cmd4800Name = 0x10
	// cmd4800Version asks for the 36 byte version answer.
	cmd4800Version = 0x16
)

// queryLen4800 is the size of every detail request:
// 4 byte header + 4 byte sequence number + 12 byte device identity.
const queryLen4800 = 20

// flagNoData4800 is bit 2 of the reply flag byte. A device that does not
// support a command answers with the 20 byte frame
//
//	83 04 00 14 <seq:4B> <deviceID:12B>
//
// i.e. the flag bit is set and no payload follows (measured on the NPort 6450).
// That is a valid "not supported / no data" answer, NOT a parse error.
const flagNoData4800 = 0x04

// minLen4800 is the shortest reply that still carries the device IPv4 address.
// 20 byte replies (flag 0x04) have no IP and are discarded (PROTOCOL_SPEC.md §2.2).
const minLen4800 = 24

// protocol4800 describes the UDP/4800 discovery protocol.
func protocol4800() *protocolSpec {
	return &protocolSpec{
		Port:       port4800,
		Name:       ProtoName4800,
		ListenPort: 0,
		Build:      staticRequest(request4800),
		Parse:      parse4800Fallback,
	}
}

// parse4800Fallback adapts parse4800 to the protocolSpec signature.
func parse4800Fallback(payload []byte, _ net.IP) (*Device, bool) {
	return parse4800(payload)
}

// Parse4800 decodes a 0x81 discovery reply (exported for the unit tests).
func Parse4800(payload []byte) (*Device, bool) { return parse4800(payload) }

// parse4800 decodes a discovery reply.
//
// Layout (PROTOCOL_SPEC.md §2.2):
//
//	[0]     = 0x81                      reply command
//	[1]     = 0x00 / 0x04               flags (0x04 => no IP, dropped)
//	[2:4]   = total length (BE16)
//	[4:8]   = 0
//	[8:20]  = 12 byte device id, last 6 bytes are the MAC
//	[20:24] = device IPv4
//	[24:]   = optional trailing data (second IP of a dual-IP host) - ignored
func parse4800(payload []byte) (*Device, bool) {
	if len(payload) < minLen4800 {
		return nil, false
	}
	if payload[0] != replyHeader4800 {
		return nil, false
	}
	ip := net.IPv4(payload[20], payload[21], payload[22], payload[23])
	if !ValidDeviceIP(ip) {
		return nil, false
	}
	device := &Device{
		IP:       ip.String(),
		MAC:      NormalizeMAC(payload[14:20]),
		Protocol: ProtoName4800,
	}
	// The full 12 byte identity is echoed by the model query, so keep it.
	device.deviceID = append([]byte(nil), payload[8:20]...)
	if device.MAC == "" {
		device.deviceID = nil
	}
	return device, true
}

// buildQuery4800 builds one 20 byte detail request:
//
//	<cmd> 00 00 14 <seq:4B BE> <deviceID:12B>
//
// The length stored inside the frame (0x14 = 20) proves that the 4 byte zero
// field of the specification text does not exist, so the captures are followed
// here (PROTOCOL_SPEC.md §2.3).
//
// A device id that is not exactly 12 bytes long identifies nothing, so nil is
// returned instead of a frame that no device would accept.
func buildQuery4800(command byte, deviceID []byte, seq uint32) []byte {
	if len(deviceID) != 12 {
		return nil
	}
	request := make([]byte, queryLen4800)
	request[0] = command
	binary.BigEndian.PutUint16(request[2:4], queryLen4800)
	binary.BigEndian.PutUint32(request[4:8], seq)
	copy(request[8:20], deviceID)
	return request
}

// BuildModelRequest builds the 0x03 model query (PROTOCOL_SPEC.md §2.3).
//
// The captured frame is
//
//	03 00 00 14 <seq:4B BE> <deviceID:12B>
//
// i.e. 20 bytes: 4 byte header (command + BE16 length 0x14), 4 byte sequence
// number, 12 byte device identity.
func BuildModelRequest(deviceID []byte, seq uint32) []byte {
	return buildQuery4800(cmd4800Model, deviceID, seq)
}

// BuildNameRequest builds the 0x10 device name query (v1.2).
//
// It has exactly the same 20 byte shape as the model query, only the command
// byte differs; the device answers with 0x90 and a NUL terminated ASCII name.
func BuildNameRequest(deviceID []byte, seq uint32) []byte {
	return buildQuery4800(cmd4800Name, deviceID, seq)
}

// BuildVersionRequest builds the 0x16 firmware version query (v1.2).
func BuildVersionRequest(deviceID []byte, seq uint32) []byte {
	return buildQuery4800(cmd4800Version, deviceID, seq)
}

// isNoDataReply reports whether payload is the "command not supported / no
// data" form of an answer: the right reply command with the 0x04 flag set, or
// a bare header without any payload.
//
// This distinction matters (v1.2): the NPort 6450 answers the 0x03 model query
// with `83 04 00 14 <seq> <id>` and stops there. Treating that as a parse
// failure is correct in isolation, but it must never be reported as an error
// and it must not stop the fallback chain - the model is simply unknown and is
// derived from the device name instead.
func isNoDataReply(payload []byte, header byte) bool {
	if len(payload) < queryLen4800 || payload[0] != header {
		return false
	}
	if payload[1]&flagNoData4800 != 0 {
		return true
	}
	return len(payload) <= queryLen4800
}

// ParseModelReply decodes a 0x83 model query reply.
//
// The payload is a "key<TAB>value<LF>" property list. The model name is taken
// from the "Model" entry; the offset differs between firmware families so the
// key is searched for instead of using a fixed offset (PROTOCOL_SPEC.md §2.3).
//
// Returns the echoed 12 byte device id, the model name and whether a model was
// actually found.
func ParseModelReply(payload []byte) (deviceID []byte, model string, ok bool) {
	deviceID, model, _, ok = ParseModelReplyFull(payload)
	return deviceID, model, ok
}

// ParseModelReplyFull decodes a 0x83 property reply into its model and firmware
// properties (U7).
//
// Both are optional: most firmware families only answer "Model", while some
// also publish "Firmware" (the MGate MB3180 in the reference network does not).
// ok reports whether at least one of the two was found. A "no data" answer
// (flag 0x04, no payload) returns ok == false with the echoed device id and is
// not an error.
func ParseModelReplyFull(payload []byte) (deviceID []byte, model, firmware string, ok bool) {
	if len(payload) < queryLen4800 || payload[0] != replyHeader4800Model {
		return nil, "", "", false
	}
	id := append([]byte(nil), payload[8:20]...)

	if isNoDataReply(payload, replyHeader4800Model) {
		return id, "", "", false
	}

	model = modelFromProperties(payload[20:], "Model")
	firmware = modelFromProperties(payload[20:], "Firmware")
	if model == "" && firmware == "" {
		return id, "", "", false
	}
	return id, model, firmware, true
}

// ParseNameReply decodes a 0x90 name reply (v1.2).
//
// The name is the first NUL terminated ASCII string after the 20 byte header:
//
//	90 00 00 xx <seq:4B> <deviceID:12B> "NP6450_0001" 00 ...
//
// ok is false for a "no data" answer or an empty name.
func ParseNameReply(payload []byte) (deviceID []byte, name string, ok bool) {
	if len(payload) < queryLen4800 || payload[0] != replyHeader4800Name {
		return nil, "", false
	}
	id := append([]byte(nil), payload[8:20]...)
	if isNoDataReply(payload, replyHeader4800Name) {
		return id, "", false
	}
	name = fixedString(payload[queryLen4800:])
	return id, name, name != ""
}

// ParseVersionReply decodes a 0x96 version reply (v1.2).
//
// The answer is 36 bytes:
//
//	96 00 00 24 <seq:4B> <deviceID:12B> <tail:16B>
//
// and the version lives in the two bytes of the tail (verified against three
// devices on hardware, see versionFromTail4800):
//
//	tail[2] = minor version, decimal digits (see minorFromTail4800)
//	tail[3] = major version, plain decimal
//
// tail[8:10] is a little endian short serial number (579 on the MGate MB3180,
// 5599 on the NPort 6450). It is not displayed, but it is decoded so a later
// version can use it without touching the parser again.
//
// ok is false for a "no data" answer, a truncated answer or an implausible
// version number.
func ParseVersionReply(payload []byte) (deviceID []byte, version string, shortSerial uint16, ok bool) {
	if len(payload) < queryLen4800 || payload[0] != replyHeader4800Version {
		return nil, "", 0, false
	}
	id := append([]byte(nil), payload[8:20]...)
	if isNoDataReply(payload, replyHeader4800Version) {
		return id, "", 0, false
	}
	tail := payload[queryLen4800:]
	if len(tail) < 4 {
		return id, "", 0, false
	}
	if len(tail) >= 10 {
		shortSerial = binary.LittleEndian.Uint16(tail[8:10])
	}
	version, ok = versionFromTail4800(tail[2], tail[3])
	if !ok {
		return id, "", shortSerial, false
	}
	return id, version, shortSerial, true
}

// versionFromTail4800 renders the two version bytes of a 0x96 answer as
// "V<major>.<minor>".
//
// Measured on hardware (cross checked with the vendor tools, all three truths
// have to hold at the same time):
//
//	MGate MB3180: minor=0x07 major=0x02 -> V2.7  (MXConfig shows V2.7build25060913)
//	NPort 6450:   minor=0x10 major=0x01 -> V1.10 (DSU shows Ver1.10)
//	AWK-1132C:    minor=0x00 major=0x01 -> V1.0  (tail 00 00 00 01 00 0d 0d 01 ...)
//	AWK-1137C:    minor=0x0b major=0x01 -> V1.11 (tail 00 00 0b 01 00 0d 09 01 ...)
//
// hence the major number is a plain decimal byte while the minor number is a
// pair of decimal digits: 0x10 is ten (not sixteen) and 0x0b is eleven (not
// "zero and B"). The decoding rule itself lives in minorFromTail4800; a minor
// of 0 is a legitimate version ("V1.0"), so only a zero / implausible major and
// a byte that cannot be read as a decimal minor mean "no usable version" - the
// caller then keeps the field empty instead of inventing a number.
func versionFromTail4800(minorBCD, major byte) (string, bool) {
	if major == 0 || major > 99 {
		return "", false
	}
	minor, ok := minorFromTail4800(minorBCD)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("V%d.%d", major, minor), true
}

// minorFromTail4800 decodes the minor version byte of a 0x96 answer.
//
// The byte holds two decimal digits, high nibble first, except for the single
// digit form:
//
//	0x00 ->  0      0x07 ->  7      0x10 -> 10      0x99 -> 99
//	0x0b -> 11      0x0c -> 12      (single digit form, whole byte is decimal)
//	0x1A -> invalid (multi digit form, the low digit must be 0..9)
//	0xA1 -> invalid (the high digit is not a decimal digit)
//
// The single digit form is what the AWK-1137C uses: 0x0b is a firmware that
// reports minor 11, so rejecting every low nibble above 9 (which is what the
// previous BCD-only check did) dropped the whole answer and left the 固件版本
// column empty. A multi digit value keeps the strict digit rule, so 0x1A and
// 0xA1 stay invalid instead of being guessed as 20 / 161.
func minorFromTail4800(value byte) (int, bool) {
	high, low := value>>4, value&0x0F
	if high == 0 {
		return int(low), true
	}
	if high > 9 || low > 9 {
		return 0, false
	}
	minor := int(high)*10 + int(low)
	if minor > 99 {
		return 0, false
	}
	return minor, true
}

// BCDToDecimal converts one strictly BCD encoded byte to its decimal value.
//
// It pins the "0x10 is ten, never sixteen" rule of the multi digit form in a
// unit test (the tolerant decoder that also accepts the single digit form is
// minorFromTail4800).
func BCDToDecimal(value byte) (int, bool) {
	high, low := value>>4, value&0x0F
	if high > 9 || low > 9 {
		return 0, false
	}
	return int(high)*10 + int(low), true
}

// modelFromProperties extracts a single "key<TAB>value" property from the
// payload of a 0x83 answer.
func modelFromProperties(payload []byte, key string) string {
	needle := []byte(key + "\t")
	idx := bytes.Index(payload, needle)
	if idx < 0 {
		return ""
	}
	rest := payload[idx+len(needle):]
	end := len(rest)
	for i := 0; i < len(rest); i++ {
		if rest[i] == '\n' || rest[i] == '\r' || rest[i] == 0 {
			end = i
			break
		}
	}
	return strings.TrimSpace(cleanText(string(rest[:end])))
}
