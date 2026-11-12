package discovery

import (
	"net"
	"strconv"
)

// adapterCtx carries the per-adapter information that some protocols need to
// embed inside the request frame (the WSU/5800 request advertises the local
// MAC, IP and listening port, see PROTOCOL_SPEC.md §5.1).
type adapterCtx struct {
	// Name is the Windows adapter name, e.g. "WLAN" or "VMnet1".
	Name string
	// IP is the adapter IPv4 address.
	IP net.IP
	// Mask is the adapter subnet mask, always 4 bytes.
	Mask net.IPMask
	// MAC is the adapter hardware address (may be nil for virtual adapters).
	MAC net.HardwareAddr
	// ListenPort is the local UDP port bound to receive the replies of the
	// protocol currently being sent (used only by WSU/5800).
	ListenPort int
}

// protocolSpec describes one discovery protocol.
type protocolSpec struct {
	// Port is the UDP destination port.
	Port int
	// Name is the protocol label stored in Device.Protocol.
	Name string
	// ListenPort is the preferred local UDP port for receiving replies.
	// Zero means "let the OS pick an ephemeral port".
	ListenPort int
	// Build renders the request payload(s) for one adapter. Several payloads
	// may be returned (the 1029 fallback sends two different frames).
	Build func(ac adapterCtx) [][]byte
	// Parse decodes a reply payload. src is the UDP source address and is
	// used by fallback protocols that cannot decode the frame at all.
	Parse func(payload []byte, src net.IP) (*Device, bool)
}

// allProtocols returns the full protocol set in send order.
//
// Order matters only for the UI (the first protocol that answers a device wins
// the "协议" column until a higher ranked one is seen).
func allProtocols() []*protocolSpec {
	return []*protocolSpec{
		protocol4800(),
		protocol4000(),
		protocolAXOM(),
		protocolWSU(),
		protocol29168(),
		protocol1029(),
		protocol22222(),
	}
}

// fallbackParser builds the parser used by the send-only fallback ports. It
// tries every known reply layout and finally degrades to "report the source IP
// only" (PROTOCOL_SPEC.md §6).
func fallbackParser(name string) func(payload []byte, src net.IP) (*Device, bool) {
	return func(payload []byte, src net.IP) (*Device, bool) {
		if d, ok := parse4800(payload); ok {
			d.Protocol = name
			return d, true
		}
		if d, ok := parse4000(payload, src); ok {
			d.Protocol = name
			return d, true
		}
		if d, ok := parseAXOM(payload); ok {
			d.Protocol = name
			return d, true
		}
		if d, ok := parseWSU(payload); ok {
			d.Protocol = name
			return d, true
		}
		if len(payload) > 0 && src != nil && ValidDeviceIP(src) {
			return &Device{IP: src.String(), Protocol: name}, true
		}
		return nil, false
	}
}

// staticRequest returns a Build function that always yields the same payload.
func staticRequest(payload []byte) func(adapterCtx) [][]byte {
	frozen := append([]byte(nil), payload...)
	return func(adapterCtx) [][]byte {
		out := make([]byte, len(frozen))
		copy(out, frozen)
		return [][]byte{out}
	}
}

// scanIPString looks for the first dotted-quad IPv4 address inside b.
// Used as a defensive fallback for protocols whose fixed offsets are unknown
// on some firmware revisions.
func scanIPString(b []byte) string {
	for i := 0; i < len(b); i++ {
		if b[i] < '0' || b[i] > '9' {
			continue
		}
		j := i
		dots := 0
		for j < len(b) && ((b[j] >= '0' && b[j] <= '9') || b[j] == '.') {
			if b[j] == '.' {
				dots++
			}
			j++
		}
		if dots == 3 {
			if ip := net.ParseIP(string(b[i:j])); ip != nil {
				if v4 := ip.To4(); v4 != nil && ValidDeviceIP(v4) {
					return v4.String()
				}
			}
		}
		i = j
	}
	return ""
}

// scanMACString looks for the first "xx:xx:xx:xx:xx:xx" pattern inside b.
func scanMACString(b []byte) string {
	const macLen = 17
	for i := 0; i+macLen <= len(b); i++ {
		if !isHexByte(b[i]) || !isHexByte(b[i+1]) || b[i+2] != ':' {
			continue
		}
		ok := true
		for k := 3; k < macLen; k++ {
			if k%3 == 2 {
				if b[i+k] != ':' {
					ok = false
					break
				}
			} else if !isHexByte(b[i+k]) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if mac := ParseMACString(string(b[i : i+macLen])); mac != "" {
			return mac
		}
	}
	return ""
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// itoa is a tiny helper so protocol files avoid importing strconv twice.
func itoa(v int) string { return strconv.Itoa(v) }
