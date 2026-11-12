package discovery

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
)

// Fixtures are taken verbatim from PROTOCOL_SPEC.md §9 (which in turn were
// decoded from the reference capture files by _analysis/decode_fixtures.py).
const (
	fixture4800Reply24 = "8100001800000000005101801a51500b880f8c29c0a87ffe"
	fixture4800Reply40 = "8100002800000000002600805226500b88102389c0a87ffe500b88102389c0a87efe500b8810238a"
	fixture4800Reply20 = "8104001400000000002600805226500b88102389"
	fixture4800Model   = "8300006800000000005101801a51500b880f8c29540004000001000000004d6f64656c094e5035313130410a557067746f75740938303030300a" +
		"5365637572697479566965770956310a"
	fixture4000Reply64 = "c90000402627cad5547286000700c0a800a30090e80005d0454f4d2d313036" +
		"000000000000000000000000000000000000000000000000000000000000000000"
	fixtureAXOMReply = "41584f4d7c00000000080107740000000000000110000000a450c89b60823b64dad72df91e3da7c8" +
		"340000012000000061776b2d31313631630000000000000000000000000000000000000000000000" +
		"1000000104000000c0a87ffc3300000106000000500b880e1b530000010000070400000002000000" +
		"3900000104000000c0a87f64"
	fixtureAXOMRequest = "41584f4d2000000000080107180000000000000110000000a450c89b60823b64dad72df91e3da7c8"
)

// mustHex decodes a hex string, failing the test on malformed input.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return raw
}

// buildWSUReply assembles a 218 byte WSU reply using the offsets documented in
// PROTOCOL_SPEC.md §5.2. No real UDP/5800 frame existed in the reference
// capture, so the fixture is synthesized from the documented layout.
//
// The reply marker at [2:4] and the sub frame length at [4:8] are filled in the
// way the hardware fills them, so the synthesized frame passes the same
// structural checks as a captured one.
func buildWSUReply(model, ip, mac, mask, requesterIP string) []byte {
	frame := make([]byte, wsuReplyLen)
	frame[0], frame[1] = 0x0D, 0xBD
	binary.BigEndian.PutUint16(frame[wsuFlagOffset:wsuFlagOffset+2], wsuReplyFlag)
	binary.BigEndian.PutUint32(frame[wsuLengthOffset:wsuLengthOffset+4], uint32(wsuReplyLen-wsuLengthBias))
	copy(frame[20:26], []byte{0x50, 0x0B, 0x88, 0x09, 0x2B, 0xDC})
	copy(frame[26:32], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	copyFixedString(frame[46:58], model)
	copyFixedString(frame[79:95], ip)
	copyFixedString(frame[95:113], mac)
	copyFixedString(frame[113:127], mask)
	copyFixedString(frame[177:193], requesterIP)
	return frame
}

func TestParse4800(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantOK  bool
		wantIP  string
		wantMAC string
	}{
		{name: "24B NPort 5110A", payload: fixture4800Reply24, wantOK: true, wantIP: "192.168.127.254", wantMAC: "50:0B:88:0F:8C:29"},
		{name: "40B dual IP host", payload: fixture4800Reply40, wantOK: true, wantIP: "192.168.127.254", wantMAC: "50:0B:88:10:23:89"},
		{name: "20B without IP is dropped", payload: fixture4800Reply20, wantOK: false},
		{name: "wrong command byte", payload: "8200001800000000005101801a51500b880f8c29c0a87ffe", wantOK: false},
		{name: "truncated", payload: "8100001800000000005101801a51500b880f8c", wantOK: false},
		{name: "zero IP is rejected", payload: "8100001800000000005101801a51500b880f8c2900000000", wantOK: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			device, ok := Parse4800(mustHex(t, test.payload))
			if ok != test.wantOK {
				t.Fatalf("ok = %v, want %v", ok, test.wantOK)
			}
			if !test.wantOK {
				return
			}
			if device.IP != test.wantIP {
				t.Errorf("IP = %q, want %q", device.IP, test.wantIP)
			}
			if device.MAC != test.wantMAC {
				t.Errorf("MAC = %q, want %q", device.MAC, test.wantMAC)
			}
			if device.Protocol != ProtoName4800 {
				t.Errorf("Protocol = %q, want %q", device.Protocol, ProtoName4800)
			}
			if len(device.DeviceID()) != 12 {
				t.Errorf("device id = %x, want 12 bytes", device.DeviceID())
			}
		})
	}
}

// build4000Reply assembles a 64 byte EDS answer the way the hardware does.
//
// The important detail, measured on five switches (edsconfig-cv.pcapng): the
// IPv4 field at [14:18] carries the *requester* address, so the fixture takes
// it as a parameter and the parser must prefer the UDP source address.
func build4000Reply(model, requesterIP string, mac []byte) []byte {
	frame := make([]byte, 64)
	frame[0] = replyHeader4000
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	binary.BigEndian.PutUint16(frame[4:6], sessionID4000)
	if ip := net.ParseIP(requesterIP).To4(); ip != nil {
		copy(frame[14:18], ip)
	}
	copy(frame[18:24], mac)
	copyFixedString(frame[24:64], model)
	return frame
}

func TestParse4000(t *testing.T) {
	tests := []struct {
		name      string
		payload   []byte
		src       net.IP
		wantOK    bool
		wantIP    string
		wantMAC   string
		wantModel string
	}{
		{
			// The frame field holds the PC address (192.168.0.163); the device
			// address is the source address and must win.
			name:      "source address wins over the in-frame requester address",
			payload:   mustHex(t, fixture4000Reply64),
			src:       net.IPv4(192, 168, 127, 3),
			wantOK:    true,
			wantIP:    "192.168.127.3",
			wantMAC:   "00:90:E8:00:05:D0",
			wantModel: "EOM-106",
		},
		{
			name:      "no source address falls back to the frame field",
			payload:   mustHex(t, fixture4000Reply64),
			src:       nil,
			wantOK:    true,
			wantIP:    "192.168.0.163",
			wantMAC:   "00:90:E8:00:05:D0",
			wantModel: "EOM-106",
		},
		{
			// The two switches that only answer UDP/4000 (they never appear in
			// the 4800 or AXOM replies) - this is the regression that made them
			// invisible before the 0x48 discovery command was used.
			name:      "EDS-510A-3SFP-2SSC that only answers 4000",
			payload:   build4000Reply("EDS-510A-3SFP-2SSC", "192.168.127.100", []byte{0x00, 0x90, 0xE8, 0xD6, 0x59, 0x85}),
			src:       net.IPv4(192, 168, 127, 1),
			wantOK:    true,
			wantIP:    "192.168.127.1",
			wantMAC:   "00:90:E8:D6:59:85",
			wantModel: "EDS-510A-3SFP-2SSC",
		},
		{
			name:      "EOM-409-3SSC that only answers 4000",
			payload:   build4000Reply("EOM-409-3SSC", "192.168.127.100", []byte{0x50, 0x0B, 0x88, 0x0F, 0xD0, 0xD9}),
			src:       net.IPv4(192, 168, 127, 2),
			wantOK:    true,
			wantIP:    "192.168.127.2",
			wantMAC:   "50:0B:88:0F:D0:D9",
			wantModel: "EOM-409-3SSC",
		},
		{name: "wrong command byte", payload: mustHex(t, "c80000402627cad5547286000700c0a800a30090e80005d0"), src: net.IPv4(192, 168, 127, 3), wantOK: false},
		{name: "too short", payload: mustHex(t, "c90000402627cad5547286000700c0a800a3"), src: net.IPv4(192, 168, 127, 3), wantOK: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			device, ok := Parse4000(test.payload, test.src)
			if ok != test.wantOK {
				t.Fatalf("ok = %v, want %v", ok, test.wantOK)
			}
			if !test.wantOK {
				return
			}
			if device.IP != test.wantIP {
				t.Errorf("IP = %q, want %q", device.IP, test.wantIP)
			}
			if device.MAC != test.wantMAC {
				t.Errorf("MAC = %q, want %q", device.MAC, test.wantMAC)
			}
			if device.Model != test.wantModel {
				t.Errorf("Model = %q, want %q", device.Model, test.wantModel)
			}
		})
	}
}

// TestBuildRequests4000 pins the command byte that actually works.
//
// Measured: five EDS switches answer 0x48 and stay silent for 0x49, with every
// other byte identical (analysis/probe_4000_pair.py). The official tool sends
// both, so both are built here - but the 0x48 one is the one that produces
// replies, and a regression to 0x49 would silently hide every EDS switch that
// does not answer 4800 or 40404.
func TestBuildRequests4000(t *testing.T) {
	requests := buildRequests4000(adapterCtx{})
	if len(requests) != 2 {
		t.Fatalf("len(requests) = %d, want 2", len(requests))
	}
	for i, request := range requests {
		if len(request) != 6 {
			t.Fatalf("len(requests[%d]) = %d, want 6", i, len(request))
		}
		if binary.BigEndian.Uint16(request[2:4]) != 6 {
			t.Errorf("requests[%d] length field = %d, want 6", i, binary.BigEndian.Uint16(request[2:4]))
		}
		if binary.BigEndian.Uint16(request[4:6]) != sessionID4000 {
			t.Errorf("requests[%d] session = 0x%04X, want 0x%04X",
				i, binary.BigEndian.Uint16(request[4:6]), sessionID4000)
		}
	}
	if requests[0][0] != command4000Companion {
		t.Errorf("requests[0] command = 0x%02X, want the companion 0x%02X",
			requests[0][0], command4000Companion)
	}
	if requests[1][0] != command4000Discover {
		t.Fatalf("requests[1] command = 0x%02X, want the discovery 0x%02X",
			requests[1][0], command4000Discover)
	}
	if command4000Discover != 0x48 {
		t.Fatalf("command4000Discover = 0x%02X, want 0x48 (the byte five switches answer)",
			command4000Discover)
	}
}

func TestParseAXOM(t *testing.T) {
	device, ok := ParseAXOM(mustHex(t, fixtureAXOMReply))
	if !ok {
		t.Fatal("ParseAXOM returned false for the reference fixture")
	}
	if device.IP != "192.168.127.252" {
		t.Errorf("IP = %q, want 192.168.127.252", device.IP)
	}
	if device.MAC != "50:0B:88:0E:1B:53" {
		t.Errorf("MAC = %q, want 50:0B:88:0E:1B:53", device.MAC)
	}
	if device.Name != "awk-1161c" {
		t.Errorf("Name = %q, want awk-1161c", device.Name)
	}
	if device.Protocol != ProtoNameAXOM {
		t.Errorf("Protocol = %q, want %q", device.Protocol, ProtoNameAXOM)
	}
}

func TestParseAXOMRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		{},
		[]byte("AXOM"),
		append([]byte("AXOM"), make([]byte, 20)...),
		append([]byte("XXXX"), make([]byte, 60)...),
	}
	for index, payload := range cases {
		if _, ok := ParseAXOM(payload); ok {
			t.Errorf("case %d: garbage accepted as an AXOM reply", index)
		}
	}
}

func TestBuildAXOMRequest(t *testing.T) {
	requests := buildAXOMRequests(adapterCtx{Name: "WLAN", IP: net.IPv4(192, 168, 0, 163)})
	// Two dialects: ...07 for the WIFI 6 family, ...01 for the EDS-G4012 class.
	if len(requests) != len(axomRequestTypes) {
		t.Fatalf("len(requests) = %d, want %d", len(requests), len(axomRequestTypes))
	}
	for index, request := range requests {
		if len(request) != axomRequestLen {
			t.Fatalf("request %d: len = %d, want %d", index, len(request), axomRequestLen)
		}
		if request[4] != byte(axomRequestLen-8) {
			t.Errorf("request %d: [4] = 0x%02X, want 0x%02X", index, request[4], axomRequestLen-8)
		}
	}

	// The first dialect must still match the captured WIFI 6 request byte for byte.
	reference := mustHex(t, fixtureAXOMRequest)
	for i := 0; i < 24; i++ {
		if requests[0][i] != reference[i] {
			t.Errorf("request[0][%d] = 0x%02X, want 0x%02X", i, requests[0][i], reference[i])
		}
	}

	// The two requests may only differ in the request type byte [11].
	if requests[0][11] != 0x07 || requests[1][11] != 0x01 {
		t.Errorf("request type bytes = 0x%02X/0x%02X, want 0x07/0x01", requests[0][11], requests[1][11])
	}
	for i := 0; i < axomRequestLen; i++ {
		if i == 11 {
			continue
		}
		if requests[0][i] != requests[1][i] {
			t.Fatalf("requests differ at [%d]: 0x%02X vs 0x%02X", i, requests[0][i], requests[1][i])
		}
	}
}

func TestParseWSU(t *testing.T) {
	frame := buildWSUReply("AWK-1131A-US", "192.168.127.253", "50:0B:88:09:2B:DC", "255.255.255.0", "192.168.127.100")
	device, ok := ParseWSU(frame)
	if !ok {
		t.Fatal("ParseWSU returned false for the synthesized fixture")
	}
	if device.Model != "AWK-1131A-US" {
		t.Errorf("Model = %q, want AWK-1131A-US", device.Model)
	}
	if device.IP != "192.168.127.253" {
		t.Errorf("IP = %q, want 192.168.127.253", device.IP)
	}
	if device.MAC != "50:0B:88:09:2B:DC" {
		t.Errorf("MAC = %q, want 50:0B:88:09:2B:DC", device.MAC)
	}
	if device.Protocol != ProtoNameWSU {
		t.Errorf("Protocol = %q, want %q", device.Protocol, ProtoNameWSU)
	}
}

func TestParseWSURejectsBadMagic(t *testing.T) {
	frame := buildWSUReply("AWK-1131A-US", "192.168.127.253", "50:0B:88:09:2B:DC", "255.255.255.0", "192.168.127.100")
	frame[0] = 0x00
	if _, ok := ParseWSU(frame); ok {
		t.Fatal("frame with a broken magic was accepted")
	}
}

func TestParseWSUFallsBackToScan(t *testing.T) {
	// Fixed offsets hold garbage, the scan fallback must still recover the IP.
	frame := buildWSUReply("", "192.168.127.253", "50:0B:88:09:2B:DC", "255.255.255.0", "192.168.127.100")
	copy(frame[46:58], []byte{0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f})
	device, ok := ParseWSU(frame)
	if !ok {
		t.Fatal("ParseWSU returned false although the frame carries an IP")
	}
	if device.IP != "192.168.127.253" {
		t.Errorf("IP = %q, want 192.168.127.253 (recovered by scanning)", device.IP)
	}
}

func TestBuildWSURequest(t *testing.T) {
	ac := adapterCtx{
		Name:       "WLAN",
		IP:         net.IPv4(192, 168, 0, 163),
		Mask:       net.CIDRMask(24, 32),
		MAC:        net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		ListenPort: 15802,
	}
	requests := buildWSURequests(ac)
	if len(requests) != 1 {
		t.Fatalf("len(requests) = %d, want 1", len(requests))
	}
	request := requests[0]
	if len(request) != wsuRequestLen {
		t.Fatalf("len(request) = %d, want %d", len(request), wsuRequestLen)
	}
	if request[0] != 0x00 || request[1] != 0x01 || request[2] != 0x00 || request[3] != 0x01 {
		t.Errorf("prefix = %x, want 00010001", request[0:4])
	}
	if got := uint32(request[4])<<24 | uint32(request[5])<<16 | uint32(request[6])<<8 | uint32(request[7]); got != uint32(wsuRequestLen-36) {
		t.Errorf("[4:8] = %d, want %d", got, wsuRequestLen-36)
	}
	if got := string(request[20:26]); got != string(ac.MAC) {
		t.Errorf("[20:26] = %x, want %x", request[20:26], ac.MAC)
	}
	if got := fixedString(request[46:62]); got != "192.168.0.163" {
		t.Errorf("[46:62] = %q, want 192.168.0.163", got)
	}
	if got := fixedString(request[62:68]); got != "15802" {
		t.Errorf("[62:68] = %q, want 15802", got)
	}
}

func TestParseModelReply(t *testing.T) {
	deviceID, model, ok := ParseModelReply(mustHex(t, fixture4800Model))
	if !ok {
		t.Fatal("ParseModelReply returned false for the reference fixture")
	}
	if model != "NP5110A" {
		t.Errorf("model = %q, want NP5110A", model)
	}
	if len(deviceID) != 12 {
		t.Errorf("device id = %x, want 12 bytes", deviceID)
	}
}

func TestParseModelReplyWithoutModel(t *testing.T) {
	frame := make([]byte, 32)
	frame[0] = 0x83
	if _, _, ok := ParseModelReply(frame); ok {
		t.Fatal("frame without a Model property was accepted")
	}
}

func TestBuildModelRequest(t *testing.T) {
	deviceID := mustHex(t, "005101801a51500b880f8c29")
	request := BuildModelRequest(deviceID, 7)
	// The captured frame is `03 00 00 14 | 00 00 00 00 | <deviceID 12B>` = 20
	// bytes, i.e. the 4 byte field is the sequence number itself. PROTOCOL_SPEC
	// §2.3 lists both a <seq> and an extra zero field (24 bytes), which
	// contradicts the length 0x14 stored in the frame; the capture wins.
	want := mustHex(t, "0300001400000007005101801a51500b880f8c29")
	if len(request) != len(want) {
		t.Fatalf("len(request) = %d, want %d", len(request), len(want))
	}
	for i := range want {
		if request[i] != want[i] {
			t.Fatalf("request = %x, want %x", request, want)
		}
	}
	if BuildModelRequest([]byte{1, 2, 3}, 1) != nil {
		t.Error("BuildModelRequest accepted a short device id")
	}
}

func TestFallbackPorts(t *testing.T) {
	tests := []struct {
		name      string
		spec      *protocolSpec
		wantPort  int
		wantCount int
		wantLen   int
	}{
		{name: "29168", spec: protocol29168(), wantPort: 29168, wantCount: 1, wantLen: 8},
		{name: "1029", spec: protocol1029(), wantPort: 1029, wantCount: 2, wantLen: 6},
		{name: "22222", spec: protocol22222(), wantPort: 22222, wantCount: 1, wantLen: 28},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.spec.Port != test.wantPort {
				t.Errorf("Port = %d, want %d", test.spec.Port, test.wantPort)
			}
			requests := test.spec.Build(adapterCtx{IP: net.IPv4(192, 168, 0, 163)})
			if len(requests) != test.wantCount {
				t.Fatalf("len(requests) = %d, want %d", len(requests), test.wantCount)
			}
			for _, request := range requests {
				if len(request) != test.wantLen {
					t.Errorf("len(request) = %d, want %d", len(request), test.wantLen)
				}
			}
		})
	}
}

func TestFallbackParserUsesSourceIP(t *testing.T) {
	parse := fallbackParser(ProtoName22222)
	device, ok := parse([]byte{0xFF, 0xEE, 0xDD}, net.IPv4(192, 168, 127, 9))
	if !ok {
		t.Fatal("fallback parser did not report the source IP")
	}
	if device.IP != "192.168.127.9" {
		t.Errorf("IP = %q, want 192.168.127.9", device.IP)
	}
	if device.Protocol != ProtoName22222 {
		t.Errorf("Protocol = %q, want %q", device.Protocol, ProtoName22222)
	}
}

func TestFallbackParserDecodesKnownLayouts(t *testing.T) {
	parse := fallbackParser(ProtoName29168)
	device, ok := parse(mustHex(t, fixture4800Reply24), net.IPv4(10, 0, 0, 1))
	if !ok {
		t.Fatal("fallback parser failed on a 0x81 frame")
	}
	if device.IP != "192.168.127.254" || device.Protocol != ProtoName29168 {
		t.Errorf("device = %+v, want IP 192.168.127.254 over %s", device, ProtoName29168)
	}
}
