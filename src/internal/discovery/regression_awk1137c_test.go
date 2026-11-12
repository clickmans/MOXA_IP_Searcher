package discovery

import (
	"context"
	"net"
	"testing"
	"time"
)

// AWK-1137C regression fixtures (bug AWK-1137C: the device answered UDP/5800
// but its reply was dropped by the magic word check, and the 0x16 answer it
// does send was rejected as an impossible version).
//
// Device under test: IP 192.168.100.253, MAC 00:90:E8:00:00:4E,
// 12 byte identity 3012198902770090e800004e, firmware V1.11.
const (
	// fixtureWSUReplyAWK1137C is the real 234 byte UDP/5800 reply, taken
	// verbatim from the capture file _analysis/wifi_frames.txt (lines 9-10).
	// Its magic is 0x1DBF, i.e. the high byte is 0x1D and not 0x0D, which is
	// what the old isWSUMagic rejected.
	fixtureWSUReplyAWK1137C = "1dbf0001000000c600013498384313cf000000000090e800004e246a0e1a4cfd" +
		"00000003000100c20001000100bc41574b2d31313337432d4555000000000000" +
		"0000000000000000000000000000003139322e3136382e3130302e3235330030" +
		"303a39303a45383a30303a30303a3445003235352e3235352e3235352e300000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"00000000000000000000000000000000003139322e3136382e3130302e313030" +
		"00884796b9c85c8095ffdc8c5d3a2283e82bb80f1fd07a4e6839627230000000" +
		"00000000000000000000"

	// fixtureVersionReplyAWK1137C is the real 36 byte UDP/4800 0x16 answer of
	// the same device: 20 byte header + tail
	// 00 00 0b 01 00 0d 09 01 00 00 00 00 01 00 02 00, i.e. minor 0x0b and
	// major 0x01, which renders as V1.11.
	fixtureVersionReplyAWK1137C = "96000024" + "00000300" + "3012198902770090e800004e" +
		"00000b01000d09010000000001000200"

	// awkWSUAnswerIP is the device address carried by the captured frame.
	awkWSUAnswerIP = "192.168.100.253"
	// awkWSUMAC is the MAC carried by the captured frame.
	awkWSUMAC = "00:90:E8:00:00:4E"
)

// TestIsWSUMagicAWK1137CFamily pins the widened magic table: both observed
// high bytes (0x0D for the older WIFI4 family, 0x1D for the AWK-1137C) and both
// observed low bytes are accepted, everything else stays out of the parser.
func TestIsWSUMagicAWK1137CFamily(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		want  bool
	}{
		{name: "AWK-1131A 0x0DBD", value: 0x0DBD, want: true},
		{name: "AWK-1132C 0x0DBF", value: 0x0DBF, want: true},
		{name: "AWK-1137C 0x1DBF", value: 0x1DBF, want: true},
		{name: "0x1D family second low byte 0x1DBD", value: 0x1DBD, want: true},
		{name: "unknown product 0x0DAA", value: 0x0DAA, want: false},
		{name: "unknown family 0x2DBF", value: 0x2DBF, want: false},
		{name: "zero 0x0000", value: 0x0000, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isWSUMagic(test.value); got != test.want {
				t.Errorf("isWSUMagic(%#04x) = %v, want %v", test.value, got, test.want)
			}
		})
	}
}

// TestParseWSUAWK1137CRealFrame proves that the captured 0x1D frame now enters
// the parser and yields the model, the address and the MAC of the device.
func TestParseWSUAWK1137CRealFrame(t *testing.T) {
	frame := mustHex(t, fixtureWSUReplyAWK1137C)
	if len(frame) != wsuReplyLenAWK1132C {
		t.Fatalf("fixture length = %d, want the measured %d bytes", len(frame), wsuReplyLenAWK1132C)
	}
	// 234 bytes is a valid reply length, not the 218 of the documented layout.
	if !wsuLengthConsistent(frame) {
		t.Fatalf("[4:8] does not match len-36 = %d", len(frame)-wsuLengthBias)
	}
	if got := len(frame); got == wsuReplyLen {
		t.Fatalf("fixture is the 218 byte layout, expected the measured 234 byte one")
	}

	device, ok := ParseWSU(frame)
	if !ok {
		t.Fatal("ParseWSU rejected the real AWK-1137C reply")
	}
	if device.Model != "AWK-1137C-EU" {
		t.Errorf("Model = %q, want AWK-1137C-EU", device.Model)
	}
	if device.IP != awkWSUAnswerIP {
		t.Errorf("IP = %q, want %s", device.IP, awkWSUAnswerIP)
	}
	if device.MAC != awkWSUMAC {
		t.Errorf("MAC = %q, want %s", device.MAC, awkWSUMAC)
	}
	if device.Protocol != ProtoNameWSU {
		t.Errorf("Protocol = %q, want %q", device.Protocol, ProtoNameWSU)
	}

	// The three magic words of the same family decode the same frame.
	for _, magic := range []uint16{wsuMagicAWK1131A, wsuMagicAWK1132C, wsuMagicAWK1137C, wsuMagicAWK1137CBD} {
		variant := append([]byte(nil), frame...)
		variant[0], variant[1] = byte(magic>>8), byte(magic&0xFF)
		if _, accepted := ParseWSU(variant); !accepted {
			t.Errorf("frame with magic %#04x was rejected", magic)
		}
	}
}

// TestParseVersionReplyAWK1137C pins the real 0x16 answer of the device: the
// minor byte 0x0b must be read as eleven, so the row reports V1.11.
func TestParseVersionReplyAWK1137C(t *testing.T) {
	payload := mustHex(t, fixtureVersionReplyAWK1137C)
	if len(payload) != 36 {
		t.Fatalf("fixture length = %d, want the measured 36 bytes", len(payload))
	}

	deviceID, version, shortSerial, ok := ParseVersionReply(payload)
	if !ok {
		t.Fatal("ParseVersionReply rejected the real AWK-1137C answer")
	}
	if version != "V1.11" {
		t.Errorf("version = %q, want V1.11", version)
	}
	if shortSerial != 0 {
		t.Errorf("shortSerial = %d, want 0", shortSerial)
	}
	if got, want := hexString(deviceID), "3012198902770090e800004e"; got != want {
		t.Errorf("deviceID = %s, want %s", got, want)
	}
}

// TestVersionFromTail4800AllKnownTruths is the encoding table of the minor
// version byte: the three truths measured on hardware plus every value that has
// to stay invalid instead of being guessed.
func TestVersionFromTail4800AllKnownTruths(t *testing.T) {
	tests := []struct {
		name     string
		device   string
		minorBCD byte
		major    byte
		want     string
		wantOK   bool
	}{
		{name: "MGate MB3180", device: "MGate MB3180", minorBCD: 0x07, major: 0x02, want: "V2.7", wantOK: true},
		{name: "NPort 6450", device: "NPort 6450", minorBCD: 0x10, major: 0x01, want: "V1.10", wantOK: true},
		{name: "AWK-1137C", device: "AWK-1137C", minorBCD: 0x0b, major: 0x01, want: "V1.11", wantOK: true},
		{name: "AWK-1132C", device: "AWK-1132C", minorBCD: 0x00, major: 0x01, want: "V1.0", wantOK: true},
		{name: "0x1A is a multi digit byte with an impossible low digit", minorBCD: 0x1A, major: 0x01, want: "", wantOK: false},
		{name: "0xA1 has no decimal high digit", minorBCD: 0xA1, major: 0x01, want: "", wantOK: false},
		{name: "major zero is not a version", minorBCD: 0x05, major: 0x00, want: "", wantOK: false},
		{name: "single digit form 0x0c", minorBCD: 0x0c, major: 0x02, want: "V2.12", wantOK: true},
		{name: "single digit form 0x0f", minorBCD: 0x0f, major: 0x03, want: "V3.15", wantOK: true},
		{name: "highest two digit minor 0x99", minorBCD: 0x99, major: 0x01, want: "V1.99", wantOK: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := versionFromTail4800(test.minorBCD, test.major)
			if ok != test.wantOK {
				t.Fatalf("versionFromTail4800(%#02x, %#02x) ok = %v, want %v",
					test.minorBCD, test.major, ok, test.wantOK)
			}
			if got != test.want {
				t.Errorf("versionFromTail4800(%#02x, %#02x) = %q, want %q",
					test.minorBCD, test.major, got, test.want)
			}
		})
	}
}

// TestMinorFromTail4800 covers the decoder itself, byte by byte.
func TestMinorFromTail4800(t *testing.T) {
	tests := []struct {
		value  byte
		want   int
		wantOK bool
	}{
		{value: 0x00, want: 0, wantOK: true},
		{value: 0x05, want: 5, wantOK: true},
		{value: 0x0A, want: 10, wantOK: true},
		{value: 0x0b, want: 11, wantOK: true},
		{value: 0x0f, want: 15, wantOK: true},
		{value: 0x10, want: 10, wantOK: true},
		{value: 0x27, want: 27, wantOK: true},
		{value: 0x99, want: 99, wantOK: true},
		{value: 0x1A, want: 0, wantOK: false},
		{value: 0xA1, want: 0, wantOK: false},
		{value: 0xFF, want: 0, wantOK: false},
	}
	for _, test := range tests {
		got, ok := minorFromTail4800(test.value)
		if ok != test.wantOK || (ok && got != test.want) {
			t.Errorf("minorFromTail4800(%#02x) = %d, %v; want %d, %v",
				test.value, got, ok, test.want, test.wantOK)
		}
	}
}

// TestSameAddressDeviceIsNotMislabeledAfterMerge pins the third defect that the
// real machine run exposed: when the WSU row of a device is stored before its
// 4800 discovery answer, the 12 byte identity only becomes known through the
// merge. The identity index of the aggregator has to learn about it, otherwise
// the 0x96 answer of the device is matched by IP only and is written to every
// other device that shares the address - measured once as an AWK-1131A row
// reporting the firmware V1.11 of the AWK-1137C.
func TestSameAddressDeviceIsNotMislabeledAfterMerge(t *testing.T) {
	aggregator := newAggregator()
	awkID := mustHexBytes("3012198902770090e800004e")

	// 1. The WSU reply of the AWK-1137C arrives first: a row without identity.
	aggregator.add(&Device{
		IP:       awkWSUAnswerIP,
		MAC:      awkWSUMAC,
		Model:    "AWK-1137C-EU",
		Protocol: ProtoNameWSU,
	})

	// 2. The other wireless device of the same address (no 4800 answer at all).
	aggregator.add(&Device{
		IP:       awkWSUAnswerIP,
		MAC:      "50:0B:88:00:01:9F",
		Model:    "AWK-1131A-EU",
		Protocol: ProtoNameWSU,
	})

	// 3. The 4800 discovery answer of the AWK-1137C merges its identity in.
	aggregator.add(&Device{
		IP:       awkWSUAnswerIP,
		MAC:      awkWSUMAC,
		Protocol: ProtoName4800,
		deviceID: awkID,
	})

	if !aggregator.setVersion(awkID, awkWSUAnswerIP, "V1.11", 0) {
		t.Fatal("setVersion did not reach the AWK-1137C row")
	}

	rows := aggregator.snapshot()
	byMAC := make(map[string]Device, len(rows))
	for _, row := range rows {
		byMAC[row.MAC] = row
	}
	if got := byMAC[awkWSUMAC].Firmware; got != "V1.11" {
		t.Errorf("AWK-1137C firmware = %q, want V1.11", got)
	}
	if got := byMAC["50:0B:88:00:01:9F"].Firmware; got != "" {
		t.Errorf("AWK-1131A firmware = %q, want empty (it never answers 0x16)", got)
	}
	if got := byMAC["50:0B:88:00:01:9F"].Model; got != "AWK-1131A-EU" {
		t.Errorf("AWK-1131A model = %q, want AWK-1131A-EU", got)
	}
}

// startFakeAWK1137C emulates the UDP/4800 side of the device on the loopback
// address: it answers the three detail queries the way the AWK-1137C does
// (0x03 / 0x10 "no data", 0x16 with the captured version tail).
//
// The helper skips the test instead of failing when the port cannot be taken,
// so a busy machine never turns a passing suite red.
func startFakeAWK1137C(t *testing.T, versionTail []byte) (stop func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port4800})
	if err != nil {
		t.Skipf("无法在 127.0.0.1:%d 上模拟设备: %v", port4800, err)
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, source, readErr := conn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			if n < queryLen4800 || source == nil {
				continue
			}
			request := append([]byte(nil), buffer[:n]...)
			var reply []byte
			switch request[0] {
			case cmd4800Model:
				reply = buildDetailReply(replyHeader4800Model, flagNoData4800, request[8:20], nil)
			case cmd4800Name:
				reply = buildDetailReply(replyHeader4800Name, flagNoData4800, request[8:20], nil)
			case cmd4800Version:
				frame := make([]byte, queryLen4800)
				frame[0] = replyHeader4800Version
				frame[3] = byte(queryLen4800 + len(versionTail))
				copy(frame[8:20], request[8:20])
				reply = append(frame, versionTail...)
			default:
				continue
			}
			_, _ = conn.WriteToUDP(reply, source)
		}
	}()
	return func() {
		_ = conn.Close()
		<-done
	}
}

// loopbackIndex returns the interface index of the loopback adapter, which is
// what IP_UNICAST_IF has to be pinned to for the mock device to be reachable.
func loopbackIndex() int {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 1
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Index
		}
	}
	return 1
}

// TestAWK1137CEndToEnd replays the whole receive path of the device - the 0x81
// discovery answer, the captured 234 byte WSU frame (magic 0x1DBF) and the
// three detail queries of queryOneDevice against a local mock - and asserts the
// final row: one row for the AWK with model, region and firmware filled, and a
// second device that shares its address left untouched.
//
// Only the address field of the captured WSU frame is rewritten (the mock
// device has to answer on the loopback), every other byte is the captured one.
func TestAWK1137CEndToEnd(t *testing.T) {
	awkID := mustHexBytes("3012198902770090e800004e")
	deviceIP := net.IPv4(127, 0, 0, 1)
	versionPayload := mustHex(t, fixtureVersionReplyAWK1137C)
	stop := startFakeAWK1137C(t, versionPayload[queryLen4800:])
	defer stop()

	aggregator := newAggregator()
	loopback := Adapter{
		Name:  "回环",
		IP:    deviceIP,
		Mask:  net.CIDRMask(8, 32),
		Index: loopbackIndex(),
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: deviceIP, Port: 0})
	if err != nil {
		t.Fatalf("无法创建测试套接字: %v", err)
	}
	defer func() { _ = socket.Close() }()

	ep4800 := &endpoint{adapter: loopback, spec: protocol4800(), conn: socket}
	epWSU := &endpoint{adapter: loopback, spec: protocolWSU(), conn: socket}

	// 1. The 0x81 discovery answer: it creates the row and stores the 12 byte
	// identity that the detail queries need.
	discovery := make([]byte, minLen4800)
	discovery[0] = replyHeader4800
	discovery[3] = minLen4800
	copy(discovery[8:20], awkID)
	copy(discovery[20:24], deviceIP.To4())
	handleReply(ep4800, discovery, deviceIP, aggregator)

	// 2. A second device on the same address (the reference network has an
	// EDS-518E answering from the very same IP): it must keep its own empty
	// model and firmware columns.
	decoyMAC := "00:90:E8:12:34:56"
	aggregator.add(&Device{
		IP:       deviceIP.String(),
		MAC:      decoyMAC,
		Protocol: ProtoName4800,
		Adapters: []string{"回环"},
		deviceID: mustHexBytes("00310080ed5e0090e8123456"),
	})

	// 3. The captured WSU reply (magic 0x1DBF) fills the model column.
	wsuFrame := mustHex(t, fixtureWSUReplyAWK1137C)
	copyFixedString(wsuFrame[wsuIPOffset:wsuIPOffset+wsuIPLen], deviceIP.String())
	handleReply(epWSU, wsuFrame, deviceIP, aggregator)

	// 4. The three detail queries of the real code path; the mock answers the
	// 0x16 query with the captured version tail.
	target := Device{
		IP:       deviceIP.String(),
		MAC:      awkWSUMAC,
		Protocol: ProtoName4800,
		Adapters: []string{"回环"},
		deviceID: awkID,
	}
	queryOneDevice(context.Background(), loopback, target, detailQueryMin, aggregator)

	rows := aggregator.snapshot()
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (the AWK and the device sharing its address): %+v", len(rows), rows)
	}
	byMAC := make(map[string]Device, len(rows))
	for _, row := range rows {
		byMAC[row.MAC] = row
	}

	awk, ok := byMAC[awkWSUMAC]
	if !ok {
		t.Fatalf("the AWK-1137C row is missing, got %+v", rows)
	}
	if awk.Model != "AWK-1137C-EU" {
		t.Errorf("AWK model = %q, want AWK-1137C-EU", awk.Model)
	}
	if awk.Firmware != "V1.11" {
		t.Errorf("AWK firmware = %q, want V1.11", awk.Firmware)
	}
	if awk.Region != "EU" {
		t.Errorf("AWK region = %q, want EU", awk.Region)
	}
	if awk.IP != deviceIP.String() {
		t.Errorf("AWK IP = %q, want %s", awk.IP, deviceIP.String())
	}

	decoy, ok := byMAC[decoyMAC]
	if !ok {
		t.Fatalf("the device sharing the address is missing, got %+v", rows)
	}
	if decoy.Model != "" {
		t.Errorf("decoy model = %q, want empty", decoy.Model)
	}
	if decoy.Firmware != "" {
		t.Errorf("decoy firmware = %q, want empty", decoy.Firmware)
	}
	if decoy.Region != "" {
		t.Errorf("decoy region = %q, want empty", decoy.Region)
	}
}
