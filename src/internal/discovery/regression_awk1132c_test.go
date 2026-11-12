package discovery

import (
	"net"
	"testing"
)

// AWK-1132C regression fixtures (bug AWK-1132C: the device was discovered but
// both the 产品型号 and the 固件版本 columns stayed empty).
//
// Device under test: IP 192.168.100.253, MAC 00:90:E8:00:00:D7,
// 12 byte identity 3012198903770090e80000d7.
const (
	// fixtureWSUReplyAWK1132C is the real 234 byte UDP/5800 reply, taken
	// verbatim from the capture file _analysis/wifi4_frames.txt (line 6). The
	// frame differs from the documented AWK-1131A layout in two ways: the magic
	// is 0x0DBF and it is 16 bytes longer.
	fixtureWSUReplyAWK1132C = "0dbf0001000000c60004a768384314b1000000000090e80000d7246a0e1a4cfd" +
		"00000003000100c20001000100bc41574b2d31313332432d5553000000000000" +
		"0000000000000000000000000000003139322e3136382e3130302e3235330030" +
		"303a39303a45383a30303a30303a4437003235352e3235352e3235352e300000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"00000000000000000000000000000000003139322e3136382e3130302e313030" +
		"003cb631650df5ddce8e0d9690d83c1a8fbc3c41ef23d33d952f627230000000" +
		"00000000000000000000"

	// fixtureVersionReplyAWK1132C is the real 36 byte UDP/4800 0x16 answer of
	// the same device: 20 byte header + tail
	// 00 00 00 01 00 0d 0d 01 00 00 00 00 01 00 02 00.
	fixtureVersionReplyAWK1132C = "96000024" + "00000001" + "3012198903770090e80000d7" +
		"00000001000d0d010000000001000200"
)

// TestParseWSUAWK1132CRealFrame pins the whole regression: the captured frame
// must be accepted and must yield the model, the IP and the MAC of the device.
func TestParseWSUAWK1132CRealFrame(t *testing.T) {
	frame := mustHex(t, fixtureWSUReplyAWK1132C)
	if len(frame) != wsuReplyLenAWK1132C {
		t.Fatalf("fixture length = %d, want the measured %d bytes", len(frame), wsuReplyLenAWK1132C)
	}
	// The frame is self consistent: [4:8] must equal len-36.
	if !wsuLengthConsistent(frame) {
		t.Fatalf("[4:8] = %d does not match len-36 = %d", len(frame)-wsuLengthBias, len(frame)-wsuLengthBias)
	}

	device, ok := ParseWSU(frame)
	if !ok {
		t.Fatal("ParseWSU rejected the real AWK-1132C reply")
	}
	if device.Model != "AWK-1132C-US" {
		t.Errorf("Model = %q, want AWK-1132C-US", device.Model)
	}
	if device.IP != "192.168.100.253" {
		t.Errorf("IP = %q, want 192.168.100.253", device.IP)
	}
	if device.MAC != "00:90:E8:00:00:D7" {
		t.Errorf("MAC = %q, want 00:90:E8:00:00:D7", device.MAC)
	}
	if device.Protocol != ProtoNameWSU {
		t.Errorf("Protocol = %q, want %q", device.Protocol, ProtoNameWSU)
	}
}

// TestIsWSUMagicAcceptanceMatrix documents which magic words are known and
// proves that an arbitrary datagram cannot enter the parser.
func TestIsWSUMagicAcceptanceMatrix(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		want  bool
	}{
		{name: "AWK-1131A 0x0DBD", value: 0x0DBD, want: true},
		{name: "AWK-1132C 0x0DBF", value: 0x0DBF, want: true},
		{name: "unrelated 0x1234", value: 0x1234, want: false},
		{name: "same low byte but wrong family", value: 0x00BF, want: false},
		{name: "family byte only", value: 0x0D00, want: false},
		{name: "zero", value: 0x0000, want: false},
		{name: "request frame marker", value: 0x0001, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isWSUMagic(test.value); got != test.want {
				t.Errorf("isWSUMagic(%#04x) = %v, want %v", test.value, got, test.want)
			}
		})
	}
}

// TestParseWSURejectsStructurallyInvalidFrames keeps the frame acceptance
// narrow: only the magic words above, at least 32 bytes, and the 0x0001 reply
// marker at [2:4].
func TestParseWSURejectsStructurallyInvalidFrames(t *testing.T) {
	real := mustHex(t, fixtureWSUReplyAWK1132C)

	t.Run("unknown magic 0x1234", func(t *testing.T) {
		frame := append([]byte(nil), real...)
		frame[0], frame[1] = 0x12, 0x34
		if _, ok := ParseWSU(frame); ok {
			t.Error("frame with magic 0x1234 was accepted")
		}
	})

	t.Run("too short 20 bytes", func(t *testing.T) {
		if _, ok := ParseWSU(append([]byte(nil), real[:20]...)); ok {
			t.Error("20 byte frame was accepted")
		}
	})

	t.Run("reply marker is not 0x0001", func(t *testing.T) {
		frame := append([]byte(nil), real...)
		frame[wsuFlagOffset], frame[wsuFlagOffset+1] = 0x00, 0x02
		if _, ok := ParseWSU(frame); ok {
			t.Error("frame without the 0x0001 reply marker was accepted")
		}
	})

	t.Run("empty and random payloads", func(t *testing.T) {
		for index, payload := range [][]byte{nil, {}, {0x0D, 0xBF}, make([]byte, 40)} {
			if _, ok := ParseWSU(payload); ok {
				t.Errorf("payload %d was accepted as a WSU reply", index)
			}
		}
	})
}

// TestParseWSUMismatchedLengthFallsBackToScan proves that a frame whose
// declared length contradicts the real length is not trusted blindly: the fixed
// offsets are dropped and the scan fallback recovers the IP.
func TestParseWSUMismatchedLengthFallsBackToScan(t *testing.T) {
	frame := mustHex(t, fixtureWSUReplyAWK1132C)
	// Declare a length that fits a 218 byte frame while the frame is 234 bytes.
	frame[wsuLengthOffset], frame[wsuLengthOffset+1] = 0x00, 0x00
	frame[wsuLengthOffset+2], frame[wsuLengthOffset+3] = 0x00, 0xB6

	if wsuLengthConsistent(frame) {
		t.Fatal("wsuLengthConsistent accepted a contradicting length field")
	}
	device, ok := ParseWSU(frame)
	if !ok {
		t.Fatal("ParseWSU rejected a frame that still carries an IP")
	}
	if device.IP != "192.168.100.253" {
		t.Errorf("IP = %q, want 192.168.100.253 (recovered by scanning)", device.IP)
	}
	if device.Model != "" {
		t.Errorf("Model = %q, want empty for an untrusted layout", device.Model)
	}
}

// TestVersionFromTail4800AWK1132C pins the second half of the regression: the
// real 0x16 tail of the AWK-1132C must render as V1.0 instead of being dropped.
func TestVersionFromTail4800AWK1132C(t *testing.T) {
	payload := mustHex(t, fixtureVersionReplyAWK1132C)
	if len(payload) != 36 {
		t.Fatalf("fixture length = %d, want the measured 36 bytes", len(payload))
	}

	deviceID, version, shortSerial, ok := ParseVersionReply(payload)
	if !ok {
		t.Fatal("ParseVersionReply rejected the real AWK-1132C answer")
	}
	if version != "V1.0" {
		t.Errorf("version = %q, want V1.0", version)
	}
	if shortSerial != 0 {
		t.Errorf("shortSerial = %d, want 0", shortSerial)
	}
	if got, want := hexString(deviceID), "3012198903770090e80000d7"; got != want {
		t.Errorf("deviceID = %s, want %s", got, want)
	}
}

// TestVersionFromTail4800StillRejectsInvalidValues keeps the other guards in
// place: only "minor == 0" became valid, everything implausible stays invalid.
func TestVersionFromTail4800StillRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name     string
		minorBCD byte
		major    byte
		want     string
		wantOK   bool
	}{
		{name: "V1.0 from the AWK-1132C tail", minorBCD: 0x00, major: 0x01, want: "V1.0", wantOK: true},
		{name: "major zero stays invalid", minorBCD: 0x00, major: 0x00, want: "", wantOK: false},
		{name: "0x1A is not BCD", minorBCD: 0x1A, major: 0x01, want: "", wantOK: false},
		{name: "0xA1 is not BCD", minorBCD: 0xA1, major: 0x01, want: "", wantOK: false},
		{name: "0xFF is not BCD", minorBCD: 0xFF, major: 0x01, want: "", wantOK: false},
		{name: "0xFA has an invalid low nibble", minorBCD: 0xFA, major: 0x01, want: "", wantOK: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := versionFromTail4800(test.minorBCD, test.major)
			if ok != test.wantOK {
				t.Fatalf("versionFromTail4800(%#02x, %#02x) ok = %v, want %v", test.minorBCD, test.major, ok, test.wantOK)
			}
			if got != test.want {
				t.Errorf("versionFromTail4800(%#02x, %#02x) = %q, want %q", test.minorBCD, test.major, got, test.want)
			}
		})
	}
}

// TestAWK1132COneRowWithModelAndFirmware replays both captured answers through
// the real receive path (handleReply: adapter stamping, the 0x83 interception,
// the protocol decoder and the aggregator) and asserts the merge result: one
// single row for the AWK, with model and firmware filled, next to the two other
// devices that share its IP.
//
// The 5800 frame comes from the capture file, i.e. this is a mock replay of the
// real frame: while the fix was verified the device did not answer UDP/5800.
func TestAWK1132COneRowWithModelAndFirmware(t *testing.T) {
	aggregator := newAggregator()
	ether := Adapter{Name: "以太网", IP: net.IPv4(192, 168, 100, 100)}
	ep4800 := &endpoint{adapter: ether, spec: protocol4800()}
	epWSU := &endpoint{adapter: ether, spec: protocolWSU()}
	sourceIP := net.IPv4(192, 168, 100, 253)

	// 0x81 discovery answer of the AWK (built from the captured 12 byte id and
	// the captured address).
	awkID := mustHexBytes("3012198903770090e80000d7")
	discovery := make([]byte, 24)
	discovery[0] = replyHeader4800
	discovery[3] = 24
	copy(discovery[8:20], awkID)
	copy(discovery[20:24], []byte{192, 168, 100, 253})
	handleReply(ep4800, discovery, sourceIP, aggregator)

	otherDevices := []struct {
		mac string
		id  string
	}{
		{mac: "00:90:E8:12:34:56", id: "0031008012340090e812345600"},
		{mac: "00:90:E8:00:00:53", id: "003100800e530090e800005300"},
	}
	for _, other := range otherDevices {
		aggregator.add(&Device{
			IP:       "192.168.100.253",
			MAC:      other.mac,
			Protocol: ProtoName4800,
			Adapters: []string{"以太网"},
			deviceID: mustHexBytes(other.id),
		})
	}

	// The WSU reply carries the model, the 0x16 answer the firmware.
	wsuFrame := mustHex(t, fixtureWSUReplyAWK1132C)
	handleReply(epWSU, wsuFrame, sourceIP, aggregator)
	wsUser, ok := ParseWSU(wsuFrame)
	if !ok {
		t.Fatal("ParseWSU rejected the real AWK-1132C reply")
	}
	if !aggregator.setModel(awkID, "192.168.100.253", wsUser.Model) {
		t.Fatal("setModel did not reach the AWK row")
	}
	versionID, version, shortSerial, ok := ParseVersionReply(mustHex(t, fixtureVersionReplyAWK1132C))
	if !ok {
		t.Fatal("ParseVersionReply rejected the real AWK-1132C answer")
	}
	if !aggregator.setVersion(versionID, "192.168.100.253", version, shortSerial) {
		t.Fatal("setVersion did not reach the AWK row")
	}

	rows := aggregator.snapshot()
	byMAC := make(map[string]Device, len(rows))
	for _, row := range rows {
		byMAC[row.MAC] = row
	}

	awk, ok := byMAC["00:90:E8:00:00:D7"]
	if !ok {
		t.Fatalf("the AWK row is missing, got %d rows: %+v", len(rows), rows)
	}
	if awk.Model != "AWK-1132C-US" {
		t.Errorf("AWK model = %q, want AWK-1132C-US", awk.Model)
	}
	if awk.Firmware != "V1.0" {
		t.Errorf("AWK firmware = %q, want V1.0", awk.Firmware)
	}
	if awk.IP != "192.168.100.253" {
		t.Errorf("AWK IP = %q, want 192.168.100.253", awk.IP)
	}
	if len(awk.Adapters) != 1 || awk.Adapters[0] != "以太网" {
		t.Errorf("AWK adapters = %v, want [以太网]", awk.Adapters)
	}

	// The two devices sharing the IP must stay separate rows.
	for _, mac := range []string{"00:90:E8:12:34:56", "00:90:E8:00:00:53"} {
		other, ok := byMAC[mac]
		if !ok {
			t.Errorf("the row of %s was dropped", mac)
			continue
		}
		if other.Model == "AWK-1132C-US" {
			t.Errorf("%s: model was overwritten with the AWK model", mac)
		}
		if other.Firmware != "" {
			t.Errorf("%s: firmware = %q, want empty", mac, other.Firmware)
		}
	}
}

// hexString renders b as lowercase hex without importing encoding/hex twice.
func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0x0F])
	}
	return string(out)
}
