package discovery

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

// axomReplyTLV is one type/value pair used to assemble a synthetic AXOM frame.
type axomReplyTLV struct {
	typ   uint32
	value []byte
}

// buildAXOMReply assembles an AXOM reply from TLVs.
//
// The 40 byte prefix is magic(4) + len(1) + pad(3) + type(4) + bodyLen(4) +
// seq(4) + nonceLen(4) + nonce(16); only the magic matters for the parser.
// Every TLV is `type(BE32) | len(LE32) | value`, padded to a 4 byte boundary.
func buildAXOMReply(tlvs []axomReplyTLV) []byte {
	frame := make([]byte, axomTLVOffset)
	copy(frame[0:4], []byte("AXOM"))
	frame[4] = 0x7c
	for _, tlv := range tlvs {
		header := make([]byte, 8)
		binary.BigEndian.PutUint32(header[0:4], tlv.typ)
		binary.LittleEndian.PutUint32(header[4:8], uint32(len(tlv.value)))
		frame = append(frame, header...)
		frame = append(frame, tlv.value...)
		if pad := len(tlv.value) % 4; pad != 0 {
			frame = append(frame, make([]byte, 4-pad)...)
		}
	}
	return frame
}

// TestParseAXOMFirmware covers U7: the firmware TLV 0x36001000 carries the
// version string, and the serial / description / location TLVs of the same frame
// are decoded into the struct without being displayed.
func TestParseAXOMFirmware(t *testing.T) {
	frame := buildAXOMReply([]axomReplyTLV{
		{typ: axomTypeIP, value: []byte{192, 168, 127, 3}},
		{typ: axomTypeMAC, value: []byte{0x50, 0x0B, 0x88, 0x0E, 0x1B, 0x53}},
		{typ: axomTypeName, value: append([]byte("eom-106"), 0, 0)},
		// "V3.1.10 build 26102915\n" - the exact capture confirmed on hardware.
		{typ: axomTypeFirmware, value: []byte("56332e312e3130206275696c642032363130323931350a")},
		{typ: axomTypeSerial, value: []byte("SN12345678")},
		{typ: axomTypeDescription, value: []byte("4d61696e")},      // "Main"
		{typ: axomTypeLocation, value: []byte("4c6f636174696f6e")}, // "Location"
	})

	device, ok := ParseAXOM(frame)
	if !ok {
		t.Fatal("ParseAXOM rejected a well formed frame")
	}
	if device.Firmware != "V3.1.10 build 26102915" {
		t.Errorf("Firmware = %q, want %q", device.Firmware, "V3.1.10 build 26102915")
	}
	if device.Name != "eom-106" {
		t.Errorf("Name = %q, want eom-106", device.Name)
	}
	if device.IP != "192.168.127.3" {
		t.Errorf("IP = %q, want 192.168.127.3", device.IP)
	}
	if device.Serial != "SN12345678" {
		t.Errorf("Serial = %q, want SN12345678", device.Serial)
	}
	if device.Description != "Main" {
		t.Errorf("Description = %q, want Main", device.Description)
	}
	if device.Location != "Location" {
		t.Errorf("Location = %q, want Location", device.Location)
	}
}

// axomRealCapture is a verbatim EOM-106 reply captured from 192.168.127.4 with
// _analysis/ui_v11/probe_axom.py. The firmware TLV value is PLAIN ASCII here
// (`56 33 2e 31 2e 31 30 ...` reads "V3.1.10 build 26102915\n"), while the
// specification described it as hex encoded - both encodings must work.
const axomRealCapture = "41584f4d20010000000801011801000000000001100000000000000000000000" +
	"0000000000000000320000010c0000004d4f5841524453414d504c4533000001060000" +
	"000090e80005d000003400000107000000454f4d2d3130360031000001040000008600" +
	"00001000000104000000c0a87f041100000104000000ffffff00120000010400000000" +
	"0000001300000104000000000000001310000104000000000000003600100017000000" +
	"56332e312e3130206275696c642032363130323931350a00370000011e0000004d616e" +
	"6167656420526564756e64616e74205377697463682030303030370000380000010f00" +
	"0000537769746368204c6f636174696f6e003a00000101000000040000003900000104" +
	"000000c0a800a33b00000102000000bb010000"

// TestParseAXOMRealCaptureFirmware decodes the real device answer end to end.
func TestParseAXOMRealCaptureFirmware(t *testing.T) {
	device, ok := ParseAXOM(mustHex(t, axomRealCapture))
	if !ok {
		t.Fatal("ParseAXOM rejected the captured EOM-106 reply")
	}
	if device.Firmware != "V3.1.10 build 26102915" {
		t.Errorf("Firmware = %q, want %q", device.Firmware, "V3.1.10 build 26102915")
	}
	if device.IP != "192.168.127.4" {
		t.Errorf("IP = %q, want 192.168.127.4", device.IP)
	}
	if device.MAC != "00:90:E8:00:05:D0" {
		t.Errorf("MAC = %q, want 00:90:E8:00:05:D0", device.MAC)
	}
	if device.Name != "EOM-106" {
		t.Errorf("Name = %q, want EOM-106", device.Name)
	}
	if device.Serial != "MOXARDSAMPLE" {
		t.Errorf("Serial = %q, want MOXARDSAMPLE", device.Serial)
	}
	if device.Description != "Managed Redundant Switch 00007" {
		t.Errorf("Description = %q", device.Description)
	}
	if device.Location != "Switch Location" {
		t.Errorf("Location = %q", device.Location)
	}
	// The model TLV does not exist on this product, which is exactly why the
	// UI falls back to the name for the 产品型号 column (U4).
	if device.Model != "" {
		t.Errorf("Model = %q, want empty", device.Model)
	}
}

// TestParseAXOMWithoutFirmware makes sure a frame without the firmware TLV -
// the case of most products - simply leaves the field empty.
func TestParseAXOMWithoutFirmware(t *testing.T) {
	device, ok := ParseAXOM(mustHex(t, fixtureAXOMReply))
	if !ok {
		t.Fatal("ParseAXOM rejected the reference fixture")
	}
	if device.Firmware != "" {
		t.Errorf("Firmware = %q, want empty", device.Firmware)
	}
}

// TestDecodeAXOMHexText pins the decoder rules of U7: hex encoded ASCII (the
// documented form) and plain ASCII (the form the hardware actually sends) are
// both accepted, everything else degrades to an empty value.
func TestDecodeAXOMHexText(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "hex form with trailing newline",
			input: []byte("56332e312e3130206275696c642032363130323931350a"),
			want:  "V3.1.10 build 26102915",
		},
		{
			name:  "hex form with crlf and spaces",
			input: []byte("56332e300d0a2020"),
			want:  "V3.0",
		},
		{
			name:  "hex form without padding",
			input: []byte("56332e31"),
			want:  "V3.1",
		},
		{
			name:  "plain ascii as sent by the EOM-106",
			input: []byte("V3.1.10 build 26102915\n"),
			want:  "V3.1.10 build 26102915",
		},
		{
			name:  "plain ascii with crlf",
			input: []byte("V3.0\r\n"),
			want:  "V3.0",
		},
		{
			name:  "plain ascii that is not hex at all",
			input: []byte("zzzz"),
			want:  "zzzz",
		},
		{
			name:  "empty",
			input: nil,
			want:  "",
		},
		{
			name:  "non printable bytes",
			input: []byte{0xff, 0xfe},
			want:  "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := decodeAXOMHexText(test.input); got != test.want {
				t.Errorf("decodeAXOMHexText(%x) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

// TestDecodeAXOMHexTextFromInvalidVendor proves a truncated vendor string does
// not leak a half decoded firmware version into the column.
func TestDecodeAXOMHexTextFromInvalidVendor(t *testing.T) {
	raw, err := hex.DecodeString("56332e312e3130ff3135")
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	if got := decodeAXOMHexText(raw); got != "" {
		t.Errorf("decodeAXOMHexText = %q, want empty (0xFF is not printable)", got)
	}
}

// TestParse4800Firmware covers U7 for the 4800 property reply: the "Firmware"
// key is used when the product reports it (MGate / NPort firmware does not, in
// which case the field stays empty and no extra request is sent).
func TestParse4800Firmware(t *testing.T) {
	deviceID := mustHex(t, "005101801a51500b880f8c29")
	payload := make([]byte, 20)
	payload[0] = replyHeader4800Model
	copy(payload[8:20], deviceID)
	payload = append(payload, []byte("Model\tMB3180\nFirmware\tV2.5 build 210915\n")...)

	id, model, firmware, ok := ParseModelReplyFull(payload)
	if !ok {
		t.Fatal("ParseModelReplyFull returned false")
	}
	if len(id) != 12 {
		t.Errorf("device id = %x, want 12 bytes", id)
	}
	if model != "MB3180" {
		t.Errorf("model = %q, want MB3180", model)
	}
	if firmware != "V2.5 build 210915" {
		t.Errorf("firmware = %q, want %q", firmware, "V2.5 build 210915")
	}

	// A reply with only "Model" - the real MGate MB3180 case - must not fail
	// and must leave the firmware empty.
	withoutFirmware := append([]byte(nil), payload[:20]...)
	withoutFirmware = append(withoutFirmware, []byte("Model\tMB3180\n")...)
	_, model, firmware, ok = ParseModelReplyFull(withoutFirmware)
	if !ok || model != "MB3180" || firmware != "" {
		t.Errorf("model=%q firmware=%q ok=%v, want MB3180 / \"\" / true", model, firmware, ok)
	}

	// A firmware-only reply is still usable.
	firmwareOnly := append([]byte(nil), payload[:20]...)
	firmwareOnly = append(firmwareOnly, []byte("Firmware\tV2.6\n")...)
	_, model, firmware, ok = ParseModelReplyFull(firmwareOnly)
	if !ok || model != "" || firmware != "V2.6" {
		t.Errorf("model=%q firmware=%q ok=%v, want \"\" / V2.6 / true", model, firmware, ok)
	}
}

// TestParsersWithoutFirmwareField proves the other protocols keep the firmware
// column empty instead of inventing a value (U7).
func TestParsersWithoutFirmwareField(t *testing.T) {
	from4800, ok := Parse4800(mustHex(t, fixture4800Reply24))
	if !ok {
		t.Fatal("Parse4800 rejected the reference fixture")
	}
	if from4800.Firmware != "" {
		t.Errorf("4800 Firmware = %q, want empty", from4800.Firmware)
	}

	from4000, ok := Parse4000(mustHex(t, fixture4000Reply64), net.IPv4(192, 168, 127, 3))
	if !ok {
		t.Fatal("Parse4000 rejected the reference fixture")
	}
	if from4000.Firmware != "" {
		t.Errorf("4000 Firmware = %q, want empty", from4000.Firmware)
	}

	fromWSU, ok := ParseWSU(buildWSUReply("AWK-1131A-US", "192.168.127.253", "50:0B:88:09:2B:DC", "255.255.255.0", "192.168.127.100"))
	if !ok {
		t.Fatal("ParseWSU rejected the synthesized fixture")
	}
	if fromWSU.Firmware != "" {
		t.Errorf("5800 Firmware = %q, want empty", fromWSU.Firmware)
	}
}

// TestAggregatorSetFirmware mirrors TestAggregatorSetModel: one 0x83 answer
// fills the firmware of every row of that device.
func TestAggregatorSetFirmware(t *testing.T) {
	aggregator := newAggregator()
	deviceID := make([]byte, 12)
	copy(deviceID, []byte{0x00, 0x26, 0x00, 0x80, 0x52, 0x26, 0x50, 0x0B, 0x88, 0x10, 0x23, 0x89})
	for _, ip := range []string{"192.168.127.254", "192.168.127.253"} {
		aggregator.add(&Device{IP: ip, MAC: "50:0B:88:10:23:89", Protocol: ProtoName4800, Adapters: []string{"WLAN"}, deviceID: deviceID})
	}

	if !aggregator.setFirmware(deviceID, "192.168.127.254", "V2.5 build 210915") {
		t.Fatal("setFirmware did not match the stored device id")
	}
	for _, device := range aggregator.snapshot() {
		if device.Firmware != "V2.5 build 210915" {
			t.Errorf("%s: Firmware = %q, want the answered version", device.IP, device.Firmware)
		}
	}
	if aggregator.setFirmware(deviceID, "", "") {
		t.Error("setFirmware accepted an empty version")
	}
}

// TestMergeKeepsFirmware verifies that merging a second observation of the same
// device never wipes an already known firmware string.
func TestMergeKeepsFirmware(t *testing.T) {
	aggregator := newAggregator()
	aggregator.add(&Device{IP: "192.168.127.3", MAC: "50:0B:88:0E:1B:53", Protocol: ProtoName4800, Firmware: "V3.1.10 build 26102915", Adapters: []string{"WLAN"}})
	aggregator.add(&Device{IP: "192.168.127.3", MAC: "50:0B:88:0E:1B:53", Protocol: ProtoNameAXOM, Name: "eom-106", Adapters: []string{"WLAN"}})

	devices := aggregator.snapshot()
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
	if devices[0].Firmware != "V3.1.10 build 26102915" {
		t.Errorf("Firmware = %q, want the value seen by the first observation", devices[0].Firmware)
	}
	if devices[0].Name != "eom-106" {
		t.Errorf("Name = %q, want eom-106", devices[0].Name)
	}
}

// TestDeviceStats covers the U6 counting rules used by the status bar.
func TestDeviceStats(t *testing.T) {
	tests := []struct {
		name      string
		devices   []Device
		wantCount int
		wantDup   int
	}{
		{
			name:      "empty",
			devices:   nil,
			wantCount: 0,
			wantDup:   0,
		},
		{
			name: "one device one address",
			devices: []Device{
				{IP: "192.168.127.253", MAC: "50:0B:88:09:2B:DC"},
			},
			wantCount: 1,
			wantDup:   0,
		},
		{
			name: "one device two addresses counts once",
			devices: []Device{
				{IP: "192.168.127.254", MAC: "50:0B:88:10:23:89"},
				{IP: "192.168.127.253", MAC: "50:0B:88:10:23:89"},
			},
			wantCount: 1,
			wantDup:   0,
		},
		{
			name: "two devices sharing one IP",
			devices: []Device{
				{IP: "192.168.127.253", MAC: "50:0B:88:09:2B:DC"},
				{IP: "192.168.127.253", MAC: "00:90:E8:00:05:D0"},
				{IP: "192.168.127.254", MAC: "50:0B:88:0F:8C:29"},
			},
			wantCount: 3,
			wantDup:   2,
		},
		{
			name: "rows without MAC each count as one device",
			devices: []Device{
				{IP: "192.168.127.10", Protocol: ProtoName29168},
				{IP: "192.168.127.10", Protocol: ProtoName1029},
			},
			wantCount: 2,
			wantDup:   2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := DeviceCount(test.devices); got != test.wantCount {
				t.Errorf("DeviceCount = %d, want %d", got, test.wantCount)
			}
			if got := DuplicateIPDeviceCount(test.devices); got != test.wantDup {
				t.Errorf("DuplicateIPDeviceCount = %d, want %d", got, test.wantDup)
			}
		})
	}
}

// TestFirmwareTrimKeepsInnerSpaces guards the trimming rule: only the outer
// whitespace of a decoded value is removed.
func TestFirmwareTrimKeepsInnerSpaces(t *testing.T) {
	value := []byte(hex.EncodeToString([]byte("  V3.1.10 build 2610  \n")))
	got := decodeAXOMHexText(value)
	if got != "V3.1.10 build 2610" {
		t.Errorf("decodeAXOMHexText = %q, want %q", got, "V3.1.10 build 2610")
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("decodeAXOMHexText = %q, want no line breaks", got)
	}
}
