package discovery

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// deviceIDNPort6450 is the 12 byte identity of the NPort 6450 in the reference
// network (192.168.127.250, MAC 00:90:E8:3C:F2:20).
var deviceIDNPort6450 = mustHexBytes("0060008050640090e83cf220")

// deviceIDMGateMB3180 is the 12 byte identity of the MGate MB3180 in the
// reference network (192.168.127.254, MAC 00:90:E8:F1:DA:9B).
var deviceIDMGateMB3180 = mustHexBytes("0031008000310090e8f1da9b")

// mustHexBytes decodes a hex string outside of a *testing.T (package level vars).
func mustHexBytes(encoded string) []byte {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		panic("bad fixture: " + encoded)
	}
	return raw
}

// buildDetailReply assembles a 4800 detail answer with an optional payload.
//
//	frame[0]    = reply command (0x83 / 0x90 / 0x96)
//	frame[1]    = flags (0x04 => no data)
//	frame[2:4]  = total length (BE16)
//	frame[4:8]  = sequence number
//	frame[8:20] = device id
//	frame[20:]  = payload
func buildDetailReply(command, flags byte, deviceID, payload []byte) []byte {
	frame := make([]byte, queryLen4800)
	frame[0] = command
	frame[1] = flags
	frame[3] = byte(queryLen4800 + len(payload))
	copy(frame[8:20], deviceID)
	return append(frame, payload...)
}

// buildVersionReply assembles a real 36 byte 0x96 answer.
//
//	tail[2] = minor version, BCD encoded
//	tail[3] = major version, decimal
//	tail[8:10] = short serial number, little endian
func buildVersionReply(deviceID []byte, minorBCD, major byte, shortSerial uint16) []byte {
	tail := make([]byte, 16)
	tail[2] = minorBCD
	tail[3] = major
	tail[8] = byte(shortSerial)
	tail[9] = byte(shortSerial >> 8)
	frame := make([]byte, queryLen4800)
	frame[0] = replyHeader4800Version
	frame[3] = byte(queryLen4800 + len(tail))
	copy(frame[8:20], deviceID)
	return append(frame, tail...)
}

// TestParseVersionReplyRealDevices pins the two version formats that were cross
// checked against the vendor tools on hardware (v1.2):
//
//	MGate MB3180: minor 0x07 major 0x02 -> V2.7  (MXConfig: V2.7build25060913)
//	NPort 6450:   minor 0x10 major 0x01 -> V1.10 (DSU: Ver1.10)
func TestParseVersionReplyRealDevices(t *testing.T) {
	tests := []struct {
		name        string
		deviceID    []byte
		minorBCD    byte
		major       byte
		shortSerial uint16
		wantVersion string
	}{
		{
			name:        "MGate MB3180",
			deviceID:    deviceIDMGateMB3180,
			minorBCD:    0x07,
			major:       0x02,
			shortSerial: 579,
			wantVersion: "V2.7",
		},
		{
			name:        "NPort 6450 minor is BCD, so 0x10 is ten",
			deviceID:    deviceIDNPort6450,
			minorBCD:    0x10,
			major:       0x01,
			shortSerial: 5599,
			wantVersion: "V1.10",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := buildVersionReply(test.deviceID, test.minorBCD, test.major, test.shortSerial)
			if len(payload) != 36 {
				t.Fatalf("frame length = %d, want the measured 36 bytes", len(payload))
			}
			deviceID, version, shortSerial, ok := ParseVersionReply(payload)
			if !ok {
				t.Fatalf("ParseVersionReply rejected %x", payload)
			}
			if version != test.wantVersion {
				t.Errorf("version = %q, want %q", version, test.wantVersion)
			}
			if shortSerial != test.shortSerial {
				t.Errorf("shortSerial = %d, want %d", shortSerial, test.shortSerial)
			}
			if !bytes.Equal(deviceID, test.deviceID) {
				t.Errorf("deviceID = %x, want %x", deviceID, test.deviceID)
			}
		})
	}
}

// TestVersionFromTail4800BCDBoundaries covers the decoding rule itself,
// including every value that must be rejected instead of guessed.
func TestVersionFromTail4800BCDBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		minorBCD byte
		major    byte
		want     string
		wantOK   bool
	}{
		{name: "v1.10", minorBCD: 0x10, major: 1, want: "V1.10", wantOK: true},
		{name: "v1.0 minor zero is a real version", minorBCD: 0x00, major: 1, want: "V1.0", wantOK: true},
		{name: "v2.7", minorBCD: 0x07, major: 2, want: "V2.7", wantOK: true},
		{name: "v3.99 highest two digit minor", minorBCD: 0x99, major: 3, want: "V3.99", wantOK: true},
		{name: "v9.9 highest single digit", minorBCD: 0x09, major: 9, want: "V9.9", wantOK: true},
		{name: "major zero is not a version", minorBCD: 0x07, major: 0, want: "", wantOK: false},
		{name: "major above 99 is implausible", minorBCD: 0x07, major: 100, want: "", wantOK: false},
		{name: "major 255 is implausible", minorBCD: 0x07, major: 0xFF, want: "", wantOK: false},
		{name: "minor high nibble is not BCD", minorBCD: 0x1A, major: 2, want: "", wantOK: false},
		{name: "minor low nibble is not BCD", minorBCD: 0xA1, major: 2, want: "", wantOK: false},
		{name: "minor 0xFF is not BCD", minorBCD: 0xFF, major: 2, want: "", wantOK: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := versionFromTail4800(test.minorBCD, test.major)
			if ok != test.wantOK {
				t.Fatalf("versionFromTail4800(%#02x, %d) ok = %v, want %v", test.minorBCD, test.major, ok, test.wantOK)
			}
			if got != test.want {
				t.Errorf("versionFromTail4800(%#02x, %d) = %q, want %q", test.minorBCD, test.major, got, test.want)
			}
		})
	}
}

// TestBCDToDecimal documents the encoding rule in one place: the minor version
// byte is BCD, so 0x10 means ten and never sixteen.
func TestBCDToDecimal(t *testing.T) {
	tests := []struct {
		value  byte
		want   int
		wantOK bool
	}{
		{value: 0x00, want: 0, wantOK: true},
		{value: 0x07, want: 7, wantOK: true},
		{value: 0x10, want: 10, wantOK: true},
		{value: 0x99, want: 99, wantOK: true},
		{value: 0x1A, want: 0, wantOK: false},
		{value: 0xA0, want: 0, wantOK: false},
		{value: 0xFF, want: 0, wantOK: false},
	}
	for _, test := range tests {
		got, ok := BCDToDecimal(test.value)
		if ok != test.wantOK || (ok && got != test.want) {
			t.Errorf("BCDToDecimal(%#02x) = %d, %v; want %d, %v", test.value, got, ok, test.want, test.wantOK)
		}
	}
}

// TestParseVersionReplyInvalidAnswers makes sure a truncated, mismatched or
// "no data" answer leaves the firmware column empty instead of inventing a
// version.
func TestParseVersionReplyInvalidAnswers(t *testing.T) {
	valid := buildVersionReply(deviceIDMGateMB3180, 0x07, 0x02, 579)

	t.Run("wrong command byte", func(t *testing.T) {
		broken := append([]byte(nil), valid...)
		broken[0] = replyHeader4800Model
		if _, _, _, ok := ParseVersionReply(broken); ok {
			t.Error("ParseVersionReply accepted a 0x83 frame")
		}
	})

	t.Run("truncated tail", func(t *testing.T) {
		if _, _, _, ok := ParseVersionReply(valid[:22]); ok {
			t.Error("ParseVersionReply accepted a 22 byte frame")
		}
	})

	t.Run("no data flag", func(t *testing.T) {
		rejected := buildDetailReply(replyHeader4800Version, flagNoData4800, deviceIDMGateMB3180, nil)
		_, version, _, ok := ParseVersionReply(rejected)
		if ok || version != "" {
			t.Errorf("version = %q ok = %v, want empty / false", version, ok)
		}
	})

	t.Run("header only", func(t *testing.T) {
		headerOnly := buildDetailReply(replyHeader4800Version, 0, deviceIDMGateMB3180, nil)
		if _, version, _, ok := ParseVersionReply(headerOnly); ok || version != "" {
			t.Errorf("version = %q ok = %v, want empty / false", version, ok)
		}
	})
}

// TestParseModelReplyNoData pins the v1.2 rule for the answer the NPort 6450
// gives to the 0x03 model query:
//
//	83 04 00 14 <seq:4B> <deviceID:12B>      (20 bytes, flag 0x04, no payload)
//
// That is "command not supported / no data" - a valid answer, not a parse error.
// The model stays empty and the fallback chain (name -> model) takes over.
func TestParseModelReplyNoData(t *testing.T) {
	rejected := buildDetailReply(replyHeader4800Model, flagNoData4800, deviceIDNPort6450, nil)
	if len(rejected) != 20 {
		t.Fatalf("len(rejected) = %d, want the measured 20 bytes", len(rejected))
	}
	deviceID, model, firmware, ok := ParseModelReplyFull(rejected)
	if ok {
		t.Error("ParseModelReplyFull reported a model for a no-data answer")
	}
	if model != "" || firmware != "" {
		t.Errorf("model = %q firmware = %q, want both empty", model, firmware)
	}
	if !bytes.Equal(deviceID, deviceIDNPort6450) {
		t.Errorf("deviceID = %x, want the echoed identity", deviceID)
	}
	// The same 20 byte frame is not a discovery reply either (no IP inside).
	if _, ok := Parse4800(rejected); ok {
		t.Error("Parse4800 accepted a 20 byte frame as a device")
	}

	// A frame that only carries the header without the flag bit is just as
	// empty: no payload means no model.
	headerOnly := buildDetailReply(replyHeader4800Model, 0, deviceIDNPort6450, nil)
	if _, model, _, ok := ParseModelReplyFull(headerOnly); ok || model != "" {
		t.Errorf("model = %q ok = %v, want empty / false", model, ok)
	}
}

// TestParseNameReply covers the 0x10 answer: the name is the first NUL
// terminated ASCII string after the 20 byte header.
func TestParseNameReply(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		wantName string
		wantOK   bool
	}{
		{
			name:     "NPort 6450 with serial suffix",
			payload:  append([]byte("NP6450_5599"), 0, 0, 0),
			wantName: "NP6450_5599",
			wantOK:   true,
		},
		{
			name:     "MGate MB3180 with serial suffix",
			payload:  append([]byte("MG-MB3180_579"), 0, 0),
			wantName: "MG-MB3180_579",
			wantOK:   true,
		},
		{
			name:     "name fills the frame without terminator",
			payload:  []byte("NP5110A"),
			wantName: "NP5110A",
			wantOK:   true,
		},
		{
			name:     "empty name",
			payload:  []byte{0, 0, 0, 0},
			wantName: "",
			wantOK:   false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frame := buildDetailReply(replyHeader4800Name, 0, deviceIDNPort6450, test.payload)
			deviceID, name, ok := ParseNameReply(frame)
			if ok != test.wantOK || name != test.wantName {
				t.Fatalf("name = %q ok = %v, want %q / %v", name, ok, test.wantName, test.wantOK)
			}
			if ok && !bytes.Equal(deviceID, deviceIDNPort6450) {
				t.Errorf("deviceID = %x, want the echoed identity", deviceID)
			}
		})
	}

	// A no-data answer is not a name.
	rejected := buildDetailReply(replyHeader4800Name, flagNoData4800, deviceIDNPort6450, nil)
	if _, name, ok := ParseNameReply(rejected); ok || name != "" {
		t.Errorf("name = %q ok = %v, want empty / false", name, ok)
	}
	// A 0x83 frame must never be read as a name.
	modelFrame := buildDetailReply(replyHeader4800Model, 0, deviceIDNPort6450, []byte("Model\tX\n"))
	if _, name, ok := ParseNameReply(modelFrame); ok || name != "" {
		t.Errorf("name = %q ok = %v, want empty / false", name, ok)
	}
}

// TestBuildDetailRequests pins the on-the-wire shape of the three detail
// requests: 20 bytes, command byte, BE16 length 0x14, sequence number and the
// 12 byte identity.
func TestBuildDetailRequests(t *testing.T) {
	builders := map[string]struct {
		build   func([]byte, uint32) []byte
		command byte
	}{
		"0x03 model":   {build: BuildModelRequest, command: cmd4800Model},
		"0x10 name":    {build: BuildNameRequest, command: cmd4800Name},
		"0x16 version": {build: BuildVersionRequest, command: cmd4800Version},
	}
	for label, builder := range builders {
		request := builder.build(deviceIDNPort6450, 0x01020304)
		if len(request) != 20 {
			t.Fatalf("%s: len = %d, want 20", label, len(request))
		}
		if request[0] != builder.command {
			t.Errorf("%s: command = %#02x, want %#02x", label, request[0], builder.command)
		}
		if request[1] != 0 || request[2] != 0 || request[3] != 0x14 {
			t.Errorf("%s: header = % x, want 00 00 14", label, request[1:4])
		}
		if got := request[4:8]; !bytes.Equal(got, []byte{1, 2, 3, 4}) {
			t.Errorf("%s: sequence = % x, want 01 02 03 04", label, got)
		}
		if !bytes.Equal(request[8:20], deviceIDNPort6450) {
			t.Errorf("%s: identity = %x, want %x", label, request[8:20], deviceIDNPort6450)
		}
	}

	// An identity of the wrong length cannot be asked about.
	if request := BuildNameRequest([]byte{1, 2, 3}, 1); request != nil {
		t.Errorf("BuildNameRequest with a short id = % x, want nil", request)
	}
	if request := BuildVersionRequest(nil, 1); request != nil {
		t.Errorf("BuildVersionRequest with no id = % x, want nil", request)
	}
	// The three requests of one device must differ only in their command byte.
	model := BuildModelRequest(deviceIDNPort6450, 7)
	name := BuildNameRequest(deviceIDNPort6450, 7)
	version := BuildVersionRequest(deviceIDNPort6450, 7)
	if bytes.Equal(model, name) || bytes.Equal(name, version) || bytes.Equal(model, version) {
		t.Error("the three detail requests are not distinguishable")
	}
}
