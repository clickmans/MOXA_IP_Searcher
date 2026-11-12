package discovery

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"math/rand"
	"testing"
)

// Firmware block of the WIFI4 (UDP/5800) reply - PROTOCOL_SPEC.md §5.3.1.
//
// The tail of a WSU reply is not a plain field: it is a 25 byte AES-128-ECB
// block holding two OVERLAPPING 16 byte cipher blocks, written by the device as
// enc(buf[0:16]) and then enc(buf[9:25]). Decrypting therefore has to run in the
// reverse order, [9:25] first.
const (
	// fixtureFWBlockAWK1131A is the captured tail [193:218] of the 218 byte
	// AWK-1131A-EU reply (_analysis/wifi_frames.txt).
	fixtureFWBlockAWK1131A = "31b7ede93df933b0e2ec5c89f4c349802f3a1ad0dde03159e8"
	// fixtureFWBlockAWK1137C is the captured tail [193:221] of the 234 byte
	// AWK-1137C-EU reply (same capture file). Only the FIRST 25 bytes take part
	// in the decryption: the trailing "9br0" of the fourty one byte tail belong
	// to the next field.
	fixtureFWBlockAWK1137C = "884796b9c85c8095ffdc8c5d3a2283e82bb80f1fd07a4e6839627230"
	// fixtureFWBlockAWK1132C is the captured tail [193:218] of the AWK-1132C-US
	// reply (third independent vector, cross checked against a freshly cut
	// frame). Its plain text is one byte shorter than the others - "1.0" instead
	// of "1.11" - which is exactly why the sanitiser must not require a fixed
	// version width.
	fixtureFWBlockAWK1132C = "3cb631650df5ddce8e0d9690d83c1a8fbc3c41ef23d33d952f"

	// wantFirmwareAWK1131A / wantFirmwareAWK1137C / wantFirmwareAWK1132C are the
	// strings the vendor's Wireless Search Utility shows for the three captured
	// blocks.
	wantFirmwareAWK1131A = "1.27 Build 25092317"
	wantFirmwareAWK1137C = "1.11 Build 25092317"
	wantFirmwareAWK1132C = "1.0 Build 24031213"

	// fixtureFWBlockZero is a block of 25 NUL bytes: the plain text it decodes
	// to is not printable, so the sanitiser has to reject it.
	fixtureFWBlockZero = "00000000000000000000000000000000000000000000000000"
)

// wsuFrameWithFirmwareBlock returns a complete 218 byte WSU reply whose tail
// [193:218] carries the given 25 byte block.
//
// The frame is the synthesized template of protocol_test.go (documented layout,
// correct magic, correct reply marker and correct sub frame length), so the
// parser accepts it and every field except the firmware stays as documented.
func wsuFrameWithFirmwareBlock(t *testing.T, block string) []byte {
	t.Helper()
	raw := mustHex(t, block)
	if len(raw) != wsuFirmwareBlockLen {
		t.Fatalf("block length = %d, want the fixed %d bytes", len(raw), wsuFirmwareBlockLen)
	}
	frame := buildWSUReply("AWK-1131A-US", "192.168.100.253", "50:0B:88:00:01:9F", "255.255.255.0", "192.168.100.100")
	if len(frame) != wsuFirmwareMinPayloadLen {
		t.Fatalf("template length = %d, want %d", len(frame), wsuFirmwareMinPayloadLen)
	}
	copy(frame[wsuFirmwareOffset:wsuFirmwareOffset+wsuFirmwareBlockLen], raw)
	return frame
}

// TestDecodeWSUFirmwareCapturedBlocks is the truth table of the decoder: the
// three captured blocks of three different device models plus every input that
// has to yield an empty string instead of a garbled one.
func TestDecodeWSUFirmwareCapturedBlocks(t *testing.T) {
	awk1131A := mustHex(t, fixtureFWBlockAWK1131A)
	// The AWK-1137C tail is 28 bytes long; the first 25 are the block.
	awk1137C := mustHex(t, fixtureFWBlockAWK1137C)[:wsuFirmwareBlockLen]

	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{name: "AWK-1131A captured block", input: wsuFrameWithFirmwareBlock(t, fixtureFWBlockAWK1131A), want: wantFirmwareAWK1131A},
		{name: "AWK-1137C captured block (first 25 of 28 bytes)", input: wsuFrameWithFirmwareBlock(t, hex.EncodeToString(awk1137C)), want: wantFirmwareAWK1137C},
		{name: "AWK-1132C captured block", input: wsuFrameWithFirmwareBlock(t, fixtureFWBlockAWK1132C), want: wantFirmwareAWK1132C},
		{name: "raw block alone is not a payload", input: awk1131A, want: ""},
		{name: "short frame of 100 bytes is skipped", input: make([]byte, 100), want: ""},
		{name: "frame one byte too short for the block", input: make([]byte, wsuFirmwareMinPayloadLen-1), want: ""},
		{name: "all zero ciphertext is not printable", input: wsuFrameWithFirmwareBlock(t, fixtureFWBlockZero), want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := DecodeWSUFirmware(test.input); got != test.want {
				t.Errorf("DecodeWSUFirmware(%d bytes) = %q, want %q", len(test.input), got, test.want)
			}
		})
	}
}

// TestDecodeWSUFirmwareDoesNotTouchPayload pins that the decoder works on a copy:
// the received frame is kept verbatim (the GUI and the packet captures compare
// it byte by byte), so decryption must never write back into payload.
func TestDecodeWSUFirmwareDoesNotTouchPayload(t *testing.T) {
	frame := wsuFrameWithFirmwareBlock(t, fixtureFWBlockAWK1131A)
	before := append([]byte(nil), frame...)

	if got := DecodeWSUFirmware(frame); got != wantFirmwareAWK1131A {
		t.Fatalf("DecodeWSUFirmware = %q, want %q", got, wantFirmwareAWK1131A)
	}
	if !bytes.Equal(before, frame) {
		t.Errorf("the payload was modified by the decoder:\n before=%x\n after =%x", before, frame)
	}
}

// TestWSUFirmwareEncryptionRoundTrip proves the algorithm in BOTH directions,
// the way PROTOCOL_SPEC.md §5.3.1 verified it: encrypting the plain string with
// the fixed key and the device's ordering (write [0:16] first, then the
// overlapping [9:25]) reproduces the captured ciphertext byte for byte. A
// decoder that gets the order or the key size wrong cannot pass this test.
func TestWSUFirmwareEncryptionRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		plain    string
		captured string
	}{
		{name: "AWK-1131A", plain: wantFirmwareAWK1131A, captured: fixtureFWBlockAWK1131A},
		{name: "AWK-1137C", plain: wantFirmwareAWK1137C, captured: fixtureFWBlockAWK1137C[:50]},
		{name: "AWK-1132C", plain: wantFirmwareAWK1132C, captured: fixtureFWBlockAWK1132C},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block, err := aes.NewCipher(wsuFirmwareKey[:])
			if err != nil {
				t.Fatalf("aes.NewCipher: %v", err)
			}
			// NUL padded plain text, exactly the 25 bytes the device encrypts.
			buf := make([]byte, wsuFirmwareBlockLen)
			copy(buf, test.plain)
			// Device order: encrypt the head block, then the overlapping tail.
			head := make([]byte, wsuCipherBlockLen)
			block.Encrypt(head, buf[0:wsuCipherBlockLen])
			copy(buf[0:wsuCipherBlockLen], head)
			tail := make([]byte, wsuCipherBlockLen)
			block.Encrypt(tail, buf[wsuFirmwareTailOffset:wsuFirmwareTailOffset+wsuCipherBlockLen])
			copy(buf[wsuFirmwareTailOffset:wsuFirmwareTailOffset+wsuCipherBlockLen], tail)

			if got, want := hex.EncodeToString(buf), hex.EncodeToString(mustHex(t, test.captured)); got != want {
				t.Errorf("re-encrypted block = %s, want the captured %s", got, want)
			}
			if got := DecodeWSUFirmware(wsuFrameWithFirmwareBlock(t, hex.EncodeToString(buf))); got != test.plain {
				t.Errorf("DecodeWSUFirmware of the re-encrypted block = %q, want %q", got, test.plain)
			}
		})
	}
}

// TestParseWSUFirmwareFromFrame checks the integration point: the parser puts the
// decoded version into Device.Firmware (marked provisional), and the model /
// address / MAC decoding of the same frame is untouched.
func TestParseWSUFirmwareFromFrame(t *testing.T) {
	tests := []struct {
		name            string
		block           string
		want            string
		wantProvisional bool
	}{
		{name: "AWK-1131A block", block: fixtureFWBlockAWK1131A, want: wantFirmwareAWK1131A, wantProvisional: true},
		{name: "all zero block stays empty", block: fixtureFWBlockZero, want: "", wantProvisional: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frame := wsuFrameWithFirmwareBlock(t, test.block)
			device, ok := ParseWSU(frame)
			if !ok {
				t.Fatal("ParseWSU rejected the frame")
			}
			if device.Firmware != test.want {
				t.Errorf("Firmware = %q, want %q", device.Firmware, test.want)
			}
			// The rest of the row must be unaffected by the new field.
			if device.Model != "AWK-1131A-US" {
				t.Errorf("Model = %q, want AWK-1131A-US", device.Model)
			}
			if device.IP != "192.168.100.253" {
				t.Errorf("IP = %q, want 192.168.100.253", device.IP)
			}
			if device.MAC != "50:0B:88:00:01:9F" {
				t.Errorf("MAC = %q, want 50:0B:88:00:01:9F", device.MAC)
			}
			if device.Protocol != ProtoNameWSU {
				t.Errorf("Protocol = %q, want %q", device.Protocol, ProtoNameWSU)
			}
		})
	}
}

// TestParseWSUFirmwareOfRealAWK1137CFrame runs the decoder over the captured
// 234 byte reply: the block sits at the same offset in the longer frame, so the
// real frame of the device reports "1.11 Build 25092317" - the string the
// official WSU shows - while the 4800 answer of the same device keeps saying
// V1.11 (both are right, they are two renderings of the same build).
func TestParseWSUFirmwareOfRealAWK1137CFrame(t *testing.T) {
	frame := mustHex(t, fixtureWSUReplyAWK1137C)
	if len(frame) != wsuReplyLenAWK1132C {
		t.Fatalf("fixture length = %d, want %d", len(frame), wsuReplyLenAWK1132C)
	}
	device, ok := ParseWSU(frame)
	if !ok {
		t.Fatal("ParseWSU rejected the captured AWK-1137C reply")
	}
	if device.Firmware != wantFirmwareAWK1137C {
		t.Errorf("Firmware = %q, want %q", device.Firmware, wantFirmwareAWK1137C)
	}
	if device.Model != "AWK-1137C-EU" {
		t.Errorf("Model = %q, want AWK-1137C-EU", device.Model)
	}
	if device.MAC != awkWSUMAC {
		t.Errorf("MAC = %q, want %s", device.MAC, awkWSUMAC)
	}
}

// TestWSUFirmwareDoesNotOverwriteKnownFirmware pins the precedence rule in the
// order that a real scan sees it: another protocol already answered a version,
// so the decoded one must not replace it - while a row that has no firmware at
// all receives it.
func TestWSUFirmwareDoesNotOverwriteKnownFirmware(t *testing.T) {
	parsed, ok := ParseWSU(wsuFrameWithFirmwareBlock(t, fixtureFWBlockAWK1131A))
	if !ok {
		t.Fatal("ParseWSU rejected the frame")
	}
	if parsed.Firmware != wantFirmwareAWK1131A {
		t.Fatalf("parsed Firmware = %q, want %q", parsed.Firmware, wantFirmwareAWK1131A)
	}
	parsed.Adapters = appendUnique(nil, "WLAN")

	// 1. A row that already knows its version (e.g. the 0x16 answer) keeps it.
	known := newAggregator()
	known.add(&Device{
		IP:       "192.168.100.253",
		MAC:      "50:0B:88:00:01:9F",
		Model:    "AWK-1131A-EU",
		Firmware: "V1.11",
		Protocol: ProtoName4800,
		Adapters: []string{"WLAN"},
	})
	known.add(parsed)
	rows := known.snapshot()
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1 (same MAC and IP): %+v", len(rows), rows)
	}
	if rows[0].Firmware != "V1.11" {
		t.Errorf("Firmware = %q, want the known V1.11 to survive", rows[0].Firmware)
	}
	if rows[0].FirmwareProvisional {
		t.Error("FirmwareProvisional = true, want false for an answered version")
	}

	// 2. A row without any firmware receives the decoded value.
	fresh := newAggregator()
	fresh.add(parsed)
	freshRows := fresh.snapshot()
	if len(freshRows) != 1 {
		t.Fatalf("rows = %d, want 1", len(freshRows))
	}
	if freshRows[0].Firmware != wantFirmwareAWK1131A {
		t.Errorf("Firmware = %q, want %q", freshRows[0].Firmware, wantFirmwareAWK1131A)
	}
	if !freshRows[0].FirmwareProvisional {
		t.Error("FirmwareProvisional = false, want true for a decoded version")
	}
}

// TestAnsweredVersionReplacesProvisionalFirmware covers the other arrival order,
// the one the reference AWK-1137C produces: the WSU reply is received before the
// 0x16 answer, and the answer of the device itself then takes over.
func TestAnsweredVersionReplacesProvisionalFirmware(t *testing.T) {
	deviceID := mustHexBytes("3012198902770090e800004e")
	aggregator := newAggregator()

	// The WSU reply first: a row without identity carrying a decoded version.
	parsed, ok := ParseWSU(mustHex(t, fixtureWSUReplyAWK1137C))
	if !ok {
		t.Fatal("ParseWSU rejected the captured AWK-1137C reply")
	}
	aggregator.add(parsed)

	// The 4800 discovery answer merges the identity in, the 0x16 answer brings
	// the version the device reports about itself.
	aggregator.add(&Device{
		IP:       awkWSUAnswerIP,
		MAC:      awkWSUMAC,
		Protocol: ProtoName4800,
		deviceID: deviceID,
	})
	if !aggregator.setVersion(deviceID, awkWSUAnswerIP, "V1.11", 0) {
		t.Fatal("setVersion did not reach the AWK row")
	}

	rows := aggregator.snapshot()
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1: %+v", len(rows), rows)
	}
	if rows[0].Firmware != "V1.11" {
		t.Errorf("Firmware = %q, want V1.11 (the 0x96 answer wins over the decoded string)", rows[0].Firmware)
	}
	if rows[0].FirmwareProvisional {
		t.Error("FirmwareProvisional = true, want false after the 0x96 answer")
	}
}

// TestProvisionalFirmwareKeepsDetailQueriesRunning pins that a row whose only
// firmware is a decoded one is still a candidate for the 0x83 / 0x10 / 0x16
// queries: the decoded string must not make the device look complete.
func TestProvisionalFirmwareKeepsDetailQueriesRunning(t *testing.T) {
	deviceID := mustHexBytes("3012198902770090e800004e")
	aggregator := newAggregator()
	aggregator.add(&Device{
		IP:                  awkWSUAnswerIP,
		MAC:                 awkWSUMAC,
		Model:               "AWK-1137C-EU",
		Name:                "AWK-1137C",
		Firmware:            wantFirmwareAWK1137C,
		FirmwareProvisional: true,
		Protocol:            ProtoNameWSU,
		deviceID:            deviceID,
		Adapters:            []string{"WLAN"},
	})

	pending := aggregator.pendingDetailQueries()
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want the row of the device: %+v", len(pending), pending)
	}

	// Once the device answered its version, the row is complete and is not
	// queried again.
	if !aggregator.setVersion(deviceID, awkWSUAnswerIP, "V1.11", 0) {
		t.Fatal("setVersion did not reach the row")
	}
	if got := aggregator.pendingDetailQueries(); len(got) != 0 {
		t.Errorf("pending after the answer = %d, want 0: %+v", len(got), got)
	}
}

// TestSanitizeWSUFirmware is the byte level table of the sanitiser: printable
// ASCII up to the first NUL, 4..24 characters, and at least one '.', otherwise
// nothing at all.
func TestSanitizeWSUFirmware(t *testing.T) {
	padded := func(s string) []byte {
		buf := make([]byte, wsuFirmwareBlockLen)
		copy(buf, s)
		return buf
	}
	tests := []struct {
		name string
		buf  []byte
		want string
	}{
		{name: "captured plain text", buf: padded(wantFirmwareAWK1131A), want: wantFirmwareAWK1131A},
		{name: "shortest captured version", buf: padded(wantFirmwareAWK1132C), want: wantFirmwareAWK1132C},
		{name: "24 characters is the maximum", buf: padded("1.234567890123456789012"), want: "1.234567890123456789012"},
		{name: "no NUL terminator is rejected", buf: bytes.Repeat([]byte{'A'}, wsuFirmwareBlockLen), want: ""},
		{name: "embedded NUL after printable text", buf: padded("1.27\x00Build"), want: "1.27"},
		{name: "leading NUL is empty", buf: padded("\x00abc"), want: ""},
		{name: "control character is rejected", buf: padded("1.27\tBuild"), want: ""},
		{name: "high byte is rejected", buf: padded("1.27\x9bBuild"), want: ""},
		{name: "non ASCII UTF-8 tail is rejected", buf: padded("1.27 Build \xe4\xb8\xad"), want: ""},
		{name: "surrounding blanks are trimmed", buf: padded("  1.27 Build 25092317  "), want: wantFirmwareAWK1131A},
		{name: "blank only is empty", buf: padded("    "), want: ""},
		{name: "all zero block", buf: make([]byte, wsuFirmwareBlockLen), want: ""},

		// The printable fragments QA observed with random blocks: too short to
		// be a version, no matter how printable they are.
		{name: "1 printable character", buf: padded("f"), want: ""},
		{name: "2 printable characters", buf: padded("Qx"), want: ""},
		{name: "3 printable characters", buf: padded("reC"), want: ""},
		{name: "3 printable characters with a dot", buf: padded("1.2"), want: ""},
		// Long enough, but not the "<major>.<minor> Build <build>" shape.
		{name: "8 printable characters without a dot", buf: padded("abcdefgh"), want: ""},
		{name: "printable sentence without a dot", buf: padded("1,27 Build"), want: ""},
		{name: "dot but no digit", buf: padded("..reC"), want: ""},
		{name: "letters and a dot but no digit", buf: padded("reC.build"), want: ""},
		{name: "digits and a dot with a V prefix", buf: padded("V1.0"), want: "V1.0"},
		{name: "shortest accepted shape", buf: padded("10.1"), want: "10.1"},
		{name: "3 character version is below the floor", buf: padded("1.0\x00"), want: ""},
		{name: "trailing blank does not count towards the length", buf: padded("1.0 "), want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sanitizeWSUFirmware(test.buf); got != test.want {
				t.Errorf("sanitizeWSUFirmware(% x) = %q, want %q", test.buf, got, test.want)
			}
		})
	}
}

// TestDecodeWSUFirmwareRandomBlocksStayEmpty replays the negative experiment of
// the QA report: 2000 random 25 byte blocks decrypt to printable fragments in
// about 0.5% of the cases ('f', 'Q', 'reC', '"Wg', ...), and none of them may
// reach the 固件版本号 column.
//
// The generator is seeded, so the test is deterministic and the same 2000
// blocks are tried on every run; the count is asserted to be zero rather than
// "smaller than before" so a future loosening of the sanitiser fails loudly.
func TestDecodeWSUFirmwareRandomBlocksStayEmpty(t *testing.T) {
	const (
		blockCount = 2000
		seed       = 20261103
	)
	source := rand.New(rand.NewSource(seed))
	block := make([]byte, wsuFirmwareBlockLen)
	accepted := make([]string, 0, 4)
	for index := 0; index < blockCount; index++ {
		if _, err := source.Read(block); err != nil {
			t.Fatalf("random source failed: %v", err)
		}
		frame := wsuFrameWithFirmwareBlock(t, hex.EncodeToString(block))
		if got := DecodeWSUFirmware(frame); got != "" {
			accepted = append(accepted, got)
		}
	}
	if len(accepted) != 0 {
		t.Errorf("%d of %d random blocks reached the firmware column: %q", len(accepted), blockCount, accepted)
	}
}
