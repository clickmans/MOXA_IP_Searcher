package lldp

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// TestEncodeOID pins the hand written BER OID encoder against the byte string
// that was captured from MXConfigCS asking for lldpLocChassisId.
func TestEncodeOID(t *testing.T) {
	tests := []struct {
		oid  string
		want string
	}{
		// 1.0 -> 40 (0x28), 8802 -> 0xC4 0x62 (base 128), then 1.1.2.1.3.2.0.
		{oid: "1.0.8802.1.1.2.1.3.2.0", want: "060a28c46201010201030200"},
		{oid: "1.3.6.1.2.1.1.5.0", want: "06082b06010201010500"},
		{oid: "1.0.8802.1.1.2.1.4.1.1.5.0.4.1", want: "060e28c4620101020104010105000401"},
	}
	for _, test := range tests {
		t.Run(test.oid, func(t *testing.T) {
			encoded, err := encodeOID(test.oid)
			if err != nil {
				t.Fatalf("encodeOID(%q) error: %v", test.oid, err)
			}
			got := hex.EncodeToString(encoded)
			want := strings.ReplaceAll(test.want, " ", "")
			if got != want {
				t.Fatalf("encodeOID(%q) = %s, want %s", test.oid, got, want)
			}
			// Round trip through the decoder as well.
			if decoded := decodeOID(encoded[2:]); decoded != test.oid {
				t.Fatalf("decodeOID round trip = %q, want %q", decoded, test.oid)
			}
		})
	}

	for _, invalid := range []string{"", "1", "1.x.3", "3.1.1", "1.40.1", "1..2"} {
		if _, err := encodeOID(invalid); err == nil {
			t.Errorf("encodeOID(%q) must fail", invalid)
		}
	}
}

// TestEncodeRequestStructure decodes a freshly built request and checks every
// field the agent will look at: SEQUENCE, version 1 (SNMPv2c), community
// "public", the PDU tag and one NULL valued varbind.
func TestEncodeRequestStructure(t *testing.T) {
	for _, pduTag := range []byte{pduGetRequest, pduGetNextRequest} {
		packet, err := encodeRequest(pduTag, 4711, DefaultCommunity, oidChassisID)
		if err != nil {
			t.Fatalf("encodeRequest(%#x) error: %v", pduTag, err)
		}
		if packet[0] != tagSequence {
			t.Fatalf("first byte = %#x, want 0x30", packet[0])
		}
		message, _, err := readTLV(packet, 0)
		if err != nil {
			t.Fatalf("readTLV: %v", err)
		}
		version, offset, err := readTLV(message.content, 0)
		if err != nil {
			t.Fatalf("readTLV(version): %v", err)
		}
		if got := signedInteger(version.content); got != snmpVersion2c {
			t.Errorf("version = %d, want %d (SNMPv2c)", got, snmpVersion2c)
		}
		community, offset, err := readTLV(message.content, offset)
		if err != nil {
			t.Fatalf("readTLV(community): %v", err)
		}
		if string(community.content) != "public" {
			t.Errorf("community = %q, want public", community.content)
		}
		pdu, _, err := readTLV(message.content, offset)
		if err != nil {
			t.Fatalf("readTLV(pdu): %v", err)
		}
		if pdu.tag != pduTag {
			t.Errorf("pdu tag = %#x, want %#x", pdu.tag, pduTag)
		}
		requestID, pduOffset, err := readTLV(pdu.content, 0)
		if err != nil {
			t.Fatalf("readTLV(request-id): %v", err)
		}
		if got := signedInteger(requestID.content); got != 4711 {
			t.Errorf("request-id = %d, want 4711", got)
		}
		errorStatus, pduOffset, err := readTLV(pdu.content, pduOffset)
		if err != nil {
			t.Fatalf("readTLV(error-status): %v", err)
		}
		if got := signedInteger(errorStatus.content); got != 0 {
			t.Errorf("error-status = %d, want 0", got)
		}
		errorIndex, pduOffset, err := readTLV(pdu.content, pduOffset)
		if err != nil {
			t.Fatalf("readTLV(error-index): %v", err)
		}
		if got := signedInteger(errorIndex.content); got != 0 {
			t.Errorf("error-index = %d, want 0", got)
		}
		varBindList, _, err := readTLV(pdu.content, pduOffset)
		if err != nil {
			t.Fatalf("readTLV(varbind list): %v", err)
		}
		varbind, _, err := readTLV(varBindList.content, 0)
		if err != nil {
			t.Fatalf("readTLV(varbind): %v", err)
		}
		oid, indexOffset, err := readTLV(varbind.content, 0)
		if err != nil {
			t.Fatalf("readTLV(oid): %v", err)
		}
		if got := decodeOID(oid.content); got != oidChassisID {
			t.Errorf("varbind oid = %q, want %q", got, oidChassisID)
		}
		value, _, err := readTLV(varbind.content, indexOffset)
		if err != nil {
			t.Fatalf("readTLV(value): %v", err)
		}
		if value.tag != tagNull || len(value.content) != 0 {
			t.Errorf("value = tag %#x len %d, want NULL", value.tag, len(value.content))
		}
	}
}

// realResponseHex is a GetResponse captured from 192.168.127.4 for
// lldpRemChassisId.0.4.1: request-id 1, community "public", one varbind with the
// MAC shaped chassis id 00 90 E8 D6 59 85.
const realResponseHex = "3032" + "020101" + "04067075626c6963" + "a225" +
	"020101" + "020100" + "020100" + "301a" + "3018" +
	"060e28c4620101020104010105000401" + "04060090e8d65985"

// TestDecodeResponse decodes that real answer.
func TestDecodeResponse(t *testing.T) {
	packet, err := hex.DecodeString(strings.ReplaceAll(realResponseHex, " ", ""))
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	response, err := decodeResponse(packet)
	if err != nil {
		t.Fatalf("decodeResponse: %v", err)
	}
	if response.Version != snmpVersion2c {
		t.Errorf("version = %d, want %d", response.Version, snmpVersion2c)
	}
	if response.Community != "public" {
		t.Errorf("community = %q, want public", response.Community)
	}
	if response.PDUTag != pduGetResponse {
		t.Errorf("pdu tag = %#x, want %#x", response.PDUTag, pduGetResponse)
	}
	if response.RequestID != 1 {
		t.Errorf("request-id = %d, want 1", response.RequestID)
	}
	if response.ErrorStatus != 0 || response.ErrorIndex != 0 {
		t.Errorf("error status/index = %d/%d, want 0/0", response.ErrorStatus, response.ErrorIndex)
	}
	if len(response.VarBinds) != 1 {
		t.Fatalf("len(varbinds) = %d, want 1", len(response.VarBinds))
	}
	varbind := response.VarBinds[0]
	const wantOID = "1.0.8802.1.1.2.1.4.1.1.5.0.4.1"
	if varbind.OID != wantOID {
		t.Errorf("oid = %q, want %q", varbind.OID, wantOID)
	}
	if varbind.Value.tag != tagOctetString {
		t.Errorf("value tag = %#x, want OCTET STRING", varbind.Value.tag)
	}
	if got := varbind.Value.String(); got != "0090e8d65985" {
		t.Errorf("value = %q, want 0090e8d65985", got)
	}
}

// TestDecodeResponseRejectsMalformedData guards the error paths so a damaged
// datagram is skipped instead of crashing the reader.
func TestDecodeResponseRejectsMalformedData(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"not a sequence": "0400",
		"truncated":      "3033",
		// A well formed message whose PDU is a GetRequest, not a GetResponse.
		"wrong pdu tag": "300d" + "020101" + "04067075626c6963" + "a000",
		// A varbind whose first element is an INTEGER instead of an OID.
		"bad oid in varbind": "301f" + "020101" + "04067075626c6963" + "a212" +
			"020101" + "020100" + "020100" + "3007" + "3005" + "020101" + "0500",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			packet, err := hex.DecodeString(strings.ReplaceAll(raw, " ", ""))
			if err != nil {
				t.Skipf("fixture is not valid hex: %v", err)
			}
			if _, err := decodeResponse(packet); err == nil {
				t.Fatalf("decodeResponse(%s) must fail", name)
			}
		})
	}
}

// TestValueRendering covers every value type the LLDP MIB uses and the three
// SNMPv2c exception values.
func TestValueRendering(t *testing.T) {
	tests := []struct {
		name  string
		value snmpValue
		want  string
		end   bool
		empty bool
	}{
		{
			name:  "integer 4",
			value: snmpValue{tag: tagInteger, raw: []byte{0x04}},
			want:  "4",
		},
		{
			name:  "integer negative",
			value: snmpValue{tag: tagInteger, raw: []byte{0xFF, 0xFE}},
			want:  "-2",
		},
		{
			name:  "text octet string",
			value: snmpValue{tag: tagOctetString, raw: []byte("Managed Redundant Switch 00007")},
			want:  "Managed Redundant Switch 00007",
		},
		{
			name:  "mac shaped octet string",
			value: snmpValue{tag: tagOctetString, raw: []byte{0x00, 0x90, 0xE8, 0x00, 0x05, 0xD0}},
			want:  "0090e80005d0",
		},
		{
			name:  "port id text",
			value: snmpValue{tag: tagOctetString, raw: []byte("c85b76f2204a")},
			want:  "c85b76f2204a",
		},
		{
			name:  "oid value",
			value: snmpValue{tag: tagOID, raw: []byte{0x28, 0xC4, 0x62, 0x01}},
			want:  "1.0.8802.1",
		},
		{
			name:  "ip address",
			value: snmpValue{tag: tagIPAddress, raw: []byte{192, 168, 127, 4}},
			want:  "192.168.127.4",
		},
		{
			name:  "counter32",
			value: snmpValue{tag: tagCounter32, raw: []byte{0x00, 0x00, 0x01, 0x00}},
			want:  "256",
		},
		{
			name:  "gauge32",
			value: snmpValue{tag: tagGauge32, raw: []byte{0x01, 0x00}},
			want:  "256",
		},
		{
			name:  "timeticks",
			value: snmpValue{tag: tagTimeTicks, raw: []byte{0x00, 0x00, 0x0E, 0x10}},
			want:  "3600",
		},
		{
			name:  "counter64",
			value: snmpValue{tag: tagCounter64, raw: []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}},
			want:  "4294967296",
		},
		{
			name:  "null has no text",
			value: snmpValue{tag: tagNull},
			want:  "",
			empty: true,
		},
		{
			name:  "noSuchObject ends the walk",
			value: snmpValue{tag: tagNoSuchObject},
			want:  "",
			end:   true,
			empty: true,
		},
		{
			name:  "noSuchInstance ends the walk",
			value: snmpValue{tag: tagNoSuchInstance},
			want:  "",
			end:   true,
			empty: true,
		},
		{
			name:  "endOfMibView ends the walk",
			value: snmpValue{tag: tagEndOfMibView},
			want:  "",
			end:   true,
			empty: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.value.String(); got != test.want {
				t.Errorf("String() = %q, want %q", got, test.want)
			}
			if got := test.value.isEnd(); got != test.end {
				t.Errorf("isEnd() = %v, want %v", got, test.end)
			}
			if got := test.value.isEmpty(); got != test.empty {
				t.Errorf("isEmpty() = %v, want %v", got, test.empty)
			}
		})
	}
}

// TestReadTLVLongForm checks the multi byte length form used by larger replies.
func TestReadTLVLongForm(t *testing.T) {
	content := make([]byte, 300)
	for index := range content {
		content[index] = byte(index % 251)
	}
	encoded := encodeTLV(tagOctetString, content)
	if encoded[0] != tagOctetString || encoded[1] != 0x82 {
		t.Fatalf("header = % x, want 04 82 ..", encoded[:2])
	}
	decoded, next, err := readTLV(encoded, 0)
	if err != nil {
		t.Fatalf("readTLV: %v", err)
	}
	if next != len(encoded) {
		t.Errorf("next = %d, want %d", next, len(encoded))
	}
	if len(decoded.content) != len(content) {
		t.Fatalf("len(content) = %d, want %d", len(decoded.content), len(content))
	}
	for index := range content {
		if decoded.content[index] != content[index] {
			t.Fatalf("content[%d] = %d, want %d", index, decoded.content[index], content[index])
		}
	}
}

// TestOptionsDefaults documents the zero value contract.
func TestOptionsDefaults(t *testing.T) {
	settings := Options{}.normalized()
	if settings.Timeout != DefaultTimeout {
		t.Errorf("timeout = %v, want %v", settings.Timeout, DefaultTimeout)
	}
	if settings.Community != DefaultCommunity {
		t.Errorf("community = %q, want %q", settings.Community, DefaultCommunity)
	}
	if settings.port != snmpPort {
		t.Errorf("port = %d, want %d", settings.port, snmpPort)
	}
	custom := Options{Timeout: 20 * time.Millisecond, Community: "readonly", port: 16161}.normalized()
	if custom.Timeout != 20*time.Millisecond || custom.Community != "readonly" || custom.port != 16161 {
		t.Errorf("explicit options were not kept: %+v", custom)
	}
}

// TestAgentAddressRejectsUnusableInput keeps Fetch from dialling something that
// is not a device address.
func TestAgentAddressRejectsUnusableInput(t *testing.T) {
	for _, invalid := range []string{"", "  ", "not-an-ip", "::1", "fe80::1"} {
		if _, err := agentAddress(invalid, snmpPort); err == nil {
			t.Errorf("agentAddress(%q) must fail", invalid)
		}
	}
	address, err := agentAddress(" 192.168.127.4 ", snmpPort)
	if err != nil {
		t.Fatalf("agentAddress: %v", err)
	}
	if address != "192.168.127.4:161" {
		t.Errorf("address = %q, want 192.168.127.4:161", address)
	}
}

// TestFetchUnansweredTimeoutIsNoSNMP simulates a device that swallows the
// request (the NPort 6450 behaviour) with a local UDP sink that never answers.
//
// The important part is the budget: one retry of a 50 ms timeout must return
// far below the 1.2 s the UI promises.
func TestFetchUnansweredTimeoutIsNoSNMP(t *testing.T) {
	sink, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot open a local UDP sink: %v", err)
	}
	address, ok := sink.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = sink.Close()
		t.Skip("unexpected local address type")
	}
	defer func() { _ = sink.Close() }()

	started := time.Now()
	table, err := Fetch(context.Background(), "127.0.0.1", Options{
		Timeout: 50 * time.Millisecond,
		port:    address.Port,
	})
	elapsed := time.Since(started)

	if table != nil {
		t.Errorf("table = %+v, want nil", table)
	}
	if !errors.Is(err, ErrNoSNMP) {
		t.Fatalf("err = %v, want ErrNoSNMP", err)
	}
	if elapsed > 1200*time.Millisecond {
		t.Errorf("Fetch took %v, want < 1.2 s", elapsed)
	}
	if elapsed < 50*time.Millisecond {
		t.Errorf("Fetch returned in %v, the timeout was not applied", elapsed)
	}
}

// TestFetchCancelledContext keeps a cancelled request from dialling at all.
func TestFetchCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Fetch(ctx, "192.168.127.4", Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
