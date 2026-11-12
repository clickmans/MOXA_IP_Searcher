package discovery

import (
	"bytes"
	"testing"
)

// TestModelFromName pins the v1.2 fallback chain: a device that does not answer
// the 0x03 model query still reports a product code as its name, and that code
// is turned into the marketing model name.
//
// The expected values are the two devices of the reference network
// (NP6450_0001 -> NPort 6450, MG-MB3180_0001 -> MGate MB3180) plus the families
// whose code already is the marketing name.
func TestModelFromName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "NPort 6450 with serial suffix", in: "NP6450_0001", want: "NPort 6450"},
		{name: "NPort 6450 without suffix", in: "NP6450", want: "NPort 6450"},
		{name: "NPort 5110A", in: "NP5110A", want: "NPort 5110A"},
		{name: "NPort 5110A with suffix", in: "NP5110A_1234", want: "NPort 5110A"},
		{name: "MGate MB3180 with serial suffix", in: "MG-MB3180_0001", want: "MGate MB3180"},
		{name: "MGate MB3180 without suffix", in: "MG-MB3180", want: "MGate MB3180"},
		{name: "MGate MB3660", in: "MG-MB3660_12", want: "MGate MB3660"},
		{name: "EDS switch keeps its code", in: "EDS-510E_1234", want: "EDS-510E"},
		{name: "EDS switch without suffix", in: "EDS-408A", want: "EDS-408A"},
		{name: "EOM embedded switch keeps its code", in: "EOM-106", want: "EOM-106"},
		{name: "IA access point keeps its code", in: "IA-2410", want: "IA-2410"},
		{name: "AWK wireless keeps its code", in: "AWK-1131A-US", want: "AWK-1131A-US"},
		{name: "unknown code is returned unchanged", in: "XYZ-9000_7", want: "XYZ-9000"},
		{name: "underscore but no numeric suffix", in: "switch_A", want: "switch_A"},
		{name: "trailing underscore carries no information", in: "NP6450_", want: "NPort 6450"},
		{name: "only the prefix", in: "NP", want: "NP"},
		{name: "only the MGate prefix", in: "MG-", want: "MG-"},
		{name: "surrounding blanks", in: "  NP6450_0001  ", want: "NPort 6450"},
		{name: "empty", in: "", want: ""},
		{name: "only blanks", in: "   ", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ModelFromName(test.in); got != test.want {
				t.Errorf("ModelFromName(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

// TestStripDeviceNameSuffix documents exactly which suffixes are removed.
func TestStripDeviceNameSuffix(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "NP6450_0001", want: "NP6450"},
		{in: "MG-MB3180_0001", want: "MG-MB3180"},
		{in: "EDS-510E_1234", want: "EDS-510E"},
		{in: "NP6450", want: "NP6450"},
		{in: "MG-MB3180", want: "MG-MB3180"},
		{in: "switch_A", want: "switch_A"},
		{in: "NP6450_a", want: "NP6450_a"},
		{in: "NP6450_", want: "NP6450_"},
		{in: "_5599", want: "_5599"},
		{in: "MG-MB3180_0001_2", want: "MG-MB3180_0001"},
		{in: "", want: ""},
	}
	for _, test := range tests {
		if got := stripDeviceNameSuffix(test.in); got != test.want {
			t.Errorf("stripDeviceNameSuffix(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

// TestModelFromNameNeverReturnsEmptyForACode keeps the promise of the fallback
// chain: an unrecognised code is better than an empty cell.
func TestModelFromNameNeverReturnsEmptyForACode(t *testing.T) {
	for _, code := range []string{"NP6450_0001", "MG-MB3180_0001", "EDS-510E_1", "EOM-106", "QUIRKY_9", "X"} {
		if got := ModelFromName(code); got == "" {
			t.Errorf("ModelFromName(%q) = \"\", want a non empty model", code)
		}
	}
}

// TestResolveModelChain pins the order of the fallback chain: the answered model
// wins, then the name, then nothing.
func TestResolveModelChain(t *testing.T) {
	tests := []struct {
		name  string
		model string
		dev   string
		want  string
	}{
		{name: "answered model wins", model: "MGate MB3180", dev: "MG-MB3180_0001", want: "MGate MB3180"},
		{name: "answered model wins over a different name", model: "NPort 6450", dev: "EOM-106", want: "NPort 6450"},
		{name: "name is used when the model is empty", model: "", dev: "NP6450_0001", want: "NPort 6450"},
		{name: "name with blanks", model: "   ", dev: "MG-MB3180_0001", want: "MGate MB3180"},
		{name: "nothing known stays empty", model: "", dev: "", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ResolveModel(test.model, test.dev); got != test.want {
				t.Errorf("ResolveModel(%q, %q) = %q, want %q", test.model, test.dev, got, test.want)
			}
		})
	}
}

// TestDisplayModelPlaceholder is the rule the GUI applies: "-" when neither a
// model nor a usable name is known.
func TestDisplayModelPlaceholder(t *testing.T) {
	if got := DisplayModel("", "NP6450_0001"); got != "NPort 6450" {
		t.Errorf("DisplayModel = %q, want NPort 6450", got)
	}
	if got := DisplayModel("", ""); got != "-" {
		t.Errorf("DisplayModel = %q, want -", got)
	}
}

// TestAggregatorResolvesModelFromName is the end to end version of the fallback
// chain: a 4800 device that only answered the 0x10 name query is reported with
// the derived model, while the name column keeps the raw device name.
func TestAggregatorResolvesModelFromName(t *testing.T) {
	aggregator := newAggregator()
	aggregator.add(&Device{
		IP:       "192.168.100.250",
		MAC:      "00:90:E8:00:00:20",
		Protocol: ProtoName4800,
		Adapters: []string{"WLAN"},
		deviceID: append([]byte(nil), deviceIDNPort6450...),
	})
	if !aggregator.setName(deviceIDNPort6450, "192.168.100.250", "NP6450_0001") {
		t.Fatal("setName did not match the stored device id")
	}
	// A 0x96 answer provides the firmware of the same row.
	if !aggregator.setVersion(deviceIDNPort6450, "192.168.100.250", "V1.10", 5599) {
		t.Fatal("setVersion did not match the stored device id")
	}

	devices := aggregator.snapshot()
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
	if devices[0].Model != "NPort 6450" {
		t.Errorf("Model = %q, want NPort 6450 (derived from the name)", devices[0].Model)
	}
	if devices[0].Name != "NP6450_0001" {
		t.Errorf("Name = %q, want the raw device name", devices[0].Name)
	}
	if devices[0].Firmware != "V1.10" {
		t.Errorf("Firmware = %q, want V1.10", devices[0].Firmware)
	}
	if devices[0].ShortSerial != 5599 {
		t.Errorf("ShortSerial = %d, want 5599", devices[0].ShortSerial)
	}
}

// TestAggregatorKeepsAnsweredModel makes sure the derivation never overwrites a
// model the device actually reported (the MGate MB3180 case).
func TestAggregatorKeepsAnsweredModel(t *testing.T) {
	aggregator := newAggregator()
	aggregator.add(&Device{
		IP:       "192.168.100.254",
		MAC:      "00:90:E8:00:00:9B",
		Protocol: ProtoName4800,
		Adapters: []string{"以太网"},
		deviceID: append([]byte(nil), deviceIDMGateMB3180...),
	})
	aggregator.setModel(deviceIDMGateMB3180, "192.168.100.254", "MGate MB3180")
	aggregator.setName(deviceIDMGateMB3180, "192.168.100.254", "MG-MB3180_0001")
	aggregator.setVersion(deviceIDMGateMB3180, "192.168.100.254", "V2.7", 579)

	devices := aggregator.snapshot()
	if devices[0].Model != "MGate MB3180" {
		t.Errorf("Model = %q, want the answered MGate MB3180", devices[0].Model)
	}
	if devices[0].Name != "MG-MB3180_0001" {
		t.Errorf("Name = %q, want MG-MB3180_0001", devices[0].Name)
	}
	if devices[0].Firmware != "V2.7" {
		t.Errorf("Firmware = %q, want V2.7", devices[0].Firmware)
	}
}

// TestPendingDetailQueries covers the scheduling rule of the detail phase: one
// entry per device identity, only for rows that miss at least one answer.
func TestPendingDetailQueries(t *testing.T) {
	aggregator := newAggregator()
	// Two addresses of one device: only one query may be scheduled.
	for _, ip := range []string{"192.168.100.254", "192.168.100.253"} {
		aggregator.add(&Device{
			IP:       ip,
			MAC:      "00:90:E8:00:00:9B",
			Protocol: ProtoName4800,
			Adapters: []string{"以太网"},
			deviceID: append([]byte(nil), deviceIDMGateMB3180...),
		})
	}
	// A row without a 12 byte identity cannot be asked anything.
	aggregator.add(&Device{IP: "192.168.100.3", MAC: "50:0B:88:00:00:67", Protocol: ProtoNameAXOM, Name: "EOM-106"})

	pending := aggregator.pendingDetailQueries()
	if len(pending) != 1 {
		t.Fatalf("pendingDetailQueries = %d, want 1 (one query per identity)", len(pending))
	}
	if pending[0].IP != "192.168.100.254" {
		t.Errorf("pending device = %s, want the first row of the device", pending[0].IP)
	}
	if got := len(aggregator.pendingDetailQueries()); got != 0 {
		t.Errorf("pendingDetailQueries on the second call = %d, want 0", got)
	}
}

// TestAggregatorSetVersionKeepsKnownFirmware proves the 0x16 answer never
// overwrites a firmware string that a 0x83 property list already provided.
func TestAggregatorSetVersionKeepsKnownFirmware(t *testing.T) {
	aggregator := newAggregator()
	aggregator.add(&Device{
		IP:       "192.168.100.254",
		MAC:      "00:90:E8:00:00:9B",
		Protocol: ProtoName4800,
		Adapters: []string{"以太网"},
		deviceID: append([]byte(nil), deviceIDMGateMB3180...),
	})
	aggregator.setFirmware(deviceIDMGateMB3180, "192.168.100.254", "V2.6 build 210915")
	aggregator.setVersion(deviceIDMGateMB3180, "192.168.100.254", "V2.7", 579)

	if got := aggregator.snapshot()[0].Firmware; got != "V2.6 build 210915" {
		t.Errorf("Firmware = %q, want the first known version", got)
	}
	if aggregator.setVersion(deviceIDMGateMB3180, "", "", 0) {
		t.Error("setVersion accepted an empty answer")
	}
}

// TestAXOMRowsUnchangedByFallback proves the v1.2 model fallback does not
// disturb the AXOM (40404) rows: those products report a host name and no model
// TLV at all, so the derived model equals the name and the table keeps showing
// exactly what v1.1 showed (型号 = EOM-106, 名称 = "-", 固件 unchanged).
func TestAXOMRowsUnchangedByFallback(t *testing.T) {
	tests := []struct {
		ip        string
		lastOctet byte
		mac       []byte
		firmware  string
	}{
		{ip: "192.168.100.3", lastOctet: 3, mac: []byte{0x50, 0x0B, 0x88, 0x00, 0x00, 0x67}, firmware: "V3.1.6 build 24072314"},
		{ip: "192.168.100.4", lastOctet: 4, mac: []byte{0x00, 0x90, 0xE8, 0x00, 0x00, 0xD0}, firmware: "V3.1.10 build 26102915"},
	}
	aggregator := newAggregator()
	for _, test := range tests {
		frame := buildAXOMReply([]axomReplyTLV{
			{typ: axomTypeIP, value: []byte{192, 168, 100, test.lastOctet}},
			{typ: axomTypeMAC, value: test.mac},
			{typ: axomTypeName, value: append([]byte("EOM-106"), 0, 0)},
			{typ: axomTypeFirmware, value: []byte(test.firmware + "\n")},
		})
		device, ok := ParseAXOM(frame)
		if !ok {
			t.Fatalf("%s: ParseAXOM rejected the synthetic frame", test.ip)
		}
		if device.IP != test.ip {
			t.Fatalf("IP = %q, want %q", device.IP, test.ip)
		}
		aggregator.add(device)
	}

	devices := aggregator.snapshot()
	if len(devices) != 2 {
		t.Fatalf("len(devices) = %d, want 2", len(devices))
	}
	for _, device := range devices {
		want := ""
		for _, test := range tests {
			if test.ip == device.IP {
				want = test.firmware
			}
		}
		if device.Model != "EOM-106" {
			t.Errorf("%s: Model = %q, want the derived EOM-106", device.IP, device.Model)
		}
		if device.Name != "EOM-106" {
			t.Errorf("%s: Name = %q, want EOM-106", device.IP, device.Name)
		}
		if device.Firmware != want {
			t.Errorf("%s: Firmware = %q, want %q", device.IP, device.Firmware, want)
		}
		if device.Protocol != ProtoNameAXOM {
			t.Errorf("%s: Protocol = %q, want %q", device.IP, device.Protocol, ProtoNameAXOM)
		}
	}
}

// TestUnicastIFValueByteOrder pins the encoding of the IP_UNICAST_IF option:
// the interface index as four bytes in NETWORK byte order.
//
// A host order (little endian) encoding would send {10, 0, 0, 0} for index 10,
// which Windows reads as 167772160 - an interface that does not exist - so the
// socket would drop every unicast packet. That is exactly the bug this test
// exists to prevent from coming back.
func TestUnicastIFValueByteOrder(t *testing.T) {
	tests := []struct {
		name  string
		index int
		want  []byte
	}{
		{name: "index 10 (the WLAN adapter of the reference machine)", index: 10, want: []byte{0x00, 0x00, 0x00, 0x0A}},
		{name: "index 1", index: 1, want: []byte{0x00, 0x00, 0x00, 0x01}},
		{name: "index 21 (the Ethernet adapter)", index: 21, want: []byte{0x00, 0x00, 0x00, 0x15}},
		{name: "index 255", index: 255, want: []byte{0x00, 0x00, 0x00, 0xFF}},
		{name: "index 256 crosses the byte boundary", index: 256, want: []byte{0x00, 0x00, 0x01, 0x00}},
		{name: "index 0x01020304", index: 0x01020304, want: []byte{0x01, 0x02, 0x03, 0x04}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := unicastIFValue(test.index)
			if len(got) != 4 {
				t.Fatalf("len = %d, want exactly 4 bytes", len(got))
			}
			if !bytes.Equal(got, test.want) {
				t.Errorf("unicastIFValue(%d) = % x, want % x", test.index, got, test.want)
			}
			// The value is also what syscall.SetsockoptInt would have to send
			// if it did not swap the bytes.
			if network := uint32(got[0])<<24 | uint32(got[1])<<16 | uint32(got[2])<<8 | uint32(got[3]); network != uint32(test.index) {
				t.Errorf("big endian value = %d, want %d", network, test.index)
			}
		})
	}
}

// TestSetUnicastInterfaceRejectsBadInput keeps the helper from touching the
// socket for an unusable interface index.
func TestSetUnicastInterfaceRejectsBadInput(t *testing.T) {
	if err := setUnicastInterface(nil, 10); err == nil {
		t.Error("setUnicastInterface(nil, 10) returned no error")
	}
	conn, err := listenUDP(bytesToIPv4(127, 0, 0, 1), 0)
	if err != nil {
		t.Skipf("cannot bind a loopback socket: %v", err)
	}
	defer conn.Close()
	if err := setUnicastInterface(conn, 0); err == nil {
		t.Error("setUnicastInterface(conn, 0) returned no error")
	}
}

// bytesToIPv4 builds a net.IP from four octets without importing net here.
func bytesToIPv4(a, b, c, d byte) []byte { return []byte{a, b, c, d} }
