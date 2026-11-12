package discovery

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{name: "normal", input: []byte{0x50, 0x0B, 0x88, 0x0F, 0x8C, 0x29}, want: "50:0B:88:0F:8C:29"},
		{name: "all zero is unknown", input: []byte{0, 0, 0, 0, 0, 0}, want: ""},
		{name: "broadcast is unknown", input: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, want: ""},
		{name: "too short", input: []byte{0x01, 0x02}, want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := NormalizeMAC(test.input); got != test.want {
				t.Errorf("NormalizeMAC(%x) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestParseMACString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "50:0B:88:0E:1B:53", want: "50:0B:88:0E:1B:53"},
		{input: "50-0b-88-0e-1b-53", want: "50:0B:88:0E:1B:53"},
		{input: "500B880E1B53", want: "50:0B:88:0E:1B:53"},
		{input: " 50:0b:88:0e:1b:53\x00\x00", want: "50:0B:88:0E:1B:53"},
		{input: "", want: ""},
		{input: "not-a-mac", want: ""},
		{input: "50:0B:88:0E:1B", want: ""},
	}
	for _, test := range tests {
		if got := ParseMACString(test.input); got != test.want {
			t.Errorf("ParseMACString(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

// TestAggregatorKeepsSameIPDevices covers REQUIREMENTS.md R4: two devices that
// share one IP must produce two rows, because the row identity is (MAC, IP).
func TestAggregatorKeepsSameIPDevices(t *testing.T) {
	aggregator := newAggregator()
	aggregator.add(&Device{IP: "192.168.127.253", MAC: "50:0B:88:09:2B:DC", Protocol: ProtoNameAXOM, Adapters: []string{"WLAN"}})
	aggregator.add(&Device{IP: "192.168.127.253", MAC: "00:90:E8:00:05:D0", Protocol: ProtoName4000, Adapters: []string{"WLAN"}})

	devices := aggregator.snapshot()
	if len(devices) != 2 {
		t.Fatalf("len(devices) = %d, want 2 (same IP, different MAC)", len(devices))
	}
	if got := DuplicateIPCount(devices); got != 1 {
		t.Errorf("DuplicateIPCount = %d, want 1", got)
	}
}

// TestAggregatorKeepsBothIPsOfOneDevice is the counterpart of R4: a device with
// two IP addresses must appear twice, because the tool exists to list every
// reachable address and hiding one would be worse than a duplicate MAC column.
func TestAggregatorKeepsBothIPsOfOneDevice(t *testing.T) {
	aggregator := newAggregator()
	aggregator.add(&Device{IP: "192.168.127.254", MAC: "50:0B:88:10:23:89", Protocol: ProtoName4800, Adapters: []string{"WLAN"}})
	aggregator.add(&Device{IP: "192.168.127.254", MAC: "50:0B:88:10:23:89", Protocol: ProtoName4000, Adapters: []string{"WLAN"}})
	aggregator.add(&Device{IP: "192.168.127.253", MAC: "50:0B:88:10:23:89", Protocol: ProtoName4800, Adapters: []string{"以太网"}})

	devices := aggregator.snapshot()
	if len(devices) != 2 {
		t.Fatalf("len(devices) = %d, want 2 (one MAC, two IPs)", len(devices))
	}
	byIP := map[string]Device{}
	for _, device := range devices {
		byIP[device.IP] = device
	}
	first, ok := byIP["192.168.127.254"]
	if !ok {
		t.Fatal("192.168.127.254 is missing from the result")
	}
	// The two observations of the same (MAC, IP) pair must still be merged.
	if first.Protocol != ProtoName4800 {
		t.Errorf("Protocol = %q, want the highest priority %q", first.Protocol, ProtoName4800)
	}
	if _, ok := byIP["192.168.127.253"]; !ok {
		t.Fatal("192.168.127.253 is missing from the result")
	}
	if got := DuplicateIPCount(devices); got != 0 {
		t.Errorf("DuplicateIPCount = %d, want 0 (different IPs)", got)
	}
}

func TestAggregatorMergesSameMAC(t *testing.T) {
	aggregator := newAggregator()
	aggregator.add(&Device{IP: "192.168.127.254", MAC: "50:0B:88:0F:8C:29", Protocol: ProtoNameWSU, Adapters: []string{"WLAN"}})
	aggregator.add(&Device{IP: "192.168.127.254", MAC: "50:0B:88:0F:8C:29", Protocol: ProtoName4800, Model: "NP5110A", Adapters: []string{"VMnet1"}})

	devices := aggregator.snapshot()
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
	if devices[0].Protocol != ProtoName4800 {
		t.Errorf("Protocol = %q, want the highest priority %q", devices[0].Protocol, ProtoName4800)
	}
	if devices[0].Model != "NP5110A" {
		t.Errorf("Model = %q, want NP5110A", devices[0].Model)
	}
	if len(devices[0].Adapters) != 2 {
		t.Errorf("Adapters = %v, want both adapter names", devices[0].Adapters)
	}
}

func TestAggregatorKeepsSeparateRowsWithoutMAC(t *testing.T) {
	aggregator := newAggregator()
	aggregator.add(&Device{IP: "192.168.127.10", Protocol: ProtoName29168, Adapters: []string{"WLAN"}})
	aggregator.add(&Device{IP: "192.168.127.10", Protocol: ProtoName1029, Adapters: []string{"WLAN"}})

	if got := len(aggregator.snapshot()); got != 2 {
		t.Fatalf("len(devices) = %d, want 2 (unknown MAC degrades to IP+protocol)", got)
	}
}

func TestAggregatorSetModel(t *testing.T) {
	aggregator := newAggregator()
	deviceID := make([]byte, 12)
	copy(deviceID, []byte{0x00, 0x51, 0x01, 0x80, 0x1A, 0x51, 0x50, 0x0B, 0x88, 0x0F, 0x8C, 0x29})
	aggregator.add(&Device{IP: "192.168.127.254", MAC: "50:0B:88:0F:8C:29", Protocol: ProtoName4800, Adapters: []string{"WLAN"}, deviceID: deviceID})

	if !aggregator.setModel(deviceID, "192.168.127.254", "NP5110A") {
		t.Fatal("setModel did not match the stored device id")
	}
	devices := aggregator.snapshot()
	if len(devices) != 1 || devices[0].Model != "NP5110A" {
		t.Fatalf("devices = %+v, want one row modelled NP5110A", devices)
	}
	if got := len(aggregator.pendingModelQueries()); got != 0 {
		t.Errorf("pendingModelQueries = %d, want 0 after the model arrived", got)
	}
}

func TestAggregatorPendingModelQueriesRunsOnce(t *testing.T) {
	aggregator := newAggregator()
	deviceID := make([]byte, 12)
	copy(deviceID, []byte{0x00, 0x26, 0x00, 0x80, 0x52, 0x26, 0x50, 0x0B, 0x88, 0x10, 0x23, 0x89})
	aggregator.add(&Device{IP: "192.168.127.254", MAC: "50:0B:88:10:23:89", Protocol: ProtoName4800, Adapters: []string{"WLAN"}, deviceID: deviceID})

	if got := len(aggregator.pendingModelQueries()); got != 1 {
		t.Fatalf("pendingModelQueries = %d, want 1", got)
	}
	if got := len(aggregator.pendingModelQueries()); got != 0 {
		t.Fatalf("pendingModelQueries = %d on the second call, want 0", got)
	}
}

// TestAggregatorModelAppliesToEveryIPOfOneDevice keeps the model column
// consistent when one device shows up under two addresses: a single 0x83 answer
// must fill the model of both rows and only one query may be sent.
func TestAggregatorModelAppliesToEveryIPOfOneDevice(t *testing.T) {
	aggregator := newAggregator()
	deviceID := make([]byte, 12)
	copy(deviceID, []byte{0x00, 0x26, 0x00, 0x80, 0x52, 0x26, 0x50, 0x0B, 0x88, 0x10, 0x23, 0x89})
	for _, ip := range []string{"192.168.127.254", "192.168.127.253"} {
		aggregator.add(&Device{IP: ip, MAC: "50:0B:88:10:23:89", Protocol: ProtoName4800, Adapters: []string{"WLAN"}, deviceID: deviceID})
	}

	if got := len(aggregator.pendingModelQueries()); got != 1 {
		t.Fatalf("pendingModelQueries = %d, want 1 (one query per device identity)", got)
	}
	if !aggregator.setModel(deviceID, "192.168.127.254", "MB3180") {
		t.Fatal("setModel did not match the stored device id")
	}
	for _, device := range aggregator.snapshot() {
		if device.Model != "MB3180" {
			t.Errorf("%s: Model = %q, want MB3180 on every row of the device", device.IP, device.Model)
		}
	}
}

func TestSortDevices(t *testing.T) {
	devices := []Device{
		{IP: "192.168.127.254", MAC: "50:0B:88:0F:8C:29"},
		{IP: "192.168.2.1", MAC: "00:90:E8:00:05:D0"},
		{IP: "192.168.127.253", MAC: "00:90:E8:00:05:D1"},
	}
	SortDevices(devices)
	want := []string{"192.168.2.1", "192.168.127.253", "192.168.127.254"}
	for i := range want {
		if devices[i].IP != want[i] {
			t.Fatalf("devices = %v, want %v", devices, want)
		}
	}
}

func TestBroadcastTargets(t *testing.T) {
	adapter := Adapter{
		Name: "WLAN",
		IP:   net.IPv4(192, 168, 0, 163).To4(),
		Mask: net.CIDRMask(24, 32),
	}
	targets := broadcastTargets(adapter)
	if len(targets) != 2 {
		t.Fatalf("len(targets) = %d, want 2 (limited + directed)", len(targets))
	}
	if !targets[0].Equal(net.IPv4bcast) {
		t.Errorf("targets[0] = %v, want 255.255.255.255", targets[0])
	}
	if !targets[1].Equal(net.IPv4(192, 168, 0, 255)) {
		t.Errorf("targets[1] = %v, want 192.168.0.255", targets[1])
	}
}

func TestBroadcastTargetsSkipsRedundant(t *testing.T) {
	// A /0 interface would derive 255.255.255.255 twice and a /32 interface
	// would derive its own address; neither must be added.
	cases := []Adapter{
		{Name: "any", IP: net.IPv4(10, 0, 0, 1).To4(), Mask: net.CIDRMask(0, 32)},
		{Name: "host", IP: net.IPv4(10, 0, 0, 1).To4(), Mask: net.CIDRMask(32, 32)},
	}
	for _, adapter := range cases {
		if got := len(broadcastTargets(adapter)); got != 1 {
			t.Errorf("adapter %s: len(targets) = %d, want 1", adapter.Name, got)
		}
	}
}

func TestScanWithoutAdaptersFailsGracefully(t *testing.T) {
	// On a machine without IPv4 adapters the scan must still return a usable
	// (empty) result instead of panicking.
	result := Scan(context.Background(), Options{Rounds: 1, RoundDuration: 20 * time.Millisecond}, nil)
	if result == nil {
		t.Fatal("Scan returned nil")
	}
	if result.Devices == nil {
		t.Error("result.Devices is nil, want an empty slice (JSON must render [])")
	}
	if result.Errors == nil {
		t.Error("result.Errors is nil, want an empty slice")
	}
}

func TestScanCollectsProgress(t *testing.T) {
	var rounds []int
	var phases []Phase
	result := Scan(context.Background(),
		Options{Rounds: 2, RoundDuration: 20 * time.Millisecond, ModelQueryWait: 0},
		func(progress Progress) {
			rounds = append(rounds, progress.Round)
			phases = append(phases, progress.Phase)
		})
	if result == nil {
		t.Fatal("Scan returned nil")
	}
	if len(result.Adapters) == 0 {
		t.Skip("no IPv4 adapter on this machine, progress callback cannot be verified")
	}

	// v1.3: the broadcast rounds are unchanged (0 = preparing, then 1..N) and the
	// model enhancement reports one extra event of its own phase. It must not
	// announce a further round: the round count stays at N.
	broadcast := make([]int, 0, len(rounds))
	models := 0
	for index, phase := range phases {
		switch phase {
		case PhaseBroadcast:
			broadcast = append(broadcast, rounds[index])
		case PhaseModels:
			models++
			if rounds[index] != 2 {
				t.Errorf("model phase reported round %d, want the final round 2", rounds[index])
			}
		default:
			t.Errorf("unexpected phase %v", phase)
		}
	}
	if len(broadcast) != 3 {
		t.Fatalf("broadcast progress events = %v, want [0 1 2]", broadcast)
	}
	if broadcast[0] != 0 || broadcast[1] != 1 || broadcast[2] != 2 {
		t.Errorf("broadcast progress events = %v, want [0 1 2]", broadcast)
	}
	if models != 1 {
		t.Errorf("model phase events = %d, want exactly 1", models)
	}
}

func TestFormatAdapterList(t *testing.T) {
	if got := FormatAdapterList(nil); got != "未找到已启用的 IPv4 网卡" {
		t.Errorf("FormatAdapterList(nil) = %q", got)
	}
	adapters := []Adapter{
		{Name: "WLAN", IP: net.IPv4(192, 168, 0, 163).To4(), Mask: net.CIDRMask(24, 32)},
		{Name: "VMnet1", IP: net.IPv4(192, 168, 18, 1).To4(), Mask: net.CIDRMask(24, 32)},
	}
	want := "192.168.0.163/24 (WLAN) · 192.168.18.1/24 (VMnet1)"
	if got := FormatAdapterList(adapters); got != want {
		t.Errorf("FormatAdapterList = %q, want %q", got, want)
	}
}

func TestOptionsFromTimeout(t *testing.T) {
	options := OptionsFromTimeout(1500)
	total := time.Duration(options.Rounds)*options.RoundDuration + options.ModelQueryWait
	if total > 1600*time.Millisecond {
		t.Errorf("total = %v, want the scan to stay near the 1500 ms budget", total)
	}
	if options.RoundDuration < 100*time.Millisecond {
		t.Errorf("RoundDuration = %v, want at least 100 ms", options.RoundDuration)
	}
	if def := OptionsFromTimeout(0); def.Rounds != 3 || def.RoundDuration != 400*time.Millisecond {
		t.Errorf("OptionsFromTimeout(0) = %+v, want the defaults", def)
	}
}
