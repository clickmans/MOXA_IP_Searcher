package discovery

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// ubusLoginAnswer is the answer of a real AWK-1161C (captured with
//
//	curl -sk -X POST https://192.168.100.253/ubus -d '{"jsonrpc":"2.0",...}'
//
// ). It is the fixture of every parser test below.
const ubusLoginAnswer = `{"jsonrpc":"2.0","id":1,"result":[0,` +
	`{"login_msg":"","login_fail_msg":"Failed to login","model":"AWK-1161C-UN"}]}`

// TestParseUBUSModel pins the happy path: the model of the reference device,
// including its regional suffix.
func TestParseUBUSModel(t *testing.T) {
	if got := parseUBUSModel([]byte(ubusLoginAnswer)); got != "AWK-1161C-UN" {
		t.Fatalf("parseUBUSModel = %q, want AWK-1161C-UN", got)
	}

	// The model is trimmed and NUL padded values are accepted.
	padded := `{"jsonrpc":"2.0","id":1,"result":[0,{"model":"  AWK-1132C-US\u0000 "}]}`
	if got := parseUBUSModel([]byte(padded)); got != "AWK-1132C-US" {
		t.Errorf("parseUBUSModel(padded) = %q, want AWK-1132C-US", got)
	}

	// Unknown members of the payload object are ignored.
	extra := `{"result":[0,{"model":"EDS-405A","login_msg":"","code":0}],"id":1}`
	if got := parseUBUSModel([]byte(extra)); got != "EDS-405A" {
		t.Errorf("parseUBUSModel(extra members) = %q, want EDS-405A", got)
	}
}

// TestParseUBUSModelRejectsBadAnswers proves that every malformed answer is
// silent: "" (the caller keeps its fallback value) and never a panic.
func TestParseUBUSModelRejectsBadAnswers(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "空 body", body: ""},
		{name: "只有空白", body: "   \n\t "},
		{name: "非 JSON", body: "<html>404 Not Found</html>"},
		{name: "截断的 JSON", body: `{"jsonrpc":"2.0","result":[0,{"model":`},
		{name: "result[0] 非零", body: `{"jsonrpc":"2.0","id":1,"result":[4,"Invalid argument"]}`},
		{name: "result[0] 非零且带对象", body: `{"jsonrpc":"2.0","id":1,"result":[1,{"model":"AWK-1161C-UN"}]}`},
		{name: "result[0] 不是数字", body: `{"jsonrpc":"2.0","id":1,"result":["0",{"model":"X"}]}`},
		{name: "缺少 result", body: `{"jsonrpc":"2.0","id":1}`},
		{name: "result 只有一个元素", body: `{"jsonrpc":"2.0","id":1,"result":[0]}`},
		{name: "error 对象", body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params"}}`},
		{name: "error 对象带 result", body: `{"jsonrpc":"2.0","id":1,"result":[0,{"model":"X"}],"error":{"code":-32000}}`},
		{name: "model 为空", body: `{"jsonrpc":"2.0","id":1,"result":[0,{"login_msg":"","model":""}]}`},
		{name: "没有 model 成员", body: `{"jsonrpc":"2.0","id":1,"result":[0,{"login_msg":""}]}`},
		{name: "model 不是字符串", body: `{"jsonrpc":"2.0","id":1,"result":[0,{"model":123}]}`},
		{name: "model 含控制字符", body: `{"jsonrpc":"2.0","id":1,"result":[0,{"model":"AWK\u0000\u0001X"}]}`},
		{name: "model 过长", body: `{"jsonrpc":"2.0","id":1,"result":[0,{"model":"` + strings.Repeat("A", maxModelLen+1) + `"}]}`},
		{name: "payload 是字符串", body: `{"jsonrpc":"2.0","id":1,"result":[0,"ok"]}`},
		{name: "payload 是数组", body: `{"jsonrpc":"2.0","id":1,"result":[0,[{"model":"X"}]]}`},
	}
	for _, test := range tests {
		if got := parseUBUSModel([]byte(test.body)); got != "" {
			t.Errorf("parseUBUSModel(%s) = %q, want %q", test.name, got, "")
		}
	}
	// A nil body behaves like an empty one.
	if got := parseUBUSModel(nil); got != "" {
		t.Errorf("parseUBUSModel(nil) = %q, want %q", got, "")
	}
}

// TestSanitizeModel pins the rules of the model sanitiser.
func TestSanitizeModel(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "AWK-1161C-UN", want: "AWK-1161C-UN"},
		{in: " AWK-1161C-UN\n", want: "AWK-1161C-UN"},
		{in: "AWK-1161C-UN\x00\x00", want: "AWK-1161C-UN"},
		{in: "", want: ""},
		{in: "   ", want: ""},
		{in: "\x00\x00", want: ""},
		{in: "AWK\t1161C", want: ""},
		{in: strings.Repeat("A", maxModelLen), want: strings.Repeat("A", maxModelLen)},
		{in: strings.Repeat("A", maxModelLen+1), want: ""},
	}
	for _, test := range tests {
		if got := sanitizeModel(test.in); got != test.want {
			t.Errorf("sanitizeModel(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

// TestRegionFromModel pins the regional suffix rule of v1.3.
func TestRegionFromModel(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{model: "AWK-1161C-UN", want: "UN"},
		{model: "AWK-1132C-US", want: "US"},
		{model: "AWK-1131A-EU", want: "EU"},
		{model: "AWK-1161C-CN", want: "CN"},
		{model: "AWK-1161C-un", want: "UN"},
		{model: "  AWK-1161C-UN  ", want: "UN"},
		{model: "EDS-405A", want: ""},
		{model: "MGate MB3180", want: ""},
		{model: "NPort 6450", want: ""},
		{model: "EOM-106", want: ""},
		{model: "awk-1161c", want: ""},
		{model: "AWK-1161C-U", want: ""},
		{model: "AWK-1161C-UNUS", want: ""},
		{model: "AWK-1161C-", want: ""},
		{model: "", want: ""},
		{model: "-", want: ""},
		// The suffix must come after the LAST dash.
		{model: "AWK-UN-1161C", want: ""},
	}
	for _, test := range tests {
		if got := RegionFromModel(test.model); got != test.want {
			t.Errorf("RegionFromModel(%q) = %q, want %q", test.model, got, test.want)
		}
	}
}

// TestDecideAXOMModelIsPure checks that the ownership rule never touches the
// network: it only compares the row with the local ARP table.
func TestDecideAXOMModelIsPure(t *testing.T) {
	arp := map[string]string{
		// The device that actually owns the address in the reference network.
		"192.168.100.253": "50:0B:88:00:00:1A",
		"192.168.100.250": "00:90:E8:00:00:20",
	}

	// Hit: the row MAC is the MAC ARP resolves for that IP.
	if got, ok := decideAXOMModel(arp, "192.168.100.253", "50:0B:88:00:00:1A", "AWK-1161C-UN"); !ok {
		t.Fatal("decideAXOMModel(owner) = false, want true")
	} else if got != "AWK-1161C-UN" {
		t.Errorf("decideAXOMModel(owner) = %q, want AWK-1161C-UN", got)
	}

	// Hit, different textual MAC form (dashes, lower case).
	if got, ok := decideAXOMModel(arp, "192.168.100.253", "50-0b-88-00-00-1a", "AWK-1161C-UN"); !ok || got != "AWK-1161C-UN" {
		t.Errorf("decideAXOMModel(dashed mac) = (%q, %v), want (AWK-1161C-UN, true)", got, ok)
	}

	// Miss: same IP, other device (the EDS-405A sharing the address).
	if got, ok := decideAXOMModel(arp, "192.168.100.253", "50:0B:88:00:00:2C", "AWK-1161C-UN"); ok || got != "" {
		t.Errorf("decideAXOMModel(shared IP, other MAC) = (%q, %v), want (\"\", false)", got, ok)
	}

	// Miss: the address is not in the ARP table at all.
	if got, ok := decideAXOMModel(arp, "192.168.100.99", "50:0B:88:00:00:1A", "AWK-1161C-UN"); ok || got != "" {
		t.Errorf("decideAXOMModel(unresolved IP) = (%q, %v), want (\"\", false)", got, ok)
	}

	// Miss: an empty table, an empty MAC and an empty model.
	if _, ok := decideAXOMModel(map[string]string{}, "192.168.100.253", "50:0B:88:00:00:1A", "AWK-1161C-UN"); ok {
		t.Error("an empty ARP table must not adopt a model")
	}
	if _, ok := decideAXOMModel(nil, "192.168.100.253", "50:0B:88:00:00:1A", "AWK-1161C-UN"); ok {
		t.Error("a nil ARP table must not adopt a model")
	}
	if _, ok := decideAXOMModel(arp, "192.168.100.253", "", "AWK-1161C-UN"); ok {
		t.Error("a row without MAC must not adopt a model")
	}
	if _, ok := decideAXOMModel(arp, "", "50:0B:88:00:00:1A", "AWK-1161C-UN"); ok {
		t.Error("a row without IP must not adopt a model")
	}
	if _, ok := decideAXOMModel(arp, "192.168.100.253", "50:0B:88:00:00:1A", "   "); ok {
		t.Error("an empty model must not be adopted")
	}
}

// TestPendingAXOMRows pins which rows take part in the enhancement.
func TestPendingAXOMRows(t *testing.T) {
	aggregator := newAggregator()
	const ip = "192.168.100.253"
	// The AWK-1161C: AXOM, host name fallback, no real model -> candidate.
	aggregator.add(&Device{IP: ip, MAC: "50:0B:88:00:00:1A", Name: "awk-1161c", Protocol: ProtoNameAXOM})
	// The EDS-405A behind the very same address: also a candidate (the ARP check
	// decides later whether the answer belongs to it).
	aggregator.add(&Device{IP: ip, MAC: "50:0B:88:00:00:2C", Name: "EDS-405A", Protocol: ProtoNameAXOM})
	// A 4800 device with a real model must never be a candidate.
	aggregator.add(&Device{IP: "192.168.100.250", MAC: "00:90:E8:00:00:20", Model: "NPort 6450", Protocol: ProtoName4800})
	// An AXOM row without a MAC cannot prove its ownership.
	aggregator.add(&Device{IP: "192.168.100.251", Name: "no-mac", Protocol: ProtoNameAXOM})

	pending := aggregator.pendingAXOMRows()
	if len(pending) != 2 {
		t.Fatalf("len(pendingAXOMRows) = %d, want 2", len(pending))
	}
	for _, row := range pending {
		if row.Protocol != ProtoNameAXOM {
			t.Errorf("pending row %s has protocol %q", row.MAC, row.Protocol)
		}
		if row.MAC == "" || row.IP == "" {
			t.Errorf("pending row %+v is missing IP or MAC", row)
		}
		if row.Model != "" {
			t.Errorf("pending row %s already carries model %q", row.MAC, row.Model)
		}
	}
	if pending[0].Adapters == nil && pending[1].Adapters == nil {
		t.Log("no adapters recorded, which is fine for this fixture")
	}

	order, byIP := pendingAXOMTargets(pending)
	if len(order) != 1 || order[0] != ip {
		t.Fatalf("pendingAXOMTargets order = %v, want [%s]", order, ip)
	}
	if len(byIP[ip]) != 2 {
		t.Errorf("len(byIP[%s]) = %d, want 2", ip, len(byIP[ip]))
	}
}

// TestSetAXOMModelNeverOverwrites proves requirement 5: a real model - the one
// answered by the 4800 property list - is never replaced, and a second answer
// does not churn a row that was already enhanced.
func TestSetAXOMModelNeverOverwrites(t *testing.T) {
	aggregator := newAggregator()
	const ip = "192.168.100.253"
	aggregator.add(&Device{IP: ip, MAC: "00:90:E8:00:00:D7", Model: "AWK-1132C-US", Protocol: ProtoName4800})
	aggregator.add(&Device{IP: ip, MAC: "50:0B:88:00:00:1A", Name: "awk-1161c", Protocol: ProtoNameAXOM})

	// The 4800 row is untouchable: a different MAC does not match it anyway.
	if aggregator.setAXOMModel(ip, "00:90:E8:00:00:D7", "AWK-1161C-UN") {
		t.Error("setAXOMModel overwrote a device that already had a real model")
	}
	if aggregator.setAXOMModel(ip, "50:0B:88:00:00:1A", "AWK-1161C-UN") != true {
		t.Fatal("setAXOMModel(axon row) = false, want true")
	}
	// A second run must not replace the model it just adopted.
	if aggregator.setAXOMModel(ip, "50:0B:88:00:00:1A", "AWK-9999C-XX") != false {
		t.Error("setAXOMModel replaced an existing model on the second run")
	}
	// An unrelated MAC changes nothing.
	if aggregator.setAXOMModel(ip, "50:0B:88:00:00:2C", "EDS-405A") != false {
		t.Error("setAXOMModel matched a row with a different MAC")
	}
	// An empty model is never stored.
	if aggregator.setAXOMModel(ip, "50:0B:88:00:00:1A", "") != false {
		t.Error("setAXOMModel accepted an empty model")
	}

	devices := aggregator.snapshot()
	byMAC := make(map[string]Device, len(devices))
	for _, device := range devices {
		byMAC[device.MAC] = device
	}
	if got := byMAC["50:0B:88:00:00:1A"].Model; got != "AWK-1161C-UN" {
		t.Errorf("AXOM row model = %q, want AWK-1161C-UN", got)
	}
	if got := byMAC["50:0B:88:00:00:1A"].Region; got != "UN" {
		t.Errorf("AXOM row region = %q, want UN", got)
	}
	if got := byMAC["50:0B:88:00:00:1A"].Name; got != "awk-1161c" {
		t.Errorf("AXOM row name = %q, want awk-1161c (must be preserved)", got)
	}
	if got := byMAC["00:90:E8:00:00:D7"].Model; got != "AWK-1132C-US" {
		t.Errorf("4800 row model = %q, want AWK-1132C-US", got)
	}
	if got := byMAC["00:90:E8:00:00:D7"].Region; got != "US" {
		t.Errorf("4800 row region = %q, want US (derived from the model tail)", got)
	}
}

// TestSnapshotKeepsFallbackWhenEnhancementFailed proves requirement 4: when the
// model phase brings nothing, the row keeps exactly its previous value.
func TestSnapshotKeepsFallbackWhenEnhancementFailed(t *testing.T) {
	aggregator := newAggregator()
	aggregator.add(&Device{IP: "192.168.100.253", MAC: "50:0B:88:00:00:1A",
		Name: "awk-1161c", Protocol: ProtoNameAXOM})

	devices := aggregator.snapshot()
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
	if got := devices[0].Model; got != "awk-1161c" {
		t.Errorf("Model = %q, want the host name fallback awk-1161c", got)
	}
	if got := devices[0].Region; got != "" {
		t.Errorf("Region = %q, want an empty region for a host name", got)
	}
}

// appendARPTestRow serialises one MIB_IPNETROW exactly as Windows lays it out.
func appendARPTestRow(buffer []byte, mac []byte, ip net.IP, rowType uint32) []byte {
	return appendARPTestRowOnInterface(buffer, 21, mac, ip, rowType)
}

// appendARPTestRowOnInterface does the same for a specific interface index.
func appendARPTestRowOnInterface(buffer []byte, index uint32, mac []byte, ip net.IP, rowType uint32) []byte {
	row := mibIPNetRow{
		Index:       index,
		PhysAddrLen: uint32(len(mac)),
		Addr:        binary.LittleEndian.Uint32(ip.To4()),
		Type:        rowType,
	}
	copy(row.PhysAddr[:], mac)
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&row)), mibIPNetRowSize)
	return append(buffer, raw...)
}

// TestParseARPRows decodes a synthetic table: complete Ethernet entries of type
// dynamic/static are kept, everything else is dropped.
func TestParseARPRows(t *testing.T) {
	buffer := make([]byte, 4)
	buffer = appendARPTestRow(buffer, []byte{0x50, 0x0b, 0x88, 0x00, 0x00, 0x1a}, net.IPv4(192, 168, 100, 253), arpTypeDynamic)
	buffer = appendARPTestRow(buffer, []byte{0x00, 0x90, 0xe8, 0x00, 0x00, 0x20}, net.IPv4(192, 168, 100, 250), arpTypeStatic)
	// Type "invalid" (2): a neighbour that is being resolved, no usable MAC.
	buffer = appendARPTestRow(buffer, []byte{0x50, 0x0b, 0x88, 0x00, 0x00, 0x2c}, net.IPv4(192, 168, 100, 252), arpTypeInvalid)
	// Type "other" (1) is not trusted either.
	buffer = appendARPTestRow(buffer, []byte{0x50, 0x0b, 0x88, 0x00, 0x00, 0x2d}, net.IPv4(192, 168, 100, 254), arpTypeOther)
	// A non Ethernet entry (PhysAddrLen 0).
	buffer = appendARPTestRow(buffer, nil, net.IPv4(192, 168, 100, 249), arpTypeDynamic)
	// The broadcast and the all zero MAC are never reported.
	buffer = appendARPTestRow(buffer, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, net.IPv4(255, 255, 255, 255), arpTypeStatic)
	buffer = appendARPTestRow(buffer, []byte{0, 0, 0, 0, 0, 0}, net.IPv4(192, 168, 100, 248), arpTypeDynamic)
	binary.LittleEndian.PutUint32(buffer[0:4], 7)

	rows := parseARPRows(buffer)
	if len(rows) != 2 {
		t.Fatalf("parseARPRows returned %d rows (%+v), want 2", len(rows), rows)
	}
	table := selectARPTable(rows, nil)
	want := map[string]string{
		"192.168.100.253": "50:0B:88:00:00:1A",
		"192.168.100.250": "00:90:E8:00:00:20",
	}
	if len(table) != len(want) {
		t.Fatalf("selectARPTable returned %v, want %v", table, want)
	}
	for ip, mac := range want {
		if table[ip] != mac {
			t.Errorf("table[%s] = %q, want %q", ip, table[ip], mac)
		}
	}

	// A truncated buffer keeps the rows that are complete.
	truncated := buffer[:4+mibIPNetRowSize]
	if got := parseARPRows(truncated); len(got) != 1 {
		t.Errorf("parseARPRows(truncated) = %v, want one row", got)
	}
	// Unusable input must not panic.
	for _, empty := range [][]byte{nil, {}, {0}, {0, 0, 0}} {
		if got := parseARPRows(empty); len(got) != 0 {
			t.Errorf("parseARPRows(%v) = %v, want no rows", empty, got)
		}
		if got := selectARPTable(nil, nil); len(got) != 0 {
			t.Errorf("selectARPTable(nil) = %v, want an empty table", got)
		}
	}
}

// TestSelectARPTablePrefersOnLinkAdapter pins the resolution of the reference
// network, where 192.168.100.253 is cached on TWO interfaces at once:
//
//	WLAN     (192.168.99.163/24,  index 10) -> 00:90:E8:00:01:85  (EDS-408A)
//	Ethernet (192.168.100.100/24, index 21) -> 50:0B:88:00:00:1A  (AWK-1161C)
//
// Only the Ethernet interface routes to that address, so only its MAC may be
// used as the ownership proof - the WLAN entry would mislabel the row.
func TestSelectARPTablePrefersOnLinkAdapter(t *testing.T) {
	const ip = "192.168.100.253"
	rows := []arpRow{
		{Index: 10, IP: ip, MAC: "00:90:E8:00:01:85"},
		{Index: 21, IP: ip, MAC: "50:0B:88:00:00:1A"},
	}
	adapters := []Adapter{
		{Name: "WLAN", IP: net.IPv4(192, 168, 99, 163).To4(), Mask: net.CIDRMask(24, 32), Index: 10},
		{Name: "以太网", IP: net.IPv4(192, 168, 100, 100).To4(), Mask: net.CIDRMask(24, 32), Index: 21},
	}
	if got := selectARPTable(rows, adapters)[ip]; got != "50:0B:88:00:00:1A" {
		t.Errorf("on-link selection = %q, want 50:0B:88:00:00:1A (Ethernet)", got)
	}
	// The order of the raw rows must not matter.
	reversed := []arpRow{rows[1], rows[0]}
	if got := selectARPTable(reversed, adapters)[ip]; got != "50:0B:88:00:00:1A" {
		t.Errorf("on-link selection (reversed rows) = %q, want the Ethernet entry", got)
	}
	// Without a known adapter the last row wins, as the raw table suggests.
	if got := selectARPTable(rows, nil)[ip]; got != "50:0B:88:00:00:1A" {
		t.Errorf("fallback selection = %q, want the last row", got)
	}
	// An address outside every adapter subnet keeps the fallback as well.
	offLink := []arpRow{
		{Index: 10, IP: "10.9.9.9", MAC: "00:90:E8:00:01:85"},
		{Index: 21, IP: "10.9.9.9", MAC: "50:0B:88:00:00:1A"},
	}
	if got := selectARPTable(offLink, adapters)["10.9.9.9"]; got != "50:0B:88:00:00:1A" {
		t.Errorf("off-link selection = %q, want the last row", got)
	}
	// Exactly one entry per address survives.
	if got := len(selectARPTable(rows, adapters)); got != 1 {
		t.Errorf("len(table) = %d, want 1", got)
	}
}

// TestReadARPMatchesWindowsArp cross-checks the hand declared MIB_IPNETROW
// layout against the table Windows itself prints: if a field were misplaced the
// MAC (or the address) of every entry would be garbage and this test fails.
//
// It needs no device - only the local ARP cache - and skips when arp.exe cannot
// be executed.
func TestReadARPMatchesWindowsArp(t *testing.T) {
	output, err := exec.Command("arp", "-a").Output()
	if err != nil {
		t.Skipf("arp -a 不可用: %v", err)
	}
	expected := parseWindowsARPOutput(string(output))
	if len(expected) == 0 {
		t.Skip("本机 ARP 表为空，无法交叉验证")
	}

	got, err := ReadARPTable()
	if err != nil {
		t.Fatalf("ReadARPTable: %v", err)
	}
	compared := 0
	for ip, mac := range expected {
		if tableMAC, ok := got[ip]; ok {
			compared++
			if tableMAC != mac {
				t.Errorf("ARP 归属不一致: %s 声明 %s，GetIpNetTable 解析为 %s", ip, mac, tableMAC)
			}
			continue
		}
		t.Errorf("GetIpNetTable 缺少 arp -a 里的静态/动态条目: %s -> %s", ip, mac)
	}
	if compared == 0 {
		t.Fatalf("没有任何条目可以交叉验证（解析出 %d 条）", len(got))
	}
	if len(got) == 0 {
		t.Fatal("ReadARPTable 返回空表，但 arp -a 有条目")
	}
	t.Logf("交叉验证通过：arp -a 的 %d 条单播条目与 GetIpNetTable 完全一致（共解析 %d 条）",
		compared, len(got))
}

// parseWindowsARPOutput extracts the "IP  MAC" pairs of `arp -a`.
//
// Only unicast, non broadcast entries with a real hardware address are kept:
// the table also lists 255.255.255.255 and the multicast groups, which
// ReadARPTable deliberately drops.
func parseWindowsARPOutput(output string) map[string]string {
	table := make(map[string]string, 32)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(fields[0]).To4()
		if ip == nil || !ValidDeviceIP(ip) || ip.IsMulticast() {
			continue
		}
		mac := ParseMACString(fields[1])
		if mac == "" {
			continue
		}
		table[ip.String()] = mac
	}
	return table
}

// TestFetchUBUSModelRejectsBadAddress keeps the actual request off the network
// for inputs that cannot be a device address.
func TestFetchUBUSModelRejectsBadAddress(t *testing.T) {
	ctx := context.Background()
	for _, ip := range []string{"", "not-an-ip", "192.168.100.253:443", "::1"} {
		if _, err := fetchUBUSModel(ctx, ip, 50*time.Millisecond); err == nil {
			t.Errorf("fetchUBUSModel(%q) returned no error", ip)
		}
	}
}

// TestUBUSModelCallOverTLS drives the real HTTP client against a local TLS
// server: it proves that the self signed certificate is accepted, that exactly
// one request leaves the client and that the answer is parsed.
func TestUBUSModelCallOverTLS(t *testing.T) {
	var (
		calls   int
		payload string
	)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/ubus" {
			t.Errorf("path = %s, want /ubus", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("读取请求体失败: %v", err)
		}
		payload = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(ubusLoginAnswer))
	}))
	defer server.Close()

	model, err := ubusModelCall(context.Background(), server.URL+"/ubus", 2*time.Second)
	if err != nil {
		t.Fatalf("ubusModelCall: %v", err)
	}
	if model != "AWK-1161C-UN" {
		t.Errorf("model = %q, want AWK-1161C-UN", model)
	}
	if calls != 1 {
		t.Errorf("requests = %d, want exactly 1", calls)
	}
	if !strings.Contains(payload, ubusMethodContentsForLogin) ||
		!strings.Contains(payload, ubusAnonymousSession) ||
		!strings.Contains(payload, ubusObjectWebUI) {
		t.Errorf("请求体不含匿名会话/对象/方法: %s", payload)
	}
}

// TestUBUSModelCallTimeout proves the 800 ms budget is enforced, so a device
// that does not answer can only delay the scan by that much.
func TestUBUSModelCallTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte(ubusLoginAnswer))
	}))
	defer func() {
		close(release)
		server.Close()
	}()

	started := time.Now()
	model, err := ubusModelCall(context.Background(), server.URL+"/ubus", 80*time.Millisecond)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("a query that never answers must return an error")
	}
	if model != "" {
		t.Errorf("model = %q, want an empty string", model)
	}
	if elapsed > 2*time.Second {
		t.Errorf("超时未生效: 耗时 %v", elapsed)
	}
}

// TestUBUSModelCallNon200 keeps a HTTP error away from the parser.
func TestUBUSModelCallNon200(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer server.Close()

	if _, err := ubusModelCall(context.Background(), server.URL+"/ubus", time.Second); err == nil {
		t.Fatal("a 404 must be reported as an error")
	}
}

// TestEnhanceAXOMModelsWithoutCandidatesIsSilent makes sure the phase returns
// immediately when there is nothing to enhance (no network, no ARP read).
func TestEnhanceAXOMModelsWithoutCandidatesIsSilent(t *testing.T) {
	aggregator := newAggregator()
	aggregator.add(&Device{IP: "192.168.100.250", MAC: "00:90:E8:00:00:20", Model: "NPort 6450", Protocol: ProtoName4800})

	done := make(chan struct{})
	go func() {
		enhanceAXOMModels(context.Background(), aggregator, testAdapters, axomModelTimeout)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("enhanceAXOMModels blocked although there was no candidate")
	}
	if devices := aggregator.snapshot(); len(devices) != 1 || devices[0].Model != "NPort 6450" {
		t.Errorf("snapshot = %+v, want the unchanged 4800 row", devices)
	}
	// A nil aggregator must not panic either.
	enhanceAXOMModels(context.Background(), nil, testAdapters, axomModelTimeout)
	// A cancelled context is handled like any other failure.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	enhanceAXOMModels(ctx, aggregator, testAdapters, axomModelTimeout)
}

// TestNewUBUSModelRequestIsValidJSON pins the envelope that the device expects.
func TestNewUBUSModelRequestIsValidJSON(t *testing.T) {
	request := newUBUSModelRequest()
	if len(request) == 0 {
		t.Fatal("newUBUSModelRequest returned nothing")
	}
	var envelope map[string]any
	if err := json.Unmarshal(request, &envelope); err != nil {
		t.Fatalf("请求不是合法 JSON: %v", err)
	}
	if envelope["method"] != "call" {
		t.Errorf("method = %v, want call", envelope["method"])
	}
	if envelope["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v, want 2.0", envelope["jsonrpc"])
	}
	params, ok := envelope["params"].([]any)
	if !ok || len(params) != 4 {
		t.Fatalf("params = %v, want 4 elements", envelope["params"])
	}
	if params[0] != ubusAnonymousSession || params[1] != ubusObjectWebUI || params[2] != ubusMethodContentsForLogin {
		t.Errorf("params = %v, want the anonymous path", params)
	}
	if _, ok := params[3].(map[string]any); !ok {
		t.Errorf("params[3] = %v, want an empty object", params[3])
	}
}

// testAdapters is the interface list the link-local tests derive their zones
// from. It mirrors the reference machine (Ethernet 192.168.100.100 = index 21,
// WLAN 192.168.99.163 = index 10) without depending on the build machine.
var testAdapters = []Adapter{
	{Name: "WLAN", IP: net.IPv4(192, 168, 99, 163).To4(), Mask: net.CIDRMask(24, 32), Index: 10},
	{Name: "以太网", IP: net.IPv4(192, 168, 100, 100).To4(), Mask: net.CIDRMask(24, 32), Index: 21},
}

// TestEUI64LinkLocal pins the EUI-64 derivation (v1.3.1).
//
// The address is the identity of the device: fe80::/10 + the MAC with the U/L
// bit flipped and ff:fe inserted. Both reference values were verified against
// the real devices with curl.
func TestEUI64LinkLocal(t *testing.T) {
	tests := []struct {
		mac  string
		want string
	}{
		// The reference AWK-1161C.
		{mac: "50:0B:88:00:00:1A", want: "fe80::520b:88ff:fe00:1a"},
		// The AWK-1132C; note the leading zeros of the last group ("0fd7").
		{mac: "00:90:E8:00:00:D7", want: "fe80::290:e8ff:fe00:d7"},
		// The EDS-405A: the 0x02 bit of the first byte stays clear (0x50 has it).
		{mac: "50:0B:88:00:00:2C", want: "fe80::520b:88ff:fe00:2c"},
		// A MAC whose first byte has the 0x02 bit set: it must be cleared.
		{mac: "02:00:00:00:00:01", want: "fe80::ff:fe00:1"},
	}
	for _, test := range tests {
		mac, err := net.ParseMAC(test.mac)
		if err != nil {
			t.Fatalf("ParseMAC(%q): %v", test.mac, err)
		}
		if got := eui64LinkLocal(mac); got != test.want {
			t.Errorf("eui64LinkLocal(%s) = %q, want %q", test.mac, got, test.want)
		}
	}

	// Unusable inputs never produce a guessed address.
	invalid := []net.HardwareAddr{
		nil,
		{},
		{0x50, 0x0B, 0x88}, // too short
		{0x50, 0x0B, 0x88, 0x00, 0x00, 0x1A, 0x00}, // too long
		{0, 0, 0, 0, 0, 0},                         // all zero
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},       // broadcast (group bit)
		{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01},       // multicast
		{0x33, 0x33, 0x00, 0x00, 0x00, 0x01},       // multicast
	}
	for _, mac := range invalid {
		if got := eui64LinkLocal(mac); got != "" {
			t.Errorf("eui64LinkLocal(%X) = %q, want an empty string", []byte(mac), got)
		}
	}
}

// TestUBUSLinkLocalTarget pins the dial target and the request URL.
func TestUBUSLinkLocalTarget(t *testing.T) {
	const linkLocal = "fe80::520b:88ff:fe00:1a"
	if got, want := ubusLinkLocalTarget(linkLocal, 21), "[fe80::520b:88ff:fe00:1a%21]:443"; got != want {
		t.Errorf("ubusLinkLocalTarget(zone 21) = %q, want %q", got, want)
	}
	// Without a zone the target is still syntactically valid, only unscoped.
	if got, want := ubusLinkLocalTarget(linkLocal, 0), "[fe80::520b:88ff:fe00:1a]:443"; got != want {
		t.Errorf("ubusLinkLocalTarget(no zone) = %q, want %q", got, want)
	}
	if got, want := ubusLinkLocalTarget(linkLocal, -3), "[fe80::520b:88ff:fe00:1a]:443"; got != want {
		t.Errorf("ubusLinkLocalTarget(negative zone) = %q, want %q", got, want)
	}
	// The URL carries no zone: the dial target does.
	if got, want := ubusLinkLocalURL(linkLocal), "https://[fe80::520b:88ff:fe00:1a]:443/ubus"; got != want {
		t.Errorf("ubusLinkLocalURL = %q, want %q", got, want)
	}
	// The IPv4 URL is unchanged.
	if got, want := ubusURL("192.168.100.253"), "https://192.168.100.253:443/ubus"; got != want {
		t.Errorf("ubusURL = %q, want %q", got, want)
	}
	// A scoped URL must be parseable as well, so that a future caller can put
	// the zone into the URL instead of the dial target.
	scoped := "https://[fe80::1%2521]/ubus"
	if _, err := http.NewRequest(http.MethodPost, scoped, nil); err != nil {
		t.Errorf("scoped IPv6 URL被拒绝: %v", err)
	}
}

// TestAdapterIndexFor pins the reverse lookup of the interface index.
func TestAdapterIndexFor(t *testing.T) {
	if got := adapterIndexFor(testAdapters, []string{"以太网"}); got != 21 {
		t.Errorf("adapterIndexFor(以太网) = %d, want 21", got)
	}
	// The first known name wins.
	if got := adapterIndexFor(testAdapters, []string{"gone", "WLAN"}); got != 10 {
		t.Errorf("adapterIndexFor(gone, WLAN) = %d, want 10", got)
	}
	if got := adapterIndexFor(testAdapters, []string{"gone"}); got != 0 {
		t.Errorf("adapterIndexFor(unknown) = %d, want 0", got)
	}
	if got := adapterIndexFor(nil, []string{"以太网"}); got != 0 {
		t.Errorf("adapterIndexFor(nil adapters) = %d, want 0", got)
	}
	if got := adapterIndexFor(testAdapters, nil); got != 0 {
		t.Errorf("adapterIndexFor(no names) = %d, want 0", got)
	}
}

// TestFetchUBUSModelLinkLocalRejectsUnusableInput keeps the IPv6 channel off the
// network for inputs that cannot work.
func TestFetchUBUSModelLinkLocalRejectsUnusableInput(t *testing.T) {
	ctx := context.Background()
	if _, err := fetchUBUSModelLinkLocal(ctx, "", 21, 50*time.Millisecond); err == nil {
		t.Error("an empty link-local address must be rejected")
	}
	if _, err := fetchUBUSModelLinkLocal(ctx, "fe80::1", 0, 50*time.Millisecond); err == nil {
		t.Error("an unknown zone must be rejected instead of dialling unscoped")
	}
	if _, err := fetchUBUSModelLinkLocal(ctx, "fe80::1", -1, 50*time.Millisecond); err == nil {
		t.Error("a negative zone must be rejected")
	}
}

// ubusChannelStubs replaces the two network channels and the ARP read for the
// duration of one test.
type ubusChannelStubs struct {
	// linkLocal answers the IPv6 link-local query.
	linkLocal func(ctx context.Context, linkLocal string, zone int, timeout time.Duration) (string, error)
	// address answers the IPv4 query.
	address func(ctx context.Context, ip string, timeout time.Duration) (string, error)
	// arp is what the ARP read returns.
	arp map[string]string
	// arpErr makes the ARP read fail.
	arpErr error
}

// stubUBUSChannels installs the stubs and restores the real functions afterwards.
func stubUBUSChannels(t *testing.T, stubs ubusChannelStubs) {
	t.Helper()
	previousLinkLocal, previousAddress, previousARP := ubusLinkLocalQuery, ubusAddressQuery, readARPTable
	t.Cleanup(func() {
		ubusLinkLocalQuery, ubusAddressQuery, readARPTable = previousLinkLocal, previousAddress, previousARP
	})
	ubusLinkLocalQuery = stubs.linkLocal
	ubusAddressQuery = stubs.address
	readARPTable = func() (map[string]string, error) {
		if stubs.arpErr != nil {
			return map[string]string{}, stubs.arpErr
		}
		return stubs.arp, nil
	}
}

// sharedIPRow is one AXOM row of the reference network: three devices on
// 192.168.100.253, all seen over the Ethernet adapter.
func sharedIPRow(mac, name string) *Device {
	return &Device{
		IP: "192.168.100.253", MAC: mac, Name: name,
		Protocol: ProtoNameAXOM, Adapters: []string{"以太网"},
	}
}

// TestEnhancePrefersLinkLocal is the priority test of v1.3.1: when the
// link-local channel answers, the IPv4 channel must not run at all.
func TestEnhancePrefersLinkLocal(t *testing.T) {
	var linkLocalCalls, addressCalls int
	stubUBUSChannels(t, ubusChannelStubs{
		linkLocal: func(_ context.Context, linkLocal string, zone int, _ time.Duration) (string, error) {
			linkLocalCalls++
			if linkLocal != "fe80::520b:88ff:fe00:1a" {
				t.Errorf("link-local = %q, want the EUI-64 address of 50:0B:88:00:00:1A", linkLocal)
			}
			if zone != 21 {
				t.Errorf("zone = %d, want the index of 以太网 (21)", zone)
			}
			return "AWK-1161C-UN", nil
		},
		address: func(_ context.Context, ip string, _ time.Duration) (string, error) {
			addressCalls++
			t.Errorf("IPv4 通道被调用（%s），但链路本地通道已经成功", ip)
			return "", errors.New("unexpected IPv4 call")
		},
		// Even an ARP table that points somewhere else must not matter: the
		// link-local answer needs no ownership proof.
		arp: map[string]string{"192.168.100.253": "00:90:E8:00:00:D7"},
	})

	aggregator := newAggregator()
	aggregator.add(sharedIPRow("50:0B:88:00:00:1A", "awk-1161c"))

	enhanceAXOMModels(context.Background(), aggregator, testAdapters, axomModelTimeout)

	if linkLocalCalls != 1 {
		t.Errorf("link-local calls = %d, want exactly 1", linkLocalCalls)
	}
	if addressCalls != 0 {
		t.Errorf("IPv4 calls = %d, want 0", addressCalls)
	}
	devices := aggregator.snapshot()
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
	if devices[0].Model != "AWK-1161C-UN" || devices[0].Region != "UN" {
		t.Errorf("row = %+v, want AWK-1161C-UN / UN", devices[0])
	}
	if devices[0].Name != "awk-1161c" {
		t.Errorf("Name = %q, want the discovered host name to be preserved", devices[0].Name)
	}
}

// TestEnhanceFallsBackToIPv4 proves the fallback: a failed link-local attempt
// hands the row over to the v1.3 path, ARP check included.
func TestEnhanceFallsBackToIPv4(t *testing.T) {
	var linkLocalCalls, addressCalls int
	stubUBUSChannels(t, ubusChannelStubs{
		linkLocal: func(_ context.Context, linkLocal string, _ int, _ time.Duration) (string, error) {
			linkLocalCalls++
			return "", errors.New("dial tcp6 " + linkLocal + ": i/o timeout")
		},
		address: func(_ context.Context, ip string, _ time.Duration) (string, error) {
			addressCalls++
			if ip != "192.168.100.253" {
				t.Errorf("IPv4 query for %q, want 192.168.100.253", ip)
			}
			return "AWK-1161C-UN", nil
		},
		arp: map[string]string{"192.168.100.253": "50:0B:88:00:00:1A"},
	})

	aggregator := newAggregator()
	aggregator.add(sharedIPRow("50:0B:88:00:00:1A", "awk-1161c"))

	enhanceAXOMModels(context.Background(), aggregator, testAdapters, axomModelTimeout)

	if linkLocalCalls != 1 || addressCalls != 1 {
		t.Fatalf("calls = (link-local %d, ipv4 %d), want (1, 1)", linkLocalCalls, addressCalls)
	}
	devices := aggregator.snapshot()
	if devices[0].Model != "AWK-1161C-UN" || devices[0].Region != "UN" {
		t.Errorf("row = %+v, want AWK-1161C-UN / UN after the fallback", devices[0])
	}
}

// TestEnhanceLinkLocalFailureNoModelFallsBack covers the other two ways the
// link-local channel can end without a model: an empty model and a device that
// is not there at all (both must fall back, not abort).
func TestEnhanceLinkLocalFailureNoModelFallsBack(t *testing.T) {
	stubUBUSChannels(t, ubusChannelStubs{
		linkLocal: func(context.Context, string, int, time.Duration) (string, error) {
			return "", nil // HTTP 200 but no model (the EDS login page)
		},
		address: func(context.Context, string, time.Duration) (string, error) {
			return "AWK-1161C-UN", nil
		},
		arp: map[string]string{"192.168.100.253": "50:0B:88:00:00:1A"},
	})
	aggregator := newAggregator()
	aggregator.add(sharedIPRow("50:0B:88:00:00:1A", "awk-1161c"))
	enhanceAXOMModels(context.Background(), aggregator, testAdapters, axomModelTimeout)
	if devices := aggregator.snapshot(); devices[0].Model != "AWK-1161C-UN" {
		t.Errorf("Model = %q, want the IPv4 fallback value", devices[0].Model)
	}
}

// TestEnhanceSkipsLinkLocalWithoutMACOrZone covers requirement 4: a row without
// a usable MAC, or with an adapter that is no longer known, must not panic and
// must not lose its fallback value.
func TestEnhanceSkipsLinkLocalWithoutMACOrZone(t *testing.T) {
	// A MAC that cannot be parsed can neither be derived into a link-local
	// address nor matched against the ARP table, so the row is skipped by both
	// channels - and keeps its fallback.
	t.Run("MAC 无法解析", func(t *testing.T) {
		var linkLocalCalls, addressCalls int
		stubUBUSChannels(t, ubusChannelStubs{
			linkLocal: func(context.Context, string, int, time.Duration) (string, error) {
				linkLocalCalls++
				return "SHOULD-NOT-BE-ASKED", nil
			},
			address: func(context.Context, string, time.Duration) (string, error) {
				addressCalls++
				return "AWK-1161C-UN", nil
			},
			arp: map[string]string{"192.168.100.253": "50:0B:88:00:00:1A"},
		})
		aggregator := newAggregator()
		aggregator.add(&Device{IP: "192.168.100.253", MAC: "not-a-mac", Name: "broken",
			Protocol: ProtoNameAXOM, Adapters: []string{"以太网"}})
		enhanceAXOMModels(context.Background(), aggregator, testAdapters, axomModelTimeout)
		if linkLocalCalls != 0 || addressCalls != 0 {
			t.Errorf("calls = (%d, %d), want (0, 0): a broken MAC cannot be attributed",
				linkLocalCalls, addressCalls)
		}
		if devices := aggregator.snapshot(); devices[0].Model != "broken" {
			t.Errorf("Model = %q, want the untouched host name fallback", devices[0].Model)
		}
	})

	// A row whose adapter is not in the list any more has no zone; the IPv4
	// channel still resolves it.
	t.Run("网卡索引未知", func(t *testing.T) {
		var linkLocalCalls int
		stubUBUSChannels(t, ubusChannelStubs{
			linkLocal: func(context.Context, string, int, time.Duration) (string, error) {
				linkLocalCalls++
				return "SHOULD-NOT-BE-ASKED", nil
			},
			address: func(context.Context, string, time.Duration) (string, error) {
				return "AWK-1161C-UN", nil
			},
			arp: map[string]string{"192.168.100.253": "50:0B:88:00:00:1A"},
		})
		aggregator := newAggregator()
		aggregator.add(&Device{IP: "192.168.100.253", MAC: "50:0B:88:00:00:1A", Name: "awk-1161c",
			Protocol: ProtoNameAXOM, Adapters: []string{"已拔掉的网卡"}})
		enhanceAXOMModels(context.Background(), aggregator, testAdapters, axomModelTimeout)
		if linkLocalCalls != 0 {
			t.Errorf("链路本地通道被调用 %d 次，want 0", linkLocalCalls)
		}
		if devices := aggregator.snapshot(); devices[0].Model != "AWK-1161C-UN" {
			t.Errorf("Model = %q, want the IPv4 fallback value", devices[0].Model)
		}
	})

	// A row without any adapter name (and without adapters passed in) must not
	// panic either; it falls back to IPv4.
	t.Run("没有网卡名", func(t *testing.T) {
		var linkLocalCalls int
		stubUBUSChannels(t, ubusChannelStubs{
			linkLocal: func(context.Context, string, int, time.Duration) (string, error) {
				linkLocalCalls++
				return "SHOULD-NOT-BE-ASKED", nil
			},
			address: func(context.Context, string, time.Duration) (string, error) {
				return "AWK-1161C-UN", nil
			},
			arp: map[string]string{"192.168.100.253": "50:0B:88:00:00:1A"},
		})
		aggregator := newAggregator()
		aggregator.add(&Device{IP: "192.168.100.253", MAC: "50:0B:88:00:00:1A", Name: "awk-1161c",
			Protocol: ProtoNameAXOM})
		enhanceAXOMModels(context.Background(), aggregator, nil, axomModelTimeout)
		if linkLocalCalls != 0 {
			t.Errorf("链路本地通道被调用 %d 次，want 0", linkLocalCalls)
		}
		if devices := aggregator.snapshot(); devices[0].Model != "AWK-1161C-UN" {
			t.Errorf("Model = %q, want the IPv4 fallback value", devices[0].Model)
		}
	})
}

// TestEnhanceLinkLocalDoesNotCrossContaminate is the collision scenario of the
// reference network: three devices behind one address, only one of them has
// IPv6 and answers. The others must keep their fallback value.
func TestEnhanceLinkLocalDoesNotCrossContaminate(t *testing.T) {
	stubUBUSChannels(t, ubusChannelStubs{
		linkLocal: func(_ context.Context, linkLocal string, _ int, _ time.Duration) (string, error) {
			// Only the AWK-1161C answers; the other two time out.
			if linkLocal == "fe80::520b:88ff:fe00:1a" {
				return "AWK-1161C-UN", nil
			}
			return "", errors.New("i/o timeout")
		},
		address: func(context.Context, string, time.Duration) (string, error) {
			t.Error("IPv4 通道被调用：ARP 归属行已经由链路本地通道解决")
			return "", errors.New("unexpected")
		},
		// ARP currently points at the AWK-1161C, which the IPv6 channel already
		// resolved - so the IPv4 request could not change anything.
		arp: map[string]string{"192.168.100.253": "50:0B:88:00:00:1A"},
	})
	aggregator := newAggregator()
	aggregator.add(sharedIPRow("50:0B:88:00:00:1A", "awk-1161c"))
	aggregator.add(sharedIPRow("50:0B:88:00:00:2C", "EDS-405A"))
	aggregator.add(sharedIPRow("00:90:E8:00:01:D2", "EDS-408A-SS-SC"))

	enhanceAXOMModels(context.Background(), aggregator, testAdapters, axomModelTimeout)

	byMAC := make(map[string]Device, 3)
	for _, device := range aggregator.snapshot() {
		byMAC[device.MAC] = device
	}
	if got := byMAC["50:0B:88:00:00:1A"].Model; got != "AWK-1161C-UN" {
		t.Errorf("AWK row model = %q, want AWK-1161C-UN", got)
	}
	if got := byMAC["50:0B:88:00:00:2C"].Model; got != "EDS-405A" {
		t.Errorf("EDS-405A model = %q, want the host name fallback", got)
	}
	if got := byMAC["00:90:E8:00:01:D2"].Model; got != "EDS-408A-SS-SC" {
		t.Errorf("EDS-408A model = %q, want the host name fallback", got)
	}
	if got := byMAC["50:0B:88:00:00:2C"].Region; got != "" {
		t.Errorf("EDS-405A region = %q, want an empty region", got)
	}
}

// TestEnhanceFallsBackWhenNoMACMatchesARP proves the ARP gate of the fallback is
// still in force and that a hopeless IPv4 request is not even sent.
func TestEnhanceFallsBackWhenNoMACMatchesARP(t *testing.T) {
	var addressCalls int
	stubUBUSChannels(t, ubusChannelStubs{
		linkLocal: func(context.Context, string, int, time.Duration) (string, error) {
			return "", errors.New("no ipv6")
		},
		address: func(context.Context, string, time.Duration) (string, error) {
			addressCalls++
			return "AWK-1161C-UN", nil
		},
		// ARP resolves the address to a device that is not one of our rows.
		arp: map[string]string{"192.168.100.253": "AA:BB:CC:DD:EE:FF"},
	})
	aggregator := newAggregator()
	aggregator.add(sharedIPRow("50:0B:88:00:00:1A", "awk-1161c"))
	enhanceAXOMModels(context.Background(), aggregator, testAdapters, axomModelTimeout)
	if addressCalls != 0 {
		t.Errorf("IPv4 calls = %d, want 0 (no row could adopt the answer)", addressCalls)
	}
	if devices := aggregator.snapshot(); devices[0].Model != "awk-1161c" {
		t.Errorf("Model = %q, want the untouched fallback", devices[0].Model)
	}
}

// TestHasARPClaimant pins the small predicate behind that short cut.
func TestHasARPClaimant(t *testing.T) {
	arp := map[string]string{"192.168.100.253": "50:0B:88:00:00:1A"}
	owner := []Device{{MAC: "50:0B:88:00:00:1A"}, {MAC: "50:0B:88:00:00:2C"}}
	if !hasARPClaimant(arp, "192.168.100.253", owner) {
		t.Error("hasARPClaimant(owner in rows) = false, want true")
	}
	if hasARPClaimant(arp, "192.168.100.253", []Device{{MAC: "50:0B:88:00:00:2C"}}) {
		t.Error("hasARPClaimant(other rows) = true, want false")
	}
	if hasARPClaimant(arp, "192.168.100.99", owner) {
		t.Error("hasARPClaimant(unresolved address) = true, want false")
	}
	if hasARPClaimant(map[string]string{}, "192.168.100.253", owner) {
		t.Error("hasARPClaimant(empty table) = true, want false")
	}
	// Case and separator differences of the MAC must not matter.
	if !hasARPClaimant(map[string]string{"192.168.100.253": "50-0b-88-00-00-1a"},
		"192.168.100.253", []Device{{MAC: "50:0B:88:00:00:1A"}}) {
		t.Error("hasARPClaimant must compare normalized MACs")
	}
}

// TestEnhanceSurvivesARPReadFailure proves the IPv6 result is kept even when the
// ARP table cannot be read at all.
func TestEnhanceSurvivesARPReadFailure(t *testing.T) {
	stubUBUSChannels(t, ubusChannelStubs{
		linkLocal: func(_ context.Context, linkLocal string, _ int, _ time.Duration) (string, error) {
			if linkLocal == "fe80::520b:88ff:fe00:1a" {
				return "AWK-1161C-UN", nil
			}
			return "", errors.New("i/o timeout")
		},
		address: func(context.Context, string, time.Duration) (string, error) {
			t.Error("IPv4 通道被调用：ARP 表不可读时不应发起查询")
			return "", errors.New("unexpected")
		},
		arpErr: errors.New("GetIpNetTable failed"),
	})
	aggregator := newAggregator()
	aggregator.add(sharedIPRow("50:0B:88:00:00:1A", "awk-1161c"))
	aggregator.add(sharedIPRow("50:0B:88:00:00:2C", "EDS-405A"))

	enhanceAXOMModels(context.Background(), aggregator, testAdapters, axomModelTimeout)

	byMAC := make(map[string]Device, 2)
	for _, device := range aggregator.snapshot() {
		byMAC[device.MAC] = device
	}
	if got := byMAC["50:0B:88:00:00:1A"].Model; got != "AWK-1161C-UN" {
		t.Errorf("AWK row model = %q, want AWK-1161C-UN", got)
	}
	if got := byMAC["50:0B:88:00:00:2C"].Model; got != "EDS-405A" {
		t.Errorf("EDS row model = %q, want the untouched fallback", got)
	}
}
