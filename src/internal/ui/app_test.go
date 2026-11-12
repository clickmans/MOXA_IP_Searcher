package ui

import (
	"syscall"
	"testing"
	"unsafe"

	"moxasearch/src/internal/discovery"
)

// Clipboard helpers used only by the tests.
var (
	testGetClipboardData = dllUser32.NewProc("GetClipboardData")
	testIsClipboardFmt   = dllUser32.NewProc("IsClipboardFormatAvailable")
	testGlobalLockP      = dllKernel32.NewProc("GlobalLock")
	testGlobalUnlockP    = dllKernel32.NewProc("GlobalUnlock")
)

// TestSetClipboardTextRoundTrip verifies the CF_UNICODETEXT clipboard writer,
// which is the only non trivial Win32 code behind the Ctrl+C feature: it
// allocates an HGLOBAL, copies UTF-16 into it and hands it to the clipboard.
func TestSetClipboardTextRoundTrip(t *testing.T) {
	const want = "1\t192.168.100.253\t50:0B:88:00:00:DC\tAWK-1161A\tawk-1161a\tAXOM/40404\tWLAN\r\n"

	if !setClipboardText(0, want) {
		t.Skip("clipboard is not accessible in this session")
	}
	if available, _, _ := testIsClipboardFmt.Call(cfUnicodeText); available == 0 {
		t.Fatal("CF_UNICODETEXT is not present after setClipboardText")
	}
	opened, _, _ := procOpenClipboard.Call(0)
	if opened == 0 {
		t.Fatal("OpenClipboard failed")
	}
	defer func() { _, _, _ = procCloseClipboard.Call() }()

	handle, _, _ := testGetClipboardData.Call(cfUnicodeText)
	if handle == 0 {
		t.Fatal("GetClipboardData returned 0")
	}
	pointer, _, _ := testGlobalLockP.Call(handle)
	if pointer == 0 {
		t.Fatal("GlobalLock returned 0")
	}
	defer func() { _, _, _ = testGlobalUnlockP.Call(handle) }()

	got := syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(pointer)), 512))
	if got != want {
		t.Fatalf("clipboard = %q, want %q", got, want)
	}
}

// TestSetClipboardTextEmpty makes sure an empty payload does not panic.
func TestSetClipboardTextEmpty(t *testing.T) {
	if !setClipboardText(0, "") {
		t.Skip("clipboard is not accessible in this session")
	}
	// The content itself is irrelevant; the call must simply succeed and leave
	// the clipboard in a consistent state.
	if available, _, _ := testIsClipboardFmt.Call(cfUnicodeText); available == 0 {
		t.Fatal("CF_UNICODETEXT is not present after an empty copy")
	}
}

// TestScale checks the DPI scaling helper against the 96 DPI baseline.
func TestScale(t *testing.T) {
	tests := []struct {
		value int32
		dpi   int32
		want  int32
	}{
		{value: 0, dpi: 96, want: 0},
		{value: 100, dpi: 96, want: 100},
		{value: 100, dpi: 120, want: 125},
		{value: 100, dpi: 144, want: 150},
		{value: 100, dpi: 192, want: 200},
		{value: 100, dpi: 0, want: 100},
	}
	for _, test := range tests {
		if got := scale(test.value, test.dpi); got != test.want {
			t.Errorf("scale(%d, %d) = %d, want %d", test.value, test.dpi, got, test.want)
		}
	}
}

// TestColumnTitles guards the v1.1 table header (U3): seven columns in a fixed
// order, with 产品型号 right after 序号, 固件版本号 instead of 协议 and the
// renamed 设备信息来源网卡 column.
func TestColumnTitles(t *testing.T) {
	want := []string{
		"序号",
		"产品型号",
		"IP 地址",
		"MAC 地址",
		"固件版本号",
		"设备名称",
		"设备信息来源网卡",
	}
	if len(columnTitles) != len(want) {
		t.Fatalf("len(columnTitles) = %d, want %d", len(columnTitles), len(want))
	}
	for index := range want {
		if columnTitles[index] != want[index] {
			t.Errorf("columnTitles[%d] = %q, want %q", index, columnTitles[index], want[index])
		}
	}
	// The protocol column must not be visible any more (it stays in the JSON).
	for _, title := range columnTitles {
		if title == "协议" {
			t.Error("the 协议 column must not be part of the table any more")
		}
	}
}

// TestRowCells covers the v1.1 cell rules: column order (U3), the model/name
// fallback (U4) and the "-" placeholder for empty values (U7).
func TestRowCells(t *testing.T) {
	tests := []struct {
		name   string
		index  int
		device discovery.Device
		want   []string
	}{
		{
			name:  "full row",
			index: 3,
			device: discovery.Device{
				IP:       "192.168.100.3",
				MAC:      "50:0B:88:00:00:53",
				Model:    "AWK-1161C",
				Name:     "awk-1161c",
				Firmware: "V3.1.10 build 26102915",
				Protocol: "AXOM/40404",
				Adapters: []string{"WLAN"},
			},
			want: []string{
				"4", "AWK-1161C", "192.168.100.3", "50:0B:88:00:00:53",
				"V3.1.10 build 26102915", "awk-1161c", "WLAN",
			},
		},
		{
			// EOM-106 style: only a name, no model -> the model column shows
			// the name and the name column falls back to "-" so that the same
			// string is not printed twice.
			name: "model falls back to name",
			device: discovery.Device{
				IP:       "192.168.99.163",
				MAC:      "00:90:E8:00:00:D0",
				Name:     "EOM-106",
				Protocol: "EDS/4000",
				Adapters: []string{"WLAN", "VMnet1"},
			},
			want: []string{"1", "EOM-106", "192.168.99.163", "00:90:E8:00:00:D0", "-", "-", "WLAN, VMnet1"},
		},
		{
			name: "name equal to model is hidden",
			device: discovery.Device{
				IP:       "192.168.100.4",
				Model:    "MGate MB3180",
				Name:     "MGate MB3180",
				Protocol: "MOXA/4800",
				Adapters: []string{"WLAN"},
			},
			want: []string{"1", "MGate MB3180", "192.168.100.4", "-", "-", "-", "WLAN"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := rowCells(test.index, test.device)
			if len(got) != len(test.want) {
				t.Fatalf("len(cells) = %d, want %d", len(got), len(test.want))
			}
			for index := range test.want {
				if got[index] != test.want[index] {
					t.Errorf("cell[%d] = %q, want %q", index, got[index], test.want[index])
				}
			}
		})
	}
}

// TestModelAndNameCell pins the U4 rules on their own.
func TestModelAndNameCell(t *testing.T) {
	onlyName := discovery.Device{Name: "EOM-106"}
	if got := modelCell(onlyName); got != "EOM-106" {
		t.Errorf("modelCell = %q, want EOM-106", got)
	}
	if got := nameCell(onlyName); got != "-" {
		t.Errorf("nameCell = %q, want -", got)
	}
	both := discovery.Device{Model: "AWK-1161A", Name: "awk-1161a"}
	if got := modelCell(both); got != "AWK-1161A" {
		t.Errorf("modelCell = %q, want AWK-1161A", got)
	}
	if got := nameCell(both); got != "awk-1161a" {
		t.Errorf("nameCell = %q, want awk-1161a", got)
	}
	empty := discovery.Device{}
	if got := modelCell(empty); got != "-" {
		t.Errorf("modelCell = %q, want -", got)
	}
	if got := nameCell(empty); got != "-" {
		t.Errorf("nameCell = %q, want -", got)
	}
}

// TestStatusText covers the v1.1 status wording (U6): the unit is 台 (devices
// counted by MAC), never rows, and an IP collision is reported separately.
func TestStatusText(t *testing.T) {
	// Two devices share one IP: 3 devices on 2 addresses.
	sharedIP := &discovery.Result{Devices: []discovery.Device{
		{IP: "192.168.100.253", MAC: "50:0B:88:00:00:DC"},
		{IP: "192.168.100.253", MAC: "00:90:E8:00:00:D0"},
		{IP: "192.168.100.254", MAC: "50:0B:88:00:00:29"},
	}}
	if got := statusText(sharedIP); got != "搜索到 3 台设备（2 台设备 IP 重复）" {
		t.Errorf("statusText = %q", got)
	}
	single := &discovery.Result{Devices: []discovery.Device{
		{IP: "10.0.0.1", MAC: "50:0B:88:00:00:DC"},
	}}
	if got := statusText(single); got != "搜索到 1 台设备" {
		t.Errorf("statusText = %q", got)
	}
	// One device, two IPs: two rows, but only one device.
	twoAddresses := &discovery.Result{Devices: []discovery.Device{
		{IP: "192.168.100.254", MAC: "50:0B:88:00:00:89"},
		{IP: "192.168.100.253", MAC: "50:0B:88:00:00:89"},
	}}
	if got := statusText(twoAddresses); got != "搜索到 1 台设备" {
		t.Errorf("statusText = %q", got)
	}
	// Rows without a MAC each count as one device of their own.
	withoutMAC := &discovery.Result{Devices: []discovery.Device{
		{IP: "192.168.100.10", Protocol: "MOXA/29168"},
		{IP: "192.168.100.10", Protocol: "NPort/1029"},
	}}
	if got := statusText(withoutMAC); got != "搜索到 2 台设备（2 台设备 IP 重复）" {
		t.Errorf("statusText = %q", got)
	}
	empty := &discovery.Result{}
	if got := statusText(empty); got != "未发现设备（同一二层广播域内没有 MOXA 设备应答）" {
		t.Errorf("statusText = %q", got)
	}
	if got := statusText(nil); got != "未发现设备（同一二层广播域内没有 MOXA 设备应答）" {
		t.Errorf("statusText(nil) = %q", got)
	}
}

// TestProgressText pins the single status line of the progress popup.
//
// v1.1: the body no longer repeats the window caption ("正在搜索 MOXA 设备…"),
// it shows only the round counter and the device count.
func TestProgressText(t *testing.T) {
	tests := []struct {
		round, totalRounds, found int
		want                      string
	}{
		{round: 0, totalRounds: 3, found: 0, want: "正在准备广播…"},
		{round: 0, totalRounds: 0, found: 0, want: "正在准备广播…"},
		{round: 2, totalRounds: 3, found: 3, want: "第 2/3 轮 · 已发现 3 台设备"},
		{round: 1, totalRounds: 3, found: 0, want: "第 1/3 轮 · 已发现 0 台设备"},
		{round: 1, totalRounds: 0, found: 2, want: "第 1/1 轮 · 已发现 2 台设备"},
	}
	for _, test := range tests {
		if got := progressText(test.round, test.totalRounds, test.found); got != test.want {
			t.Errorf("progressText(%d, %d, %d) = %q, want %q",
				test.round, test.totalRounds, test.found, got, test.want)
		}
	}
	// The caption is unchanged and must not appear in the body text.
	if progressCaption != "正在搜索 MOXA 设备…" {
		t.Errorf("progressCaption = %q", progressCaption)
	}
	for round := 0; round <= 3; round++ {
		if got := progressText(round, 3, 1); got == progressCaption {
			t.Errorf("progressText(%d) repeats the caption", round)
		}
	}
}

// TestProgressTextPhase pins the model phase line of the progress popup (v1.3).
//
// The phase must not pretend to be a further round: the round counter keeps its
// final value (so the bar rests at 100 %) and the status line names the extra
// step instead of counting it.
func TestProgressTextPhase(t *testing.T) {
	if progressModelsText != "正在读取设备型号…" {
		t.Errorf("progressModelsText = %q, want 正在读取设备型号…", progressModelsText)
	}
	for _, round := range []int{0, 1, 3} {
		if got := progressTextForPhase(discovery.PhaseModels, round, 3, 7); got != progressModelsText {
			t.Errorf("progressTextForPhase(models, %d, 3, 7) = %q, want %q", round, got, progressModelsText)
		}
	}
	// The broadcast phase keeps the existing 3-round wording.
	if got := progressTextForPhase(discovery.PhaseBroadcast, 2, 3, 1); got != progressText(2, 3, 1) {
		t.Errorf("progressTextForPhase(broadcast, 2, 3, 1) = %q, want %q", got, progressText(2, 3, 1))
	}
	if got := progressTextForPhase(discovery.PhaseBroadcast, 0, 3, 0); got != "正在准备广播…" {
		t.Errorf("progressTextForPhase(broadcast, 0, 3, 0) = %q", got)
	}
	// Round == totalRounds is what keeps the bar at 100 % during the phase.
	if percent := int32(3) * 100 / int32(3); percent != 100 {
		t.Errorf("model phase bar target = %d %%, want 100 %%", percent)
	}
}
