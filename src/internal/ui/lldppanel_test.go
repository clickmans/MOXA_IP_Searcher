package ui

import (
	"errors"
	"strings"
	"testing"

	"moxasearch/src/internal/lldp"

	"moxasearch/src/internal/discovery"
)

// TestLVNItemChangedValue pins the notification code the LLDP panel depends on.
//
// The project once hard coded NM_DBLCLK as -116 instead of -3, which silently
// disabled the double click handler for four releases. LVN_ITEMCHANGED is
// (LVN_FIRST - 1) with LVN_FIRST == -100, i.e. -101; if that value is ever
// mistyped the panel would never react to a selection change and the build
// would still work - exactly the failure mode this test exists to prevent.
func TestLVNItemChangedValue(t *testing.T) {
	if lvnFirst != -100 {
		t.Fatalf("lvnFirst = %d, want -100 (LVN_FIRST)", lvnFirst)
	}
	if lvnItemChanged != -101 {
		t.Fatalf("lvnItemChanged = %d, want -101 (LVN_ITEMCHANGED)", lvnItemChanged)
	}
	if lvnItemChanged == nmDblClk {
		t.Fatal("LVN_ITEMCHANGED and NM_DBLCLK must not share a value")
	}
	// Sanity check of the other code the same handler uses.
	if nmDblClk != -3 {
		t.Fatalf("nmDblClk = %d, want -3 (NM_DBLCLK)", nmDblClk)
	}
}

// TestLLDPColumnTitles pins the five columns of the neighbour panel.
func TestLLDPColumnTitles(t *testing.T) {
	want := []string{"端口", "邻居 ID", "邻居端口", "描述", "系统名"}
	if len(lldpColumnTitles) != len(want) {
		t.Fatalf("len(lldpColumnTitles) = %d, want %d", len(lldpColumnTitles), len(want))
	}
	for index := range want {
		if lldpColumnTitles[index] != want[index] {
			t.Errorf("lldpColumnTitles[%d] = %q, want %q", index, lldpColumnTitles[index], want[index])
		}
	}
}

// TestLLDPNeighborCells covers the cell rendering of one neighbour row.
func TestLLDPNeighborCells(t *testing.T) {
	full := lldp.Neighbor{
		Port:       4,
		ChassisID:  "0090e8d65985",
		PortID:     "7",
		PortDesc:   "100FX,SC,Single,40.",
		SystemName: "Managed Redundant Switch 49538",
	}
	got := lldpNeighborCells(full)
	want := []string{"4", "0090e8d65985", "7", "100FX,SC,Single,40.", "Managed Redundant Switch 49538"}
	if len(got) != len(want) {
		t.Fatalf("len(cells) = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf("cell[%d] = %q, want %q", index, got[index], want[index])
		}
	}

	// The port 2 neighbour of 192.168.127.4 has no description and no system
	// name; both must render as the "-" placeholder, not as an empty cell.
	empty := lldpNeighborCells(lldp.Neighbor{Port: 2, ChassisID: "c85b76f2204a", PortID: "c85b76f2204a"})
	if empty[0] != "2" || empty[3] != "-" || empty[4] != "-" {
		t.Errorf("cells = %v, want the empty columns as \"-\"", empty)
	}
}

// TestLLDPSummary pins every wording of the panel summary line: idle, reading,
// the successful table and both degraded cases.
func TestLLDPSummary(t *testing.T) {
	if got := lldpSummary(lldpStateIdle, "", nil, nil); got != "选中上方一台设备可查看它的 LLDP 邻居" {
		t.Errorf("idle = %q", got)
	}
	if got := lldpSummary(lldpStateReading, "192.168.127.4", nil, nil); got != "正在读取 192.168.127.4 的 LLDP 邻居…" {
		t.Errorf("reading = %q", got)
	}
	if got := lldpSummary(lldpStateNoSNMP, "", nil, lldp.ErrNoSNMP); got != "该设备未响应 SNMP（community=public），无法读取 LLDP" {
		t.Errorf("no snmp = %q", got)
	}
	failed := lldpSummary(lldpStateFailed, "", nil, errors.New("网络不可达"))
	if failed != "读取 LLDP 失败：网络不可达" {
		t.Errorf("failed = %q", failed)
	}

	table := &lldp.Table{
		ChassisID:  "0090e80005d0",
		SystemName: "Managed Redundant Switch 00007",
		SystemDesc: "EOM-106",
		Neighbors:  make([]lldp.Neighbor, 4),
	}
	// The success line is fixed by the specification: three fields, separated by
	// full width spaces, nothing else. Compared as a whole string on purpose.
	ready := lldpSummary(lldpStateReady, "", table, nil)
	const wantReady = "机箱 ID：0090e80005d0　系统名：Managed Redundant Switch 00007　描述：EOM-106"
	if ready != wantReady {
		t.Errorf("ready = %q, want %q", ready, wantReady)
	}

	emptyTable := &lldp.Table{ChassisID: "0090e80005d0"}
	emptyText := lldpSummary(lldpStateReady, "", emptyTable, nil)
	if !strings.Contains(emptyText, "该设备没有 LLDP 邻居") {
		t.Errorf("empty table summary = %q", emptyText)
	}
	// A column the device did not answer renders as "-", never as an empty gap.
	if !strings.Contains(emptyText, "系统名：-") {
		t.Errorf("empty table summary = %q, want a - placeholder", emptyText)
	}
}

// TestSplitHeights covers the vertical split between the device table, the drag
// bar and the LLDP panel (v1.9): the two tables plus the bar always fill the
// content area exactly, the table keeps six rows and the panel keeps its own
// minimum, and the user's share is honoured only inside those bounds.
func TestSplitHeights(t *testing.T) {
	cases := []struct {
		name          string
		contentHeight int32
		dpi           int32
	}{
		{name: "96 dpi minimum window", contentHeight: 400, dpi: 96},
		{name: "96 dpi default window", contentHeight: 616, dpi: 96},
		{name: "120 dpi", contentHeight: 700, dpi: 120},
		{name: "144 dpi", contentHeight: 800, dpi: 144},
		{name: "192 dpi", contentHeight: 1000, dpi: 192},
		{name: "very small client", contentHeight: 240, dpi: 96},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			line := test.dpi * 19 / 96
			bar := scale(splitterHeightDIP, test.dpi)
			listMinimum := listMinimumHeight(0, lldpListMinRows, line, test.dpi)
			// The panel minimum is the summary line, the gap and two rows.
			panelMinimum := line + scale(4, test.dpi) + scale(6, test.dpi) +
				listMinimumHeight(0, lldpPanelMinRows, line, test.dpi)

			for _, share := range []int32{1, 100, defaultListSharePermille, 500, 900, 999} {
				listHeight, panelHeight := splitHeights(test.contentHeight, bar, listMinimum, panelMinimum, share)
				if listHeight < 0 || panelHeight < 0 {
					t.Fatalf("share %d: list %d / panel %d must not be negative", share, listHeight, panelHeight)
				}
				if listHeight+panelHeight+bar != test.contentHeight {
					t.Fatalf("share %d: list %d + panel %d + bar %d != content %d",
						share, listHeight, panelHeight, bar, test.contentHeight)
				}
				usable := test.contentHeight - bar
				if listMinimum+panelMinimum <= usable {
					// Both floors fit - the normal case: neither may be broken.
					if listHeight < listMinimum {
						t.Fatalf("share %d: list %d < device table minimum %d", share, listHeight, listMinimum)
					}
					if panelHeight < panelMinimum {
						t.Fatalf("share %d: panel %d < panel minimum %d", share, panelHeight, panelMinimum)
					}
				}
			}
		})
	}

	// Default share on the default window: the table gets 58 % of the split area
	// and the panel 42 %, which is what v1.8 showed.
	bar := scale(splitterHeightDIP, 96)
	listHeight, panelHeight := splitHeights(616, bar, 169, 106, defaultListSharePermille)
	if want := (616 - bar) * 58 / 100; listHeight != want {
		t.Errorf("list height = %d, want %d (58 %%)", listHeight, want)
	}
	if listHeight+panelHeight+bar != 616 {
		t.Errorf("split does not fill 616: %d + %d + %d", listHeight, panelHeight, bar)
	}

	// Dragging to the very top and to the very bottom hits two hard limits.
	if top, _ := splitHeights(616, bar, 169, 106, 1); top != 169 {
		t.Errorf("fully collapsed table = %d, want the six row floor 169", top)
	}
	if _, bottom := splitHeights(616, bar, 169, 106, 999); bottom != 106 {
		t.Errorf("fully expanded table leaves %d for the panel, want its floor 106", bottom)
	}

	// A zero content area must not produce a negative height, and a share of 0
	// falls back to the default instead of collapsing the table.
	if list, panel := splitHeights(0, bar, 169, 106, 0); list != 0 || panel != 0 {
		t.Errorf("splitHeights(0) = %d/%d, want 0/0", list, panel)
	}
	fallback, _ := splitHeights(616, bar, 169, 106, 0)
	if fallback != (616-bar)*defaultListSharePermille/1000 {
		t.Errorf("a zero share must fall back to the default, got %d", fallback)
	}
}

// TestIdleStatusCarriesVersion pins the idle status line, including the version
// the release is named after.
func TestIdleStatusCarriesVersion(t *testing.T) {
	if AppVersion != "1.9.1" {
		t.Fatalf("AppVersion = %q, want 1.9.1", AppVersion)
	}
	bare := (&App{}).idleStatus()
	if bare != "就绪 · v1.9.1" {
		t.Errorf("idleStatus() = %q", bare)
	}
	withAdapters := (&App{adapterHint: "4 张网卡"}).idleStatus()
	if withAdapters != "就绪 · 4 张网卡 · v1.9.1" {
		t.Errorf("idleStatus() = %q", withAdapters)
	}
}

// TestLLDPPanelDropsStaleGeneration covers the generation guard: a slow answer of
// a device that is no longer selected must not touch the panel.
func TestLLDPPanelDropsStaleGeneration(t *testing.T) {
	panel := &lldpPanel{app: &App{}, selectedRow: 3, generation: 5, reading: true}
	panel.pendingGeneration = 4
	panel.pendingTable = &lldp.Table{ChassisID: "stale"}
	panel.onResult()
	if !panel.reading {
		t.Fatal("a stale result must not end the read of the current selection")
	}
	if panel.pendingTable != nil {
		t.Fatal("the stale result must be consumed")
	}

	panel.pendingGeneration = 5
	panel.pendingTable = &lldp.Table{ChassisID: "0090e80005d0"}
	panel.onResult()
	if panel.reading {
		t.Fatal("the result of the current generation must end the read")
	}
}

// TestLLDPPanelNilSafety keeps a partially constructed panel harmless: the
// window procedure calls into it before onCreate completes.
func TestLLDPPanelNilSafety(t *testing.T) {
	var panel *lldpPanel
	panel.layout(0, 0, 10, 10)
	panel.setInfo("x")
	panel.reset()
	panel.fill(nil)
	panel.onSelectionChanged(0)
	panel.onResult()
	panel.destroy()
	if got := panel.describeDevice(0); got != "" {
		t.Errorf("describeDevice on a nil panel = %q", got)
	}
}

// TestLLDPPanelIgnoresScanningSelection documents the "no read while scanning"
// rule without a window: the guard must be the first thing the handler checks.
func TestLLDPPanelIgnoresScanningSelection(t *testing.T) {
	app := &App{scanning: true, devices: []discovery.Device{{IP: "192.168.127.4"}}}
	panel := &lldpPanel{app: app, selectedRow: -1}
	panel.onSelectionChanged(0)
	if panel.selectedRow != -1 {
		t.Fatalf("selectedRow = %d, a scan is running and must not start a read", panel.selectedRow)
	}
	if panel.generation != 0 {
		t.Fatalf("generation = %d, want 0", panel.generation)
	}
}

// TestLLDPPanelKeepsSameRowSelection covers "reading A then A again": a repeated
// notification for the row the panel already describes starts no second read.
func TestLLDPPanelKeepsSameRowSelection(t *testing.T) {
	app := &App{devices: []discovery.Device{{IP: "192.168.127.4"}}}
	panel := &lldpPanel{app: app, selectedRow: 0, generation: 7, reading: true}
	panel.onSelectionChanged(0)
	if panel.generation != 7 {
		t.Fatalf("generation = %d, want 7 (no new read)", panel.generation)
	}
	if !panel.reading {
		t.Fatal("the running read must not be cancelled")
	}
}
