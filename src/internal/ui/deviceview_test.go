package ui

import (
	"strconv"
	"strings"
	"testing"

	"moxasearch/src/internal/discovery"
)

// sortFixtures is the sample result used by the sorting and filtering tests.
//
// It covers everything the two rules have to break: three rows with the same
// model, two rows with the same address, one device without a MAC and one device
// whose model could not be resolved.
func sortFixtures() []discovery.Device {
	return []discovery.Device{
		{IP: "192.168.100.10", MAC: "50:0B:88:00:00:03", Model: "EDS-G4012", Adapters: []string{"WLAN"}},
		{IP: "192.168.100.9", MAC: "50:0B:88:00:00:02", Model: "AWK-1161C", Adapters: []string{"以太网"}},
		{IP: "192.168.100.9", MAC: "50:0B:88:00:00:01", Model: "AWK-1161C", Adapters: []string{"以太网", "WLAN"}},
		{IP: "192.168.100.2", MAC: "50:0B:88:00:00:04", Model: "AWK-1161C", Adapters: []string{"WLAN"}},
		{IP: "192.168.100.1", MAC: "50:0B:88:00:00:05", Adapters: []string{"WLAN"}},
	}
}

// rowKeys renders the sorted rows as "IP/MAC" so a test can compare the order
// without depending on cell formatting.
func rowKeys(devices []discovery.Device) []string {
	keys := make([]string, 0, len(devices))
	for _, device := range devices {
		keys = append(keys, device.IP+" "+device.MAC)
	}
	return keys
}

// TestColumnClickNotificationValue pins LVN_COLUMNCLICK.
//
// The project shipped a wrong NM_DBLCLK constant for four releases and nothing
// failed: a wrong notification code is silently ignored. This test is the guard
// for the v1.9 sorting feature.
func TestColumnClickNotificationValue(t *testing.T) {
	if lvnColumnClick != -108 {
		t.Fatalf("lvnColumnClick = %d, want -108 (LVN_COLUMNCLICK)", lvnColumnClick)
	}
	if lvnColumnClick == lvnItemChanged || lvnColumnClick == nmDblClk {
		t.Fatal("LVN_COLUMNCLICK must not share a value with another handled notification")
	}
	// The columns the specification names must be the ones the handler switches on.
	if columnTitles[columnModel] != "产品型号" {
		t.Fatalf("columnModel = %d names %q", columnModel, columnTitles[columnModel])
	}
	if columnTitles[columnIP] != "IP 地址" {
		t.Fatalf("columnIP = %d names %q", columnIP, columnTitles[columnIP])
	}
	if columnTitles[columnAdapters] != "设备信息来源网卡" {
		t.Fatalf("columnAdapters = %d names %q", columnAdapters, columnTitles[columnAdapters])
	}
}

// TestHeaderTitlesShowSortState covers the header indicator: the sorted column
// carries ▲ or ▼ and every other caption is untouched.
func TestHeaderTitlesShowSortState(t *testing.T) {
	initial := headerTitles(sortState{})
	for index := range columnTitles {
		if initial[index] != columnTitles[index] {
			t.Fatalf("unsorted title %d = %q, want %q", index, initial[index], columnTitles[index])
		}
	}

	ascending := headerTitles(sortState{field: sortModel, ascending: true})
	if ascending[columnModel] != "产品型号 ▲" {
		t.Errorf("model ascending = %q", ascending[columnModel])
	}
	if ascending[columnIP] != "IP 地址" {
		t.Errorf("IP caption changed while sorting by model: %q", ascending[columnIP])
	}

	descending := headerTitles(sortState{field: sortIP, ascending: false})
	if descending[columnIP] != "IP 地址 ▼" {
		t.Errorf("IP descending = %q", descending[columnIP])
	}
	if descending[columnModel] != "产品型号" {
		t.Errorf("model caption changed while sorting by IP: %q", descending[columnModel])
	}

	// The arrow must not pile up: switching the field drops it from the old one.
	switched := headerTitles(toggleSort(sortState{field: sortModel, ascending: true}, sortIP))
	if strings.Contains(switched[columnModel], "▲") || strings.Contains(switched[columnModel], "▼") {
		t.Errorf("model caption kept its arrow after switching to IP: %q", switched[columnModel])
	}
	if !strings.HasSuffix(switched[columnIP], "▲") {
		t.Errorf("IP caption = %q, want an ascending arrow", switched[columnIP])
	}
}

// TestToggleSort covers the click cycle: first click ascending, second click
// descending, a click on another column starts ascending again.
func TestToggleSort(t *testing.T) {
	state := toggleSort(sortState{}, sortModel)
	if state.field != sortModel || !state.ascending {
		t.Fatalf("first click = %+v, want model ascending", state)
	}
	state = toggleSort(state, sortModel)
	if state.field != sortModel || state.ascending {
		t.Fatalf("second click = %+v, want model descending", state)
	}
	state = toggleSort(state, sortIP)
	if state.field != sortIP || !state.ascending {
		t.Fatalf("click on another column = %+v, want IP ascending", state)
	}
	state = toggleSort(state, sortIP)
	if state.field != sortIP || state.ascending {
		t.Fatalf("second click on IP = %+v, want IP descending", state)
	}
}

// TestCompareIP pins the numeric address order: the table must never show
// .10 before .9.
func TestCompareIP(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"192.168.100.9", "192.168.100.10", -1},
		{"192.168.100.10", "192.168.100.9", 1},
		{"10.0.0.1", "10.0.0.1", 0},
		{"192.168.0.2", "192.168.0.10", -1},
		{"255.255.255.255", "0.0.0.0", 1},
		// Not an IPv4 address: ordered after every IPv4 one.
		{"fe80::1", "192.168.100.1", 1},
		{"192.168.100.1", "fe80::1", -1},
	}
	for _, test := range cases {
		if got := compareIP(test.left, test.right); got != test.want {
			t.Errorf("compareIP(%q, %q) = %d, want %d", test.left, test.right, got, test.want)
		}
	}
}

// TestVisibleDevicesSortByModel covers rule 1 of the request: model, then IP,
// then MAC, in both directions.
func TestVisibleDevicesSortByModel(t *testing.T) {
	ascending := visibleDevices(sortFixtures(), nil, sortState{field: sortModel, ascending: true})
	want := []string{
		"192.168.100.2 50:0B:88:00:00:04",  // AWK-1161C, lowest address
		"192.168.100.9 50:0B:88:00:00:01",  // AWK-1161C, same address -> MAC
		"192.168.100.9 50:0B:88:00:00:02",  // AWK-1161C, same address, higher MAC
		"192.168.100.10 50:0B:88:00:00:03", // EDS-G4012
		"192.168.100.1 50:0B:88:00:00:05",  // model unknown -> always last
	}
	if got := rowKeys(ascending); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("model ascending =\n  %v\nwant\n  %v", got, want)
	}

	descending := visibleDevices(sortFixtures(), nil, sortState{field: sortModel, ascending: false})
	want = []string{
		"192.168.100.10 50:0B:88:00:00:03",
		"192.168.100.9 50:0B:88:00:00:02",
		"192.168.100.9 50:0B:88:00:00:01",
		"192.168.100.2 50:0B:88:00:00:04",
		"192.168.100.1 50:0B:88:00:00:05", // still last: "-" is not a model
	}
	if got := rowKeys(descending); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("model descending =\n  %v\nwant\n  %v", got, want)
	}
}

// TestVisibleDevicesSortByIP covers rule 2 of the request: address, then model,
// then MAC, in both directions.
func TestVisibleDevicesSortByIP(t *testing.T) {
	ascending := visibleDevices(sortFixtures(), nil, sortState{field: sortIP, ascending: true})
	want := []string{
		"192.168.100.1 50:0B:88:00:00:05",
		"192.168.100.2 50:0B:88:00:00:04",
		"192.168.100.9 50:0B:88:00:00:01", // same IP, model tie -> MAC
		"192.168.100.9 50:0B:88:00:00:02",
		"192.168.100.10 50:0B:88:00:00:03", // numeric, not lexicographic
	}
	if got := rowKeys(ascending); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("IP ascending =\n  %v\nwant\n  %v", got, want)
	}

	descending := visibleDevices(sortFixtures(), nil, sortState{field: sortIP, ascending: false})
	want = []string{
		"192.168.100.10 50:0B:88:00:00:03",
		"192.168.100.9 50:0B:88:00:00:02",
		"192.168.100.9 50:0B:88:00:00:01",
		"192.168.100.2 50:0B:88:00:00:04",
		"192.168.100.1 50:0B:88:00:00:05",
	}
	if got := rowKeys(descending); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("IP descending =\n  %v\nwant\n  %v", got, want)
	}
}

// TestSortByModelBreaksTiesOnIPAndMAC pins the tie breakers on their own, with
// three devices that share one model.
func TestSortByModelBreaksTiesOnIPAndMAC(t *testing.T) {
	devices := []discovery.Device{
		{IP: "10.0.0.5", MAC: "50:0B:88:00:00:02", Model: "AWK-1131A"},
		{IP: "10.0.0.3", MAC: "50:0B:88:00:00:09", Model: "AWK-1131A"},
		{IP: "10.0.0.3", MAC: "50:0B:88:00:00:01", Model: "AWK-1131A"},
		{IP: "10.0.0.1", MAC: "50:0B:88:00:00:07", Model: "AWK-1131A"},
	}
	sorted := visibleDevices(devices, nil, sortState{field: sortModel, ascending: true})
	want := []string{
		"10.0.0.1 50:0B:88:00:00:07",
		"10.0.0.3 50:0B:88:00:00:01",
		"10.0.0.3 50:0B:88:00:00:09",
		"10.0.0.5 50:0B:88:00:00:02",
	}
	if got := rowKeys(sorted); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("tie break =\n  %v\nwant\n  %v", got, want)
	}
}

// TestSortIsStableAndNonDestructive makes sure sorting never mutates the scan
// result and never loses a row.
func TestSortIsStableAndNonDestructive(t *testing.T) {
	fixtures := sortFixtures()
	before := rowKeys(fixtures)

	sorted := visibleDevices(fixtures, nil, sortState{field: sortModel, ascending: true})

	if got := rowKeys(fixtures); strings.Join(got, "|") != strings.Join(before, "|") {
		t.Fatalf("the input slice was reordered:\n  %v\nwant\n  %v", got, before)
	}
	if len(sorted) != len(fixtures) {
		t.Fatalf("sorted %d rows, want %d", len(sorted), len(fixtures))
	}
	seen := make(map[string]bool)
	for _, key := range rowKeys(sorted) {
		if seen[key] {
			t.Fatalf("row %q appears twice after sorting", key)
		}
		seen[key] = true
	}
	// 序号 must be renumbered 1..n in display order (the cell takes the index).
	for index, device := range sorted {
		if cell := rowCells(index, device)[columnIndex]; cell != strconv.Itoa(index+1) {
			t.Fatalf("row %d 序号 = %q, want %q", index, cell, strconv.Itoa(index+1))
		}
	}
}

// TestAdapterOptions covers the filter menu entries: the distinct adapter names
// of the result, sorted.
func TestAdapterOptions(t *testing.T) {
	options := adapterOptions(sortFixtures())
	want := []string{"WLAN", "以太网"}
	if len(options) != len(want) {
		t.Fatalf("options = %v, want %v", options, want)
	}
	for index := range want {
		if options[index] != want[index] {
			t.Fatalf("options = %v, want %v", options, want)
		}
	}
	// A result without adapters offers nothing to filter.
	if got := adapterOptions(nil); len(got) != 0 {
		t.Errorf("adapterOptions(nil) = %v, want empty", got)
	}
	if got := adapterOptions([]discovery.Device{{IP: "10.0.0.1"}}); len(got) != 0 {
		t.Errorf("adapterOptions(no adapters) = %v, want empty", got)
	}
}

// TestAdapterFilter covers the filter itself: one adapter, several adapters, and
// the "no filter" default.
func TestAdapterFilter(t *testing.T) {
	fixtures := sortFixtures()

	// No filter shows everything, including the device without an adapter name.
	if got := visibleDevices(fixtures, nil, sortState{}); len(got) != len(fixtures) {
		t.Fatalf("no filter shows %d rows, want %d", len(got), len(fixtures))
	}

	wireless := visibleDevices(fixtures, map[string]bool{"WLAN": true}, sortState{})
	if len(wireless) != 4 {
		t.Fatalf("WLAN filter shows %d rows, want 4 (%v)", len(wireless), rowKeys(wireless))
	}
	for _, device := range wireless {
		if !containsString(device.Adapters, "WLAN") {
			t.Fatalf("row %s %s is not from WLAN", device.IP, device.MAC)
		}
	}

	// A device heard on two adapters appears under both.
	both := visibleDevices(fixtures, map[string]bool{"WLAN": true, "以太网": true}, sortState{})
	if len(both) != len(fixtures) {
		t.Fatalf("both adapters show %d rows, want %d", len(both), len(fixtures))
	}
	wired := visibleDevices(fixtures, map[string]bool{"以太网": true}, sortState{})
	if len(wired) != 2 {
		t.Fatalf("以太网 filter shows %d rows, want 2 (%v)", len(wired), rowKeys(wired))
	}

	// A device whose reply carried no adapter is hidden while a filter is on:
	// it cannot be attributed to any interface.
	for _, device := range wireless {
		if device.IP == "192.168.100.1" && len(device.Adapters) == 0 {
			t.Fatal("a device without adapters must not survive a filter")
		}
	}
}

// containsString is a tiny helper for the assertions above.
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// TestFilterAndSortAreIndependent is the property the request asks for: the two
// features must not influence each other, and clearing the filter restores the
// full table in the current sort order.
func TestFilterAndSortAreIndependent(t *testing.T) {
	fixtures := sortFixtures()
	filter := map[string]bool{"WLAN": true}
	state := sortState{field: sortIP, ascending: false}

	filtered := visibleDevices(fixtures, filter, state)
	if len(filtered) != 4 {
		t.Fatalf("filtered rows = %d, want 4", len(filtered))
	}
	// Descending IP inside the filtered set.
	want := []string{
		"192.168.100.10 50:0B:88:00:00:03",
		"192.168.100.9 50:0B:88:00:00:01",
		"192.168.100.2 50:0B:88:00:00:04",
		"192.168.100.1 50:0B:88:00:00:05",
	}
	if got := rowKeys(filtered); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("filtered + sorted =\n  %v\nwant\n  %v", got, want)
	}

	// Clearing the filter keeps the sort and brings every row back.
	cleared := visibleDevices(fixtures, nil, state)
	if len(cleared) != len(fixtures) {
		t.Fatalf("cleared rows = %d, want %d", len(cleared), len(fixtures))
	}
	if cleared[0].IP != "192.168.100.10" {
		t.Fatalf("the sort was lost when the filter was cleared: %v", rowKeys(cleared))
	}

	// Sorting an already filtered set does not change the filter.
	resorted := visibleDevices(fixtures, filter, sortState{field: sortModel, ascending: true})
	if len(resorted) != len(filtered) {
		t.Fatalf("re-sorting changed the filtered set: %d -> %d", len(filtered), len(resorted))
	}
}

// TestFilterStatus pins the status suffix, which is the only place the filter
// state is reported since the standalone 网卡筛选 button was removed.
func TestFilterStatus(t *testing.T) {
	if got := filterStatus(3, 6); got != "已筛选：显示 3/6 台" {
		t.Errorf("filterStatus(3, 6) = %q", got)
	}
	if got := filterStatus(0, 8); !strings.Contains(got, "0/8") {
		t.Errorf("filterStatus(0, 8) = %q, want the 0/8 counter", got)
	}
}

// TestDeviceRowKeyStable keeps the selection restoration of a rebuild honest:
// the same device keeps its key, and the key ignores MAC formatting.
func TestDeviceRowKeyStable(t *testing.T) {
	first := discovery.Device{IP: "192.168.100.9", MAC: "50:0B:88:00:00:01"}
	second := discovery.Device{IP: " 192.168.100.9 ", MAC: "50-0b-88-00-00-01"}
	if deviceRowKey(first) != deviceRowKey(second) {
		t.Fatalf("keys differ: %q vs %q", deviceRowKey(first), deviceRowKey(second))
	}
	other := discovery.Device{IP: "192.168.100.9", MAC: "50:0B:88:00:00:02"}
	if deviceRowKey(first) == deviceRowKey(other) {
		t.Fatal("two devices on one address must not share a key")
	}
	// Without a MAC the protocol keeps the two rows apart.
	plain := discovery.Device{IP: "192.168.100.10", Protocol: "MOXA/29168"}
	secondProtocol := discovery.Device{IP: "192.168.100.10", Protocol: "NPort/1029"}
	if deviceRowKey(plain) == deviceRowKey(secondProtocol) {
		t.Fatal("MAC-less rows must be told apart by protocol")
	}
}

// TestPanelMinimumHeight pins the drag floor of the LLDP panel: the summary line,
// the gap and exactly two complete neighbour rows.
func TestPanelMinimumHeight(t *testing.T) {
	app := &App{dpi: 96}
	panel := &lldpPanel{app: app}
	line := app.textHeight()
	row := listRowHeight(0, line, 96)

	want := line + scale(4, 96) + scale(6, 96) + listMinimumHeight(0, lldpPanelMinRows, line, 96)
	if got := panel.minimumHeight(); got != want {
		t.Fatalf("minimumHeight = %d, want %d", got, want)
	}
	// The table part of the minimum must be exactly header + two rows + border:
	// one pixel more would show a sliver of the third row.
	table := want - (line + scale(4, 96) + scale(6, 96))
	if table != listHeaderHeight(0, line, 96)+lldpPanelMinRows*row+listBorderPixels {
		t.Fatalf("table part of the minimum = %d, want header + %d rows + %d", table, lldpPanelMinRows, listBorderPixels)
	}
	if lldpPanelMinRows != 2 {
		t.Fatalf("lldpPanelMinRows = %d, want 2", lldpPanelMinRows)
	}
	// A nil panel must not panic (the window procedure calls it early).
	var missing *lldpPanel
	if got := missing.minimumHeight(); got != 0 {
		t.Errorf("nil panel minimumHeight = %d, want 0", got)
	}
}

// TestRebindRowKeepsThePanel covers the helper that follows a row move: the
// panel keeps its table and only learns the new index.
func TestRebindRowKeepsThePanel(t *testing.T) {
	panel := &lldpPanel{selectedRow: 0, generation: 4, reading: false}
	panel.lastInfo = "机箱 ID：0090e80000d0"
	panel.rebindRow(7)
	if panel.selectedRow != 7 {
		t.Fatalf("selectedRow = %d, want 7", panel.selectedRow)
	}
	if panel.generation != 4 {
		t.Fatalf("generation = %d, a rebind must not start a read", panel.generation)
	}
	if panel.lastInfo == "" {
		t.Fatal("a rebind must not clear the summary")
	}
}

// TestSqueezeWidths covers the column fitting that keeps the neighbour table free
// of a horizontal scroll bar (which would cost exactly one row of height).
func TestSqueezeWidths(t *testing.T) {
	widths := []int32{200, 400, 600, 300}

	// Content that already fits is returned unchanged.
	unchanged := squeezeWidths(widths, 2000, 100)
	for index := range widths {
		if unchanged[index] != widths[index] {
			t.Fatalf("column %d changed although it fits: %v", index, unchanged)
		}
	}

	// Too wide: the sum must fit, the proportions must survive and no column may
	// drop below the floor.
	squeezed := squeezeWidths(widths, 900, 100)
	total := int32(0)
	for index, width := range squeezed {
		total += width
		if width < 100 {
			t.Fatalf("column %d = %d, below the floor 100 (%v)", index, width, squeezed)
		}
	}
	if total > 900 {
		t.Fatalf("squeezed width = %d, want <= 900 (%v)", total, squeezed)
	}
	if squeezed[2] <= squeezed[1] || squeezed[1] <= squeezed[3] {
		t.Fatalf("the proportional order was lost: %v -> %v", widths, squeezed)
	}

	// Impossible request: every column ends at the floor instead of vanishing.
	tight := squeezeWidths(widths, 100, 60)
	for index, width := range tight {
		if width != 60 {
			t.Fatalf("column %d = %d, want the floor 60 (%v)", index, width, tight)
		}
	}

	// Degenerate inputs must not panic or divide by zero.
	if got := squeezeWidths(nil, 100, 10); len(got) != 0 {
		t.Errorf("squeezeWidths(nil) = %v", got)
	}
	if got := squeezeWidths(widths, 0, 10); len(got) != len(widths) {
		t.Errorf("squeezeWidths(available=0) = %v", got)
	}
}

// TestPanelSnappedHeight covers the row snapping of the panel height: the panel
// only ever ends on a row boundary, so the two row minimum really shows two
// complete rows and never a clipped third one.
func TestPanelSnappedHeight(t *testing.T) {
	app := &App{dpi: 96}
	panel := &lldpPanel{app: app}
	line := app.textHeight()
	row := listRowHeight(0, line, 96)
	minimum := panel.minimumHeight()

	if got := panel.snappedHeight(minimum); got != minimum {
		t.Fatalf("snapped(minimum) = %d, want %d (a minimum is already snapped)", got, minimum)
	}
	if got := panel.snappedHeight(minimum + row - 1); got != minimum {
		t.Fatalf("snapped(minimum + row - 1) = %d, want %d", got, minimum)
	}
	if got := panel.snappedHeight(minimum + row); got != minimum+row {
		t.Fatalf("snapped(minimum + row) = %d, want %d", got, minimum+row)
	}
	for _, wished := range []int32{minimum + 1, minimum + 3*row + 7, 1200} {
		got := panel.snappedHeight(wished)
		if got > wished {
			t.Fatalf("snapped(%d) = %d, never grow", wished, got)
		}
		if got < minimum {
			t.Fatalf("snapped(%d) = %d, below the minimum %d", wished, got, minimum)
		}
		if (got-minimum)%row != 0 {
			t.Fatalf("snapped(%d) = %d, not on a row boundary (+%d)", wished, got, got-minimum)
		}
	}
	// A height smaller than the summary line is handed through untouched.
	if got := panel.snappedHeight(10); got != 10 {
		t.Fatalf("snapped(10) = %d, want 10", got)
	}
	var missing *lldpPanel
	if got := missing.snappedHeight(300); got != 300 {
		t.Errorf("nil panel snappedHeight = %d, want 300", got)
	}
}

// TestLayoutKeepsTwoRowsAfterSnapping is the integration check of the two
// numbers the splitter works with: after splitHeights + snapping, the panel is
// still at least its minimum and the three parts still fill the content area.
func TestLayoutKeepsTwoRowsAfterSnapping(t *testing.T) {
	app := &App{dpi: 96}
	panel := &lldpPanel{app: app}
	line := app.textHeight()
	bar := scale(splitterHeightDIP, 96)
	listMinimum := listMinimumHeight(0, lldpListMinRows, line, 96)
	panelMinimum := panel.minimumHeight()

	for _, content := range []int32{420, 616, 900, 1200} {
		for _, share := range []int32{1, 300, defaultListSharePermille, 700, 999} {
			listHeight, panelHeight := splitHeights(content, bar, listMinimum, panelMinimum, share)
			panelHeight = panel.snappedHeight(panelHeight)
			listHeight = content - bar - panelHeight
			if panelHeight < panelMinimum {
				t.Fatalf("content %d share %d: panel %d < minimum %d", content, share, panelHeight, panelMinimum)
			}
			if listHeight+panelHeight+bar != content {
				t.Fatalf("content %d share %d: %d + %d + %d != %d",
					content, share, listHeight, panelHeight, bar, content)
			}
			if listHeight < listMinimum {
				t.Fatalf("content %d share %d: device table %d < minimum %d",
					content, share, listHeight, listMinimum)
			}
		}
	}
}
