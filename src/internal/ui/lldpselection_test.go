package ui

import (
	"context"
	"errors"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"moxasearch/src/internal/discovery"
	"moxasearch/src/internal/lldp"
)

// fakeReader replaces the LLDP reader so a test can count how often a table is
// actually read and answer with a canned result.
type fakeReader struct {
	mu    sync.Mutex
	ips   []string
	table *lldp.Table
	err   error
	// calls receives one token per invocation (buffered, never blocks).
	calls chan string
}

// newFakeReader installs a fake reader for the duration of one test.
func newFakeReader(t *testing.T, table *lldp.Table, err error) *fakeReader {
	t.Helper()
	reader := &fakeReader{table: table, err: err, calls: make(chan string, 64)}
	previous := fetchTable
	fetchTable = reader.fetch
	t.Cleanup(func() { fetchTable = previous })
	return reader
}

// fetch is the replacement of lldp.Fetch.
func (f *fakeReader) fetch(_ context.Context, ip string, _ lldp.Options) (*lldp.Table, error) {
	f.mu.Lock()
	f.ips = append(f.ips, ip)
	table, err := f.table, f.err
	f.mu.Unlock()
	select {
	case f.calls <- ip:
	default:
	}
	return table, err
}

// count returns how many times the reader was called.
func (f *fakeReader) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ips)
}

// waitFor blocks until the reader has been called at least n times.
func (f *fakeReader) waitFor(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if f.count() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("reader called %d times, want at least %d", f.count(), n)
}

// expectNoMore fails when another read happens during the settle window.
func (f *fakeReader) expectNoMore(t *testing.T, want int) {
	t.Helper()
	time.Sleep(120 * time.Millisecond)
	if got := f.count(); got != want {
		t.Fatalf("reader called %d times, want exactly %d (ips: %v)", got, want, f.ips)
	}
}

// waitPanelResult blocks until the panel has stored a result of its read.
func waitPanelResult(t *testing.T, panel *lldpPanel) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		panel.mu.Lock()
		done := panel.pendingTable != nil || panel.pendingErr != nil
		panel.mu.Unlock()
		if done {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the read never handed a result to the UI thread")
}

// fakePost records posted messages instead of delivering them, and lets a test
// dispatch them in order.
type fakePost struct {
	mu       sync.Mutex
	messages []uint
	params   []uintptr
}

// installFakePost replaces postMessage for the duration of one test.
func installFakePost(t *testing.T) *fakePost {
	t.Helper()
	fake := &fakePost{}
	previous := postMessage
	postMessage = func(_ syscall.Handle, msg uint, wparam, _ uintptr) {
		fake.mu.Lock()
		fake.messages = append(fake.messages, msg)
		fake.params = append(fake.params, wparam)
		fake.mu.Unlock()
	}
	t.Cleanup(func() { postMessage = previous })
	return fake
}

// count returns how many messages of one kind were posted.
func (f *fakePost) count(msg uint) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	total := 0
	for _, posted := range f.messages {
		if posted == msg {
			total++
		}
	}
	return total
}

// panelApp builds an App that is usable without a window.
//
// allDevices mirrors devices: the panel counts shared addresses over the full
// result (a filter must not hide the warning), and without a filter the two
// slices are the same.
func panelApp(devices ...discovery.Device) *App {
	return &App{devices: devices, allDevices: devices}
}

// TestOneClickProducesOneRead is the regression test for the P2 failure: a real
// click on the device table produces two LVN_ITEMCHANGED notifications, and the
// old code turned that pair into two reads (and a reset in between).
//
// The notification handler now only queues one message, so the panel is called
// once with the settled selection.
func TestOneClickProducesOneRead(t *testing.T) {
	reader := newFakeReader(t, &lldp.Table{ChassisID: "0090e80005d0"}, nil)
	fake := installFakePost(t)

	app := panelApp(
		discovery.Device{IP: "192.168.127.4", MAC: "00:90:E8:00:05:D0"},
		discovery.Device{IP: "192.168.127.3", MAC: "50:0B:88:0B:62:67"},
	)
	app.hMain = 1 // non-zero so the queue posts a message; nothing is delivered
	app.lldp = &lldpPanel{app: app, selectedRow: -1}
	app.selectedRowsFn = func() []int { return []int{0} }

	// One click = two notifications.
	app.queueSelectionChange()
	app.queueSelectionChange()
	if got := fake.count(wmAppSelection); got != 1 {
		t.Fatalf("queued %d selections for one click, want 1", got)
	}

	// The message loop dispatches the queued change once.
	app.dispatchSelectionPending()
	reader.waitFor(t, 1)
	reader.expectNoMore(t, 1)

	if app.lldp.generation != 1 {
		t.Fatalf("generation = %d, want 1", app.lldp.generation)
	}
	if app.selectionPending {
		t.Fatal("selectionPending must be cleared when the message is dispatched")
	}
}

// TestFiveClicksOnSameRowReadOnce reproduces the QA failure exactly: five clicks
// on the row that is already selected must read the table once, not five times.
func TestFiveClicksOnSameRowReadOnce(t *testing.T) {
	reader := newFakeReader(t, &lldp.Table{ChassisID: "0090e80005d0"}, nil)
	fake := installFakePost(t)

	app := panelApp(discovery.Device{IP: "192.168.127.4"})
	app.hMain = 1
	app.lldp = &lldpPanel{app: app, selectedRow: -1}
	app.selectedRowsFn = func() []int { return []int{0} }

	for click := 0; click < 5; click++ {
		app.queueSelectionChange()
		app.queueSelectionChange()
		app.dispatchSelectionPending()
		// Let the first read finish so `reading` is false for the next click.
		reader.waitFor(t, 1)
		if click == 0 {
			waitPanelResult(t, app.lldp)
			app.lldp.onResult()
		}
	}
	reader.expectNoMore(t, 1)

	if got := fake.count(wmAppSelection); got != 5 {
		t.Fatalf("queued %d selections for five clicks, want 5 (one per click)", got)
	}
	if app.lldp.generation != 1 {
		t.Fatalf("generation = %d, want 1 (no repeat read)", app.lldp.generation)
	}
}

// TestSwitchingRowsReadsOncePerDevice covers "click .4, then .3, then back": one
// read per distinct row, never more.
func TestSwitchingRowsReadsOncePerDevice(t *testing.T) {
	reader := newFakeReader(t, &lldp.Table{ChassisID: "x"}, nil)
	installFakePost(t)

	app := panelApp(
		discovery.Device{IP: "192.168.127.4"},
		discovery.Device{IP: "192.168.127.3"},
	)
	app.hMain = 1
	app.lldp = &lldpPanel{app: app, selectedRow: -1}

	rows := []int{0, 1, 0}
	for index, row := range rows {
		selected := row
		app.selectedRowsFn = func() []int { return []int{selected} }
		app.queueSelectionChange()
		app.dispatchSelectionPending()
		reader.waitFor(t, index+1)
		waitPanelResult(t, app.lldp)
		app.lldp.onResult()
	}
	reader.expectNoMore(t, 3)

	if app.lldp.generation != 3 {
		t.Fatalf("generation = %d, want 3", app.lldp.generation)
	}
	want := []string{"192.168.127.4", "192.168.127.3", "192.168.127.4"}
	for index := range want {
		if reader.ips[index] != want[index] {
			t.Errorf("read %d = %q, want %q", index, reader.ips[index], want[index])
		}
	}
}

// TestRealDeselectResetsPanel covers clicking the empty area of the table: the
// selection is empty, so the panel returns to its prompt.
func TestRealDeselectResetsPanel(t *testing.T) {
	reader := newFakeReader(t, &lldp.Table{ChassisID: "x"}, nil)
	installFakePost(t)

	app := panelApp(discovery.Device{IP: "192.168.127.4"})
	app.hMain = 1
	app.lldp = &lldpPanel{app: app, selectedRow: -1}

	app.selectedRowsFn = func() []int { return []int{0} }
	app.queueSelectionChange()
	app.dispatchSelectionPending()
	reader.waitFor(t, 1)
	waitPanelResult(t, app.lldp)
	app.lldp.onResult()

	app.selectedRowsFn = func() []int { return nil }
	app.queueSelectionChange()
	app.dispatchSelectionPending()
	reader.expectNoMore(t, 1)

	panel := app.lldp
	if panel.selectedRow != -1 {
		t.Fatalf("selectedRow = %d, want -1", panel.selectedRow)
	}
	if panel.reading {
		t.Fatal("reading must be false after a deselect")
	}
	if panel.lastInfo != lldpIdleText {
		t.Fatalf("summary = %q, want the idle prompt %q", panel.lastInfo, lldpIdleText)
	}
}

// TestQueueSelectionChangeCollapsesPosts verifies the flag that makes the two
// notifications of one click produce a single message.
func TestQueueSelectionChangeCollapsesPosts(t *testing.T) {
	fake := installFakePost(t)
	app := &App{hMain: 1}

	app.queueSelectionChange()
	app.queueSelectionChange()
	app.queueSelectionChange()
	if got := fake.count(wmAppSelection); got != 1 {
		t.Fatalf("posted %d messages, want 1", got)
	}
	if !app.selectionPending {
		t.Fatal("selectionPending must stay set while the message is queued")
	}

	// After the message is handled a new change is queued again.
	app.dispatchSelectionPending()
	if app.selectionPending {
		t.Fatal("selectionPending must be cleared by the dispatch")
	}
	app.queueSelectionChange()
	if got := fake.count(wmAppSelection); got != 2 {
		t.Fatalf("posted %d messages, want 2", got)
	}

	// Without a window nothing is posted at all (defensive).
	windowless := &App{}
	windowless.queueSelectionChange()
	if got := fake.count(wmAppSelection); got != 2 {
		t.Fatalf("a windowless app posted a message (%d total)", got)
	}
	if windowless.selectionPending {
		t.Fatal("a windowless app must not keep the flag set")
	}
}

// TestPanelSharedIPCountsTheWholeResult guards the v1.9 interaction between the
// adapter filter and the IP-collision warning: the filter hides rows from the
// table, it must not hide the fact that two devices sit on one address - SHMP
// still reaches only the ARP winner.
func TestPanelSharedIPCountsTheWholeResult(t *testing.T) {
	reader := newFakeReader(t, &lldp.Table{ChassisID: "0090e84cd232"}, nil)
	app := &App{
		// One visible row (the other device is filtered out) ...
		devices: []discovery.Device{{IP: "192.168.127.253", MAC: "00:90:E8:4C:D2:32"}},
		// ... two devices on that address in the whole result.
		allDevices: []discovery.Device{
			{IP: "192.168.127.253", MAC: "00:90:E8:4C:D2:32"},
			{IP: "192.168.127.253", MAC: "00:90:E8:8C:B6:E4"},
		},
	}
	app.lldp = &lldpPanel{app: app, selectedRow: -1}
	app.lldp.onSelectionChanged(0)
	reader.waitFor(t, 1)

	if app.lldp.sharedIP != 2 {
		t.Fatalf("sharedIP = %d, want 2 (the filter must not hide the collision)", app.lldp.sharedIP)
	}
	if !strings.Contains(app.lldp.lastInfo, "该 IP 上有 2 台设备") {
		t.Fatalf("summary = %q, want the shared-address warning", app.lldp.lastInfo)
	}
}

// TestSharedIPCount covers the helper that detects devices on one address.
func TestSharedIPCount(t *testing.T) {
	devices := []discovery.Device{
		{IP: "192.168.127.253", MAC: "00:90:E8:4C:D2:32"},
		{IP: "192.168.127.253", MAC: "00:90:E8:8C:B6:E4"},
		{IP: "192.168.127.4", MAC: "00:90:E8:00:05:D0"},
		{IP: " 192.168.127.4 ", MAC: "00:90:E8:00:05:D1"},
		{},
	}
	if got := sharedIPCount(devices, "192.168.127.253"); got != 2 {
		t.Errorf("sharedIPCount(.253) = %d, want 2", got)
	}
	if got := sharedIPCount(devices, "192.168.127.4"); got != 2 {
		t.Errorf("sharedIPCount(.4) = %d, want 2 (whitespace must not matter)", got)
	}
	if got := sharedIPCount(devices, "192.168.127.1"); got != 0 {
		t.Errorf("sharedIPCount(.1) = %d, want 0", got)
	}
	if got := sharedIPCount(devices, ""); got != 0 {
		t.Errorf("sharedIPCount(\"\") = %d, want 0", got)
	}
}

// TestSharedIPNote pins the warning text and, more importantly, that the success
// wording stays byte for byte identical when only one device owns the address.
func TestSharedIPNote(t *testing.T) {
	if note := lldpSharedNote(1); note != "" {
		t.Fatalf("lldpSharedNote(1) = %q, want empty", note)
	}
	if note := lldpSharedNote(0); note != "" {
		t.Fatalf("lldpSharedNote(0) = %q, want empty", note)
	}
	note := lldpSharedNote(3)
	if !strings.Contains(note, "该 IP 上有 3 台设备") {
		t.Fatalf("lldpSharedNote(3) = %q", note)
	}
	if !strings.Contains(note, "读取的是 ARP 命中的那一台") {
		t.Fatalf("lldpSharedNote(3) = %q", note)
	}

	table := &lldp.Table{
		ChassisID:  "0090e80005d0",
		SystemName: "Managed Redundant Switch 00007",
		SystemDesc: "EOM-106",
		Neighbors:  make([]lldp.Neighbor, 4),
	}
	const wantSingle = "机箱 ID：0090e80005d0　系统名：Managed Redundant Switch 00007　描述：EOM-106"

	// shared == 1: the specification wording, unchanged.
	single := &lldpPanel{sharedIP: 1, lastInfo: ""}
	single.setSummary(lldpSummary(lldpStateReady, "", table, nil))
	if single.lastInfo != wantSingle {
		t.Fatalf("single device summary = %q, want %q", single.lastInfo, wantSingle)
	}

	// shared == 3: the same wording plus the warning.
	shared := &lldpPanel{sharedIP: 3}
	shared.setSummary(lldpSummary(lldpStateReady, "", table, nil))
	if !strings.HasPrefix(shared.lastInfo, wantSingle) {
		t.Fatalf("shared summary = %q, want the spec wording as prefix", shared.lastInfo)
	}
	if !strings.Contains(shared.lastInfo, "该 IP 上有 3 台设备") {
		t.Fatalf("shared summary = %q, want the shared-address warning", shared.lastInfo)
	}
}

// TestPanelShowsSharedIPWarningEndToEnd drives the panel with two devices on one
// address and checks the summary line the user actually sees.
func TestPanelShowsSharedIPWarningEndToEnd(t *testing.T) {
	table := &lldp.Table{
		ChassisID:  "0090e84cd232",
		SystemName: "Managed Redundant Switch 01508",
		SystemDesc: "EDS-408A-SS-SC-T",
		Neighbors:  []lldp.Neighbor{{Port: 3, ChassisID: "0090e80005d0"}},
	}
	reader := newFakeReader(t, table, nil)

	app := panelApp(
		discovery.Device{IP: "192.168.127.253", MAC: "00:90:E8:4C:D2:32"},
		discovery.Device{IP: "192.168.127.253", MAC: "00:90:E8:8C:B6:E4"},
	)
	app.lldp = &lldpPanel{app: app, selectedRow: -1}
	app.lldp.onSelectionChanged(0)
	reader.waitFor(t, 1)
	waitPanelResult(t, app.lldp)

	if !strings.Contains(app.lldp.lastInfo, "该 IP 上有 2 台设备") {
		t.Fatalf("reading summary = %q, want the shared-address warning", app.lldp.lastInfo)
	}
	if app.lldp.sharedIP != 2 {
		t.Fatalf("sharedIP = %d, want 2", app.lldp.sharedIP)
	}

	app.lldp.onResult()
	const wantSingle = "机箱 ID：0090e84cd232　系统名：Managed Redundant Switch 01508　描述：EDS-408A-SS-SC-T"
	if !strings.HasPrefix(app.lldp.lastInfo, wantSingle) {
		t.Fatalf("ready summary = %q, want %q as prefix", app.lldp.lastInfo, wantSingle)
	}
	if !strings.Contains(app.lldp.lastInfo, "该 IP 上有 2 台设备") {
		t.Fatalf("ready summary = %q, want the shared-address warning", app.lldp.lastInfo)
	}

	// A device with its own address must not show the warning at all.
	appOne := panelApp(discovery.Device{IP: "192.168.127.4", MAC: "00:90:E8:00:05:D0"})
	appOne.lldp = &lldpPanel{app: appOne, selectedRow: -1}
	appOne.lldp.onSelectionChanged(0)
	reader.waitFor(t, 2)
	waitPanelResult(t, appOne.lldp)
	appOne.lldp.onResult()
	if appOne.lldp.lastInfo != wantSingle {
		t.Fatalf("single device summary = %q, want %q", appOne.lldp.lastInfo, wantSingle)
	}
}

// TestPanelNoSNMPKeepsSharedWarning makes sure the degraded answer of a shared
// address still says which device was asked.
func TestPanelNoSNMPKeepsSharedWarning(t *testing.T) {
	reader := newFakeReader(t, nil, lldp.ErrNoSNMP)
	app := panelApp(
		discovery.Device{IP: "192.168.127.253"},
		discovery.Device{IP: "192.168.127.253"},
		discovery.Device{IP: "192.168.127.253"},
	)
	app.lldp = &lldpPanel{app: app, selectedRow: -1}
	app.lldp.onSelectionChanged(0)
	reader.waitFor(t, 1)
	waitPanelResult(t, app.lldp)
	app.lldp.onResult()

	if !strings.HasPrefix(app.lldp.lastInfo, lldpNoSNMPText) {
		t.Fatalf("summary = %q, want the no-SNMP text as prefix", app.lldp.lastInfo)
	}
	if !strings.Contains(app.lldp.lastInfo, "该 IP 上有 3 台设备") {
		t.Fatalf("summary = %q, want the shared-address warning", app.lldp.lastInfo)
	}
}

// TestFetchErrorIsReported keeps the generic failure wording covered.
func TestFetchErrorIsReported(t *testing.T) {
	reader := newFakeReader(t, nil, errors.New("网络不可达"))
	app := panelApp(discovery.Device{IP: "192.168.127.4"})
	app.lldp = &lldpPanel{app: app, selectedRow: -1}
	app.lldp.onSelectionChanged(0)
	reader.waitFor(t, 1)
	waitPanelResult(t, app.lldp)
	app.lldp.onResult()

	if app.lldp.lastInfo != "读取 LLDP 失败：网络不可达" {
		t.Fatalf("summary = %q", app.lldp.lastInfo)
	}
	if app.lldp.reading {
		t.Fatal("reading must be false after a failure")
	}
}
