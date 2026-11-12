package ui

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"moxasearch/src/internal/discovery"
	"moxasearch/src/internal/lldp"
)

// The LLDP panel lives below the device table (v1.8). It shows the LLDP
// neighbours of the row that is selected above, read over SNMPv2c by package
// lldp. Everything that can block - the SNMP exchange itself - happens on a
// goroutine; the window procedure only builds controls and displays results.

// Control identifiers of the LLDP panel.
const (
	idcLLDPInfo = 1004
	idcLLDPList = 1005
)

// wmAppLLDP reports the outcome of an asynchronous LLDP read (v1.8).
//
// wParam carries the generation of the request so a late answer of a device
// that is no longer selected can be recognised and dropped.
const wmAppLLDP = wmApp + 5

// ListView notification codes (commctrl.h).
//
// LVN_FIRST is -100 and LVN_ITEMCHANGED is (LVN_FIRST - 1), i.e. -101. The
// constant is written as an expression on purpose: this project once used a
// hard coded -116 for NM_DBLCLK, which silently disabled the double click
// handler from v1.0 until v1.4. The unit test asserts the value.
const (
	lvnFirst       = -100
	lvnItemChanged = lvnFirst - 1 // LVN_ITEMCHANGED == -101
	// lvnColumnClick is LVN_COLUMNCLICK == (LVN_FIRST - 8) == -108. It is what
	// makes the 产品型号 / IP 地址 headers sortable (v1.9); a wrong value would
	// simply do nothing, exactly like the NM_DBLCLK bug did.
	lvnColumnClick = lvnFirst - 8
)

// lldpColumnTitles is the report header of the neighbour table.
var lldpColumnTitles = []string{"端口", "邻居 ID", "邻居端口", "描述", "系统名"}

// Panel geometry, in device independent pixels.
const (
	// lldpPanelMinRows is the number of neighbour rows the panel must keep
	// visible no matter how far the splitter is dragged down (v1.9). Two rows
	// are enough to read a switch's uplink and one leaf port, and they are the
	// hard floor of the drag.
	lldpPanelMinRows int32 = 2
	// lldpListMinRows is the number of device rows that must stay visible above
	// the panel: the two tables have to be readable at the same time.
	lldpListMinRows int32 = 6
	// lldpColumnMinDIP is the narrowest a neighbour column may be squeezed to
	// before the table would rather be too wide (v1.9).
	lldpColumnMinDIP int32 = 56
)

// Panel texts. The failure wording never mentions an error code on its own: the
// summary line is the only place the panel reports anything (no dialog, ever).
const (
	lldpIdleText      = "选中上方一台设备可查看它的 LLDP 邻居"
	lldpNoSNMPText    = "该设备未响应 SNMP（community=public），无法读取 LLDP"
	lldpNoAddressText = "该设备没有可用的 IP 地址，无法读取 LLDP"
	lldpReadingPrefix = "正在读取 "
	lldpReadingSuffix = " 的 LLDP 邻居…"
)

// Seams for the unit tests. Both have production defaults and are replaced only
// by tests, so a test can count how often a table is read and how often a
// message is posted without a window or a network.
var (
	// fetchTable reads one LLDP table (lldp.Fetch).
	fetchTable = lldp.Fetch
	// postMessage posts a message to a window (PostMessageW).
	postMessage = func(hwnd syscall.Handle, msg uint, wparam, lparam uintptr) {
		_, _, _ = procPostMessageW.Call(uintptr(hwnd), uintptr(msg), wparam, lparam)
	}
)

// lldpPanelState is the situation the summary line describes.
type lldpPanelState int

const (
	// lldpStateIdle is "nothing selected yet".
	lldpStateIdle lldpPanelState = iota
	// lldpStateReading is "the SNMP exchange is running".
	lldpStateReading
	// lldpStateReady is "the table was read".
	lldpStateReady
	// lldpStateNoSNMP is "the device does not answer SNMP at all".
	lldpStateNoSNMP
	// lldpStateFailed is "something else went wrong".
	lldpStateFailed
)

// lldpSummary renders the one line summary above the neighbour table.
//
// It is a pure function so every wording - including the degraded ones - is
// covered by a unit test without creating a window.
func lldpSummary(state lldpPanelState, ip string, table *lldp.Table, err error) string {
	switch state {
	case lldpStateIdle:
		return lldpIdleText
	case lldpStateReading:
		if strings.TrimSpace(ip) == "" {
			return lldpIdleText
		}
		return lldpReadingPrefix + strings.TrimSpace(ip) + lldpReadingSuffix
	case lldpStateNoSNMP:
		return lldpNoSNMPText
	case lldpStateFailed:
		if err != nil && strings.TrimSpace(err.Error()) != "" {
			return "读取 LLDP 失败：" + err.Error()
		}
		return "读取 LLDP 失败"
	}
	if table == nil {
		return "读取 LLDP 失败：没有返回结果"
	}
	// The success wording is fixed by the specification - chassis id, system
	// name and description separated by full width spaces. The neighbour count
	// is deliberately NOT appended: it is visible as the number of rows in the
	// table right below, and a fixed text is what the acceptance check compares.
	text := "机箱 ID：" + emptyAsDash(table.ChassisID) +
		"　系统名：" + emptyAsDash(table.SystemName) +
		"　描述：" + emptyAsDash(table.SystemDesc)
	if len(table.Neighbors) == 0 {
		// Not covered by the specification: without this hint an empty table
		// would look like a failed read.
		text += "　· 该设备没有 LLDP 邻居"
	}
	return text
}

// lldpNeighborCells renders one neighbour row.
//
// 端口 | 邻居 ID | 邻居端口 | 描述 | 系统名. An empty column becomes "-" so a
// missing value is visibly "not reported" instead of looking like a broken row.
func lldpNeighborCells(neighbor lldp.Neighbor) []string {
	return []string{
		strconv.Itoa(neighbor.Port),
		emptyAsDash(neighbor.ChassisID),
		emptyAsDash(neighbor.PortID),
		emptyAsDash(neighbor.PortDesc),
		emptyAsDash(neighbor.SystemName),
	}
}

// sharedIPCount counts the device rows that carry the same address.
//
// Two MOXA devices may share an IP address (PROTOCOL_SPEC.md §8), and SNMP -
// like the browser behind a double click - can only address the one ARP
// resolves to. The panel therefore has to say so instead of silently showing
// the neighbours of "some" device on that address.
func sharedIPCount(devices []discovery.Device, ip string) int {
	trimmed := strings.TrimSpace(ip)
	if trimmed == "" {
		return 0
	}
	count := 0
	for index := range devices {
		if strings.TrimSpace(devices[index].IP) == trimmed {
			count++
		}
	}
	return count
}

// lldpSharedNote is the suffix that warns about a shared address.
//
// It returns "" unless at least two rows share the address, which keeps the
// fixed success wording of the specification byte for byte identical for the
// normal case (a device with its own IP).
func lldpSharedNote(shared int) string {
	if shared < 2 {
		return ""
	}
	return fmt.Sprintf("　（该 IP 上有 %d 台设备，读取的是 ARP 命中的那一台）", shared)
}

// splitContent was replaced in v1.9 by splitHeights(), which knows about the
// draggable bar and the user's share instead of a fixed 42 %.
//
// The panel minimum it used to apply (220 DIP) is now derived from the rows the
// panel has to show (lldpPanelMinRows), because that is what the user drags
// against: "shrink it until two rows are left".

// infoHeight is the height of the summary line above the neighbour table.
func (p *lldpPanel) infoHeight() int32 {
	if p == nil || p.app == nil {
		return 0
	}
	return p.app.textHeight() + scale(4, p.app.dpi)
}

// infoGap is the space between the summary line and the neighbour table.
func (p *lldpPanel) infoGap() int32 {
	if p == nil || p.app == nil {
		return 0
	}
	return scale(6, p.app.dpi)
}

// minimumHeight is the smallest height the panel can be dragged to: the summary
// line, the gap and a neighbour table showing exactly lldpPanelMinRows complete
// rows.
//
// It is measured from the real control (header height from the window, row
// height from the font) instead of being a fixed 220 DIP, so two rows stay
// complete at every DPI - which is the property the drag floor promises.
func (p *lldpPanel) minimumHeight() int32 {
	if p == nil || p.app == nil {
		return 0
	}
	return p.heightForRows(lldpPanelMinRows)
}

// rowHeight is the height of one neighbour row.
//
// While the neighbour table is still empty it borrows the measurement from the
// device table above: both are the same control class with the same font, so the
// panel keeps its exact minimum from the first millisecond instead of jumping by
// a few pixels when the first neighbour arrives.
func (p *lldpPanel) rowHeight() int32 {
	if p == nil || p.app == nil {
		return 0
	}
	if height := measuredRowHeight(p.hList); height > 0 {
		return height
	}
	if height := measuredRowHeight(p.app.hList); height > 0 {
		return height
	}
	return listRowHeight(p.hList, p.app.textHeight(), p.app.dpi)
}

// fixedHeight is the part of the panel that does not depend on the row count:
// the summary line, the gap, the column header and the table border.
func (p *lldpPanel) fixedHeight() int32 {
	if p == nil || p.app == nil {
		return 0
	}
	line := p.app.textHeight()
	return p.infoHeight() + p.infoGap() +
		listHeaderHeight(p.hList, line, p.app.dpi) + listBorderPixels
}

// heightForRows returns the panel height that shows exactly rows neighbour rows.
func (p *lldpPanel) heightForRows(rows int32) int32 {
	if p == nil || p.app == nil {
		return 0
	}
	return p.fixedHeight() + rows*p.rowHeight()
}

// snappedHeight rounds a wished panel height DOWN to a whole number of rows.
//
// Two reasons (v1.9):
//   - a caller that hands out an arbitrary pixel height would leave a clipped
//     row at the bottom, which at the two row minimum looks like a broken table;
//   - the pixels taken away here go to the device table above, so nothing is
//     lost and no empty strip appears between the two tables.
//
// It only ever shrinks, so a height that was already clamped to the minimum stays
// at (or above) the minimum.
func (p *lldpPanel) snappedHeight(wished int32) int32 {
	if p == nil || p.app == nil || wished <= 0 {
		return wished
	}
	fixed := p.fixedHeight()
	row := p.rowHeight()
	if row <= 0 || wished <= fixed {
		return wished
	}
	return fixed + (wished-fixed)/row*row
}

// rebindRow updates the row the panel describes without reading anything (v1.9).
//
// A sort or a filter change renumbers every row but does not change the device
// the user selected, so the neighbour table stays valid: only the index has to
// follow, otherwise the next selection comparison would treat the same device as
// a different one and read its table again.
func (p *lldpPanel) rebindRow(row int) {
	if p == nil {
		return
	}
	p.selectedRow = row
}

// lldpPanel owns the two controls below the device table.
//
// The instance is created by onCreate and lives as long as the window; all
// fields except the mutex guarded ones are touched only on the UI thread.
type lldpPanel struct {
	app   *App
	hInfo syscall.Handle
	hList syscall.Handle

	// naturalWidths caches the content based width of every column.
	naturalWidths []int32
	// rowCount is the number of neighbour rows currently in the table (v1.9).
	// It decides whether a vertical scroll bar will take width away.
	rowCount int
	// listWidth / listHeight are the geometry of the neighbour list as handed
	// out by layout, so the column widths can be recomputed after a fill
	// without asking the control (whose client rect lags one message behind).
	listWidth  int32
	listHeight int32

	// generation counts selection changes. A result that arrives with an older
	// generation belongs to a device that is no longer selected and is dropped,
	// so a slow answer of device A can never overwrite the table of device B.
	generation int
	// selectedRow is the device row the panel currently describes (-1: none).
	selectedRow int
	// reading reports whether a read is in flight for selectedRow.
	reading bool
	// sharedIP is the number of device rows that share the address of
	// selectedRow (1 normally, more when several devices collide on one IP).
	sharedIP int
	// lastInfo is the text last written to the summary label. It is kept so the
	// unit tests can verify the exact wording without a window; only the UI
	// thread touches it.
	lastInfo string

	// mu guards the hand-over of the goroutine result to the UI thread.
	mu sync.Mutex
	// pendingGeneration is the generation of the stored result.
	pendingGeneration int
	// pendingTable is the read table (nil when err is set).
	pendingTable *lldp.Table
	// pendingErr is the error of the read.
	pendingErr error
}

// newLLDPPanel creates the summary label and the neighbour list.
func newLLDPPanel(app *App) *lldpPanel {
	if app == nil || app.hMain == 0 {
		return nil
	}
	panel := &lldpPanel{app: app, selectedRow: -1}
	panel.hInfo = createWindow(0, "STATIC", lldpIdleText,
		wsChild|wsVisible|wsClipSiblings|ssLeft|ssCenterImage|ssEndEllipsis,
		0, 0, 0, 0, app.hMain, idcLLDPInfo, app.hInstance)
	panel.hList = createWindow(0, "SysListView32", "",
		wsChild|wsVisible|wsClipSiblings|wsBorder|wsTabStop|lvsReport|lvsShowSelAlways,
		0, 0, 0, 0, app.hMain, idcLLDPList, app.hInstance)

	for _, handle := range []syscall.Handle{panel.hInfo, panel.hList} {
		if handle == 0 || app.hFontNormal == 0 {
			continue
		}
		_, _, _ = procSendMessageW.Call(uintptr(handle), wmSetFont, uintptr(app.hFontNormal), 1)
	}
	panel.setupColumns()
	panel.applyStyle()
	return panel
}

// setupColumns creates the five neighbour columns.
func (p *lldpPanel) setupColumns() {
	if p == nil || p.hList == 0 {
		return
	}
	placeholder := scale(120, p.app.dpi)
	for index, title := range lldpColumnTitles {
		text := utf16Ptr(title)
		item := LVCOLUMNW{
			Mask:    lvcfFmt | lvcfWidth | lvcfText,
			Fmt:     lvcfmtLeft,
			Cx:      placeholder,
			PszText: text,
		}
		_, _, _ = procSendMessageW.Call(uintptr(p.hList), lvmInsertColumnW,
			uintptr(index), uintptr(unsafe.Pointer(&item)))
		runtime.KeepAlive(text)
	}
}

// applyStyle switches on the extended styles of the neighbour list.
func (p *lldpPanel) applyStyle() {
	if p == nil || p.hList == 0 {
		return
	}
	style := uintptr(lvsexFullRowSelect | lvsexGridLines | lvsexDoubleBuffer)
	_, _, _ = procSendMessageW.Call(uintptr(p.hList), lvmSetExtendedListViewStyle, style, style)
}

// destroy forgets the control handles; the child windows die with the parent.
func (p *lldpPanel) destroy() {
	if p == nil {
		return
	}
	p.hInfo = 0
	p.hList = 0
	p.naturalWidths = nil
}

// layout positions the summary label and the neighbour list.
//
// The panel is given its height by App.layout through splitHeights and
// snappedHeight, which already guarantee the minimum of minimumHeight() and a
// whole number of rows; this function only divides it into the summary line and
// the table (v1.9).
func (p *lldpPanel) layout(x, y, width, height int32) {
	if p == nil || width < 0 || height < 0 {
		return
	}
	infoHeight := p.infoHeight()
	gap := p.infoGap()

	moveWindow(p.hInfo, x, y, width, infoHeight, true)
	listTop := y + infoHeight + gap
	listHeight := height - infoHeight - gap
	if listHeight < 0 {
		listHeight = 0
	}
	p.listWidth = width
	p.listHeight = listHeight
	moveWindow(p.hList, x, listTop, width, listHeight, true)
	p.refreshColumnWidths()
}

// listContentWidth is the width the neighbour columns have to fit into.
//
// The vertical scroll bar is subtracted up front when the neighbours do not fit
// into the current height: it takes its width from the client area, and columns
// that were sized against the full width would then trigger a HORIZONTAL scroll
// bar - which costs a row of height, the very thing the minimum must prevent.
func (p *lldpPanel) listContentWidth() int32 {
	if p == nil || p.app == nil {
		return 0
	}
	line := p.app.textHeight()
	available := p.listWidth - scale(4, p.app.dpi)
	row := p.rowHeight()
	capacity := p.listHeight - listHeaderHeight(p.hList, line, p.app.dpi) - listBorderPixels
	if row > 0 && int32(p.rowCount)*row > capacity {
		available -= scrollbarWidth()
	}
	if available < 0 {
		return 0
	}
	return available
}

// refreshColumnWidths re-applies the column widths for the current geometry.
func (p *lldpPanel) refreshColumnWidths() {
	if p == nil || p.hList == 0 {
		return
	}
	p.applyColumnWidths(p.listContentWidth())
}

// setInfo updates the summary line.
func (p *lldpPanel) setInfo(text string) {
	if p == nil {
		return
	}
	p.lastInfo = text
	if p.hInfo == 0 {
		return
	}
	setWindowText(p.hInfo, text)
}

// setSummary updates the summary line and appends the shared-address warning
// when the selected device has to share its IP with another one.
func (p *lldpPanel) setSummary(text string) {
	p.setInfo(text + lldpSharedNote(p.sharedIP))
}

// reset returns the panel to its idle state. It is called when the device list
// is rebuilt, because every row of the table then refers to another device.
func (p *lldpPanel) reset() {
	if p == nil {
		return
	}
	p.selectedRow = -1
	p.reading = false
	p.sharedIP = 0
	p.generation++
	p.fill(nil)
	p.setInfo(lldpIdleText)
}

// deleteRows removes every neighbour row.
func (p *lldpPanel) deleteRows() {
	if p == nil || p.hList == 0 {
		return
	}
	_, _, _ = procSendMessageW.Call(uintptr(p.hList), lvmDeleteAllItems, 0, 0)
}

// fill renders the neighbours of one table.
func (p *lldpPanel) fill(table *lldp.Table) {
	if p == nil {
		return
	}
	p.deleteRows()
	if table == nil || len(table.Neighbors) == 0 {
		p.rowCount = 0
		p.naturalWidths = nil
		p.refreshColumnWidths()
		return
	}
	rows := make([][]string, 0, len(table.Neighbors))
	for index, neighbor := range table.Neighbors {
		cells := lldpNeighborCells(neighbor)
		rows = append(rows, cells)
		insertListViewRow(p.hList, index, cells)
	}
	p.rowCount = len(table.Neighbors)
	// Column widths follow the content; they are squeezed to the visible width
	// so the table never grows a horizontal scroll bar (v1.9).
	p.naturalWidths = measureColumns(p.app.measure, p.app.dpi, lldpColumnTitles, rows)
	// The row height can only be measured from a real row, and the panel height
	// depends on it: re-run the layout once the first table has arrived.
	if p.app.hMain != 0 {
		p.app.layout()
	}
	p.refreshColumnWidths()
}

// insertListViewRow appends one row to a report mode ListView.
func insertListViewRow(hwnd syscall.Handle, row int, cells []string) {
	if hwnd == 0 || len(cells) == 0 {
		return
	}
	first := utf16Ptr(cells[0])
	item := LVITEMW{Mask: lvifText, IItem: int32(row), ISubItem: 0, PszText: first}
	_, _, _ = procSendMessageW.Call(uintptr(hwnd), lvmInsertItemW, 0, uintptr(unsafe.Pointer(&item)))
	runtime.KeepAlive(first)

	for column := 1; column < len(cells); column++ {
		text := utf16Ptr(cells[column])
		subItem := LVITEMW{Mask: lvifText, IItem: int32(row), ISubItem: int32(column), PszText: text}
		_, _, _ = procSendMessageW.Call(uintptr(hwnd), lvmSetItemTextW,
			uintptr(row), uintptr(unsafe.Pointer(&subItem)))
		runtime.KeepAlive(text)
	}
}

// applyColumnWidths writes the column widths for the given visible width.
func (p *lldpPanel) applyColumnWidths(available int32) {
	if p == nil || p.hList == 0 || available <= 0 {
		return
	}
	for index, width := range p.columnWidths(available) {
		_, _, _ = procSendMessageW.Call(uintptr(p.hList), lvmSetColumnWidth,
			uintptr(index), uintptr(width))
	}
}

// columnWidths returns the width of every column for the given visible width.
//
// Content wider than the window is squeezed instead of scrolled (v1.9): the
// horizontal scroll bar of a report ListView is ~17 DIP tall and would take that
// height away from the rows, which breaks the "two complete rows" guarantee of the
// drag minimum. The device table above keeps the v1.1 rule (never truncate, scroll
// instead) because it is the primary data table and nothing is dragged against it.
func (p *lldpPanel) columnWidths(available int32) []int32 {
	natural := p.naturalWidths
	if len(natural) != len(lldpColumnTitles) {
		natural = measureColumns(p.app.measure, p.app.dpi, lldpColumnTitles, nil)
	}
	widths := make([]int32, len(natural))
	copy(widths, natural)
	total := int32(0)
	for _, width := range widths {
		total += width
	}
	if total < available && len(widths) > 0 {
		widths[len(widths)-1] += available - total
		return widths
	}
	return squeezeWidths(widths, available, scale(lldpColumnMinDIP, p.app.dpi))
}

// onSelectionChanged reacts to a selection change of the device table.
//
// It is called from the notification handler with the row the list currently
// has selected (-1 when nothing is selected), so a repeated notification for
// the same row is ignored and a read of A is never restarted while A is still
// selected. The read itself runs on a goroutine.
func (p *lldpPanel) onSelectionChanged(row int) {
	if p == nil {
		return
	}
	app := p.app
	app.mu.Lock()
	scanning := app.scanning
	devices := app.devices
	all := app.allDevices
	app.mu.Unlock()

	if scanning {
		// During a search the table is emptied and refilled, so a selection is
		// not a device the user picked: never start a read here.
		debugf("lldp panel: selection ignored, a scan is running")
		return
	}
	if row < 0 || row >= len(devices) {
		if p.selectedRow != -1 || p.reading {
			p.reset()
		}
		return
	}
	if row == p.selectedRow {
		debugf("lldp panel: row %d is still selected, no new read", row)
		return
	}

	p.selectedRow = row
	p.generation++
	generation := p.generation
	p.reading = true
	p.fill(nil)

	ip := strings.TrimSpace(devices[row].IP)
	if !isWebAddress(ip) {
		p.reading = false
		p.sharedIP = 0
		p.setSummary(lldpNoAddressText)
		return
	}
	// Several devices may answer on one address; SNMP reaches the ARP winner
	// only, so the summary says so (same warning as the double click path).
	// The count covers the WHOLE result, not the filtered table: an active
	// adapter filter must not make the warning disappear (v1.9).
	p.sharedIP = sharedIPCount(all, ip)
	p.setSummary(lldpSummary(lldpStateReading, ip, nil, nil))
	debugf("lldp panel: row=%d ip=%s sharedIP=%d generation=%d", row, ip, p.sharedIP, generation)
	go p.read(generation, ip)
}

// read performs the SNMP exchange off the UI thread and hands the result over.
func (p *lldpPanel) read(generation int, ip string) {
	table, err := fetchTable(context.Background(), ip, lldp.Options{})
	p.mu.Lock()
	p.pendingGeneration = generation
	p.pendingTable = table
	p.pendingErr = err
	p.mu.Unlock()
	if hwnd := p.app.hMain; hwnd != 0 {
		postMessage(hwnd, wmAppLLDP, uintptr(generation), 0)
	}
}

// onResult consumes the outcome of a read on the UI thread.
func (p *lldpPanel) onResult() {
	if p == nil {
		return
	}
	p.mu.Lock()
	generation := p.pendingGeneration
	table := p.pendingTable
	err := p.pendingErr
	p.pendingTable = nil
	p.pendingErr = nil
	p.mu.Unlock()

	if generation != p.generation {
		// The selection changed while the request was running: the user is
		// already looking at another device.
		debugf("lldp panel: dropping result of generation %d (current %d)", generation, p.generation)
		return
	}
	p.reading = false
	switch {
	case errors.Is(err, lldp.ErrNoSNMP):
		p.fill(nil)
		p.setSummary(lldpSummary(lldpStateNoSNMP, "", nil, err))
	case err != nil:
		p.fill(nil)
		p.setSummary(lldpSummary(lldpStateFailed, "", nil, err))
	case table == nil:
		p.fill(nil)
		p.setSummary(lldpSummary(lldpStateFailed, "", nil, nil))
	default:
		p.fill(table)
		p.setSummary(lldpSummary(lldpStateReady, "", table, nil))
	}
}

// describeDevice is a debugging helper: it names the device a row shows.
func (p *lldpPanel) describeDevice(row int) string {
	if p == nil {
		return ""
	}
	p.app.mu.Lock()
	defer p.app.mu.Unlock()
	if row < 0 || row >= len(p.app.devices) {
		return ""
	}
	device := p.app.devices[row]
	return discovery.DisplayModel(device.Model, device.Name) + " " + device.IP
}
