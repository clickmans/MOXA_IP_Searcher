package ui

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"moxasearch/src/internal/discovery"
)

// Control identifiers.
const (
	idcList   = 1001
	idcScan   = 1002
	idcStatus = 1003
)

// Command identifiers of the adapter filter popup menu (v1.9).
//
// They are returned by TrackPopupMenu (TPM_RETURNCMD) instead of arriving as
// WM_COMMAND, so they never collide with the control ids above.
const (
	idFilterAll   = 2900
	idFilterFirst = 2901
)

// Private messages posted by the scan goroutine to the UI thread.
const (
	wmAppProgress = wmApp + 1
	wmAppDone     = wmApp + 2
	// wmAppPhase switches the progress popup to another scan phase (v1.3):
	// wParam = round, lParam = found, the phase is always PhaseModels.
	wmAppPhase = wmApp + 3
	// wmAppWeb reports the outcome of an asynchronous "open web UI" request
	// (v1.4). The text itself is passed through App.webNotice.
	wmAppWeb = wmApp + 4
	// wmAppSelection reports that a device-table selection change was seen
	// (v1.8). The notification handler only queues this message; the selection
	// is read one message-loop turn later, when both notifications of one click
	// (deselect the old row, select the new one) have been processed.
	wmAppSelection = wmApp + 6
)

// mainClassName is the registered window class of the main window.
const mainClassName = "MoxaSearchMainWindow"

// mainWindowTitle is the caption of the main window.
//
// The marketing suffix matches the house style used by the WIFI 4 config tool
// (the title bar is the one place the channel partner is always visible). Keep
// the product name first: the first characters are what the taskbar shows when
// the button is too narrow for the whole string.
const mainWindowTitle = "MOXA 设备 IP 搜索工具——买MOXA，找明高——www.mingit.com"

// AppVersion is the released version of the tool.
//
//	v1.9   draggable split, sortable headers, adapter filter
//	v1.9.1 the standalone 网卡筛选 button was removed again: the
//	       设备信息来源网卡 column header is the only filter entry point
//
// It is shown in the idle status line and it is the version in the file name of
// the versioned build (dist\MOXA_IP_Searcher_v<AppVersion>.exe), so the two can
// never drift apart.
const AppVersion = "1.9.1"

// Nominal client size in device independent pixels. It is clamped to the
// usable desktop, so a 1000x640 window at 200% scaling never leaves the screen.
const (
	windowWidthDIP  int32 = 1180
	windowHeightDIP int32 = 720
	windowMinWidth  int32 = 960
	windowMinHeight int32 = 560
)

// App owns the main window and all of its controls.
//
// There is exactly one App per process; the Win32 window procedure is a plain
// function pointer and therefore cannot carry a context, so the instance is
// published through theApp.
type App struct {
	hInstance syscall.Handle
	hMain     syscall.Handle
	hList     syscall.Handle
	hScan     syscall.Handle
	hStatus   syscall.Handle

	// lldp is the neighbour panel below the device table (v1.8). It is nil only
	// before onCreate has run or after a failed creation.
	lldp *lldpPanel

	// splitter is the drag bar between the device table and the panel (v1.9).
	splitter *splitter
	// listHeight is the height the device table currently occupies, including
	// its border. It is what the splitter starts a drag from.
	listHeight int32
	// listSharePermille is the share of the split area the device table gets,
	// in 1/1000. The panel gets the rest. Storing a share instead of a pixel
	// height keeps the split when the window is resized or the DPI changes.
	listSharePermille int32

	// sort is the sort picked by clicking a column header (v1.9).
	sort sortState
	// titles are the column captions currently shown, i.e. columnTitles with
	// the sort arrow. Column widths are measured against them.
	titles []string

	// allDevices is the unfiltered result of the last scan; devices is the list
	// of rows actually displayed (filter + sort applied). The LLDP panel, the
	// clipboard and the row renderer all work on devices, so a row index always
	// names the device the user sees.
	allDevices []discovery.Device
	// adapterFilter is the set of 设备信息来源网卡 names the table is filtered
	// to; nil (or empty) means every adapter, which is the default.
	adapterFilter map[string]bool
	// suspendSelection suppresses the queued selection notification while the
	// rows are rebuilt: rebuilding deletes and re-selects rows, and without this
	// a sort would re-read the LLDP table of the selected device over SNMP.
	suspendSelection bool
	// statusBase is the status line without the filter suffix; refreshStatus
	// appends the filter state to it.
	statusBase string

	hFontNormal syscall.Handle
	hIcon       syscall.Handle
	hBrushBg    syscall.Handle
	hBrushPanel syscall.Handle

	// measure gives the pixel size of one text line of hFontNormal; every
	// control height is derived from it instead of being hard coded (U5).
	measure *fontMeasure

	// tooltip carries the full adapter list that used to be a header line (U2).
	tooltip *tooltip

	dpi int32

	progress *progressWindow

	mu       sync.Mutex
	scanning bool
	devices  []discovery.Device
	result   *discovery.Result
	cancel   context.CancelFunc

	round       int
	totalRounds int
	found       int
	// phase is the stage the running scan is in (v1.3); it selects the status
	// line of the progress popup and of the status bar.
	phase discovery.Phase

	// adapterHint is the short adapter summary shown in the idle status line,
	// e.g. "4 张网卡".
	adapterHint string

	// webNotice carries the result of the asynchronous double click handler
	// (v1.4) from its goroutine to the UI thread; guarded by mu.
	webNotice string

	// selectionPending is true while one wmAppSelection message is queued and
	// not yet processed (v1.8). It collapses the two LVN_ITEMCHANGED messages a
	// single click produces into one selection read, which is what stops a
	// repeated click on the same row from reading its LLDP table again.
	// Only the UI thread touches it, so it needs no lock.
	selectionPending bool

	// naturalWidths caches the content based width of every column so that a
	// window resize does not have to measure every cell again.
	naturalWidths []int32

	// selectedRowsFn resolves the selected rows of the device table. It is nil
	// in production (the ListView is then asked directly) and replaced by the
	// unit tests, which have no window to ask.
	selectedRowsFn func() []int
}

// theApp is the single application instance (required by the WndProc callbacks).
var theApp *App

// Window procedure callbacks must stay reachable for the lifetime of the
// process, so they are created once at package initialisation.
var (
	mainWndProcPtr     = syscall.NewCallback(mainWndProc)
	progressWndProcPtr = syscall.NewCallback(progressWndProc)
	listWndProcPtr     = syscall.NewCallback(listWndProc)
	previousListProc   uintptr
)

// Run creates the main window and pumps messages until the window is closed.
//
// The whole function MUST stay on one OS thread: a Win32 message queue belongs
// to the thread that created the window. If the Go scheduler migrates this
// goroutine to another thread, GetMessage starts reading the queue of the new
// (empty) thread, so the WM_APP_PROGRESS / WM_APP_DONE messages posted by the
// scan goroutine are never dispatched: the progress popup never closes, the
// button stays disabled and Windows eventually reports AppHang. LockOSThread
// pins the goroutine - and with it the message queue - for the whole lifetime
// of the message loop. Do not move this call: it must run before the first
// window is created.
func Run() (int32, error) {
	runtime.LockOSThread()

	initProcessDPI()
	initCommonControls()

	dpi := systemDPI()
	app := &App{
		hInstance:   currentModule(),
		hIcon:       loadAppIcon(),
		dpi:         dpi,
		totalRounds: discovery.DefaultOptions().Rounds,
	}
	app.hBrushBg = createSolidBrush(colorBackground)
	app.hBrushPanel = createSolidBrush(colorPanel)
	theApp = app

	if err := registerWindowClass(mainClassName, app.hBrushBg, app.hIcon, mainWndProcPtr); err != nil {
		return 0, fmt.Errorf("注册窗口类失败: %w", err)
	}
	// The progress popup uses the panel (white) background.
	if err := registerWindowClass(progressClassName, app.hBrushPanel, app.hIcon, progressWndProcPtr); err != nil {
		return 0, fmt.Errorf("注册进度窗口类失败: %w", err)
	}
	// The splitter paints itself over the window background (v1.9).
	if err := registerWindowClass(splitterClassName, app.hBrushBg, 0, splitterWndProcPtr); err != nil {
		return 0, fmt.Errorf("注册分隔条窗口类失败: %w", err)
	}

	clientRectValue := RECT{
		Left:   0,
		Top:    0,
		Right:  scale(windowWidthDIP, dpi),
		Bottom: scale(windowHeightDIP, dpi),
	}
	_, _, _ = procAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&clientRectValue)),
		wsOverlappedWindow, 0, 0)
	width := clientRectValue.Right - clientRectValue.Left
	height := clientRectValue.Bottom - clientRectValue.Top

	// Never open larger than the usable desktop: with a 200% DPI scale the
	// nominal window would need twice the physical pixels.
	areaWidth, areaHeight := workArea()
	if limit := areaWidth - scale(16, dpi); width > limit && limit > 0 {
		width = limit
	}
	if limit := areaHeight - scale(16, dpi); height > limit && limit > 0 {
		height = limit
	}

	screenWidth, _, _ := procGetSystemMetrics.Call(smCxScreen)
	screenHeight, _, _ := procGetSystemMetrics.Call(smCyScreen)
	x := (int32(screenWidth) - width) / 2
	y := (int32(screenHeight) - height) / 2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}

	window := createWindow(0, mainClassName, mainWindowTitle, wsOverlappedWindow|wsClipChildren,
		x, y, width, height, 0, 0, app.hInstance)
	if window == 0 {
		return 0, fmt.Errorf("创建主窗口失败")
	}

	_, _, _ = procShowWindow.Call(uintptr(window), swShowNormal)
	_, _, _ = procUpdateWindow.Call(uintptr(window))

	return runMessageLoop(), nil
}

// mainWndProc dispatches the main window messages.
func mainWndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	app := theApp
	if app == nil {
		result, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
		return result
	}
	switch msg {
	case wmCreate:
		return app.onCreate(hwnd)
	case wmSize:
		app.layout()
		return 0
	case wmGetMinMaxInfo:
		app.applyMinMaxInfo(lparam)
		return 0
	case wmCommand:
		app.onCommand(wparam)
		return 0
	case wmNotify:
		app.onNotify(lparam)
		return 0
	case wmSetFocus:
		if app.hList != 0 {
			_, _, _ = procSetFocusW.Call(uintptr(app.hList))
		}
		return 0
	case wmCtlColorStatic:
		return app.onCtlColorStatic(wparam)
	case wmAppProgress:
		app.onProgressMessage(int(wparam), int(lparam))
		return 0
	case wmAppPhase:
		app.onPhaseMessage(int(wparam), int(lparam))
		return 0
	case wmAppWeb:
		app.onWebNotice()
		return 0
	case wmAppLLDP:
		app.onLLDPNotice()
		return 0
	case wmAppSelection:
		// One queued selection change: the notifications of the click that
		// caused it have all been dispatched, so the selection is stable now.
		app.dispatchSelectionPending()
		return 0
	case wmAppDone:
		app.onScanDone()
		return 0
	case wmClose:
		_, _, _ = procDestroyWindowW.Call(hwnd)
		return 0
	case wmDestroy:
		app.onDestroy()
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	}
	result, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return result
}

// onCreate builds every child control. Returning 0 lets the window be created.
func (a *App) onCreate(hwnd uintptr) uintptr {
	a.hMain = syscall.Handle(hwnd)
	if a.hIcon != 0 {
		_, _, _ = procSendMessageW.Call(hwnd, wmSetIcon, iconBig, uintptr(a.hIcon))
		_, _, _ = procSendMessageW.Call(hwnd, wmSetIcon, iconSmall, uintptr(a.hIcon))
	}

	// 14 pt (v1.2, was 18 pt in v1.1). Every control height is derived from the
	// measured metrics of this font, see textHeight().
	a.hFontNormal = createFont(fontPointSize, false, a.dpi)
	a.measure = newFontMeasure(a.hFontNormal)

	// The table is the first child: the "广播搜索" button sits above it in the
	// top left corner (U2).
	a.hList = createWindow(0, "SysListView32", "",
		wsChild|wsVisible|wsClipSiblings|wsBorder|wsTabStop|lvsReport|lvsShowSelAlways,
		0, 0, 0, 0, a.hMain, idcList, a.hInstance)

	a.hScan = createWindow(0, "BUTTON", "广播搜索",
		wsChild|wsVisible|wsClipSiblings|wsTabStop|bsPushButton,
		0, 0, 0, 0, a.hMain, idcScan, a.hInstance)

	a.hStatus = createWindow(0, "STATIC", "就绪",
		wsChild|wsVisible|wsClipSiblings|ssLeft|ssCenterImage|ssEndEllipsis,
		0, 0, 0, 0, a.hMain, idcStatus, a.hInstance)

	// The neighbour panel sits between the table and the status line (v1.8), so
	// the devices and their LLDP neighbours are visible at the same time.
	a.lldp = newLLDPPanel(a)
	a.splitter = newSplitter(a)

	a.titles = headerTitles(a.sort)
	a.applyFonts()
	a.setupColumns()
	a.applyListStyle()
	a.installListSubclass()
	a.layout()

	a.setStatus("就绪")
	a.refreshAdapters()
	a.statusBase = a.idleStatus()
	a.refreshStatus()
	return 0
}

// onDestroy releases the GDI objects and helper windows owned by the app.
func (a *App) onDestroy() {
	if a.splitter != nil {
		a.splitter.destroy()
		a.splitter = nil
	}
	if a.lldp != nil {
		a.lldp.destroy()
		a.lldp = nil
	}
	if a.tooltip != nil {
		a.tooltip.destroy()
		a.tooltip = nil
	}
	if a.measure != nil {
		a.measure.close()
		a.measure = nil
	}
	deleteObject(a.hFontNormal)
	a.hFontNormal = 0
}

// applyFonts assigns the Segoe UI fonts to every control.
func (a *App) applyFonts() {
	for _, handle := range []syscall.Handle{a.hScan, a.hList, a.hStatus} {
		if handle == 0 || a.hFontNormal == 0 {
			continue
		}
		_, _, _ = procSendMessageW.Call(uintptr(handle), wmSetFont, uintptr(a.hFontNormal), 1)
	}
}

// textHeight returns the pixel height of one line of the UI font.
//
// It falls back to a size derived from the nominal point size when the font
// could not be measured, so the layout never collapses to zero height.
func (a *App) textHeight() int32 {
	if a.measure != nil {
		if height := a.measure.lineHeight(); height > 0 {
			return height
		}
	}
	return scale(fontPointSize+4, a.dpi)
}

// buttonWidth returns the width the "广播搜索" button needs for its caption.
func (a *App) buttonWidth() int32 {
	minimum := scale(150, a.dpi)
	if a.measure == nil {
		return minimum
	}
	if width := a.measure.width("广播搜索") + scale(40, a.dpi); width > minimum {
		return width
	}
	return minimum
}

// columnTitles is the report header in display order (v1.1, U3).
//
// The old "协议" column is gone from the UI - the protocol string is still
// written to the JSON output for troubleshooting - and "固件版本号" was added.
var columnTitles = []string{
	"序号",
	"产品型号",
	"IP 地址",
	"MAC 地址",
	"固件版本号",
	"设备名称",
	"设备信息来源网卡",
}

// setupColumns creates the seven report columns.
//
// The initial widths are only a placeholder: fillList() measures the real
// content and layout() applies it (U5). The captions come from a.titles, which
// is columnTitles plus the sort arrow of the current sort (v1.9).
func (a *App) setupColumns() {
	if a.hList == 0 {
		return
	}
	titles := a.titles
	if len(titles) == 0 {
		titles = headerTitles(a.sort)
	}
	for index, title := range titles {
		text := utf16Ptr(title)
		item := LVCOLUMNW{
			Mask:    lvcfFmt | lvcfWidth | lvcfText,
			Fmt:     lvcfmtLeft,
			Cx:      scale(120, a.dpi),
			PszText: text,
		}
		_, _, _ = procSendMessageW.Call(uintptr(a.hList), lvmInsertColumnW,
			uintptr(index), uintptr(unsafe.Pointer(&item)))
		runtime.KeepAlive(text)
	}
}

// applyHeaderTitles rewrites the seven column captions.
//
// Only the text is sent (LVCF_TEXT), so the width the user may have just set
// stays untouched; the sort arrow is part of the caption because a comctl32 v5
// header does not draw HDF_SORTUP/DOWN arrows at all.
func (a *App) applyHeaderTitles() {
	if a.hList == 0 || len(a.titles) == 0 {
		return
	}
	for index, title := range a.titles {
		text := utf16Ptr(title)
		column := LVCOLUMNW{Mask: lvcfText, PszText: text}
		_, _, _ = procSendMessageW.Call(uintptr(a.hList), lvmSetColumnW,
			uintptr(index), uintptr(unsafe.Pointer(&column)))
		runtime.KeepAlive(text)
	}
}

// applyColumnWidths writes the content based column widths to the ListView.
//
// Columns are never squeezed: when their natural width exceeds the visible
// width the ListView shows a horizontal scroll bar instead of truncating the
// text (U5). The last column absorbs any leftover space.
//
// v1.9: the width handed to the columns already leaves room for the vertical
// scroll bar when the rows do not fit. Without that, the vertical bar appears
// first, narrows the client area by ~17 DIP, and the columns - which were sized
// against the wider client - then trigger a HORIZONTAL bar as well, which costs
// a whole row of height right at the minimum the splitter promises.
func (a *App) applyColumnWidths(outerWidth, outerHeight int32) {
	if a.hList == 0 || outerWidth <= 0 {
		return
	}
	available := outerWidth - scale(4, a.dpi)
	if a.verticalScrollbarNeeded(outerHeight) {
		available -= scrollbarWidth()
	}
	if available <= 0 {
		return
	}
	for index, width := range a.columnWidths(available) {
		_, _, _ = procSendMessageW.Call(uintptr(a.hList), lvmSetColumnWidth,
			uintptr(index), uintptr(width))
	}
}

// verticalScrollbarNeeded reports whether the device rows do not fit into the
// given height, i.e. whether the table will show a vertical scroll bar.
func (a *App) verticalScrollbarNeeded(outerHeight int32) bool {
	a.mu.Lock()
	rows := len(a.devices)
	a.mu.Unlock()
	line := a.textHeight()
	row := listRowHeight(a.hList, line, a.dpi)
	capacity := outerHeight - listHeaderHeight(a.hList, line, a.dpi) - listBorderPixels
	return row > 0 && int32(rows)*row > capacity
}

// columnWidths returns the width of every column for the given visible width.
func (a *App) columnWidths(available int32) []int32 {
	titles := a.titles
	if len(titles) == 0 {
		titles = headerTitles(a.sort)
	}
	natural := a.naturalWidths
	if len(natural) != len(titles) {
		natural = measureColumns(a.measure, a.dpi, titles, nil)
	}
	widths := make([]int32, len(natural))
	copy(widths, natural)

	total := int32(0)
	for _, width := range widths {
		total += width
	}
	if total < available && len(widths) > 0 {
		widths[len(widths)-1] += available - total
	}
	return widths
}

// applyListStyle switches on the modern ListView extended styles.
func (a *App) applyListStyle() {
	if a.hList == 0 {
		return
	}
	style := uintptr(lvsexFullRowSelect | lvsexGridLines | lvsexDoubleBuffer)
	_, _, _ = procSendMessageW.Call(uintptr(a.hList), lvmSetExtendedListViewStyle, style, style)
}

// installListSubclass hooks the ListView so that Ctrl+C can be intercepted
// before the control consumes the key (REQUIREMENTS.md §4).
func (a *App) installListSubclass() {
	if a.hList == 0 {
		return
	}
	previous, _, _ := procSetWindowLongPtrW.Call(uintptr(a.hList), gwlpWndProc, listWndProcPtr)
	previousListProc = previous
}

// listWndProc forwards every message to the original ListView procedure except
// Ctrl+C, which copies the selected rows.
func listWndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	if msg == wmKeyDown && wparam == vkC && keyPressed(vkControl) {
		if app := theApp; app != nil {
			app.copySelection()
			return 0
		}
	}
	if previousListProc == 0 {
		result, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
		return result
	}
	result, _, _ := procCallWindowProcW.Call(previousListProc, hwnd, msg, wparam, lparam)
	return result
}

// onCommand handles button clicks. It runs on the UI thread, and startScan
// only spawns the worker goroutine, so the window stays responsive.
func (a *App) onCommand(wparam uintptr) {
	id := int(wparam & 0xFFFF)
	code := int((wparam >> 16) & 0xFFFF)
	if code != bnClicked {
		return
	}
	switch id {
	case idcScan:
		a.startScan()
	}
}

// onNotify handles ListView notifications.
//
// LVN_ITEMCHANGED drives the LLDP panel (v1.8): selecting a device row reads its
// neighbour table. NM_DBLCLK opens the web UI of the activated device (v1.4).
//
// NMITEMACTIVATE is used instead of the selection so the activated row is
// unambiguous even when several rows are selected or the click lands on a row
// that was not selected before (the selection is updated by the same click, but
// the notification already carries the authoritative index).
func (a *App) onNotify(lparam uintptr) {
	if lparam == 0 {
		return
	}
	header := (*NMHDR)(unsafe.Pointer(lparam))
	if syscall.Handle(header.HwndFrom) != a.hList {
		return
	}
	code := int32(header.Code)
	if code == lvnItemChanged {
		// A single click produces two notifications: the old row is deselected
		// and the new one selected. Reading the selection here would see the
		// intermediate "nothing selected" state of the first one, which resets
		// the panel and makes the second notification start a fresh read - the
		// reason clicking the same row five times used to read five times.
		// Queueing a message instead lets both notifications finish first, so
		// the handler observes the final selection exactly once.
		a.queueSelectionChange()
		return
	}
	if code == lvnColumnClick {
		// LVN_COLUMNCLICK carries the clicked header in iSubItem; the structure
		// is byte for byte the same as the one NM_DBLCLK sends (NMITEMACTIVATE
		// extends NMLISTVIEW), so it is reused instead of duplicated.
		click := (*NMITEMACTIVATE)(unsafe.Pointer(lparam))
		a.onColumnClick(int(click.ISubItem))
		return
	}
	if code != nmDblClk {
		return
	}
	activation := (*NMITEMACTIVATE)(unsafe.Pointer(lparam))
	row := int(activation.IItem)
	debugf("NM_DBLCLK from=%#x row=%d", header.HwndFrom, row)
	if row < 0 {
		// Keyboard activation reports -1; fall back to the current selection.
		if rows := a.selectedRows(); len(rows) > 0 {
			row = rows[0]
		}
	}
	a.openDeviceWeb(row)
}

// queueSelectionChange schedules one selection read for the next message-loop
// turn (v1.8).
//
// Called from the ListView notification handler, which may run twice per click.
// While a message is already in flight the flag suppresses further posts, so a
// burst of notifications collapses into exactly one read of the final
// selection. The flag is cleared when wmAppSelection is dispatched.
func (a *App) queueSelectionChange() {
	if a.selectionPending {
		return
	}
	if a.suspendSelection {
		// The rows are being rebuilt (a sort or a filter change): the
		// notifications of that rebuild say nothing about what the user picked.
		return
	}
	if a.hMain == 0 {
		return
	}
	a.selectionPending = true
	postMessage(a.hMain, wmAppSelection, 0, 0)
}

// dispatchSelectionPending handles the queued selection change (the body of the
// wmAppSelection case), kept separate so the unit tests can drive it without a
// window.
func (a *App) dispatchSelectionPending() {
	a.selectionPending = false
	a.onDeviceSelectionChanged()
}

// onDeviceSelectionChanged forwards the current selection to the LLDP panel.
//
// The notification handler never does network IO: the panel starts a goroutine
// and reports back through wmAppLLDP.
func (a *App) onDeviceSelectionChanged() {
	if a.lldp == nil {
		return
	}
	row := -1
	if rows := a.currentSelection(); len(rows) > 0 {
		row = rows[0]
	}
	a.lldp.onSelectionChanged(row)
}

// currentSelection returns the selected rows, honouring the test seam.
func (a *App) currentSelection() []int {
	if a.selectedRowsFn != nil {
		return a.selectedRowsFn()
	}
	return a.selectedRows()
}

// onLLDPNotice shows the outcome of an asynchronous LLDP read.
func (a *App) onLLDPNotice() {
	if a.lldp != nil {
		a.lldp.onResult()
	}
}

// onColumnClick handles a click on a column header (v1.9).
//
//	产品型号  → sort by model, same model by IP, same IP by MAC
//	IP 地址   → sort by IP, same IP by model, same model by MAC
//	设备信息来源网卡 → the adapter filter menu (the column IS the filter key)
//
// Every other column does nothing: 序号 is a display artefact, and the remaining
// columns were never part of the sorting contract.
func (a *App) onColumnClick(column int) {
	switch column {
	case columnModel:
		a.sort = toggleSort(a.sort, sortModel)
	case columnIP:
		a.sort = toggleSort(a.sort, sortIP)
	case columnAdapters:
		// The 设备信息来源网卡 column is the filter key itself, so clicking its
		// header opens the filter menu right under the pointer.
		anchor, _ := cursorPosition()
		a.showFilterMenuAt(anchor)
		return
	default:
		return
	}
	debugf("column click %d -> field=%d ascending=%v", column, a.sort.field, a.sort.ascending)
	a.rebuildRows()
	a.refreshStatus()
}

// filterOptions returns the adapter names the filter menu offers.
func (a *App) filterOptions() []string {
	a.mu.Lock()
	all := a.allDevices
	a.mu.Unlock()
	return adapterOptions(all)
}

// filtering reports whether an adapter filter is active.
func (a *App) filtering() bool { return len(a.adapterFilter) > 0 }

// showFilterMenuAt opens the adapter filter menu at a screen position (v1.9).
//
// The only entry point is a click on the 设备信息来源网卡 column header: that
// column already IS the filter key, so the menu opens right under the pointer and
// the window needs no extra button (v1.9 removed the standalone 网卡筛选 button).
//
// A checkable popup menu is used instead of a dialog: the tool never shows a
// message box, and a menu closes on Esc or a click outside, so the states stay
// simple. Every adapter is checked while no filter is active, and the last entry
// clears the filter outright.
func (a *App) showFilterMenuAt(anchor POINT) {
	options := a.filterOptions()
	if len(options) == 0 {
		if len(a.allDevices) == 0 {
			a.setStatus("还没有搜索结果，请先点「广播搜索」")
		} else {
			a.setStatus("本机没有记录到设备来源网卡，无法筛选")
		}
		return
	}
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer func() {
		_, _, _ = procDestroyMenu.Call(menu)
	}()

	for index, name := range options {
		flags := uintptr(mfString)
		if !a.filtering() || a.adapterFilter[name] {
			flags |= mfChecked
		}
		text := utf16Ptr(name)
		_, _, _ = procAppendMenuW.Call(menu, flags,
			uintptr(idFilterFirst+index), uintptr(unsafe.Pointer(text)))
		runtime.KeepAlive(text)
	}
	_, _, _ = procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	clearFlags := uintptr(mfString)
	if !a.filtering() {
		clearFlags |= mfGrayed
	}
	clearText := utf16Ptr("显示全部网卡")
	_, _, _ = procAppendMenuW.Call(menu, clearFlags, uintptr(idFilterAll),
		uintptr(unsafe.Pointer(clearText)))
	runtime.KeepAlive(clearText)

	_, _, _ = procSetForegroundWindow.Call(uintptr(a.hMain))
	command, _, _ := procTrackPopupMenu.Call(menu,
		uintptr(tpmLeftAlign|tpmTopAlign|tpmReturnCmd),
		uintptr(anchor.X), uintptr(anchor.Y), 0, uintptr(a.hMain), 0)
	choice := int(command)
	switch {
	case choice == 0:
		// Dismissed with Esc or a click outside: nothing changes.
	case choice == idFilterAll:
		a.clearFilter()
	case choice >= idFilterFirst && choice < idFilterFirst+len(options):
		a.toggleAdapterFilter(options[choice-idFilterFirst])
	}
}

// toggleAdapterFilter adds or removes one adapter from the filter.
//
// Without a filter every adapter is checked, so the first click on an adapter
// means "hide this one" and the others stay visible - which is what a check list
// of all-checked entries implies. Unchecking the last visible adapter would
// leave an empty table, so it falls back to showing everything.
func (a *App) toggleAdapterFilter(name string) {
	options := a.filterOptions()
	next := make(map[string]bool, len(options))
	if !a.filtering() {
		for _, option := range options {
			next[option] = true
		}
	}
	for option, on := range a.adapterFilter {
		next[option] = on
	}
	next[name] = !next[name]
	for option, on := range next {
		if !on {
			delete(next, option)
		}
	}
	if len(next) == 0 {
		a.clearFilter()
		return
	}
	a.adapterFilter = next
	a.afterFilterChange()
}

// clearFilter shows every device again.
func (a *App) clearFilter() {
	a.adapterFilter = nil
	a.afterFilterChange()
}

// afterFilterChange re-renders the table and refreshes the status line, which is
// where the filter state is reported (the button that used to repeat it is gone).
func (a *App) afterFilterChange() {
	a.rebuildRows()
	a.refreshStatus()
}

// filterNote is the status line suffix while a filter is active.
func (a *App) filterNote() string {
	if !a.filtering() {
		return ""
	}
	a.mu.Lock()
	all, shown := a.allDevices, a.devices
	a.mu.Unlock()
	return filterStatus(discovery.DeviceCount(shown), discovery.DeviceCount(all))
}

// refreshStatus rewrites the status line from the base text plus the filter
// state. It is the only place that appends the "已筛选：显示 3/6 台" suffix, so the
// suffix can never be lost by a later status update.
func (a *App) refreshStatus() {
	text := a.statusBase
	if text == "" {
		text = a.idleStatus()
	}
	if note := a.filterNote(); note != "" {
		text += " · " + note
	}
	a.setStatus(text)
}

// onCtlColorStatic keeps the static labels transparent over the window brush.
func (a *App) onCtlColorStatic(hdc uintptr) uintptr {
	_, _, _ = procSetBkMode.Call(hdc, transparentBk)
	_, _, _ = procSetTextColor.Call(hdc, uintptr(colorText))
	return uintptr(a.hBrushBg)
}

// applyMinMaxInfo enforces the minimum window size, clamped to the usable
// desktop so the window can never become larger than the screen.
func (a *App) applyMinMaxInfo(lparam uintptr) {
	if lparam == 0 {
		return
	}
	info := (*MINMAXINFO)(unsafe.Pointer(lparam))
	minWidth := scale(windowMinWidth, a.dpi)
	minHeight := scale(windowMinHeight, a.dpi)
	areaWidth, areaHeight := workArea()
	if limit := areaWidth - scale(16, a.dpi); limit > 0 && minWidth > limit {
		minWidth = limit
	}
	if limit := areaHeight - scale(16, a.dpi); limit > 0 && minHeight > limit {
		minHeight = limit
	}
	info.MinTrackSize.X = minWidth
	info.MinTrackSize.Y = minHeight
}

// defaultListSharePermille is the share of the split area the device table gets
// on a fresh start: 58 %, which leaves the LLDP panel the 42 % it had in v1.8.
const defaultListSharePermille int32 = 580

// layoutMetrics is the geometry every layout decision is derived from.
//
// It exists so that layout() and the splitter drag compute the same numbers: the
// drag has to clamp against exactly the bounds the layout enforces, otherwise
// the bar would jump on the first pixel of a drag.
type layoutMetrics struct {
	rect          RECT
	pad           int32
	gap           int32
	buttonHeight  int32
	statusHeight  int32
	listTop       int32
	contentHeight int32
	width         int32
}

// metrics measures the window: the content area between the button row and the
// status line.
func (a *App) metrics() layoutMetrics {
	rect := clientRect(a.hMain)
	pad := scale(12, a.dpi)
	gap := scale(10, a.dpi)
	line := a.textHeight()
	buttonHeight := line + scale(16, a.dpi)
	statusHeight := line + scale(10, a.dpi)
	listTop := pad + buttonHeight + gap
	contentBottom := rect.Bottom - statusHeight - scale(6, a.dpi)
	contentHeight := contentBottom - listTop
	if contentHeight < 0 {
		contentHeight = 0
	}
	width := rect.Right - pad*2
	if width < 0 {
		width = 0
	}
	return layoutMetrics{
		rect:          rect,
		pad:           pad,
		gap:           gap,
		buttonHeight:  buttonHeight,
		statusHeight:  statusHeight,
		listTop:       listTop,
		contentHeight: contentHeight,
		width:         width,
	}
}

// splitterHeight is the height of the drag bar in pixels.
func (a *App) splitterHeight() int32 { return scale(splitterHeightDIP, a.dpi) }

// listShare returns the share of the split area the device table gets.
func (a *App) listShare() int32 {
	if a.listSharePermille <= 0 || a.listSharePermille >= 1000 {
		return defaultListSharePermille
	}
	return a.listSharePermille
}

// listMinimumHeight is the smallest height of the device table: the header plus
// lldpListMinRows complete rows, so the table stays usable next to the panel.
func (a *App) listMinimumHeight() int32 {
	return listMinimumHeight(a.hList, lldpListMinRows, a.textHeight(), a.dpi)
}

// currentListHeight is the height the device table occupies right now. It is the
// starting point of a splitter drag.
func (a *App) currentListHeight() int32 {
	if a.listHeight > 0 {
		return a.listHeight
	}
	return listMinimumHeight(a.hList, lldpListMinRows, a.textHeight(), a.dpi)
}

// splitHeights divides the content area between the device table, the drag bar
// and the LLDP panel (v1.9).
//
// Rules, in this order:
//   - the table gets its share of the space that is left after the bar,
//   - but never less than listMinimum (six rows plus the header),
//   - and never so much that the panel drops below panelMinimum (its summary
//     line plus two complete neighbour rows).
//
// When a window is so small that the two minimums cannot both be met - which the
// WM_GETMINMAXINFO floor normally prevents - the share is honoured and the panel
// simply shows fewer rows; nothing ever becomes negative or overlaps.
//
// A share outside (0, 1000) is replaced by the default, so a zero value in a
// partially constructed App still lays out sensibly.
func splitHeights(contentHeight, splitterHeight, listMinimum, panelMinimum, sharePermille int32) (listHeight, panelHeight int32) {
	if contentHeight <= 0 {
		return 0, 0
	}
	if contentHeight <= splitterHeight {
		// Degenerate client area: the bar alone would eat everything, so the
		// table takes it all and the panel is left empty.
		return contentHeight, 0
	}
	usable := contentHeight - splitterHeight
	if sharePermille <= 0 || sharePermille >= 1000 {
		sharePermille = defaultListSharePermille
	}

	listHeight = usable * sharePermille / 1000
	if listMinimum < 0 {
		listMinimum = 0
	}
	if listMinimum > usable {
		listMinimum = usable
	}
	maximum := usable - panelMinimum
	if maximum < listMinimum {
		// Both minimums do not fit: keep the share, clamp to the area only.
		if listHeight > usable {
			listHeight = usable
		}
		if listHeight < 0 {
			listHeight = 0
		}
		return listHeight, usable - listHeight
	}
	if listHeight < listMinimum {
		listHeight = listMinimum
	}
	if listHeight > maximum {
		listHeight = maximum
	}
	return listHeight, usable - listHeight
}

// setListHeight moves the divider to a requested height of the device table
// (called by the splitter for every drag step, v1.9).
//
// The request is clamped exactly like layout() does it and then stored as a
// share, so the divider keeps its position when the window is resized. A request
// that would not change the share is dropped, which is what stops a drag held
// against the limit from repainting the window on every mouse move.
func (a *App) setListHeight(height int32) {
	if a.lldp == nil {
		return
	}
	measures := a.metrics()
	bar := a.splitterHeight()
	usable := measures.contentHeight - bar
	if usable <= 0 {
		return
	}
	minimum := a.listMinimumHeight()
	maximum := usable - a.lldp.minimumHeight()
	if maximum < minimum {
		maximum = minimum
	}
	if height < minimum {
		height = minimum
	}
	if height > maximum {
		height = maximum
	}
	if height > usable {
		height = usable
	}
	if height < 0 {
		height = 0
	}
	// The share is derived from the panel height that will actually be shown
	// after snapping, otherwise rounding down a part row on every drag step would
	// accumulate and the divider would drift away from the pointer.
	panel := a.lldp.snappedHeight(usable - height)
	share := (usable - panel) * 1000 / usable
	if share <= 0 {
		share = 1
	}
	if share >= 1000 {
		share = 999
	}
	if share == a.listSharePermille {
		return
	}
	a.listSharePermille = share
	a.layout()
}

// layout repositions every control according to the current client size.
//
// v1.1 layout (U2): the "广播搜索" button is the first row / first column, the
// table fills everything below it and the status line closes the window. Every
// height is derived from the measured font, never from a hard coded pixel value
// (U5).
//
// v1.8 added the LLDP panel between the table and the status line, v1.9 replaced
// the fixed split with a draggable one: the content area is divided by
// splitHeights(), and the bar between the two tables is a real window so the
// user can move it with the mouse.
func (a *App) layout() {
	if a.hMain == 0 {
		return
	}
	measures := a.metrics()
	pad := measures.pad

	moveWindow(a.hScan, pad, pad, a.buttonWidth(), measures.buttonHeight, true)

	listHeight := measures.contentHeight
	if a.lldp != nil {
		var bar int32
		if a.splitter != nil {
			bar = a.splitterHeight()
		}
		var panelHeight int32
		listHeight, panelHeight = splitHeights(measures.contentHeight, bar,
			a.listMinimumHeight(), a.lldp.minimumHeight(), a.listShare())
		// Snap the panel to a whole number of neighbour rows; the pixels it
		// gives up go to the device table, so no empty strip appears and the
		// table never ends with a half row (v1.9).
		panelHeight = a.lldp.snappedHeight(panelHeight)
		listHeight = measures.contentHeight - bar - panelHeight
		if listHeight < 0 {
			listHeight = 0
		}
		if a.splitter != nil {
			moveWindow(a.splitter.hwnd, pad, measures.listTop+listHeight,
				measures.width, bar, true)
		}
		a.lldp.layout(pad, measures.listTop+listHeight+bar, measures.width, panelHeight)
	}

	moveWindow(a.hList, pad, measures.listTop, measures.width, listHeight, true)
	a.listHeight = listHeight
	moveWindow(a.hStatus, pad, measures.rect.Bottom-measures.statusHeight,
		measures.rect.Right-pad*2, measures.statusHeight, true)
	a.applyColumnWidths(measures.width, listHeight)
	// Moving a child never repaints the pixels it left behind (v1.9: the splitter
	// made this visible as a ghost copy of the panel summary).
	invalidateClient(a.hMain)
}

// setStatus updates the status line. Errors are reported here and nowhere
// else: the tool must never show a message box (REQUIREMENTS.md §4).
func (a *App) setStatus(text string) { setWindowText(a.hStatus, text) }

// refreshAdapters refreshes the adapter information.
//
// The old header line ("已启用网卡：192.168.0.163/24 (WLAN) · ...") is gone
// (U2): the short form goes to the status line and the full list is available
// as a tooltip on the status bar, so no information is lost.
func (a *App) refreshAdapters() {
	adapters, err := discovery.EnumerateAdapters()
	if err != nil {
		a.adapterHint = "网卡枚举失败: " + err.Error()
		return
	}
	a.adapterHint = fmt.Sprintf("%d 张网卡", len(adapters))
	full := "已启用网卡：" + discovery.FormatAdapterList(adapters)
	if a.tooltip == nil && a.hStatus != 0 {
		a.tooltip = newTooltip(a.hMain, a.hStatus, full)
	} else if a.tooltip != nil {
		a.tooltip.setText(a.hStatus, full)
	}
}

// idleStatus is the status line shown while no scan is running.
//
// v1.8 appends the version, so the running build is identifiable from a
// screenshot: "就绪 · 4 张网卡 · v1.8".
func (a *App) idleStatus() string {
	text := "就绪"
	if a.adapterHint != "" {
		text += " · " + a.adapterHint
	}
	return text + " · v" + AppVersion
}

// clearList removes every row and forgets the cached devices.
//
// The LLDP panel is reset with it (v1.8): every row index of the old table now
// points at another device, so a neighbour table kept from before the clear
// would describe the wrong switch. The adapter filter is dropped too (v1.9): a
// new search may reach other networks and therefore other adapters, and a filter
// holding an adapter that no longer answers would hide every row.
func (a *App) clearList() {
	a.mu.Lock()
	a.allDevices = nil
	a.devices = nil
	a.adapterFilter = nil
	a.mu.Unlock()
	if a.lldp != nil {
		a.lldp.reset()
	}
	if a.hList != 0 {
		_, _, _ = procSendMessageW.Call(uintptr(a.hList), lvmDeleteAllItems, 0, 0)
	}
}

// rowCells renders the seven visible cells of one device (U3/U4/U7).
//
// 序号 | 产品型号 | IP 地址 | MAC 地址 | 固件版本号 | 设备名称 | 设备信息来源网卡
func rowCells(index int, device discovery.Device) []string {
	return []string{
		strconv.Itoa(index + 1),
		modelCell(device),
		device.IP,
		emptyAsDash(device.MAC),
		emptyAsDash(device.Firmware),
		nameCell(device),
		emptyAsDash(strings.Join(device.Adapters, ", ")),
	}
}

// emptyAsDash renders an empty value as "-".
func emptyAsDash(value string) string {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		return trimmed
	}
	return "-"
}

// modelCell is the 产品型号 cell (U4).
//
// The v1.2 fallback chain - answered model, else the model derived from the
// device name (NP6450_5599 -> NPort 6450), else "-" - lives in package
// discovery, so the table, the clipboard and the JSON output cannot drift
// apart and no mapping table is duplicated in the GUI.
func modelCell(device discovery.Device) string {
	return discovery.DisplayModel(device.Model, device.Name)
}

// nameCell is the 设备名称 cell (U4).
//
// It shows "-" when the name is empty or identical to the model column, so the
// same string is never displayed twice in one row.
func nameCell(device discovery.Device) string {
	name := strings.TrimSpace(device.Name)
	if name == "" || name == modelCell(device) {
		return "-"
	}
	return name
}

// fillList adopts a finished scan result and renders it.
//
// v1.9: the result is stored unfiltered in allDevices and the rows are produced
// by rebuildRows(), which applies the filter (reset to "every adapter" here) and
// the sort the user picked earlier in the session.
func (a *App) fillList(devices []discovery.Device) {
	a.clearList()
	a.mu.Lock()
	a.allDevices = devices
	a.mu.Unlock()
	a.rebuildRows()
}

// rebuildRows re-renders the device table from allDevices (v1.9).
//
// It is the single place that knows how a result becomes rows: filter, sort,
// cells, column widths, header captions. Sorting and filtering only need to
// call it.
//
// The selection is restored by device identity (MAC + IP) instead of by row
// number: a sort moves every row, but the user is still looking at the same
// switch, so its LLDP panel must survive - and must not be read again (the
// notification is suppressed while the rows are rebuilt).
func (a *App) rebuildRows() {
	a.mu.Lock()
	all := a.allDevices
	filter := a.adapterFilter
	a.mu.Unlock()

	visible := visibleDevices(all, filter, a.sort)
	rows := make([][]string, 0, len(visible))
	for index := range visible {
		rows = append(rows, rowCells(index, visible[index]))
	}
	selected := a.selectedRowKey()

	a.suspendSelection = true
	if a.hList != 0 {
		_, _, _ = procSendMessageW.Call(uintptr(a.hList), lvmDeleteAllItems, 0, 0)
	}
	for index, cells := range rows {
		a.insertRow(index, cells)
	}
	a.mu.Lock()
	a.devices = visible
	a.mu.Unlock()
	a.titles = headerTitles(a.sort)
	a.naturalWidths = measureColumns(a.measure, a.dpi, a.titles, rows)

	a.applyHeaderTitles()
	a.restoreSelection(selected, visible)
	a.suspendSelection = false
	a.layout()
}

// selectedRowKey returns the identity of the first selected row, or "".
func (a *App) selectedRowKey() string {
	a.mu.Lock()
	devices := a.devices
	a.mu.Unlock()
	for _, row := range a.currentSelection() {
		if row >= 0 && row < len(devices) {
			return deviceRowKey(devices[row])
		}
	}
	return ""
}

// restoreSelection re-selects the row that carries key after a rebuild.
//
// A device that the filter hid loses its selection (and the panel returns to its
// prompt) - that is the honest answer, because the row the user pointed at is no
// longer in the table.
func (a *App) restoreSelection(key string, visible []discovery.Device) {
	row := -1
	if key != "" {
		for index := range visible {
			if deviceRowKey(visible[index]) == key {
				row = index
				break
			}
		}
	}
	if row < 0 {
		if a.lldp != nil {
			a.lldp.reset()
		}
		return
	}
	a.selectRow(row)
	if a.lldp != nil {
		// The row index moved but the device did not: keep the neighbour table
		// and only tell the panel where the device sits now.
		a.lldp.rebindRow(row)
	}
}

// selectRow marks one row as selected and focused without touching the panel.
func (a *App) selectRow(row int) {
	if a.hList == 0 || row < 0 {
		return
	}
	item := LVITEMW{
		State:     lvisSelected | lvisFocused,
		StateMask: lvisSelected | lvisFocused,
		IItem:     int32(row),
	}
	_, _, _ = procSendMessageW.Call(uintptr(a.hList), lvmSetItemState,
		uintptr(row), uintptr(unsafe.Pointer(&item)))
	_, _, _ = procSendMessageW.Call(uintptr(a.hList), lvmEnsureVisible, uintptr(row), 1)
}

// insertRow appends one ListView row.
func (a *App) insertRow(row int, cells []string) {
	if a.hList == 0 || len(cells) == 0 {
		return
	}
	first := utf16Ptr(cells[0])
	item := LVITEMW{Mask: lvifText, IItem: int32(row), ISubItem: 0, PszText: first}
	_, _, _ = procSendMessageW.Call(uintptr(a.hList), lvmInsertItemW, 0, uintptr(unsafe.Pointer(&item)))
	runtime.KeepAlive(first)

	for column := 1; column < len(cells); column++ {
		text := utf16Ptr(cells[column])
		subItem := LVITEMW{Mask: lvifText, IItem: int32(row), ISubItem: int32(column), PszText: text}
		_, _, _ = procSendMessageW.Call(uintptr(a.hList), lvmSetItemTextW,
			uintptr(row), uintptr(unsafe.Pointer(&subItem)))
		runtime.KeepAlive(text)
	}
}

// selectedRows returns the indexes of every selected row.
func (a *App) selectedRows() []int {
	if a.hList == 0 {
		return nil
	}
	rows := make([]int, 0, 8)
	start := int32(-1)
	for {
		result, _, _ := procSendMessageW.Call(uintptr(a.hList), lvmGetNextItem,
			uintptr(start), lvniSelected)
		index := int32(result)
		if index < 0 {
			break
		}
		rows = append(rows, int(index))
		start = index
		if len(rows) > 10000 {
			break
		}
	}
	return rows
}

// copySelection puts the selected rows on the clipboard as TSV.
func (a *App) copySelection() {
	rows := a.selectedRows()
	if len(rows) == 0 {
		return
	}
	a.mu.Lock()
	devices := a.devices
	a.mu.Unlock()

	var builder strings.Builder
	for _, row := range rows {
		if row < 0 || row >= len(devices) {
			continue
		}
		builder.WriteString(strings.Join(rowCells(row, devices[row]), "\t"))
		builder.WriteString("\r\n")
	}
	if builder.Len() == 0 {
		return
	}
	if setClipboardText(a.hMain, builder.String()) {
		a.setStatus(fmt.Sprintf("已复制 %d 行到剪贴板", len(rows)))
	} else {
		a.setStatus("复制失败：剪贴板被其他程序占用")
	}
}

// startScan launches one discovery run on a goroutine so that the UI keeps
// responding (REQUIREMENTS.md R8).
func (a *App) startScan() {
	a.mu.Lock()
	if a.scanning {
		a.mu.Unlock()
		return
	}
	a.scanning = true
	a.mu.Unlock()

	a.clearList()
	a.naturalWidths = nil
	a.round = 0
	a.found = 0
	a.phase = discovery.PhaseBroadcast
	a.setStatus("正在搜索…")
	if a.hScan != 0 {
		_, _, _ = procEnableWindow.Call(uintptr(a.hScan), 0)
	}
	a.showProgress()

	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	options := discovery.DefaultOptions()
	a.totalRounds = options.Rounds

	go func() {
		result := discovery.Scan(ctx, options, func(progress discovery.Progress) {
			message := uintptr(wmAppProgress)
			if progress.Phase == discovery.PhaseModels {
				message = uintptr(wmAppPhase)
			}
			procPostMessageW.Call(uintptr(a.hMain), message,
				uintptr(progress.Round), uintptr(progress.Found))
		})
		a.mu.Lock()
		a.result = result
		a.mu.Unlock()
		procPostMessageW.Call(uintptr(a.hMain), wmAppDone, 0, 0)
	}()
}

// onProgressMessage refreshes the progress window and the status line.
func (a *App) onProgressMessage(round, found int) {
	a.round = round
	a.found = found
	if a.progress != nil {
		a.progress.setStatus(a.phase, round, a.totalRounds, found)
	}
	if round <= 0 {
		a.setStatus("正在搜索…")
		return
	}
	a.setStatus(fmt.Sprintf("正在搜索…（第 %d/%d 轮）", round, a.totalRounds))
}

// onPhaseMessage switches the popup to the model enhancement phase (v1.3).
//
// The round counter stands at its final value here, so the bar keeps its 100 %
// target while the status line says what the extra step is doing.
func (a *App) onPhaseMessage(round, found int) {
	a.phase = discovery.PhaseModels
	a.round = round
	a.found = found
	if a.progress != nil {
		a.progress.setStatus(a.phase, round, a.totalRounds, found)
	}
	a.setStatus("正在搜索…（" + progressModelsText + "）")
}

// onScanDone consumes the scan result, closes the progress window and shows
// the devices (REQUIREMENTS.md R6).
func (a *App) onScanDone() {
	a.closeProgress()
	a.mu.Lock()
	result := a.result
	a.result = nil
	a.scanning = false
	a.mu.Unlock()

	if a.hScan != 0 {
		_, _, _ = procEnableWindow.Call(uintptr(a.hScan), 1)
	}
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	a.refreshAdapters()
	if result == nil {
		a.setStatus("搜索结束，但未取得结果")
		return
	}
	a.fillList(result.Devices)
	a.statusBase = statusText(result)
	a.refreshStatus()
}

// statusText renders the summary line, e.g.
// "搜索到 4 台设备 · 耗时 1657 ms" (U6).
//
// The unit is 台 (devices), not rows: one device may own several IP addresses
// and therefore produce several rows, so the count is taken per MAC address.
// When two devices share one IP the collision is reported as well.
func statusText(result *discovery.Result) string {
	if result == nil || len(result.Devices) == 0 {
		text := "未发现设备（同一二层广播域内没有 MOXA 设备应答）"
		if result != nil && result.Elapsed > 0 {
			text += fmt.Sprintf(" · 耗时 %d ms", result.Elapsed.Milliseconds())
		}
		return text
	}

	devices := discovery.DeviceCount(result.Devices)
	var text string
	if duplicates := discovery.DuplicateIPDeviceCount(result.Devices); duplicates > 0 {
		text = fmt.Sprintf("搜索到 %d 台设备（%d 台设备 IP 重复）", devices, duplicates)
	} else {
		text = fmt.Sprintf("搜索到 %d 台设备", devices)
	}
	if result.Elapsed > 0 {
		text += fmt.Sprintf(" · 耗时 %d ms", result.Elapsed.Milliseconds())
	}
	if len(result.Errors) > 0 {
		text += " · " + result.Errors[0]
	}
	return text
}
