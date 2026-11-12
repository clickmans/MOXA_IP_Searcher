// Package ui renders the MOXA discovery tool with plain Win32 API calls.
//
// No third party GUI toolkit is used: every window, control and message is
// driven directly through user32/gdi32/comctl32 so that the executable keeps
// zero runtime dependencies (REQUIREMENTS.md §3).
package ui

import (
	"syscall"
	"unsafe"
)

// DLL handles. All of them ship with Windows itself.
var (
	dllUser32   = syscall.NewLazyDLL("user32.dll")
	dllGdi32    = syscall.NewLazyDLL("gdi32.dll")
	dllKernel32 = syscall.NewLazyDLL("kernel32.dll")
	dllComctl32 = syscall.NewLazyDLL("comctl32.dll")
	dllShell32  = syscall.NewLazyDLL("shell32.dll")
)

// user32 procedures.
var (
	procRegisterClassExW          = dllUser32.NewProc("RegisterClassExW")
	procCreateWindowExW           = dllUser32.NewProc("CreateWindowExW")
	procDefWindowProcW            = dllUser32.NewProc("DefWindowProcW")
	procDestroyWindowW            = dllUser32.NewProc("DestroyWindow")
	procShowWindow                = dllUser32.NewProc("ShowWindow")
	procUpdateWindow              = dllUser32.NewProc("UpdateWindow")
	procGetMessageW               = dllUser32.NewProc("GetMessageW")
	procTranslateMessage          = dllUser32.NewProc("TranslateMessage")
	procDispatchMessageW          = dllUser32.NewProc("DispatchMessageW")
	procPostQuitMessage           = dllUser32.NewProc("PostQuitMessage")
	procPostMessageW              = dllUser32.NewProc("PostMessageW")
	procSendMessageW              = dllUser32.NewProc("SendMessageW")
	procSetWindowTextW            = dllUser32.NewProc("SetWindowTextW")
	procSetWindowLongPtrW         = dllUser32.NewProc("SetWindowLongPtrW")
	procCallWindowProcW           = dllUser32.NewProc("CallWindowProcW")
	procGetClientRect             = dllUser32.NewProc("GetClientRect")
	procGetWindowRect             = dllUser32.NewProc("GetWindowRect")
	procMoveWindow                = dllUser32.NewProc("MoveWindow")
	procAdjustWindowRectEx        = dllUser32.NewProc("AdjustWindowRectEx")
	procEnableWindow              = dllUser32.NewProc("EnableWindow")
	procSetFocusW                 = dllUser32.NewProc("SetFocus")
	procGetSystemMetrics          = dllUser32.NewProc("GetSystemMetrics")
	procLoadIconW                 = dllUser32.NewProc("LoadIconW")
	procLoadCursorW               = dllUser32.NewProc("LoadCursorW")
	procSetTimer                  = dllUser32.NewProc("SetTimer")
	procKillTimer                 = dllUser32.NewProc("KillTimer")
	procGetDpiForWindow           = dllUser32.NewProc("GetDpiForWindow")
	procGetDpiForSystem           = dllUser32.NewProc("GetDpiForSystem")
	procSetProcessDPIAware        = dllUser32.NewProc("SetProcessDPIAware")
	procSetProcessDpiAwarenessCtx = dllUser32.NewProc("SetProcessDpiAwarenessContext")
	procGetKeyState               = dllUser32.NewProc("GetKeyState")
	procSystemParametersInfoW     = dllUser32.NewProc("SystemParametersInfoW")
	procOpenClipboard             = dllUser32.NewProc("OpenClipboard")
	procEmptyClipboard            = dllUser32.NewProc("EmptyClipboard")
	procSetClipboardData          = dllUser32.NewProc("SetClipboardData")
	procCloseClipboard            = dllUser32.NewProc("CloseClipboard")
	procGetDC                     = dllUser32.NewProc("GetDC")
	procReleaseDC                 = dllUser32.NewProc("ReleaseDC")
	// v1.9: the draggable splitter and the adapter filter menu.
	procGetCursorPos        = dllUser32.NewProc("GetCursorPos")
	procSetCursor           = dllUser32.NewProc("SetCursor")
	procSetCapture          = dllUser32.NewProc("SetCapture")
	procReleaseCapture      = dllUser32.NewProc("ReleaseCapture")
	procBeginPaint          = dllUser32.NewProc("BeginPaint")
	procEndPaint            = dllUser32.NewProc("EndPaint")
	procFillRect            = dllUser32.NewProc("FillRect")
	procCreatePopupMenu     = dllUser32.NewProc("CreatePopupMenu")
	procAppendMenuW         = dllUser32.NewProc("AppendMenuW")
	procDestroyMenu         = dllUser32.NewProc("DestroyMenu")
	procTrackPopupMenu      = dllUser32.NewProc("TrackPopupMenu")
	procSetForegroundWindow = dllUser32.NewProc("SetForegroundWindow")
	procInvalidateRect      = dllUser32.NewProc("InvalidateRect")
)

// gdi32 procedures.
var (
	procCreateFontW           = dllGdi32.NewProc("CreateFontW")
	procCreateSolidBrush      = dllGdi32.NewProc("CreateSolidBrush")
	procDeleteObject          = dllGdi32.NewProc("DeleteObject")
	procSetBkMode             = dllGdi32.NewProc("SetBkMode")
	procSetTextColor          = dllGdi32.NewProc("SetTextColor")
	procSelectObject          = dllGdi32.NewProc("SelectObject")
	procGetTextMetricsW       = dllGdi32.NewProc("GetTextMetricsW")
	procGetTextExtentPoint32W = dllGdi32.NewProc("GetTextExtentPoint32W")
)

// kernel32 procedures.
var (
	procGetModuleHandleW = dllKernel32.NewProc("GetModuleHandleW")
	procGlobalAlloc      = dllKernel32.NewProc("GlobalAlloc")
	procGlobalLock       = dllKernel32.NewProc("GlobalLock")
	procGlobalUnlock     = dllKernel32.NewProc("GlobalUnlock")
	procGlobalFree       = dllKernel32.NewProc("GlobalFree")
)

// comctl32 / shell32 procedures.
var (
	procInitCommonControlsEx = dllComctl32.NewProc("InitCommonControlsEx")
	procShellExecuteW        = dllShell32.NewProc("ShellExecuteW")
)

// Window messages.
const (
	wmCreate         = 0x0001
	wmDestroy        = 0x0002
	wmSize           = 0x0005
	wmSetFocus       = 0x0007
	wmPaint          = 0x000F
	wmClose          = 0x0010
	wmEraseBkgnd     = 0x0014
	wmSetCursor      = 0x0020
	wmGetMinMaxInfo  = 0x0024
	wmSetFont        = 0x0030
	wmNotify         = 0x004E
	wmSetIcon        = 0x0080
	wmKeyDown        = 0x0100
	wmCommand        = 0x0111
	wmTimer          = 0x0113
	wmCtlColorStatic = 0x0138
	wmMouseMove      = 0x0200
	wmLButtonDown    = 0x0201
	wmLButtonUp      = 0x0202
	// wmCaptureChanged tells the splitter that another window stole the mouse
	// capture (Alt+Tab, a modal menu). Without it the bar would keep moving the
	// divider although the button is no longer down.
	wmCaptureChanged = 0x0215
	wmUser           = 0x0400
	wmApp            = 0x8000
)

// Window styles and flags.
const (
	wsOverlappedWindow = 0x00CF0000
	wsPopup            = 0x80000000
	wsChild            = 0x40000000
	wsVisible          = 0x10000000
	wsCaption          = 0x00C00000
	wsSysMenu          = 0x00080000
	wsBorder           = 0x00800000
	wsClipChildren     = 0x02000000
	// wsClipSiblings keeps a control from painting over its siblings. The v1.9
	// splitter moves the table and the panel summary line past each other, and
	// without this flag a static repaints its text on top of the neighbour table
	// during the move (the ghost text that was measured on the first build).
	wsClipSiblings = 0x04000000
	wsTabStop      = 0x00010000

	wsExToolWindow = 0x00000080

	swShowNormal = 1

	iconSmall = 0
	iconBig   = 1

	smCxScreen = 0
	smCyScreen = 1
	// smCxVScroll is SM_CXVSCROLL: the width a vertical scroll bar takes away
	// from a ListView client area (v1.9).
	smCxVScroll = 2

	bnClicked    = 0
	bsPushButton = 0x00000000 // BS_PUSHBUTTON

	lvifText     = 0x0001
	lvniSelected = 0x0002
	gwlpWndProc  = ^uintptr(3) // GWLP_WNDPROC == -4

	lvmFirst                    = 0x1000
	lvmDeleteAllItems           = lvmFirst + 9
	lvmGetNextItem              = lvmFirst + 12
	lvmGetItemRect              = lvmFirst + 14
	lvmGetItemCount             = lvmFirst + 4
	lvmEnsureVisible            = lvmFirst + 19
	lvmSetColumnWidth           = lvmFirst + 30
	lvmGetHeader                = lvmFirst + 31
	lvmSetItemState             = lvmFirst + 43
	lvmSetExtendedListViewStyle = lvmFirst + 54
	lvmInsertItemW              = lvmFirst + 77
	lvmSetColumnW               = lvmFirst + 96
	lvmInsertColumnW            = lvmFirst + 97
	lvmSetItemTextW             = lvmFirst + 116

	lvsReport        = 0x0001
	lvsShowSelAlways = 0x0008

	// Item state bits (LVIS_*). They are also the values LVM_SETITEMSTATE
	// expects in LVITEMW.State / StateMask, which is what rebuilds the
	// selection after a sort without a row index that could be stale.
	lvisFocused  = 0x0001
	lvisSelected = 0x0002

	lvsexFullRowSelect = 0x00000020
	lvsexGridLines     = 0x00000001
	lvsexDoubleBuffer  = 0x00010000

	lvcfmtLeft = 0x0000

	// LVCOLUMN mask bits. Note that LVCF_TEXT is 0x0004: LVCF_FMT is 0x0001,
	// LVCF_WIDTH is 0x0002, while 0x0001 is LVIF_TEXT of the item structure.
	lvcfFmt   = 0x0001
	lvcfWidth = 0x0002
	lvcfText  = 0x0004

	pbmSetPos     = 0x0402 // WM_USER + 2
	pbmSetRange32 = 0x0406 // WM_USER + 6

	// Progress bar messages of the common controls (CCM_*).
	ccmFirst      = 0x2000
	ccmSetBkColor = ccmFirst + 1

	iccListView = 0x00000001
	iccProgress = 0x00000020
	iccStandard = 0x00004000
	// iccWin95Classes is ICC_WIN95_CLASSES. It is required for the
	// "tooltips_class32" window class: ICC_STANDARD_CLASSES only registers the
	// button / edit / static / listbox / combobox / scrollbar classes, so a
	// tooltip created without this flag silently fails (CreateWindowEx returns 0).
	iccWin95Classes = 0x000000FF

	ssLeft        = 0x00000000
	ssCenterImage = 0x00000200
	ssEndEllipsis = 0x00004000

	transparentBk = 1
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
	gmemZeroInit  = 0x0040

	vkControl = 0x11
	vkC       = 0x43

	swShow = 5

	// SPI_GETWORKAREA returns the usable desktop rectangle (desktop minus the
	// taskbar) which is used to keep the window on screen on small or high DPI
	// displays.
	spiGetWorkArea = 0x0030

	// nmDblClk is NM_DBLCLK. The Win32 header defines it as (NM_FIRST - 3)
	// with NM_FIRST == 0, i.e. -3. The previous value -116 was wrong (that is
	// not a notification code at all), which is why the double click handler
	// never fired.
	nmDblClk = -3 // NM_DBLCLK == (NM_FIRST - 3)

	// htClient is HTCLIENT, the WM_SETCURSOR hit test code of the client area.
	htClient = 1
	// idcSizeNS is IDC_SIZENS: the vertical resize cursor the splitter shows.
	// It is a plain resource id, loaded with LoadCursorW(0, MAKEINTRESOURCE(...)).
	idcSizeNS = 32645
)

// Popup menu flags and commands (winuser.h).
const (
	mfString    = 0x00000000
	mfGrayed    = 0x00000001
	mfChecked   = 0x00000008
	mfSeparator = 0x00000800

	tpmLeftAlign = 0x0000
	tpmTopAlign  = 0x0000
	// tpmReturnCmd makes TrackPopupMenu return the chosen command id instead of
	// posting WM_COMMAND, so the menu is handled synchronously in one place.
	tpmReturnCmd = 0x0100
)

// Tooltip window messages and styles (commctrl.h).
const (
	tooltipsClassName = "tooltips_class32"

	ttsAlwaysTip = 0x00000001
	ttsNoPrefix  = 0x00000002

	ttfIDISHWND = 0x00000001

	ttmAddToolW        = wmUser + 50 // TTM_ADDTOOLW
	ttmUpdateTipTextW  = wmUser + 57 // TTM_UPDATETIPTEXTW
	ttmSetMaxTipWidthW = wmUser + 24 // TTM_SETMAXTIPWIDTH
)

// UI colors (COLORREF is 0x00BBGGRR).
const (
	colorBackground = 0x00F8F6F5 // RGB(0xF5, 0xF6, 0xF8)
	colorPanel      = 0x00FFFFFF // white
	colorText       = 0x00242120 // RGB(0x20, 0x21, 0x24)
	// colorProgressTrough is the empty part of the progress bar. The classic
	// (comctl32 v5) bar has a very light default background, which made a bar at
	// 0 % look like a thin white line on the white popup; this gray makes the
	// trough visible from the first millisecond.
	colorProgressTrough = 0x00D0D0D0 // RGB(0xD0, 0xD0, 0xD0)

	// The splitter between the device table and the LLDP panel (v1.9). The line
	// is light enough to look like a divider instead of a third table, and the
	// darker centre segment is the grab affordance.
	colorSplitterLine = 0x00DCDCDC // RGB(0xDC, 0xDC, 0xDC)
	colorSplitterGrip = 0x00BFBFBF // RGB(0xBF, 0xBF, 0xBF)
)

// POINT is the Win32 POINT structure.
type POINT struct {
	X int32
	Y int32
}

// RECT is the Win32 RECT structure.
type RECT struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

// MSG is the Win32 MSG structure.
type MSG struct {
	Hwnd     syscall.Handle
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       POINT
	LPrivate uint32
}

// MINMAXINFO is the Win32 MINMAXINFO structure.
type MINMAXINFO struct {
	Reserved     POINT
	MaxSize      POINT
	MaxPosition  POINT
	MinTrackSize POINT
	MaxTrackSize POINT
}

// PAINTSTRUCT is the Win32 PAINTSTRUCT structure (v1.9, splitter painting).
//
// RgbReserved is a fixed 32 byte array, so the struct is 68 bytes of fields and
// Go rounds the size up to 72 - exactly what the x64 C compiler produces, which
// is what BeginPaint checks when it writes into it.
type PAINTSTRUCT struct {
	Hdc         uintptr
	FErase      int32
	RcPaint     RECT
	FRestore    int32
	FIncUpdate  int32
	RgbReserved [32]byte
}

// WNDCLASSEXW is the Win32 WNDCLASSEXW structure.
type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     syscall.Handle
	HIcon         syscall.Handle
	HCursor       syscall.Handle
	HbrBackground syscall.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       syscall.Handle
}

// INITCOMMONCONTROLSEX is the Win32 INITCOMMONCONTROLSEX structure.
type INITCOMMONCONTROLSEX struct {
	DwSize uint32
	DwICC  uint32
}

// LVCOLUMNW is the Win32 LVCOLUMN structure (Unicode variant).
type LVCOLUMNW struct {
	Mask       uint32
	Fmt        int32
	Cx         int32
	PszText    *uint16
	CchTextMax int32
	ISubItem   int32
	IImage     int32
	IOrder     int32
	CxMin      int32
	CxDefault  int32
	CxIdeal    int32
}

// LVITEMW is the Win32 LVITEM structure (Unicode variant).
type LVITEMW struct {
	Mask       uint32
	IItem      int32
	ISubItem   int32
	State      uint32
	StateMask  uint32
	PszText    *uint16
	CchTextMax int32
	IImage     int32
	LParam     uintptr
	IIndent    int32
	IGroupID   int32
	CColumns   uint32
	PuColumns  *uint32
	PiColFmt   *int32
	IGroup     int32
}

// NMHDR is the Win32 NMHDR structure.
type NMHDR struct {
	HwndFrom syscall.Handle
	IDFrom   uintptr
	Code     uint32
}

// NMITEMACTIVATE is the Win32 NMITEMACTIVATE structure sent with NM_DBLCLK.
//
// IItem is the row that was activated (-1 when the activation did not come
// from a row, e.g. a keyboard activation). Go pads NMHDR to 24 bytes just like
// the C compiler does, so IItem lands on the correct offset 24.
type NMITEMACTIVATE struct {
	Header    NMHDR
	IItem     int32
	ISubItem  int32
	UNewState uint32
	UOldState uint32
	UChanged  uint32
	PtAction  POINT
	LParam    uintptr
}

// TEXTMETRICW is the Win32 TEXTMETRIC structure (Unicode variant).
//
// It is used to derive every control height from the actual font instead of
// hard coding pixel values, so the layout follows the font size (U5).
type TEXTMETRICW struct {
	Height           int32
	Ascent           int32
	Descent          int32
	InternalLeading  int32
	ExternalLeading  int32
	AveCharWidth     int32
	MaxCharWidth     int32
	Weight           int32
	Overhang         int32
	DigitizedAspectX int32
	DigitizedAspectY int32
	FirstChar        uint16
	LastChar         uint16
	DefaultChar      uint16
	BreakChar        uint16
	Italic           uint8
	Underlined       uint8
	StruckOut        uint8
	PitchAndFamily   uint8
	CharSet          uint8
}

// TOOLINFOW is the Win32 TOOLINFO structure (Unicode variant).
type TOOLINFOW struct {
	CbSize     uint32
	UFlags     uint32
	Hwnd       syscall.Handle
	UId        uintptr
	Rc         RECT
	HInst      syscall.Handle
	LpszText   *uint16
	LParam     uintptr
	LpReserved uintptr
}

// utf16Ptr converts a Go string to a NUL terminated UTF-16 buffer.
func utf16Ptr(s string) *uint16 {
	ptr, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		empty, _ := syscall.UTF16PtrFromString("")
		return empty
	}
	return ptr
}

// initProcessDPI turns on per monitor DPI awareness so that the window stays
// crisp on high DPI displays (REQUIREMENTS.md §3, manifest workaround).
func initProcessDPI() {
	// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 == (HANDLE)-4
	if err := procSetProcessDpiAwarenessCtx.Find(); err == nil {
		if r, _, _ := procSetProcessDpiAwarenessCtx.Call(^uintptr(3)); r != 0 {
			return
		}
	}
	if err := procSetProcessDPIAware.Find(); err == nil {
		_, _, _ = procSetProcessDPIAware.Call()
	}
}

// systemDPI returns the DPI of the primary display (96 when unknown).
func systemDPI() int32 {
	if err := procGetDpiForSystem.Find(); err == nil {
		if value, _, _ := procGetDpiForSystem.Call(); value > 0 {
			return int32(value)
		}
	}
	return 96
}

// windowDPI returns the DPI the window is currently rendered at.
func windowDPI(hwnd syscall.Handle) int32 {
	if err := procGetDpiForWindow.Find(); err == nil {
		if value, _, _ := procGetDpiForWindow.Call(uintptr(hwnd)); value > 0 {
			return int32(value)
		}
	}
	return systemDPI()
}

// scale converts a design pixel value (96 DPI baseline) to device pixels.
func scale(value int32, dpi int32) int32 {
	if dpi <= 0 {
		dpi = 96
	}
	if value == 0 {
		return 0
	}
	return int32((int64(value)*int64(dpi) + 48) / 96)
}

// initCommonControls loads the common control classes used by the UI.
func initCommonControls() {
	config := INITCOMMONCONTROLSEX{
		DwSize: uint32(unsafe.Sizeof(INITCOMMONCONTROLSEX{})),
		DwICC:  iccListView | iccProgress | iccStandard | iccWin95Classes,
	}
	_, _, _ = procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&config)))
}

// fontPointSize is the base UI font size in points-at-96-DPI units.
//
// History: 9 (v1.0) -> 18 (v1.1, too large: the table became a "zoomed" view and
// only five rows fitted on a 1600px tall display) -> 14 (v1.2, the size the
// vendor tools use). Every control height is derived from the measured font
// metrics of this size and every column width from the measured content, never
// from a hard coded pixel value, so changing this constant is enough.
const fontPointSize int32 = 14

// createFont builds a "Segoe UI" font at the requested point size.
func createFont(pointSize int32, bold bool, dpi int32) syscall.Handle {
	height := -scale(pointSize, dpi)
	weight := int32(400)
	if bold {
		weight = 600
	}
	face := utf16Ptr("Segoe UI")
	handle, _, _ := procCreateFontW.Call(
		uintptr(height), // cHeight
		0,               // cWidth
		0,               // cEscapement
		0,               // cOrientation
		uintptr(weight), // cWeight
		0,               // bItalic
		0,               // bUnderline
		0,               // bStrikeOut
		1,               // iCharSet = DEFAULT_CHARSET
		4,               // iOutPrecision = OUT_TT_PRECIS
		0,               // iClipPrecision = CLIP_DEFAULT_PRECIS
		5,               // iQuality = CLEARTYPE_QUALITY
		2,               // iPitchAndFamily = VARIABLE_PITCH
		uintptr(unsafe.Pointer(face)),
	)
	return syscall.Handle(handle)
}

// fontMeasure measures text extents with one font.
//
// A single screen device context with the font already selected is kept for
// the lifetime of the measuring window, because the table layout needs the
// width of every header and every cell (U5: columns follow their content).
// All failures degrade to zero measurements, which makes the callers fall back
// to sensible minimum widths instead of panicking.
type fontMeasure struct {
	dc       uintptr
	font     syscall.Handle
	previous uintptr
	height   int32
}

// newFontMeasure selects font into a fresh screen device context.
func newFontMeasure(font syscall.Handle) *fontMeasure {
	measure := &fontMeasure{font: font}
	if font == 0 {
		return measure
	}
	dc, _, _ := procGetDC.Call(0)
	if dc == 0 {
		return measure
	}
	measure.dc = dc
	previous, _, _ := procSelectObject.Call(dc, uintptr(font))
	measure.previous = previous

	var metrics TEXTMETRICW
	if ok, _, _ := procGetTextMetricsW.Call(dc, uintptr(unsafe.Pointer(&metrics))); ok != 0 {
		measure.height = metrics.Height + metrics.ExternalLeading
	}
	return measure
}

// lineHeight returns the pixel height of one text line (0 when unmeasurable).
func (m *fontMeasure) lineHeight() int32 {
	if m == nil {
		return 0
	}
	return m.height
}

// width returns the pixel width of s (0 when the context is unusable).
func (m *fontMeasure) width(s string) int32 {
	if m == nil || m.dc == 0 || s == "" {
		return 0
	}
	utf16Text, err := syscall.UTF16FromString(s)
	if err != nil || len(utf16Text) <= 1 {
		return 0
	}
	var size struct {
		Cx int32
		Cy int32
	}
	// GetTextExtentPoint32W counts UTF-16 code units, hence len-1 (terminator).
	ok, _, _ := procGetTextExtentPoint32W.Call(m.dc, uintptr(unsafe.Pointer(&utf16Text[0])),
		uintptr(len(utf16Text)-1), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		return 0
	}
	return size.Cx
}

// close restores the device context and releases it.
func (m *fontMeasure) close() {
	if m == nil || m.dc == 0 {
		return
	}
	if m.previous != 0 {
		_, _, _ = procSelectObject.Call(m.dc, m.previous)
		m.previous = 0
	}
	_, _, _ = procReleaseDC.Call(0, m.dc)
	m.dc = 0
}

// measureColumns returns the natural pixel width of every report column: the
// widest of the header text and all cell texts, plus horizontal cell padding.
//
// The minimum width keeps the "序号" column readable even when it is empty, and
// a nil/zero measurement (font not ready) still produces usable widths.
func measureColumns(measure *fontMeasure, dpi int32, titles []string, rows [][]string) []int32 {
	padding := scale(24, dpi)
	minimum := scale(48, dpi)
	widths := make([]int32, len(titles))
	for index, title := range titles {
		widths[index] = measure.width(title)
	}
	for _, row := range rows {
		for index := 0; index < len(row) && index < len(widths); index++ {
			if width := measure.width(row[index]); width > widths[index] {
				widths[index] = width
			}
		}
	}
	for index := range widths {
		widths[index] += padding
		if widths[index] < minimum {
			widths[index] = minimum
		}
	}
	return widths
}

// createSolidBrush allocates a solid GDI brush.
func createSolidBrush(color uintptr) syscall.Handle {
	handle, _, _ := procCreateSolidBrush.Call(color)
	return syscall.Handle(handle)
}

// deleteObject releases a GDI object.
func deleteObject(handle syscall.Handle) {
	if handle != 0 {
		_, _, _ = procDeleteObject.Call(uintptr(handle))
	}
}

// loadAppIcon loads the RT_GROUP_ICON with id 1 embedded by src\rsrc.syso.
func loadAppIcon() syscall.Handle {
	module, _, _ := procGetModuleHandleW.Call(0)
	if handle, _, _ := procLoadIconW.Call(module, 1); handle != 0 {
		return syscall.Handle(handle)
	}
	// Fallback so that the window still gets a system icon.
	if handle, _, _ := procLoadIconW.Call(0, 32512 /* IDI_APPLICATION */); handle != 0 {
		return syscall.Handle(handle)
	}
	return 0
}

// registerWindowClass registers one window class and returns the atom.
func registerWindowClass(name string, background syscall.Handle, icon syscall.Handle, wndProc uintptr) error {
	className := utf16Ptr(name)
	cursor, _, _ := procLoadCursorW.Call(0, 32512 /* IDC_ARROW */)
	class := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         0,
		LpfnWndProc:   wndProc,
		HInstance:     currentModule(),
		HIcon:         icon,
		HCursor:       syscall.Handle(cursor),
		HbrBackground: background,
		LpszClassName: className,
		HIconSm:       icon,
	}
	atom, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&class)))
	if atom == 0 {
		return err
	}
	return nil
}

// currentModule returns the HINSTANCE of the running executable.
func currentModule() syscall.Handle {
	module, _, _ := procGetModuleHandleW.Call(0)
	return syscall.Handle(module)
}

// createWindow creates a window or control and returns its handle.
func createWindow(exStyle uintptr, className, title string, style uintptr, x, y, width, height int32,
	parent syscall.Handle, menu uintptr, instance syscall.Handle) syscall.Handle {

	classPtr := utf16Ptr(className)
	titlePtr := utf16Ptr(title)
	handle, _, _ := procCreateWindowExW.Call(
		exStyle,
		uintptr(unsafe.Pointer(classPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		style,
		uintptr(x), uintptr(y), uintptr(width), uintptr(height),
		uintptr(parent), menu, uintptr(instance), 0,
	)
	return syscall.Handle(handle)
}

// setWindowText updates a control's caption.
func setWindowText(hwnd syscall.Handle, text string) {
	if hwnd == 0 {
		return
	}
	ptr := utf16Ptr(text)
	_, _, _ = procSetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(ptr)))
}

// clientRect returns the client area of a window.
func clientRect(hwnd syscall.Handle) RECT {
	var rect RECT
	_, _, _ = procGetClientRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&rect)))
	return rect
}

// windowRect returns the screen rectangle of a window.
func windowRect(hwnd syscall.Handle) RECT {
	var rect RECT
	_, _, _ = procGetWindowRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&rect)))
	return rect
}

// cursorPosition returns the mouse position in screen pixels.
//
// The splitter measures its drag in screen coordinates on purpose: the bar
// itself moves while it is being dragged, so a position relative to the bar
// would feed back into the drag.
func cursorPosition() (POINT, bool) {
	var point POINT
	ok, _, _ := procGetCursorPos.Call(uintptr(unsafe.Pointer(&point)))
	return point, ok != 0
}

// fillRect paints one rectangle with a solid brush.
func fillRect(hdc uintptr, rect RECT, brush syscall.Handle) {
	if hdc == 0 || brush == 0 {
		return
	}
	_, _, _ = procFillRect.Call(hdc, uintptr(unsafe.Pointer(&rect)), uintptr(brush))
}

// listHeaderHeight returns the pixel height of the column header of a report
// ListView, falling back to a font derived value when the control is missing
// (unit tests) or the header cannot be measured.
//
// The header is a real child window of the ListView, so it can simply be
// measured - which is exact for every DPI and font size, unlike a guess based on
// the text height alone.
func listHeaderHeight(list syscall.Handle, lineHeight, dpi int32) int32 {
	if list != 0 {
		header, _, _ := procSendMessageW.Call(uintptr(list), lvmGetHeader, 0, 0)
		if header != 0 {
			if height := windowRect(syscall.Handle(header)); height.Bottom > height.Top {
				return height.Bottom - height.Top
			}
		}
	}
	return lineHeight + scale(6, dpi)
}

// listBorderPixels is the thickness of the WS_BORDER frame of a ListView: one
// pixel per side, at every DPI (the frame is a theme metric, not a scaled one).
const listBorderPixels int32 = 2

// measuredRowHeight returns the row height of a report ListView that contains at
// least one row, or 0 when the table is empty (the only case in which the control
// cannot answer).
func measuredRowHeight(list syscall.Handle) int32 {
	if list == 0 {
		return 0
	}
	var rect RECT
	ok, _, _ := procSendMessageW.Call(uintptr(list), lvmGetItemRect, 0,
		uintptr(unsafe.Pointer(&rect)))
	if ok == 0 {
		return 0
	}
	if height := rect.Bottom - rect.Top; height > 0 {
		return height
	}
	return 0
}

// listRowHeight returns the height of one report row.
//
// The control itself is asked for the bounding rectangle of item 0 (LVIR_BOUNDS,
// i.e. RECT.Left == 0 on input), which is exact at every DPI and font size. The
// font based estimate is only used while the table is still empty - in that state
// there is no row that could be clipped, so being a few pixels off does not
// matter.
func listRowHeight(list syscall.Handle, lineHeight, dpi int32) int32 {
	if height := measuredRowHeight(list); height > 0 {
		return height
	}
	if lineHeight <= 0 {
		lineHeight = scale(fontPointSize+4, dpi)
	}
	return lineHeight + scale(4, dpi)
}

// listMinimumHeight returns the height of a report ListView that shows exactly
// rows complete rows: the column header, the rows and the two border pixels.
//
// There is deliberately no slack: with an exact row height, any extra pixel would
// show a sliver of the next row, which at the two row minimum of the LLDP panel
// reads as a broken table (v1.9).
func listMinimumHeight(list syscall.Handle, rows, lineHeight, dpi int32) int32 {
	if rows < 0 {
		rows = 0
	}
	return listHeaderHeight(list, lineHeight, dpi) +
		rows*listRowHeight(list, lineHeight, dpi) + listBorderPixels
}

// scrollbarWidth returns the width a vertical scroll bar takes from a client
// area, in pixels (0 when the metric is unavailable).
func scrollbarWidth() int32 {
	value, _, _ := procGetSystemMetrics.Call(smCxVScroll)
	if value <= 0 {
		return 0
	}
	return int32(value)
}

// squeezeWidths shrinks column widths until they fit into available.
//
// A report ListView that is narrower than the sum of its columns grows a
// HORIZONTAL scroll bar, and that bar is ~17 DIP tall: inside the LLDP panel it
// used to eat exactly the height of the row the user had just made visible, so
// "shrink the panel to two rows" could never show two complete rows (measured in
// v1.9 development). Fitting the columns is the cheaper answer.
//
// Only columns wider than floor are reduced, in proportion to their excess, so a
// wide 描述 column gives up more than a narrow 端口 column and the layout keeps
// its proportions; a final pass shaves the widest column until the sum really
// fits, because integer division never removes the last few pixels.
func squeezeWidths(widths []int32, available, floor int32) []int32 {
	out := make([]int32, len(widths))
	copy(out, widths)
	if available <= 0 || len(out) == 0 {
		return out
	}
	if floor < 0 {
		floor = 0
	}
	total := int32(0)
	for _, width := range out {
		total += width
	}
	if total <= available {
		return out
	}

	excess := total - available
	pool := int32(0)
	for _, width := range out {
		if width > floor {
			pool += width - floor
		}
	}
	if pool > 0 {
		for index := range out {
			if out[index] <= floor {
				continue
			}
			share := int32(int64(excess) * int64(out[index]-floor) / int64(pool))
			next := out[index] - share
			if next < floor {
				next = floor
			}
			out[index] = next
		}
	}
	// Exact pass: remove the remaining pixels from the widest column, never
	// dropping a column below the floor.
	for guard := 0; guard < 4096; guard++ {
		total = 0
		widest := 0
		for index, width := range out {
			total += width
			if width > out[widest] {
				widest = index
			}
		}
		if total <= available || out[widest] <= floor {
			break
		}
		out[widest]--
	}
	return out
}

// moveWindow repositions a window or control.
func moveWindow(hwnd syscall.Handle, x, y, width, height int32, repaint bool) {
	if hwnd == 0 || width < 0 || height < 0 {
		return
	}
	repaintValue := uintptr(0)
	if repaint {
		repaintValue = 1
	}
	_, _, _ = procMoveWindow.Call(uintptr(hwnd), uintptr(x), uintptr(y),
		uintptr(width), uintptr(height), repaintValue)
}

// invalidateClient repaints a window's client area and its background.
//
// Forcing it is required after a layout pass that MOVED a child: MoveWindow
// repaints the child at its new place but never the pixels the child left behind,
// so a label that is dragged downwards leaves a readable copy of its own text on
// the background (measured while building the v1.9 splitter). With
// WS_CLIPCHILDREN on the parent, erasing the background does not flash over the
// controls themselves.
func invalidateClient(hwnd syscall.Handle) {
	if hwnd == 0 {
		return
	}
	_, _, _ = procInvalidateRect.Call(uintptr(hwnd), 0, 1)
}

// runMessageLoop pumps messages until WM_QUIT arrives.
func runMessageLoop() int32 {
	var msg MSG
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) == -1 {
			return -1
		}
		if ret == 0 {
			return 0
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

// keyPressed reports whether a virtual key is currently down.
func keyPressed(vk uintptr) bool {
	state, _, _ := procGetKeyState.Call(vk)
	return int16(state) < 0
}

// setClipboardText stores text as CF_UNICODETEXT on the system clipboard.
func setClipboardText(owner syscall.Handle, text string) bool {
	utf16Text, err := syscall.UTF16FromString(text)
	if err != nil {
		return false
	}
	opened, _, _ := procOpenClipboard.Call(uintptr(owner))
	if opened == 0 {
		return false
	}
	defer func() {
		_, _, _ = procCloseClipboard.Call()
	}()
	if cleared, _, _ := procEmptyClipboard.Call(); cleared == 0 {
		return false
	}
	size := uintptr(len(utf16Text) * 2)
	memory, _, _ := procGlobalAlloc.Call(gmemMoveable|gmemZeroInit, size)
	if memory == 0 {
		return false
	}
	target, _, _ := procGlobalLock.Call(memory)
	if target == 0 {
		_, _, _ = procGlobalFree.Call(memory)
		return false
	}
	destination := (*[1 << 20]uint16)(unsafe.Pointer(target))[:len(utf16Text):len(utf16Text)]
	copy(destination, utf16Text)
	_, _, _ = procGlobalUnlock.Call(memory)
	if stored, _, _ := procSetClipboardData.Call(cfUnicodeText, memory); stored == 0 {
		_, _, _ = procGlobalFree.Call(memory)
		return false
	}
	return true
}

// shellOpen opens a URL with the default handler (used by double click).
func shellOpen(url string) bool {
	verb := utf16Ptr("open")
	target := utf16Ptr(url)
	result, _, _ := procShellExecuteW.Call(0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(target)),
		0, 0, swShow)
	return result > 32
}

// workArea returns the size of the usable desktop in physical pixels.
//
// Design sizes are expressed in device independent pixels, so on a display
// running at 200% scaling a 1000 DIP wide window needs 2000 physical pixels.
// The window must be clamped to this area, otherwise it would open larger than
// the screen and the button and the status line would be unreachable.
func workArea() (int32, int32) {
	var rect RECT
	if ok, _, _ := procSystemParametersInfoW.Call(spiGetWorkArea, 0, uintptr(unsafe.Pointer(&rect)), 0); ok != 0 {
		if rect.Right > rect.Left && rect.Bottom > rect.Top {
			return rect.Right - rect.Left, rect.Bottom - rect.Top
		}
	}
	width, _, _ := procGetSystemMetrics.Call(smCxScreen)
	height, _, _ := procGetSystemMetrics.Call(smCyScreen)
	return int32(width), int32(height)
}

// tooltip is a "tooltips_class32" control bound to exactly one child window.
//
// It replaces the old adapter summary line (U2): the enabled adapters are no
// longer printed above the table, but their full list stays reachable by
// hovering the status bar. The UTF-16 buffers handed to the control are owned
// by this struct and therefore kept alive as long as the tooltip exists.
type tooltip struct {
	hwnd   syscall.Handle
	owner  syscall.Handle
	text   *uint16
	bound  bool
	cbSize uint32
}

// TOOLINFO structure sizes.
//
// The executable ships without an embedded manifest, so comctl32 v5 is loaded
// and its TOOLINFO ends after lParam (64 bytes on x64). The v6 structure adds
// lpReserved (72 bytes). TTM_ADDTOOLW fails *silently* (returns 0, GetLastError
// stays 0) when cbSize does not match the loaded control version, so both are
// tried - measured with _analysis/ui_v11/probe/tooltiptest.
const (
	toolInfoSizeV6 = uint32(unsafe.Sizeof(TOOLINFOW{}))
	toolInfoSizeV5 = uint32(unsafe.Offsetof(TOOLINFOW{}.LpReserved))
)

// newTooltip attaches a tooltip to target.
func newTooltip(owner, target syscall.Handle, text string) *tooltip {
	if owner == 0 || target == 0 || text == "" {
		return nil
	}
	handle := createWindow(0, tooltipsClassName, "",
		wsPopup|ttsAlwaysTip|ttsNoPrefix,
		0, 0, 0, 0, owner, 0, currentModule())
	if handle == 0 {
		return nil
	}
	tip := &tooltip{hwnd: handle, owner: owner}
	// 900 px keeps a long adapter list on a few wrapped lines.
	_, _, _ = procSendMessageW.Call(uintptr(handle), ttmSetMaxTipWidthW,
		uintptr(scale(900, systemDPI())), 0)
	tip.setText(target, text)
	if !tip.bound {
		tip.destroy()
		return nil
	}
	return tip
}

// setText (re)binds the tooltip text to target.
func (t *tooltip) setText(target syscall.Handle, text string) {
	if t == nil || t.hwnd == 0 || text == "" {
		return
	}
	t.text = utf16Ptr(text)
	info := TOOLINFOW{
		CbSize:   t.cbSize,
		UFlags:   ttfIDISHWND,
		Hwnd:     t.owner,
		UId:      uintptr(target),
		HInst:    currentModule(),
		LpszText: t.text,
	}
	if t.bound {
		_, _, _ = procSendMessageW.Call(uintptr(t.hwnd), ttmUpdateTipTextW, 0,
			uintptr(unsafe.Pointer(&info)))
		return
	}
	for _, size := range []uint32{toolInfoSizeV6, toolInfoSizeV5} {
		info.CbSize = size
		result, _, _ := procSendMessageW.Call(uintptr(t.hwnd), ttmAddToolW, 0,
			uintptr(unsafe.Pointer(&info)))
		if result != 0 {
			t.bound = true
			t.cbSize = size
			return
		}
	}
}

// destroy releases the tooltip window.
func (t *tooltip) destroy() {
	if t == nil || t.hwnd == 0 {
		return
	}
	_, _, _ = procDestroyWindowW.Call(uintptr(t.hwnd))
	t.hwnd = 0
	t.text = nil
	t.bound = false
}
