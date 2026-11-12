package ui

import (
	"syscall"
	"unsafe"
)

// The splitter between the device table and the LLDP panel (v1.9).
//
// It is a small child window of its own instead of a drawn line inside the
// parent: a real window receives WM_SETCURSOR (so the sizer cursor appears when
// the pointer is over it) and can capture the mouse for the duration of a drag,
// which is what makes the divider follow the pointer even when it is moved
// outside the bar.
//
// The bar reports every drag step as an absolute client height of the device
// table; App.setListHeight clamps it against the two table minimums and turns it
// into a share of the content area, so the split survives a window resize.

const splitterClassName = "MoxaSplitter"

// splitterHeightDIP is the height of the drag bar. 10 DIP is a comfortable
// mouse target that still reads as a divider rather than as a third table.
const splitterHeightDIP int32 = 10

var splitterWndProcPtr = syscall.NewCallback(splitterWndProc)

// splitter is the drag bar. Only the UI thread touches it.
type splitter struct {
	app      *App
	hwnd     syscall.Handle
	dragging bool
	// startList is the height of the device table when the drag started,
	// startCursorY the screen position of the pointer at that moment. Both are
	// absolute, so the bar moving under the pointer cannot distort the drag.
	startList    int32
	startCursorY int32

	hBrushLine syscall.Handle
	hBrushGrip syscall.Handle
}

// newSplitter creates the drag bar as a child of the main window.
func newSplitter(app *App) *splitter {
	if app == nil || app.hMain == 0 {
		return nil
	}
	bar := &splitter{
		app:        app,
		hBrushLine: createSolidBrush(colorSplitterLine),
		hBrushGrip: createSolidBrush(colorSplitterGrip),
	}
	bar.hwnd = createWindow(0, splitterClassName, "",
		wsChild|wsVisible|wsClipSiblings, 0, 0, 0, 0, app.hMain, 0, app.hInstance)
	if bar.hwnd == 0 {
		bar.destroy()
		return nil
	}
	return bar
}

// splitterOf resolves the bar a window handle belongs to.
func splitterOf(hwnd uintptr) *splitter {
	app := theApp
	if app == nil || app.splitter == nil {
		return nil
	}
	if uintptr(app.splitter.hwnd) != hwnd {
		return nil
	}
	return app.splitter
}

// splitterWndProc handles the drag bar messages.
func splitterWndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	bar := splitterOf(hwnd)
	switch msg {
	case wmSetCursor:
		if bar != nil && uint16(lparam) == htClient {
			if cursor, _, _ := procLoadCursorW.Call(0, idcSizeNS); cursor != 0 {
				_, _, _ = procSetCursor.Call(cursor)
				return 1
			}
		}
	case wmEraseBkgnd:
		// The whole surface is painted in WM_PAINT; erasing first would only
		// flicker.
		return 1
	case wmPaint:
		if bar != nil {
			bar.paint()
			return 0
		}
	case wmLButtonDown:
		if bar != nil {
			bar.beginDrag()
			return 0
		}
	case wmMouseMove:
		if bar != nil && bar.dragging {
			bar.drag()
			return 0
		}
	case wmLButtonUp:
		if bar != nil {
			bar.endDrag()
			return 0
		}
	case wmCaptureChanged:
		if bar != nil {
			bar.dragging = false
			return 0
		}
	}
	result, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return result
}

// paint draws the divider line and its grab segment.
func (b *splitter) paint() {
	if b == nil || b.hwnd == 0 {
		return
	}
	var paint PAINTSTRUCT
	hdc, _, _ := procBeginPaint.Call(uintptr(b.hwnd), uintptr(unsafe.Pointer(&paint)))
	if hdc == 0 {
		return
	}
	defer func() {
		_, _, _ = procEndPaint.Call(uintptr(b.hwnd), uintptr(unsafe.Pointer(&paint)))
	}()

	rect := clientRect(b.hwnd)
	fillRect(hdc, rect, b.app.hBrushBg)

	// A two pixel line in the middle of the bar.
	centre := rect.Top + (rect.Bottom-rect.Top)/2
	line := RECT{Left: rect.Left, Top: centre - 1, Right: rect.Right, Bottom: centre + 1}
	fillRect(hdc, line, b.hBrushLine)

	// A darker segment in the middle: the "you can grab this" cue.
	width := scale(48, b.app.dpi)
	if width > rect.Right-rect.Left {
		width = rect.Right - rect.Left
	}
	left := rect.Left + (rect.Right-rect.Left-width)/2
	grip := RECT{Left: left, Top: line.Top, Right: left + width, Bottom: line.Bottom}
	fillRect(hdc, grip, b.hBrushGrip)
}

// beginDrag starts a drag: remember the current split and the pointer position.
func (b *splitter) beginDrag() {
	if b == nil {
		return
	}
	b.dragging = true
	b.startList = b.app.currentListHeight()
	if point, ok := cursorPosition(); ok {
		b.startCursorY = point.Y
	}
	_, _, _ = procSetCapture.Call(uintptr(b.hwnd))
}

// drag moves the divider to follow the pointer.
func (b *splitter) drag() {
	if b == nil || b.app == nil {
		return
	}
	point, ok := cursorPosition()
	if !ok {
		return
	}
	b.app.setListHeight(b.startList + (point.Y - b.startCursorY))
}

// endDrag releases the mouse capture.
func (b *splitter) endDrag() {
	if b == nil {
		return
	}
	if b.dragging {
		b.dragging = false
		_, _, _ = procReleaseCapture.Call()
	}
}

// destroy releases the brushes; the window itself dies with its parent.
func (b *splitter) destroy() {
	if b == nil {
		return
	}
	deleteObject(b.hBrushLine)
	deleteObject(b.hBrushGrip)
	b.hBrushLine = 0
	b.hBrushGrip = 0
	b.hwnd = 0
}
