package ui

import (
	"fmt"
	"syscall"
	"unsafe"

	"moxasearch/src/internal/discovery"
)

// progressClassName is the window class of the progress popup.
const progressClassName = "MoxaSearchProgressWindow"

// Progress popup control identifiers.
//
// There is deliberately no title label any more: the caption already says
// "正在搜索 MOXA 设备…" and repeating it inside the body was pure noise.
const (
	idcProgressBar  = 2002
	idcProgressInfo = 2003
)

// progressTimerID is the identifier of the 100 ms smoothing timer.
const progressTimerID = 1

// progressCaption is the window caption (title bar) of the popup.
const progressCaption = "正在搜索 MOXA 设备…"

// progressWindow is the small popup shown while a scan runs
// (REQUIREMENTS.md §4 "进度窗口"). It has no buttons and closes itself as soon
// as the scan finishes (R5/R6).
//
// v1.1 (U1): the popup is a plain owned window - NOT topmost. It is created
// with the main window as its owner (hWndParent), which keeps it above the main
// window only, and it never covers other applications.
//
// The body holds exactly two bands: the status line and the progress bar. The
// title line was removed because it duplicated the caption.
type progressWindow struct {
	hWnd     syscall.Handle
	owner    syscall.Handle
	hBar     syscall.Handle
	hInfo    syscall.Handle
	font     syscall.Handle
	brush    syscall.Handle
	dpi      int32
	position int32
	target   int32
	found    int

	// metrics is borrowed from the App (same point size) and must not be closed
	// here: it measures the text so that every band follows the font (U5).
	metrics *fontMeasure
}

// activeProgress lets the window procedure reach the live progress window.
var activeProgress *progressWindow

// showProgress creates and displays the progress popup for the current scan.
func (a *App) showProgress() {
	if a.progress != nil || a.hMain == 0 {
		return
	}
	window := &progressWindow{owner: a.hMain, dpi: a.dpi, metrics: a.measure}
	activeProgress = window
	if !window.create() {
		activeProgress = nil
		return
	}
	a.progress = window
}

// closeProgress destroys the popup and releases its GDI objects.
func (a *App) closeProgress() {
	window := a.progress
	if window == nil {
		return
	}
	a.progress = nil
	activeProgress = nil
	window.destroy()
}

// textHeight returns the pixel height of one line of the popup font.
func (w *progressWindow) textHeight() int32 {
	if w.metrics != nil {
		if height := w.metrics.lineHeight(); height > 0 {
			return height
		}
	}
	return scale(fontPointSize+4, w.dpi)
}

// progressText is the only text line of the popup body.
//
// While the first broadcast round has not finished yet it reports the
// preparation state, afterwards the round counter and the device count.
func progressText(round, totalRounds, found int) string {
	if totalRounds <= 0 {
		totalRounds = 1
	}
	if round <= 0 {
		return "正在准备广播…"
	}
	return fmt.Sprintf("第 %d/%d 轮 · 已发现 %d 台设备", round, totalRounds, found)
}

// progressModelsText is the status line of the model enhancement phase (v1.3).
//
// It replaces - not extends - the round counter: the amendment is one extra step
// after the last round, so the popup shows it while the round count already
// stands at its final value and the bar sits at 100 %.
const progressModelsText = "正在读取设备型号…"

// progressTextForPhase renders the status line of the popup for one scan phase.
//
// The broadcast phase keeps the 3-round wording of progressText; the model phase
// answers with a single line that names what is happening, because a round
// counter would be meaningless there.
func progressTextForPhase(phase discovery.Phase, round, totalRounds, found int) string {
	if phase == discovery.PhaseModels {
		return progressModelsText
	}
	return progressText(round, totalRounds, found)
}

// contentMetrics returns the popup client size and the height of each band.
//
// Everything is derived from the measured line height so that the popup grows
// with the font instead of clipping the labels (U5). With the title band gone
// the popup is two bands high, so no empty area is left behind.
func (w *progressWindow) contentMetrics() (width, height, infoHeight, barHeight int32) {
	line := w.textHeight()
	pad := scale(18, w.dpi)
	gap := scale(12, w.dpi)

	infoHeight = line
	barHeight = line * 2 / 3
	if minimum := scale(16, w.dpi); barHeight < minimum {
		barHeight = minimum
	}

	width = scale(520, w.dpi)
	if w.metrics != nil {
		// Reserve room for the widest status line the popup may ever show:
		// the round counter of the broadcast phase and the model phase line.
		samples := []string{
			progressText(999, 999, 999),
			progressTextForPhase(discovery.PhaseModels, 1, 1, 0),
		}
		for _, sample := range samples {
			if needed := w.metrics.width(sample) + pad*2 + scale(24, w.dpi); needed > width {
				width = needed
			}
		}
	}
	height = pad*2 + infoHeight + gap + barHeight
	return
}

// create builds the popup window, centred over the main window.
func (w *progressWindow) create() bool {
	style := uintptr(wsPopup | wsCaption | wsClipChildren)
	// U1: no WS_EX_TOPMOST and no SetWindowPos(HWND_TOPMOST). The popup is an
	// owned window of the main window, so it floats above the main window only.
	exStyle := uintptr(wsExToolWindow)

	clientWidth, clientHeight, _, _ := w.contentMetrics()
	outer := RECT{Left: 0, Top: 0, Right: clientWidth, Bottom: clientHeight}
	_, _, _ = procAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&outer)), style, 0, exStyle)
	width := outer.Right - outer.Left
	height := outer.Bottom - outer.Top

	ownerRect := windowRect(w.owner)
	x := ownerRect.Left + ((ownerRect.Right-ownerRect.Left)-width)/2
	y := ownerRect.Top + ((ownerRect.Bottom-ownerRect.Top)-height)/2

	handle := createWindow(exStyle, progressClassName, progressCaption, style,
		x, y, width, height, w.owner, 0, currentModule())
	if handle == 0 {
		return false
	}
	w.hWnd = handle
	_, _, _ = procShowWindow.Call(uintptr(w.hWnd), swShowNormal)
	_, _, _ = procUpdateWindow.Call(uintptr(w.hWnd))
	return true
}

// destroy tears the popup down.
func (w *progressWindow) destroy() {
	if w == nil {
		return
	}
	if w.hWnd != 0 {
		_, _, _ = procKillTimer.Call(uintptr(w.hWnd), progressTimerID)
		_, _, _ = procDestroyWindowW.Call(uintptr(w.hWnd))
		w.hWnd = 0
	}
	deleteObject(w.font)
	deleteObject(w.brush)
	w.font, w.brush = 0, 0
	w.metrics = nil
}

// setStatus updates the status line and the target position of the progress bar.
//
// phase selects the wording (round counter or model phase line); round drives
// the bar, so the model phase - which reports the final round - keeps the bar at
// 100 % while it runs.
func (w *progressWindow) setStatus(phase discovery.Phase, round, totalRounds, found int) {
	if w == nil || w.hWnd == 0 {
		return
	}
	w.found = found
	if totalRounds <= 0 {
		totalRounds = 1
	}
	if round <= 0 {
		w.target = 4
		setWindowText(w.hInfo, progressTextForPhase(phase, 0, totalRounds, found))
		return
	}
	percent := int32(round) * 100 / int32(totalRounds)
	if percent > 100 {
		percent = 100
	}
	if percent < w.position {
		percent = w.position
	}
	w.target = percent
	setWindowText(w.hInfo, progressTextForPhase(phase, round, totalRounds, found))
}

// tick advances the bar smoothly between two rounds.
func (w *progressWindow) tick() {
	if w == nil || w.hBar == 0 || w.position >= w.target {
		return
	}
	step := (w.target - w.position) / 4
	if step < 1 {
		step = 1
	}
	w.position += step
	if w.position > w.target {
		w.position = w.target
	}
	_, _, _ = procSendMessageW.Call(uintptr(w.hBar), pbmSetPos, uintptr(w.position), 0)
}

// onCreate builds the popup content: one status line plus the progress bar.
func (w *progressWindow) onCreate(hwnd uintptr) {
	w.hWnd = syscall.Handle(hwnd)
	w.brush = createSolidBrush(colorPanel)
	w.font = createFont(fontPointSize, false, w.dpi)

	if icon := loadAppIcon(); icon != 0 {
		_, _, _ = procSendMessageW.Call(hwnd, wmSetIcon, iconBig, uintptr(icon))
		_, _, _ = procSendMessageW.Call(hwnd, wmSetIcon, iconSmall, uintptr(icon))
	}

	w.hInfo = createWindow(0, "STATIC", progressText(0, 1, 0),
		wsChild|wsVisible|ssLeft, 0, 0, 0, 0, w.hWnd, idcProgressInfo, currentModule())
	w.hBar = createWindow(0, "msctls_progress32", "",
		wsChild|wsVisible, 0, 0, 0, 0, w.hWnd, idcProgressBar, currentModule())

	for _, handle := range []syscall.Handle{w.hBar, w.hInfo} {
		if handle != 0 && w.font != 0 {
			_, _, _ = procSendMessageW.Call(uintptr(handle), wmSetFont, uintptr(w.font), 1)
		}
	}
	if w.hBar != 0 {
		// A gray trough keeps the empty bar visible from 0 % on; without it the
		// classic control paints an almost white bar on a white background and
		// the user cannot tell there is a progress bar at all.
		// CCM_SETBKCOLOR/PBM_SETBKCOLOR takes the COLORREF in LPARAM and requires
		// wParam = 0 - swapping them paints the trough black.
		_, _, _ = procSendMessageW.Call(uintptr(w.hBar), ccmSetBkColor,
			0, uintptr(colorProgressTrough))
		_, _, _ = procSendMessageW.Call(uintptr(w.hBar), pbmSetRange32, 0, 100)
		_, _, _ = procSendMessageW.Call(uintptr(w.hBar), pbmSetPos, 0, 0)
	}

	w.layout()
	_, _, _ = procSetTimer.Call(hwnd, progressTimerID, 100, 0)
}

// layout positions the status line and the progress bar inside the popup.
func (w *progressWindow) layout() {
	if w.hWnd == 0 {
		return
	}
	rect := clientRect(w.hWnd)
	pad := scale(18, w.dpi)
	gap := scale(12, w.dpi)
	_, _, infoHeight, barHeight := w.contentMetrics()

	innerWidth := rect.Right - pad*2
	if innerWidth < 0 {
		innerWidth = 0
	}
	moveWindow(w.hInfo, pad, pad, innerWidth, infoHeight, true)
	moveWindow(w.hBar, pad, pad+infoHeight+gap, innerWidth, barHeight, true)
}

// progressWndProc dispatches the popup messages.
func progressWndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	window := activeProgress
	switch msg {
	case wmCreate:
		if window != nil {
			window.onCreate(hwnd)
		}
		return 0
	case wmSize:
		if window != nil {
			window.layout()
		}
		return 0
	case wmTimer:
		if window != nil {
			window.tick()
		}
		return 0
	case wmCtlColorStatic:
		_, _, _ = procSetBkMode.Call(wparam, transparentBk)
		_, _, _ = procSetTextColor.Call(wparam, uintptr(colorText))
		if window != nil && window.brush != 0 {
			return uintptr(window.brush)
		}
		return uintptr(colorPanel)
	case wmClose:
		// The popup has no close button; a stray WM_CLOSE must not tear it
		// down while the scan is still running.
		return 0
	}
	result, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return result
}
