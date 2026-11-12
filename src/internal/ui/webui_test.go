package ui

import (
	"syscall"
	"testing"
	"time"
	"unsafe"

	"moxasearch/src/internal/discovery"
)

// newWebTestApp returns an App that has just enough state for the double click
// path: a fake list handle, the given rows and a nil window handle (posting to
// a nil window is a harmless no-op, so no message loop is required).
func newWebTestApp(devices ...discovery.Device) *App {
	return &App{
		hList:      fakeListHandle,
		devices:    devices,
		allDevices: devices,
	}
}

const fakeListHandle = 0x00A1B2C0

// stubWebSeams replaces the network and shell seams and restores them on cleanup.
func stubWebSeams(t *testing.T, portOpen func(ip, port string) bool, open func(url string) bool) {
	t.Helper()
	oldPortOpen, oldShell := webPortOpenFn, shellOpenFn
	webPortOpenFn, shellOpenFn = portOpen, open
	t.Cleanup(func() { webPortOpenFn, shellOpenFn = oldPortOpen, oldShell })
}

// notifyDoubleClick builds an NMITEMACTIVATE for row and delivers it the same
// way the ListView does.
func notifyDoubleClick(app *App, hwndFrom uintptr, row int) {
	code := int32(nmDblClk) // typed, so the negative constant can go through uint32
	activation := NMITEMACTIVATE{
		Header: NMHDR{
			HwndFrom: syscall.Handle(hwndFrom),
			IDFrom:   uintptr(idcList),
			Code:     uint32(code),
		},
		IItem: int32(row),
	}
	app.onNotify(uintptr(unsafe.Pointer(&activation)))
}

// waitURL waits for the asynchronous open and returns the URL that was handed
// to the browser.
func waitURL(t *testing.T, opened <-chan string) string {
	t.Helper()
	select {
	case url := <-opened:
		return url
	case <-time.After(3 * time.Second):
		t.Fatal("the browser was not opened within 3 s")
		return ""
	}
}

// TestNMItemActivateLayout guards the struct padding: if IItem ever moves away
// from offset 24 the handler would read garbage out of the notification.
func TestNMITEMACTIVELayout(t *testing.T) {
	var activation NMITEMACTIVATE
	if size := unsafe.Sizeof(NMHDR{}); size != 24 {
		t.Fatalf("sizeof(NMHDR) = %d, want 24 on amd64", size)
	}
	if offset := unsafe.Offsetof(activation.IItem); offset != 24 {
		t.Fatalf("offsetof(IItem) = %d, want 24", offset)
	}
}

// TestNMNotificationCodes pins the notification codes.
//
// The shipped v1.0 build used -116 for NM_DBLCLK, which is not a Win32
// notification at all, so the double click handler could never fire. Win32
// defines NM_DBLCLK as NM_FIRST - 3 == -3 and NM_CLICK as -2.
func TestNMNotificationCodes(t *testing.T) {
	if nmDblClk != -3 {
		t.Fatalf("nmDblClk = %d, want -3 (NM_FIRST - 3)", nmDblClk)
	}
	if nmDblClk == -116 {
		t.Fatal("nmDblClk must not be -116; that value never arrives from a ListView")
	}
}

// TestIsWebAddress checks which addresses may be opened in a browser.
func TestIsWebAddress(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.100.250", true},
		{"10.0.0.1", true},
		{"1.1.1.1", true},
		{" 192.168.1.5 ", true},
		{"", false},
		{"0.0.0.0", false},
		{"255.255.255.255", false},
		{"192.168.1", false},
		{"not-an-ip", false},
		{"fe80::1", false},
		{"::1", false},
	}
	for _, test := range tests {
		if got := isWebAddress(test.ip); got != test.want {
			t.Errorf("isWebAddress(%q) = %v, want %v", test.ip, got, test.want)
		}
	}
}

// TestDeviceWebURL checks URL construction, including the http fallback used
// when neither port answers.
func TestDeviceWebURL(t *testing.T) {
	tests := []struct {
		ip     string
		scheme string
		want   string
	}{
		{"192.168.100.253", "https", "https://192.168.100.253"},
		{"192.168.100.253", "http", "http://192.168.100.253"},
		{"192.168.100.253", "", "http://192.168.100.253"},
		{"192.168.100.253", "ftp", "http://192.168.100.253"},
		{" 192.168.100.250 ", "http", "http://192.168.100.250"},
		{"", "http", ""},
		{"0.0.0.0", "http", ""},
		{"garbage", "https", ""},
	}
	for _, test := range tests {
		if got := deviceWebURL(test.ip, test.scheme); got != test.want {
			t.Errorf("deviceWebURL(%q, %q) = %q, want %q", test.ip, test.scheme, got, test.want)
		}
	}
}

// TestProbeWebScheme verifies the port preference: plain HTTP wins when both
// ports answer (no certificate warning), HTTPS is used when 80 is closed.
func TestProbeWebScheme(t *testing.T) {
	tests := []struct {
		name  string
		https bool
		http  bool
		want  string
	}{
		{"both open", true, true, "http"},
		{"https only", true, false, "https"},
		{"http only", false, true, "http"},
		{"neither", false, false, ""},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			stubWebSeams(t, func(ip, port string) bool {
				switch port {
				case webHTTPSPort:
					return test.https
				case webHTTPPort:
					return test.http
				}
				t.Fatalf("unexpected port %q", port)
				return false
			}, func(string) bool { return true })

			if got := probeWebScheme("192.168.100.253"); got != test.want {
				t.Fatalf("probeWebScheme = %q, want %q", got, test.want)
			}
		})
	}
}

// TestDoubleClickOpensActivatedRow is the core regression test: the row carried
// by the notification must be opened, not the first selected row.
func TestDoubleClickOpensActivatedRow(t *testing.T) {
	opened := make(chan string, 1)
	stubWebSeams(t,
		func(ip, port string) bool { return port == webHTTPPort },
		func(url string) bool { opened <- url; return true })

	app := newWebTestApp(
		discovery.Device{IP: "192.168.100.250", MAC: "00:90:E8:00:00:20"},
		discovery.Device{IP: "192.168.100.253", MAC: "50:0B:88:00:01:9F"},
	)
	notifyDoubleClick(app, uintptr(app.hList), 1)

	if url := waitURL(t, opened); url != "http://192.168.100.253" {
		t.Fatalf("opened %q, want the second row", url)
	}
}

// TestDoubleClickPrefersHTTPS checks that a TLS-only device gets an https URL.
func TestDoubleClickPrefersHTTPS(t *testing.T) {
	opened := make(chan string, 1)
	stubWebSeams(t,
		func(ip, port string) bool { return port == webHTTPSPort },
		func(url string) bool { opened <- url; return true })

	app := newWebTestApp(discovery.Device{IP: "192.168.100.3"})
	notifyDoubleClick(app, uintptr(app.hList), 0)

	if url := waitURL(t, opened); url != "https://192.168.100.3" {
		t.Fatalf("opened %q, want https://192.168.100.3", url)
	}
}

// TestDoubleClickIgnoresForeignNotification makes sure notifications of other
// controls (the button, the status label) never open a browser.
func TestDoubleClickIgnoresForeignNotification(t *testing.T) {
	opened := make(chan string, 1)
	stubWebSeams(t,
		func(string, string) bool { return true },
		func(url string) bool { opened <- url; return true })

	app := newWebTestApp(discovery.Device{IP: "192.168.100.250"})
	notifyDoubleClick(app, uintptr(app.hList)+0x10, 0)

	select {
	case url := <-opened:
		t.Fatalf("a notification from another control opened %q", url)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestDoubleClickIgnoresSingleClick verifies that only NM_DBLCLK is handled.
func TestDoubleClickIgnoresSingleClick(t *testing.T) {
	opened := make(chan string, 1)
	stubWebSeams(t,
		func(string, string) bool { return true },
		func(url string) bool { opened <- url; return true })

	app := newWebTestApp(discovery.Device{IP: "192.168.100.250"})
	activation := NMITEMACTIVATE{
		Header: NMHDR{HwndFrom: syscall.Handle(uintptr(app.hList)), Code: 0xFFFFFFFE}, // NM_CLICK == -2
		IItem:  0,
	}
	app.onNotify(uintptr(unsafe.Pointer(&activation)))

	select {
	case url := <-opened:
		t.Fatalf("NM_CLICK opened %q", url)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestDoubleClickWithoutIP checks that a row without a usable address is
// rejected instead of opening "http://".
func TestDoubleClickWithoutIP(t *testing.T) {
	opened := make(chan string, 1)
	stubWebSeams(t,
		func(string, string) bool { return true },
		func(url string) bool { opened <- url; return true })

	app := newWebTestApp(discovery.Device{MAC: "AA:BB:CC:00:00:01"})
	notifyDoubleClick(app, uintptr(app.hList), 0)

	select {
	case url := <-opened:
		t.Fatalf("a device without an IP opened %q", url)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestDoubleClickOutOfRange checks a stale row index (e.g. the list was cleared
// by a new scan) cannot reach the browser.
func TestDoubleClickOutOfRange(t *testing.T) {
	opened := make(chan string, 1)
	stubWebSeams(t,
		func(string, string) bool { return true },
		func(url string) bool { opened <- url; return true })

	app := newWebTestApp(discovery.Device{IP: "192.168.100.250"})
	notifyDoubleClick(app, uintptr(app.hList), 7)

	select {
	case url := <-opened:
		t.Fatalf("an out of range row opened %q", url)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestDoubleClickWhileScanning checks that a double click during a scan is
// ignored (the table is being rebuilt at that moment).
func TestDoubleClickWhileScanning(t *testing.T) {
	opened := make(chan string, 1)
	stubWebSeams(t,
		func(string, string) bool { return true },
		func(url string) bool { opened <- url; return true })

	app := newWebTestApp(discovery.Device{IP: "192.168.100.250"})
	app.scanning = true
	notifyDoubleClick(app, uintptr(app.hList), 0)

	select {
	case url := <-opened:
		t.Fatalf("a double click during a scan opened %q", url)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestWebNoticeIsShownOnce checks the asynchronous result is consumed by the
// UI thread exactly once.
func TestWebNoticeIsShownOnce(t *testing.T) {
	app := &App{webNotice: "已在浏览器中打开 http://192.168.100.250"}
	app.onWebNotice()
	if app.webNotice != "" {
		t.Fatalf("webNotice = %q, want it cleared", app.webNotice)
	}
	// A second dispatch without a new notice must not panic or repeat text.
	app.onWebNotice()
}
