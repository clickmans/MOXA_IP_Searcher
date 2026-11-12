package ui

import (
	"fmt"
	"net"
	"strings"
	"time"

	"moxasearch/src/internal/discovery"
)

// Ports a MOXA device serves its web UI on. Newer firmware (WIFI 6, EDS, EOM)
// listens on 443 only, older units (NPort, MGate, AWK-1131A) on 80 only, and
// many answer on both with 80 redirecting to the login page.
const (
	webHTTPSPort = "443"
	webHTTPPort  = "80"
)

// webProbeTimeout bounds a single TCP connect. Both ports are probed
// concurrently, so this is also the worst case delay before the browser opens.
const webProbeTimeout = 500 * time.Millisecond

// webPortOpenFn and shellOpenFn are seams: the unit tests replace them so the
// double click path can be verified without network access or a browser.
var (
	webPortOpenFn = webPortOpen
	shellOpenFn   = shellOpen
)

// probeWebScheme reports the scheme the device answers on: "https", "http" or
// "" when neither port accepts a connection.
//
// Plain HTTP wins when both ports are open. MOXA devices serve their login page
// on 80, while 443 uses a self signed certificate that makes every browser show
// an interstitial warning first; 80 also redirects to https when the device is
// configured that way, so preferring it costs nothing and avoids the warning in
// the common case. HTTPS is only used when 80 is closed (WIFI 6 units with
// "HTTPS only" enabled).
func probeWebScheme(ip string) string {
	httpsResult := make(chan bool, 1)
	httpResult := make(chan bool, 1)
	go func() { httpsResult <- webPortOpenFn(ip, webHTTPSPort) }()
	go func() { httpResult <- webPortOpenFn(ip, webHTTPPort) }()

	httpsOK := <-httpsResult
	httpOK := <-httpResult
	switch {
	case httpOK:
		return "http"
	case httpsOK:
		return "https"
	default:
		return ""
	}
}

// webPortOpen reports whether a TCP connection to ip:port succeeds.
func webPortOpen(ip, port string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), webProbeTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// deviceWebURL builds the URL that is handed to the default browser.
//
// An empty scheme means "nothing could be probed" - every MOXA device older
// than WIFI 6 serves plain HTTP, so http is the safer guess there. The caller
// still reports the URL, which makes a wrong guess visible instead of silent.
func deviceWebURL(ip, scheme string) string {
	ip = strings.TrimSpace(ip)
	if !isWebAddress(ip) {
		return ""
	}
	if scheme != "https" {
		scheme = "http"
	}
	return scheme + "://" + ip
}

// isWebAddress accepts a plain IPv4 unicast address. IPv6, the wildcard and the
// broadcast address are rejected: they cannot identify one device web UI.
func isWebAddress(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	ipv4 := parsed.To4()
	if ipv4 == nil {
		return false
	}
	if ipv4[0] == 0 && ipv4[1] == 0 && ipv4[2] == 0 && ipv4[3] == 0 {
		return false
	}
	if ipv4[0] == 255 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 255 {
		return false
	}
	return true
}

// openDeviceWeb opens the web UI of one list row in the default browser.
//
// The port probe runs on a goroutine so a slow or unreachable device never
// freezes the window (R8). The outcome is reported in the status line - this
// tool never shows a dialog (R5), not even when the browser cannot be started.
func (a *App) openDeviceWeb(row int) {
	a.mu.Lock()
	scanning := a.scanning
	devices := a.devices
	all := a.allDevices
	var device discovery.Device
	if row >= 0 && row < len(devices) {
		device = devices[row]
	}
	sharedIP := 0
	for index := range all {
		if device.IP != "" && all[index].IP == device.IP {
			sharedIP++
		}
	}
	a.mu.Unlock()

	if scanning {
		debugf("open web: ignored, a scan is running")
		a.setStatus("正在搜索，请等搜索完成后再双击设备")
		return
	}
	if row < 0 || row >= len(devices) {
		debugf("open web: row %d out of range (%d rows)", row, len(devices))
		return
	}

	ip := strings.TrimSpace(device.IP)
	if !isWebAddress(ip) {
		debugf("open web: no usable address %q", device.IP)
		a.setStatus("该设备没有可用的 IP 地址，无法打开 WEB 界面")
		return
	}
	debugf("open web: row=%d ip=%s sharedIP=%d", row, ip, sharedIP)

	if sharedIP > 1 {
		a.setStatus(fmt.Sprintf("正在打开 %s 的 WEB 界面…（该 IP 上有 %d 台设备）", ip, sharedIP))
	} else {
		a.setStatus("正在打开 " + ip + " 的 WEB 界面…")
	}

	go func() {
		scheme := probeWebScheme(ip)
		url := deviceWebURL(ip, scheme)
		text := ""
		switch {
		case url == "":
			text = "无法打开 WEB 界面：IP 地址无效"
		case shellOpenFn(url):
			text = "已在浏览器中打开 " + url
			if scheme == "" {
				// Neither 80 nor 443 accepted a connection. The URL is opened
				// anyway (a firewall may block the probe but not the browser),
				// but the user should not be surprised by an error page.
				text += "（80/443 未响应，浏览器可能无法打开）"
			}
			if sharedIP > 1 {
				text += fmt.Sprintf("（该 IP 上有 %d 台设备，浏览器访问的是 ARP 命中的那一台）", sharedIP)
			}
		default:
			text = "打开浏览器失败，请手动访问 " + url
		}
		debugf("open web: url=%s text=%s", url, text)
		a.mu.Lock()
		a.webNotice = text
		a.mu.Unlock()
		procPostMessageW.Call(uintptr(a.hMain), wmAppWeb, 0, 0)
	}()
}

// onWebNotice shows the result of an asynchronous open on the UI thread.
func (a *App) onWebNotice() {
	a.mu.Lock()
	text := a.webNotice
	a.webNotice = ""
	a.mu.Unlock()
	if text != "" {
		a.setStatus(text)
	}
}
