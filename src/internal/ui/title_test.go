package ui

import (
	"strings"
	"testing"
)

// TestMainWindowTitle pins the caption of the main window.
//
// The title carries the channel partner slogan, so it must not drift; it also
// has to keep the product name first because that is what the taskbar shows
// when the button is too narrow for the whole string.
func TestMainWindowTitle(t *testing.T) {
	const want = "MOXA 设备 IP 搜索工具——买MOXA，找明高——www.mingit.com"
	if mainWindowTitle != want {
		t.Fatalf("mainWindowTitle = %q, want %q", mainWindowTitle, want)
	}
	if !strings.HasPrefix(mainWindowTitle, "MOXA 设备 IP 搜索工具") {
		t.Fatalf("title must start with the product name: %q", mainWindowTitle)
	}
	if !strings.Contains(mainWindowTitle, "www.mingit.com") {
		t.Fatalf("title is missing the site: %q", mainWindowTitle)
	}
}
