package ui

import (
	"fmt"
	"os"
)

// debugf writes diagnostic lines to stderr when MOXA_DEBUG is set.
//
// The GUI build has no console, so this stays silent in normal use and is only
// meant for support sessions started from a shell with stderr redirected:
//
//	set MOXA_DEBUG=1
//	MOXA_IP_Searcher.exe 2> ui.log
func debugf(format string, args ...any) {
	if os.Getenv("MOXA_DEBUG") == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "[ui] "+format+"\n", args...)
}
