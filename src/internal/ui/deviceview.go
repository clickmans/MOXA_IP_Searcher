package ui

import (
	"sort"
	"strconv"
	"strings"

	"moxasearch/src/internal/discovery"
)

// This file holds the view model of the device table (v1.9): the sort the user
// picked by clicking a column header and the adapter filter she picked from the
// 网卡筛选 menu.
//
// Everything here is pure: the functions take the full result and return the
// rows to display, so sorting and filtering can be tested without a window and
// the table, the clipboard and the LLDP panel all see the same slice
// (App.devices).

// Column indexes of the device table. The order is the display order.
const (
	columnIndex = iota
	columnModel
	columnIP
	columnMAC
	columnFirmware
	columnName
	columnAdapters
)

// sortField names the column the table is sorted by.
type sortField int

const (
	// sortNone keeps the order the scan produced (numeric IP ascending), which
	// is what the tool showed before v1.9 and therefore the default.
	sortNone sortField = iota
	// sortModel sorts by 产品型号.
	sortModel
	// sortIP sorts by IP 地址.
	sortIP
)

// sortState is one sort: a field and a direction.
type sortState struct {
	field     sortField
	ascending bool
}

// sortIndicator is the arrow appended to the header of the sorted column.
//
// The indicator lives in the column caption instead of in a header sort arrow
// (HDF_SORTUP): this executable carries no comctl32 v6 manifest, and the v5
// header silently draws no arrow at all - the same class of bug as the
// NM_DBLCLK constant. Text is always visible.
func sortIndicator(state sortState) string {
	switch state.field {
	case sortNone:
		return ""
	case sortModel, sortIP:
		if state.ascending {
			return " ▲"
		}
		return " ▼"
	}
	return ""
}

// headerTitles returns the seven column captions with the active sort arrow.
func headerTitles(state sortState) []string {
	titles := make([]string, len(columnTitles))
	copy(titles, columnTitles)
	switch state.field {
	case sortModel:
		titles[columnModel] += sortIndicator(state)
	case sortIP:
		titles[columnIP] += sortIndicator(state)
	}
	return titles
}

// toggleSort applies one header click: the same column flips the direction,
// another column starts ascending (the convention of every file manager).
func toggleSort(current sortState, field sortField) sortState {
	if current.field == field {
		return sortState{field: field, ascending: !current.ascending}
	}
	return sortState{field: field, ascending: true}
}

// compareText orders two strings case insensitively, with the exact byte order
// as the tie breaker so the result is total and stable.
func compareText(left, right string) int {
	lowerLeft, lowerRight := strings.ToLower(left), strings.ToLower(right)
	if result := compareOrdered(lowerLeft, lowerRight); result != 0 {
		return result
	}
	return compareOrdered(left, right)
}

// compareOrdered returns -1 / 0 / 1 for left < right / equal / greater.
func compareOrdered(left, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	}
	return 0
}

// compareIP orders two addresses numerically, not lexicographically:
// 192.168.100.9 must come before 192.168.100.10.
//
// Addresses that are not IPv4 are ordered after the IPv4 ones (they cannot be
// compared numerically with them) and among themselves by text.
func compareIP(left, right string) int {
	leftIP, leftOK := parseIPv4(left)
	rightIP, rightOK := parseIPv4(right)
	switch {
	case leftOK && rightOK:
		for index := 0; index < len(leftIP); index++ {
			if leftIP[index] != rightIP[index] {
				if leftIP[index] < rightIP[index] {
					return -1
				}
				return 1
			}
		}
		return 0
	case leftOK:
		return -1
	case rightOK:
		return 1
	}
	return compareText(strings.TrimSpace(left), strings.TrimSpace(right))
}

// parseIPv4 parses a dotted quad without allocating through net.IP parsing of
// host names; it is the exact form the discovery layer reports.
func parseIPv4(address string) ([4]byte, bool) {
	var out [4]byte
	trimmed := strings.TrimSpace(address)
	parts := strings.Split(trimmed, ".")
	if len(parts) != 4 {
		return out, false
	}
	for index, part := range parts {
		if part == "" || len(part) > 3 {
			return out, false
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 || value > 255 {
			return out, false
		}
		out[index] = byte(value)
	}
	return out, true
}

// compareMAC orders two MAC addresses by their 12 hex digits, so "50-0b-..." and
// "50:0B:..." are the same device. An unknown MAC (empty) is ranked after every
// known one before the sort direction is applied.
func compareMAC(left, right string) int {
	normalizedLeft, normalizedRight := normalizeMAC(left), normalizeMAC(right)
	switch {
	case normalizedLeft == normalizedRight:
		return 0
	case normalizedLeft == "":
		return 1
	case normalizedRight == "":
		return -1
	}
	return compareOrdered(normalizedLeft, normalizedRight)
}

// normalizeMAC strips the separators and upper cases a MAC address.
func normalizeMAC(mac string) string {
	replacer := strings.NewReplacer(":", "", "-", "", ".", "", " ", "")
	return strings.ToUpper(replacer.Replace(strings.TrimSpace(mac)))
}

// compareDevices orders two rows by the active sort, including the tie breakers
// the specification asks for:
//
//	产品型号 → 型号相同按 IP 地址 → 都相同按 MAC 地址
//	IP 地址　 → IP 相同按 产品型号 → 都相同按 MAC 地址
//
// A descending sort reverses the WHOLE chain (all three levels), which is what
// every file manager does and what makes the arrow in the header mean one thing.
// The single exception is a device that did not answer its model: its "-" cell
// stays at the bottom of a model sort in both directions (see unknownModelRank).
func compareDevices(left, right discovery.Device, state sortState) int {
	switch state.field {
	case sortNone:
		return 0
	case sortModel:
		if rank := unknownModelRank(left, right); rank != 0 {
			return rank
		}
		result := compareText(modelCell(left), modelCell(right))
		if result == 0 {
			result = compareIP(left.IP, right.IP)
		}
		if result == 0 {
			result = compareMAC(left.MAC, right.MAC)
		}
		return directed(result, state)
	case sortIP:
		result := compareIP(left.IP, right.IP)
		if result == 0 {
			result = compareText(modelCell(left), modelCell(right))
		}
		if result == 0 {
			result = compareMAC(left.MAC, right.MAC)
		}
		return directed(result, state)
	}
	return 0
}

// directed applies the sort direction to a comparison.
func directed(result int, state sortState) int {
	if state.ascending {
		return result
	}
	return -result
}

// unknownModelRank keeps the rows whose model could not be resolved at the bottom
// of a model sort, in both directions.
//
// The user clicks 产品型号 to group the models she can see; a "-" at the top of
// the table would be the first thing she reads on every ascending sort.
func unknownModelRank(left, right discovery.Device) int {
	leftUnknown := modelCell(left) == "-"
	rightUnknown := modelCell(right) == "-"
	switch {
	case leftUnknown == rightUnknown:
		return 0
	case leftUnknown:
		return 1
	}
	return -1
}

// adapterOptions returns the distinct adapter names of a result, sorted.
//
// The names are exactly the ones the 设备信息来源网卡 column shows, so the filter
// menu can never offer an entry that matches no row.
func adapterOptions(devices []discovery.Device) []string {
	seen := make(map[string]struct{}, 8)
	options := make([]string, 0, 8)
	for index := range devices {
		for _, name := range devices[index].Adapters {
			trimmed := strings.TrimSpace(name)
			if trimmed == "" {
				continue
			}
			if _, ok := seen[trimmed]; ok {
				continue
			}
			seen[trimmed] = struct{}{}
			options = append(options, trimmed)
		}
	}
	sort.Strings(options)
	return options
}

// matchesAdapterFilter reports whether a device was seen by one of the selected
// adapters. An empty set means "every adapter" (the default).
//
// A device whose reply carried no adapter name at all cannot be attributed to
// any interface and is therefore hidden while a filter is active - showing it
// under every selection would be a lie about its source.
func matchesAdapterFilter(device discovery.Device, filter map[string]bool) bool {
	if len(filter) == 0 {
		return true
	}
	for _, name := range device.Adapters {
		if filter[strings.TrimSpace(name)] {
			return true
		}
	}
	return false
}

// visibleDevices applies the filter and the sort to the full result.
//
// The input slice is never modified: it is the scan result, and the JSON output
// and the status line keep describing it.
func visibleDevices(all []discovery.Device, filter map[string]bool, state sortState) []discovery.Device {
	visible := make([]discovery.Device, 0, len(all))
	for index := range all {
		if matchesAdapterFilter(all[index], filter) {
			visible = append(visible, all[index])
		}
	}
	if state.field != sortNone {
		sort.SliceStable(visible, func(i, j int) bool {
			return compareDevices(visible[i], visible[j], state) < 0
		})
	}
	return visible
}

// deviceRowKey identifies one row across a rebuild (sort or filter change).
//
// It is the same identity the discovery layer aggregates on - MAC plus address -
// so a device keeps its row (and its LLDP panel) when only the order changes.
func deviceRowKey(device discovery.Device) string {
	if device.MAC != "" {
		return "mac:" + normalizeMAC(device.MAC) + "|ip:" + strings.TrimSpace(device.IP)
	}
	return "ip:" + strings.TrimSpace(device.IP) + "|" + device.Protocol
}

// filterStatus is the status line suffix while a filter is active.
//
// It is the ONLY place the filter state is reported: v1.9 first had a dedicated
// 网卡筛选 button whose caption repeated the counter, and that button was removed
// again - the column header opens the menu, the status line states the result.
func filterStatus(shownDevices, totalDevices int) string {
	return "已筛选：显示 " + strconv.Itoa(shownDevices) + "/" + strconv.Itoa(totalDevices) + " 台"
}
