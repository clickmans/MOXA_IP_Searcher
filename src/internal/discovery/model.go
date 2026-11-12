// Package discovery implements the MOXA device discovery protocol suite:
// adapter enumeration, per-adapter broadcast send/receive and reply parsing.
//
// The package is pure Go and depends only on the standard library so that the
// resulting binary stays self contained (see REQUIREMENTS.md §3).
package discovery

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Protocol identifiers. The strings are rendered verbatim in the "协议" column
// of the GUI list and in the headless JSON output (REQUIREMENTS.md §6).
const (
	ProtoName4800  = "MOXA/4800"
	ProtoName4000  = "EDS/4000"
	ProtoNameAXOM  = "AXOM/40404"
	ProtoNameWSU   = "WSU/5800"
	ProtoName29168 = "MOXA/29168"
	ProtoName1029  = "NPort/1029"
	ProtoName22222 = "EDS/22222"
)

// protocolRank orders protocols by trustworthiness. When the same device (same
// MAC) is seen by several protocols the lowest rank wins, exactly as required
// by PROTOCOL_SPEC.md §8 (4800 > 4000 > 40404 > 5800 > 其他).
func protocolRank(name string) int {
	switch name {
	case ProtoName4800:
		return 1
	case ProtoName4000:
		return 2
	case ProtoNameAXOM:
		return 3
	case ProtoNameWSU:
		return 4
	case ProtoName29168:
		return 5
	case ProtoName1029:
		return 6
	default:
		return 9
	}
}

// Device is one row of the result table: one IP address of one device.
//
// Row identity is (MAC, IP) - never the IP alone, because several MOXA devices
// may share one IP (REQUIREMENTS.md R4), and never the MAC alone, because one
// device may own several IPs and every address has to be listed.
type Device struct {
	// IP is the dotted-quad device address (never empty for a valid row).
	IP string
	// MAC is the normalized "AA:BB:CC:DD:EE:FF" address; empty when the
	// protocol did not carry one (fallback ports).
	MAC string
	// Model is the marketing model name, e.g. "NP5110A" or "AWK-1131A-US".
	Model string
	// Region is the regional variant carried by the tail of Model, e.g. "UN",
	// "US", "EU", "CN" (v1.3). Empty when the model has no such suffix, e.g.
	// "EDS-405A" or "MGate MB3180". It is derived from the resolved model by
	// RegionFromModel, so JSON, table and clipboard always agree.
	Region string
	// Name is the device host name when the protocol exposes one.
	Name string
	// Protocol is the discovery protocol that produced this row.
	Protocol string
	// Firmware is the firmware version string when the protocol reports one,
	// e.g. "V3.1.10 build 26102915". Empty for products that do not publish it.
	Firmware string
	// FirmwareProvisional marks a Firmware value that was decoded from the
	// encrypted WIFI4 tail of a UDP/5800 reply (see DecodeWSUFirmware) instead
	// of being answered by the device's own version query.
	//
	// It only decides precedence: a provisional value fills the column of a
	// device that has no better source, but it is replaced as soon as the
	// device answers a version itself (4800 0x83 / 0x16, AXOM 0x3x). The other
	// way round the provisional value never overwrites a known one, so the
	// column keeps showing what the device reports in its own protocol - which
	// is also what the reference AWK-1137C row has always shown ("V1.11"
	// rather than the WSU rendering "1.11 Build 25092317").
	FirmwareProvisional bool
	// Adapters lists every local adapter name that saw the device.
	Adapters []string

	// Serial, Description and Location are decoded from the AXOM reply but
	// deliberately not displayed: only the firmware column was requested.
	// They are kept on the struct so that a later version can use them without
	// touching the parser again.
	Serial      string
	Description string
	Location    string

	// ShortSerial is the short serial number carried by the 0x96 version reply
	// of a 4800 device (tail[8:10], little endian; 579 / 5599 on the reference
	// devices). v1.2 only decodes it - the column is not displayed - so that a
	// later version can show it without touching the parser again.
	ShortSerial uint16

	// deviceID is the 12 byte identity of a 4800 reply (payload[8:20]).
	// It is required to build the optional model query (PROTOCOL_SPEC.md §2.3).
	deviceID []byte
	// modelAsked records that a 0x03 model query was already sent.
	modelAsked bool
	// detailAsked records that the v1.2 detail queries (0x03 / 0x10 / 0x16)
	// were already sent for this device identity.
	detailAsked bool
}

// DeviceID returns a copy of the 12 byte 4800 device identity, or nil.
func (d *Device) DeviceID() []byte {
	if len(d.deviceID) != 12 {
		return nil
	}
	out := make([]byte, 12)
	copy(out, d.deviceID)
	return out
}

// merge folds another observation of the same device into d.
func (d *Device) merge(other *Device) {
	if other == nil {
		return
	}
	if protocolRank(other.Protocol) < protocolRank(d.Protocol) {
		d.Protocol = other.Protocol
	}
	if d.IP == "" {
		d.IP = other.IP
	}
	if d.MAC == "" {
		d.MAC = other.MAC
	}
	if d.Model == "" {
		d.Model = other.Model
	}
	if d.Region == "" {
		d.Region = other.Region
	}
	if d.Name == "" {
		d.Name = other.Name
	}
	if d.Firmware == "" {
		d.Firmware = other.Firmware
		d.FirmwareProvisional = other.FirmwareProvisional
	} else if d.FirmwareProvisional && !other.FirmwareProvisional && other.Firmware != "" {
		// A version answered by the device itself beats a decoded one.
		d.Firmware = other.Firmware
		d.FirmwareProvisional = false
	}
	if d.Serial == "" {
		d.Serial = other.Serial
	}
	if d.Description == "" {
		d.Description = other.Description
	}
	if d.Location == "" {
		d.Location = other.Location
	}
	if d.ShortSerial == 0 {
		d.ShortSerial = other.ShortSerial
	}
	if len(d.deviceID) != 12 && len(other.deviceID) == 12 {
		d.deviceID = other.deviceID
	}
	d.Adapters = appendUnique(d.Adapters, other.Adapters...)
}

// ModelFromName derives the marketing model name from a device name (v1.2).
//
// 4800 devices that do not answer the 0x03 model query still publish a name
// through 0x10, and that name is a product code plus a serial suffix:
//
//	NP6450_0001      -> NPort 6450
//	MG-MB3180_0001    -> MGate MB3180
//	NP5110A          -> NPort 5110A
//	EDS-510E_1234    -> EDS-510E      (unknown prefix: returned unchanged)
//
// The mapping table lives here - not in the GUI - so that every consumer (table,
// clipboard, JSON) derives the same string, and so that adding a product family
// means adding one line to this function.
//
// An empty or unusable name yields "", every other input yields a non-empty
// string: an unrecognised code is better than an empty cell.
func ModelFromName(name string) string {
	code := stripDeviceNameSuffix(name)
	// A dangling separator left behind by a truncated name carries no meaning.
	code = strings.TrimRight(code, "_")
	if code == "" {
		return ""
	}
	// NPort serial servers: "NP6450" -> "NPort 6450".
	if strings.HasPrefix(code, "NP") && len(code) > len("NP") {
		return "NPort " + code[len("NP"):]
	}
	// MGate gateways: "MG-MB3180" -> "MGate MB3180".
	if strings.HasPrefix(code, "MG-") && len(code) > len("MG-") {
		return "MGate " + code[len("MG-"):]
	}
	// EDS switches, EOM embedded switches, IA industrial APs, AWK wireless, ...
	// are already the marketing name, so the code is returned unchanged.
	return code
}

// stripDeviceNameSuffix removes the trailing "_<digits>" serial suffix of a
// device name, e.g. "NP6450_0001" -> "NP6450".
//
// Only a purely numeric suffix is removed, so a name such as "MG-MB3180" or
// "switch_A" keeps its underscore.
func stripDeviceNameSuffix(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	underscore := strings.LastIndex(trimmed, "_")
	if underscore <= 0 || underscore == len(trimmed)-1 {
		return trimmed
	}
	suffix := trimmed[underscore+1:]
	for i := 0; i < len(suffix); i++ {
		if suffix[i] < '0' || suffix[i] > '9' {
			return trimmed
		}
	}
	return strings.TrimSpace(trimmed[:underscore])
}

// ResolveModel returns the model name to report for one device (v1.2):
// the value answered by the device, else the value derived from its name, else
// an empty string.
//
// The fallback chain is applied here instead of in the GUI so that the JSON
// output, the table and the clipboard always agree.
func ResolveModel(model, name string) string {
	if trimmed := strings.TrimSpace(model); trimmed != "" {
		return trimmed
	}
	return ModelFromName(name)
}

// DisplayModel returns the model to show in the 产品型号 column: the resolved
// model, else "-" (the placeholder every empty cell uses).
func DisplayModel(model, name string) string {
	if resolved := ResolveModel(model, name); resolved != "" {
		return resolved
	}
	return "-"
}

// RegionFromModel extracts the regional variant from the tail of a model name
// (v1.3).
//
// MOXA appends the region to the marketing name with a dash:
//
//	AWK-1161C-UN -> "UN"
//	AWK-1132C-US -> "US"
//	EDS-405A     -> ""   (last segment "405A" is not 2-3 letters)
//	MGate MB3180 -> ""   (no dash at all)
//
// Only the LAST dash separated segment counts, it has to consist of 2 or 3
// ASCII letters and it is returned in upper case. Everything else yields "" -
// the region column is empty rather than wrong.
func RegionFromModel(model string) string {
	trimmed := strings.TrimSpace(model)
	dash := strings.LastIndex(trimmed, "-")
	if dash < 0 || dash >= len(trimmed)-1 {
		return ""
	}
	suffix := trimmed[dash+1:]
	if len(suffix) < 2 || len(suffix) > 3 {
		return ""
	}
	for i := 0; i < len(suffix); i++ {
		c := suffix[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
			continue
		}
		return ""
	}
	return strings.ToUpper(suffix)
}

// dedupKey returns the aggregation key for an observation.
//
// The identity of a result row is (MAC, IPv4): one physical device may own
// several IP addresses (dual IP hosts are common on MOXA gear, see
// PROTOCOL_SPEC.md §2.2) and the tool exists to list every address, so two IPs
// of the same MAC must stay two rows. Observations of the same (MAC, IP) coming
// from several protocols or adapters are merged into one row.
//
// Without a MAC the key degrades to (IP, protocol) so that unrelated devices
// are never merged by accident (PROTOCOL_SPEC.md §8).
func dedupKey(d *Device) string {
	if d.MAC != "" {
		return "mac:" + d.MAC + "|ip:" + d.IP
	}
	return "ip:" + d.IP + "|" + d.Protocol
}

// appendUnique appends the values that are not yet present.
func appendUnique(dst []string, values ...string) []string {
	for _, v := range values {
		if v == "" {
			continue
		}
		found := false
		for _, existing := range dst {
			if existing == v {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, v)
		}
	}
	return dst
}

// aggregator collects observations coming from many sockets/goroutines.
type aggregator struct {
	mu    sync.Mutex
	rows  []*Device
	byKey map[string]*Device
	// byID maps a 12 byte 4800 device identity to EVERY row of that device.
	// A dual IP host produces one row per address but only one identity, so the
	// model answer has to be applied to all of them.
	byID map[string][]*Device
	// askedIDs remembers which device identities were already asked for their
	// model, so a dual IP device is queried once instead of once per row.
	askedIDs map[string]bool
	// askedDetailIDs does the same for the v1.2 detail queries (0x03/0x10/0x16).
	askedDetailIDs map[string]bool
}

func newAggregator() *aggregator {
	return &aggregator{
		byKey:          make(map[string]*Device, 16),
		byID:           make(map[string][]*Device, 16),
		askedIDs:       make(map[string]bool, 16),
		askedDetailIDs: make(map[string]bool, 16),
	}
}

// add stores an observation and returns the row it was merged into.
func (a *aggregator) add(in *Device) *Device {
	if in == nil || in.IP == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	key := dedupKey(in)
	if existing, ok := a.byKey[key]; ok {
		hadID := len(existing.deviceID) == 12
		existing.merge(in)
		// The observation being merged may be the one that carries the 12 byte
		// 4800 identity: the WSU reply of a device usually arrives before its
		// 4800 answer, so the row is created without an identity and only this
		// merge completes it. The identity index has to learn about that,
		// otherwise every later detail answer of the device can only be matched
		// by IP and would also be written to the other devices that share the
		// address (measured: the AWK-1131A row came back with the firmware of
		// the AWK-1137C in one of three runs).
		if !hadID && len(existing.deviceID) == 12 {
			identity := string(existing.deviceID)
			a.byID[identity] = append(a.byID[identity], existing)
		}
		return existing
	}
	row := &Device{
		IP:                  in.IP,
		MAC:                 in.MAC,
		Model:               in.Model,
		Region:              in.Region,
		Name:                in.Name,
		Protocol:            in.Protocol,
		Firmware:            in.Firmware,
		FirmwareProvisional: in.FirmwareProvisional,
		Serial:              in.Serial,
		Description:         in.Description,
		Location:            in.Location,
		ShortSerial:         in.ShortSerial,
	}
	row.Adapters = appendUnique(nil, in.Adapters...)
	if len(in.deviceID) == 12 {
		row.deviceID = in.deviceID
	}
	a.byKey[key] = row
	a.rows = append(a.rows, row)
	if len(row.deviceID) == 12 {
		a.byID[string(row.deviceID)] = append(a.byID[string(row.deviceID)], row)
	}
	return row
}

// applyAnswered applies one answered property to every row of one device.
//
// Matching is done on the 12 byte device identity first, then on the source IP
// as a defensive fallback (some firmware echoes a slightly different id - and
// the broadcast form of a query may be answered by an address we did not ask).
// update reports whether it changed the row; the return value reports whether
// the answer reached at least one row.
func (a *aggregator) applyAnswered(deviceID []byte, ip string, update func(row *Device) bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(deviceID) == 12 {
		if rows, ok := a.byID[string(deviceID)]; ok && len(rows) > 0 {
			applied := false
			for _, row := range rows {
				if update(row) {
					applied = true
				}
			}
			return applied
		}
	}
	if ip != "" {
		applied := false
		for _, row := range a.rows {
			if row.IP == ip && update(row) {
				applied = true
			}
		}
		return applied
	}
	return false
}

// setModel records the model name answered by a 0x83 reply.
func (a *aggregator) setModel(deviceID []byte, ip, model string) bool {
	if model == "" {
		return false
	}
	return a.applyAnswered(deviceID, ip, func(row *Device) bool {
		row.Model = model
		return true
	})
}

// setFirmware records the firmware version answered by a 0x83 reply (U7).
//
// It mirrors setModel: the 12 byte device identity wins, the source IP is only
// a defensive fallback. A firmware string is never overwritten by an empty one.
// A value decoded from the encrypted WIFI4 tail of a UDP/5800 reply counts as
// provisional and is replaced here: the answer of the device itself is the one
// the user asked for.
func (a *aggregator) setFirmware(deviceID []byte, ip, firmware string) bool {
	if firmware == "" {
		return false
	}
	return a.applyAnswered(deviceID, ip, func(row *Device) bool {
		row.Firmware = firmware
		row.FirmwareProvisional = false
		return true
	})
}

// setName records the device name answered by a 0x90 reply (v1.2).
//
// An already known name (e.g. the AXOM host name of the same device) is kept:
// the discovery answer that arrived first is the one the user saw, and silently
// renaming a row while the scan runs would be confusing.
func (a *aggregator) setName(deviceID []byte, ip, name string) bool {
	if name == "" {
		return false
	}
	return a.applyAnswered(deviceID, ip, func(row *Device) bool {
		if row.Name != "" {
			return false
		}
		row.Name = name
		return true
	})
}

// setVersion records the firmware version answered by a 0x96 reply (v1.2).
//
// The short serial number of the same answer is stored on the row as well; it
// is not displayed, only kept for later versions.
//
// A version that was already answered - by the 0x83 property list of the same
// device, which carries the build suffix - is kept. The one exception is a
// provisional value decoded from the encrypted tail of a UDP/5800 reply: that
// one is replaced, because the 0x96 answer is the device speaking for itself.
func (a *aggregator) setVersion(deviceID []byte, ip, version string, shortSerial uint16) bool {
	if version == "" && shortSerial == 0 {
		return false
	}
	return a.applyAnswered(deviceID, ip, func(row *Device) bool {
		changed := false
		if version != "" && (row.Firmware == "" || row.FirmwareProvisional) {
			row.Firmware = version
			row.FirmwareProvisional = false
			changed = true
		}
		if shortSerial != 0 && row.ShortSerial == 0 {
			row.ShortSerial = shortSerial
			changed = true
		}
		return changed
	})
}

// pendingModelQueries returns copies of the rows that still need a model query,
// at most one per device identity.
func (a *aggregator) pendingModelQueries() []Device {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]Device, 0, len(a.rows))
	for _, row := range a.rows {
		if row.Model != "" || len(row.deviceID) != 12 {
			continue
		}
		identity := string(row.deviceID)
		if a.askedIDs[identity] {
			continue
		}
		a.askedIDs[identity] = true
		row.modelAsked = true
		snapshot := *row
		snapshot.Adapters = append([]string(nil), row.Adapters...)
		out = append(out, snapshot)
	}
	return out
}

// pendingDetailQueries returns copies of the rows that still need at least one
// of the v1.2 detail answers (model / name / firmware), at most one per device
// identity so that a dual IP host is queried once.
//
// Rows without a 12 byte identity cannot be queried at all (the AXOM and EDS
// protocols have no such identity) and are skipped.
func (a *aggregator) pendingDetailQueries() []Device {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]Device, 0, len(a.rows))
	for _, row := range a.rows {
		if len(row.deviceID) != 12 {
			continue
		}
		if row.Model != "" && row.Name != "" && row.Firmware != "" && !row.FirmwareProvisional {
			continue
		}
		identity := string(row.deviceID)
		if a.askedDetailIDs[identity] {
			continue
		}
		a.askedDetailIDs[identity] = true
		row.detailAsked = true
		snapshot := *row
		snapshot.Adapters = append([]string(nil), row.Adapters...)
		out = append(out, snapshot)
	}
	return out
}

// pendingAXOMRows returns copies of the AXOM rows that still need their real
// model (v1.3).
//
// A row qualifies when it was reported by the UDP/40404 protocol, has an address
// and a MAC (both are needed to prove the ownership of that address), and does
// not carry a real model yet. A row whose model was already answered by the
// 4800 property list - "Model\t<value>" - is therefore never a candidate.
func (a *aggregator) pendingAXOMRows() []Device {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]Device, 0, len(a.rows))
	for _, row := range a.rows {
		if row.Protocol != ProtoNameAXOM || row.IP == "" || row.MAC == "" {
			continue
		}
		if row.Model != "" {
			continue
		}
		snapshot := *row
		snapshot.Adapters = append([]string(nil), row.Adapters...)
		out = append(out, snapshot)
	}
	return out
}

// setAXOMModel stores the model answered by the ubus interface of one device
// (v1.3).
//
// The row is identified by (IP, MAC) - the device identity of the ARP check -
// and an existing model is never replaced: a real model that arrived over the
// 4800 protocol wins over the enhanced one, and re-running the enhancement
// cannot churn the table.
func (a *aggregator) setAXOMModel(ip, mac, model string) bool {
	model = sanitizeModel(model)
	if ip == "" || mac == "" || model == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	changed := false
	for _, row := range a.rows {
		if row.IP != ip || !strings.EqualFold(row.MAC, mac) {
			continue
		}
		if row.Model != "" {
			continue
		}
		row.Model = model
		row.Region = RegionFromModel(model)
		changed = true
	}
	return changed
}

// count returns the number of distinct rows collected so far.
func (a *aggregator) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.rows)
}

// snapshot returns a sorted, detached copy of the collected rows.
//
// The 产品型号 column uses the v1.2 fallback chain (Model, else the model
// derived from the device name): resolving it here - in the discovery layer -
// keeps the table, the clipboard and the JSON output identical, and keeps the
// mapping table out of the GUI. An empty result stays empty so the GUI can show
// its "-" placeholder and the JSON its "" value.
func (a *aggregator) snapshot() []Device {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]Device, 0, len(a.rows))
	for _, row := range a.rows {
		copied := *row
		copied.Adapters = append([]string(nil), row.Adapters...)
		if len(row.deviceID) == 12 {
			copied.deviceID = append([]byte(nil), row.deviceID...)
		}
		copied.Model = ResolveModel(row.Model, row.Name)
		// The region follows the model the DEVICE answered - the 4800 property
		// list or the ubus query - and never a model derived from the host name:
		// "EDS-408A-SS-SC" ends in "SC", but that is the fibre connector of a
		// switch, not a regional suffix, and the host name is not a model at all.
		if copied.Region == "" && row.Model != "" {
			copied.Region = RegionFromModel(copied.Model)
		}
		out = append(out, copied)
	}
	SortDevices(out)
	return out
}

// SortDevices orders devices by numeric IP, then by MAC, then by protocol.
func SortDevices(devices []Device) {
	sort.SliceStable(devices, func(i, j int) bool {
		ai := net.ParseIP(devices[i].IP).To4()
		aj := net.ParseIP(devices[j].IP).To4()
		if ai != nil && aj != nil {
			for k := 0; k < 4; k++ {
				if ai[k] != aj[k] {
					return ai[k] < aj[k]
				}
			}
		} else if devices[i].IP != devices[j].IP {
			return devices[i].IP < devices[j].IP
		}
		if devices[i].MAC != devices[j].MAC {
			return devices[i].MAC < devices[j].MAC
		}
		return devices[i].Protocol < devices[j].Protocol
	})
}

// DuplicateIPCount returns how many result rows share their IP address with an
// earlier row. It feeds the status text, e.g. "找到 4 条记录（其中 1 条 IP 重复）".
func DuplicateIPCount(devices []Device) int {
	seen := make(map[string]int, len(devices))
	dup := 0
	for i := range devices {
		n := seen[devices[i].IP]
		if n > 0 {
			dup++
		}
		seen[devices[i].IP] = n + 1
	}
	return dup
}

// deviceKey is the identity of one physical device inside the result table.
//
// A row without a MAC cannot be tied to any other row, so it counts as its own
// device (the fallback ports only report a source IP).
func deviceKey(d Device) string {
	if d.MAC != "" {
		return "mac:" + d.MAC
	}
	return "row:" + d.IP + "|" + d.Protocol
}

// DeviceCount returns the number of distinct physical devices behind the rows.
//
// The status bar reports devices (台), not rows: one device may own several IP
// addresses and therefore several rows (U6). A row without a MAC counts as one
// device of its own.
func DeviceCount(devices []Device) int {
	seen := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		seen[deviceKey(device)] = struct{}{}
	}
	return len(seen)
}

// DuplicateIPDeviceCount returns how many devices share their IP address with
// at least one other device, i.e. the M of "（M 台设备 IP 重复）".
//
// Distinct addresses are visited in first-seen order so that the number is
// deterministic for tests and for the status bar.
func DuplicateIPDeviceCount(devices []Device) int {
	byIP := make(map[string]map[string]struct{}, len(devices))
	order := make([]string, 0, len(devices))
	for _, device := range devices {
		if device.IP == "" {
			continue
		}
		set, ok := byIP[device.IP]
		if !ok {
			set = make(map[string]struct{}, 2)
			byIP[device.IP] = set
			order = append(order, device.IP)
		}
		set[deviceKey(device)] = struct{}{}
	}
	total := 0
	for _, ip := range order {
		if count := len(byIP[ip]); count > 1 {
			total += count
		}
	}
	return total
}

// ValidDeviceIP reports whether ip is usable as a discovered device address.
func ValidDeviceIP(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4.Equal(net.IPv4zero) || v4.Equal(net.IPv4bcast) {
		return false
	}
	if v4.IsUnspecified() || v4.IsMulticast() {
		return false
	}
	return true
}

// NormalizeMAC renders 6 raw bytes as "AA:BB:CC:DD:EE:FF".
// All-zero and broadcast values are reported as "" (unknown).
func NormalizeMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	parts := make([]string, 6)
	nonZero := false
	for i := 0; i < 6; i++ {
		parts[i] = fmt.Sprintf("%02X", b[i])
		if b[i] != 0 {
			nonZero = true
		}
	}
	if !nonZero {
		return ""
	}
	mac := strings.Join(parts, ":")
	if mac == "FF:FF:FF:FF:FF:FF" {
		return ""
	}
	return mac
}

// ParseMACString normalizes a textual MAC address ("50:0B:88:00:00:53",
// "50-0b-88-00-00-53", ...). It returns "" when the input is not a MAC.
func ParseMACString(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	replacer := strings.NewReplacer(":", "", "-", "", ".", "", " ", "", "\x00", "")
	hex := replacer.Replace(s)
	if len(hex) != 12 {
		return ""
	}
	raw := make([]byte, 6)
	for i := 0; i < 6; i++ {
		v, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
		if err != nil {
			return ""
		}
		raw[i] = byte(v)
	}
	return NormalizeMAC(raw)
}

// cleanText strips NUL padding and control characters, then trims spaces.
// Used for every fixed-width ASCII field decoded from a reply.
func cleanText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			continue
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

// fixedString extracts a NUL terminated string from a fixed width field.
func fixedString(field []byte) string {
	if idx := indexByte(field, 0); idx >= 0 {
		field = field[:idx]
	}
	return cleanText(string(field))
}

// copyFixedString writes s into dst, left aligned and NUL padded.
func copyFixedString(dst []byte, s string) {
	for i := range dst {
		dst[i] = 0
	}
	if len(s) > len(dst) {
		s = s[:len(dst)]
	}
	copy(dst, s)
}

// indexByte returns the first occurrence of c in b, or -1.
func indexByte(b []byte, c byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}
