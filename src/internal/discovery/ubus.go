package discovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// AXOM model enhancement (v1.3).
//
// The AXOM discovery frame (UDP/40404) carries the host name, the firmware and
// the serial number of a device - but NOT its marketing model. Until v1.2 the
// 产品型号 column therefore fell back to the host name, which for an AWK-1161C
// read "awk-1161c": a host name, not a model.
//
// The very same device serves a read-only ubus object behind its login page
// that answers the complete model including the regional suffix:
//
//	POST https://<ip>/ubus
//	{"jsonrpc":"2.0","id":1,"method":"call",
//	 "params":["00000000000000000000000000000000","moxa.web.ui",
//	           "contents_for_login",{}]}
//	-> {"jsonrpc":"2.0","id":1,"result":[0,{"model":"AWK-1161C-UN", ...}]}
//
// The 32 zero characters are an anonymous session id: no login, no password,
// and nothing is written to the device. The certificate is self signed, so the
// request has to skip verification - it only ever leaves the local network and
// carries no credentials.
const (
	// ubusAnonymousSession is the anonymous ubus session id: 32 zero digits.
	ubusAnonymousSession = "00000000000000000000000000000000"
	// ubusObjectWebUI is the web UI object that exposes the model.
	ubusObjectWebUI = "moxa.web.ui"
	// ubusMethodContentsForLogin is the read-only method that returns the model.
	ubusMethodContentsForLogin = "contents_for_login"

	// ubusPort is the HTTPS port of the ubus endpoint.
	ubusPort = "443"

	// ubusMaxBodyBytes caps the answer we are willing to read.
	ubusMaxBodyBytes = 8 << 10
	// maxModelLen guards the 产品型号 column against a corrupted answer.
	maxModelLen = 64
	// axomModelTimeout bounds ONE model query including the TLS handshake.
	// Measured: the reference AWK-1161C answers in ~42 ms, so 800 ms leaves
	// room for a slow bridge while still bounding the extra scan time.
	axomModelTimeout = 800 * time.Millisecond
	// axomLinkLocalConnect bounds only the TCP connect of the IPv6 link-local
	// attempt. A link-local address nobody owns makes Windows retransmit
	// neighbour solicitations for seconds, so the connect gets a shorter budget
	// than the whole request; the AWK-1161C accepts in ~15 ms.
	axomLinkLocalConnect = 400 * time.Millisecond
	// axomModelConcurrency bounds the number of simultaneous model queries.
	axomModelConcurrency = 8
)

// Network seams (v1.3.1).
//
// The unit tests replace them with stubs so that the priority between the two
// channels (IPv6 link-local first, IPv4 + ARP as fallback) can be verified
// without a device and without touching the ARP table of the build machine.
// Production always uses the real implementations.
var (
	ubusLinkLocalQuery = fetchUBUSModelLinkLocal
	ubusAddressQuery   = fetchUBUSModel
	readARPTable       = ReadARPTable
)

// noRedirect makes the client report a 3xx answer as it is.
//
// The IPv6 channel needs this: an EDS that has no ubus object answers /ubus
// with a redirect to its own login page (or with a plain HTML page), and
// following that redirect would download a login form for nothing.
func noRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// newUBUSTransport builds the transport of a ubus query.
//
// dial is only set by the IPv6 channel, which has to dial an address that
// carries a zone (scope id) and therefore cannot be expressed as the URL host.
func newUBUSTransport(dial func(ctx context.Context, network, address string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   false,
		DisableCompression:  true,
		DialContext:         dial,
		TLSHandshakeTimeout: axomModelTimeout,
		TLSClientConfig: &tls.Config{
			// Self-signed per device certificate; the request carries no
			// credentials and never leaves the local network.
			InsecureSkipVerify: true, //nolint:gosec // see comment above
			// Older AWK firmware still negotiates TLS 1.0/1.1.
			MinVersion: tls.VersionTLS10,
		},
	}
}

// ubusHTTPClient is the shared client of the IPv4 model queries.
//
// Proxy is explicitly nil: Go would otherwise honour HTTPS_PROXY from the
// environment and send a request for a 192.168.x.x device to a corporate proxy,
// which can only fail. InsecureSkipVerify is required by the self-signed
// device certificate, ForceAttemptHTTP2 is off because the ubus daemon of the
// older firmware only speaks HTTP/1.1.
var ubusHTTPClient = &http.Client{
	Timeout:   axomModelTimeout,
	Transport: newUBUSTransport(nil),
}

// ubusCallRequest is the JSON-RPC envelope sent to /ubus.
type ubusCallRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

// ubusCallResponse is the JSON-RPC envelope answered by /ubus.
//
// Result is kept raw because its second element is an object for a success and
// a string for an error, and only a success carries a model.
type ubusCallResponse struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      int               `json:"id"`
	Result  []json.RawMessage `json:"result"`
	Error   *ubusErrorObject  `json:"error"`
}

// ubusErrorObject is the JSON-RPC error member of a rejected call.
type ubusErrorObject struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ubusModelPayload is the interesting part of a successful ubus answer.
type ubusModelPayload struct {
	Model string `json:"model"`
}

// newUBUSModelRequest renders the model query for one device.
func newUBUSModelRequest() []byte {
	// A marshal of fixed standard-library types cannot fail; the fallback keeps
	// the function total instead of panicking inside a scan.
	encoded, err := json.Marshal(ubusCallRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "call",
		Params: []any{
			ubusAnonymousSession,
			ubusObjectWebUI,
			ubusMethodContentsForLogin,
			map[string]any{},
		},
	})
	if err != nil {
		return nil
	}
	return encoded
}

// parseUBUSModel extracts the model from a ubus answer.
//
// Everything that is not a clean success is reported as "" - a malformed body,
// a JSON-RPC error object, a non zero ubus status, a short result array, a
// non-object payload or an empty model. The caller keeps the fallback value in
// that case, so an unparsable answer must never produce a half string.
func parseUBUSModel(body []byte) string {
	if len(bytes.TrimSpace(body)) == 0 {
		return ""
	}
	var response ubusCallResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return ""
	}
	if response.Error != nil {
		return ""
	}
	if len(response.Result) < 2 {
		return ""
	}
	var status int
	if err := json.Unmarshal(response.Result[0], &status); err != nil || status != 0 {
		return ""
	}
	var payload ubusModelPayload
	if err := json.Unmarshal(response.Result[1], &payload); err != nil {
		return ""
	}
	return sanitizeModel(payload.Model)
}

// sanitizeModel turns a raw model string into a value fit for the table:
// NUL padding and surrounding blanks are removed, only printable ASCII is
// accepted and the length is bounded. Anything else yields "" so that the
// caller keeps its fallback value.
func sanitizeModel(raw string) string {
	var builder strings.Builder
	builder.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		// NUL is the padding of a fixed width field: drop it, do not fail.
		if raw[i] == 0x00 {
			continue
		}
		builder.WriteByte(raw[i])
	}
	model := strings.TrimSpace(builder.String())
	if model == "" || len(model) > maxModelLen {
		return ""
	}
	for i := 0; i < len(model); i++ {
		if c := model[i]; c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return model
}

// ubusURL builds the endpoint address of one device.
//
// The address is used verbatim: a device is addressed by IP, never by name, so
// no DNS lookup can leak the query or fail the scan.
func ubusURL(ip string) string {
	return "https://" + net.JoinHostPort(ip, ubusPort) + "/ubus"
}

// eui64LinkLocal derives the IPv6 link-local address of a MAC (RFC 4291,
// EUI-64) - the address every IPv6 node forms for itself, one to one with its
// hardware address.
//
//	50:0B:88:00:00:1A -> fe80::520b:88ff:fe00:1a
//	00:90:E8:00:00:D7 -> fe80::290:e8ff:fe00:d7
//
// The first byte gets the U/L bit flipped (^ 0x02) and ff:fe is inserted in the
// middle. Because the mapping is bijective, a device can be reached by identity
// instead of by address - which is what makes the query immune to several
// devices sharing one IPv4 address.
//
// All-zero, broadcast and multicast MACs yield "": their derived address would
// be an arbitrary guess rather than the device's own.
func eui64LinkLocal(mac net.HardwareAddr) string {
	if len(mac) != 6 {
		return ""
	}
	zero := true
	for _, b := range mac {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero || mac[0]&0x01 != 0 { // unset or group (multicast/broadcast) bit
		return ""
	}
	address := make(net.IP, net.IPv6len)
	address[0], address[1] = 0xfe, 0x80
	address[8] = mac[0] ^ 0x02
	address[9], address[10] = mac[1], mac[2]
	address[11], address[12] = 0xff, 0xfe
	address[13], address[14], address[15] = mac[3], mac[4], mac[5]
	return address.String()
}

// ubusLinkLocalTarget renders the dial target of a link-local query:
// "[fe80::1%21]:443" for interface index 21, "[fe80::1]:443" when the zone is
// unknown.
//
// The zone (scope id) is mandatory for a link-local destination - the same
// fe80::/64 address exists on every interface, so without it the stack cannot
// know which link to use.
func ubusLinkLocalTarget(linkLocal string, zone int) string {
	host := linkLocal
	if zone > 0 {
		host = linkLocal + "%" + strconv.Itoa(zone)
	}
	return net.JoinHostPort(host, ubusPort)
}

// ubusLinkLocalURL renders "https://[fe80::1]:443/ubus" - deliberately WITHOUT
// the zone: the zone belongs to the dial target (ubusLinkLocalTarget), and a
// percent encoded scope inside a URL is easy to get wrong.
func ubusLinkLocalURL(linkLocal string) string {
	return "https://" + net.JoinHostPort(linkLocal, ubusPort) + "/ubus"
}

// adapterIndexFor returns the interface index of the first adapter that saw the
// device, or 0 when none of the names is known any more.
func adapterIndexFor(adapters []Adapter, names []string) int {
	for _, name := range names {
		for _, adapter := range adapters {
			if adapter.Name == name && adapter.Index > 0 {
				return adapter.Index
			}
		}
	}
	return 0
}

// fetchUBUSModel asks one device for the model behind its login page.
//
// It performs exactly ONE HTTPS request per device, bounded by timeout. Every
// failure (connection refused, TLS error, timeout, malformed JSON) is returned
// as an error so that the caller can log it in debug mode and keep the
// fallback value; nothing here is ever reported to the user.
func fetchUBUSModel(ctx context.Context, ip string, timeout time.Duration) (string, error) {
	if ip == "" {
		return "", errors.New("设备 IP 为空")
	}
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("设备 IP 无效: %q", ip)
	}
	return ubusPost(ctx, ubusHTTPClient, ubusURL(ip), timeout)
}

// fetchUBUSModelLinkLocal asks ONE device over the IPv6 link-local address
// derived from its MAC (v1.3.1).
//
// This is the precise channel: the destination identifies the device itself, so
// the answer needs no ownership proof. zone is the interface index of the
// adapter that saw the device - without it a link-local destination is not
// reachable at all.
//
// The request body, the TLS handling and the answer parsing are identical to the
// IPv4 channel; only how the peer is addressed differs.
func fetchUBUSModelLinkLocal(ctx context.Context, linkLocal string, zone int,
	timeout time.Duration) (string, error) {

	if linkLocal == "" {
		return "", errors.New("链路本地地址为空")
	}
	if zone <= 0 {
		return "", errors.New("接口索引未知，无法访问链路本地地址")
	}
	target := ubusLinkLocalTarget(linkLocal, zone)
	transport := newUBUSTransport(func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: axomLinkLocalConnect}
		return dialer.DialContext(ctx, "tcp6", target)
	})
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: noRedirect,
	}
	return ubusPost(ctx, client, ubusLinkLocalURL(linkLocal), timeout)
}

// ubusModelCall performs the ubus request against an explicit URL with the
// shared IPv4 client.
//
// Split from fetchUBUSModel so that the unit tests can drive it against a local
// TLS test server instead of a real device.
func ubusModelCall(ctx context.Context, url string, timeout time.Duration) (string, error) {
	return ubusPost(ctx, ubusHTTPClient, url, timeout)
}

// ubusPost performs one ubus JSON-RPC call and returns the parsed model.
func ubusPost(ctx context.Context, client *http.Client, url string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = axomModelTimeout
	}
	request := newUBUSModelRequest()
	if request == nil {
		return "", errors.New("构造 ubus 请求失败")
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpRequest, err := http.NewRequestWithContext(requestCtx, http.MethodPost, url,
		bytes.NewReader(request))
	if err != nil {
		return "", err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")

	response, err := client.Do(httpRequest)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, ubusMaxBodyBytes))
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ubus 返回 HTTP %d", response.StatusCode)
	}
	return parseUBUSModel(body), nil
}

// Windows ARP table access (iphlpapi!GetIpNetTable).
//
// The table is read for ONE reason: the model answer is only trustworthy for
// the device that actually owns the IP address. Several MOXA devices may share
// one IP (the reference network has an AWK-1161C, an AWK-1132C and an EDS-405A
// on 192.168.100.253), and HTTPS resolves the address through ARP, so the
// answer always belongs to the device ARP knows - not necessarily to the row we
// asked for. Comparing the row MAC with the ARP MAC is the ownership proof.
const (
	// arpTypeOther and arpTypeInvalid are never trusted.
	arpTypeOther   = 1
	arpTypeInvalid = 2
	// arpTypeDynamic is a learned entry, arpTypeStatic a configured one.
	arpTypeDynamic = 3
	arpTypeStatic  = 4

	// mibIPNetRowSize is sizeof(MIB_IPNETROW): 5 x 4 bytes rounded to the
	// 8 byte physical address field, i.e. index(4) + len(4) + addr(8) +
	// ip(4) + type(4).
	mibIPNetRowSize = 24

	// errorInsufficientBuffer is ERROR_INSUFFICIENT_BUFFER (122), the answer of
	// the size probe. errorNoData is ERROR_NO_DATA (232), an empty table.
	errorInsufficientBuffer = syscall.Errno(122)
	errorNoData             = syscall.Errno(232)

	// arpTableProbeAttempts bounds the re-read of a table that grew between the
	// probe and the real call.
	arpTableProbeAttempts = 3
)

// procGetIpNetTable is iphlpapi!GetIpNetTable.
//
//	DWORD GetIpNetTable(PMIB_IPNETTABLE pIpNetTable, PULONG pdwSize, BOOL bOrder)
//
// The standard library has no wrapper for it and the project must stay free of
// third party packages, so the documented C ABI is declared here.
var procGetIpNetTable = syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetIpNetTable")

// mibIPNetRow mirrors the Win32 MIB_IPNETROW structure (24 bytes).
//
// The field order follows the documented layout in iptypes.h / ipmib.h
// (dwIndex, dwPhysAddrLen, bPhysAddr, dwAddr, dwType). It is verified at
// runtime by TestReadARPTable against the entries `arp -a` prints: a wrong order
// yields a garbage MAC and no ARP lookup ever matches.
type mibIPNetRow struct {
	// Index is dwIndex, the interface index the entry belongs to.
	Index uint32
	// PhysAddrLen is dwPhysAddrLen, the used length of PhysAddr (6 for
	// Ethernet, 0 for an incomplete entry).
	PhysAddrLen uint32
	// PhysAddr is bPhysAddr, MAXLEN_PHYSADDR (8) bytes of hardware address.
	PhysAddr [8]byte
	// Addr is dwAddr, the IPv4 address in network byte order.
	Addr uint32
	// Type is dwType: 1 other, 2 invalid, 3 dynamic, 4 static.
	Type uint32
}

// arpRow is one complete neighbour cache entry: the interface it was learned on
// and the hardware address behind the IPv4 address.
type arpRow struct {
	// Index is the interface index the entry belongs to (dwIndex).
	Index uint32
	// IP is the dotted-quad address.
	IP string
	// MAC is the normalized "AA:BB:CC:DD:EE:FF" address.
	MAC string
}

// ReadARPTable returns the local IPv4 ARP table as IP -> "AA:BB:CC:DD:EE:FF".
//
// Only complete Ethernet entries (PhysAddrLen 6) of type dynamic or static are
// kept: an "invalid" entry is a neighbour that is being resolved right now and
// carries no MAC, and a non-Ethernet entry cannot be compared with a device MAC.
//
// One address may be cached on SEVERAL interfaces at once - the reference
// network has 192.168.100.253 on the Ethernet and on the WLAN interface, with a
// different device behind each - so the entry of the interface that actually
// routes to the address wins (see selectARPTable). That is the device an HTTPS
// connection would reach, which is precisely the ownership we have to prove.
func ReadARPTable() (map[string]string, error) {
	rows, err := readARPRows()
	if err != nil {
		return map[string]string{}, err
	}
	// A failed adapter enumeration only costs the disambiguation: the table then
	// keeps the last entry per address instead of the routed one.
	adapters, adapterErr := EnumerateAdapters()
	if adapterErr != nil {
		debugf("枚举网卡失败，ARP 归属改用最后一条记录: %v", adapterErr)
		adapters = nil
	}
	return selectARPTable(rows, adapters), nil
}

// readARPRows reads and decodes the neighbour cache of this machine.
func readARPRows() ([]arpRow, error) {
	if err := procGetIpNetTable.Find(); err != nil {
		return nil, fmt.Errorf("iphlpapi!GetIpNetTable 不可用: %w", err)
	}

	// Probe: a NULL table with size 0 answers ERROR_INSUFFICIENT_BUFFER and
	// stores the required buffer size.
	var size uint32
	code, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if syscall.Errno(code) == errorNoData {
		return nil, nil
	}
	if syscall.Errno(code) != errorInsufficientBuffer {
		return nil, fmt.Errorf("GetIpNetTable 探测失败: %w", syscall.Errno(code))
	}
	if size == 0 {
		return nil, nil
	}

	for attempt := 0; attempt < arpTableProbeAttempts; attempt++ {
		// One spare row of slack: the table may grow between the probe and the
		// call, and a slightly larger buffer costs nothing.
		buffer := make([]byte, size+mibIPNetRowSize)
		bufferSize := uint32(len(buffer))
		code, _, _ = procGetIpNetTable.Call(uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(unsafe.Pointer(&bufferSize)), 0)
		errno := syscall.Errno(code)
		switch errno {
		case 0:
			return parseARPRows(buffer), nil
		case errorNoData:
			return nil, nil
		case errorInsufficientBuffer:
			// The table grew; retry with the size the call just reported.
			if bufferSize > size {
				size = bufferSize
			} else {
				size += mibIPNetRowSize * 8
			}
			continue
		default:
			return nil, fmt.Errorf("读取 ARP 表失败: %w", errno)
		}
	}
	return nil, errors.New("读取 ARP 表失败: 表长度反复变化")
}

// parseARPRows decodes a MIB_IPNETTABLE buffer (pure, unit tested).
//
// Layout: NumEntries (4 bytes) followed by NumEntries rows of 24 bytes each.
func parseARPRows(buffer []byte) []arpRow {
	if len(buffer) < 4 {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(buffer[0:4]))
	rows := make([]arpRow, 0, count)
	for i := 0; i < count; i++ {
		offset := 4 + i*mibIPNetRowSize
		if offset+mibIPNetRowSize > len(buffer) {
			break // truncated table, keep the rows decoded so far
		}
		row := *(*mibIPNetRow)(unsafe.Pointer(&buffer[offset]))
		if row.PhysAddrLen != 6 {
			continue
		}
		if row.Type != arpTypeDynamic && row.Type != arpTypeStatic {
			continue
		}
		ip := net.IPv4(byte(row.Addr), byte(row.Addr>>8), byte(row.Addr>>16), byte(row.Addr>>24))
		if !ValidDeviceIP(ip) {
			continue
		}
		mac := NormalizeMAC(row.PhysAddr[:6])
		if mac == "" {
			continue
		}
		rows = append(rows, arpRow{Index: row.Index, IP: ip.String(), MAC: mac})
	}
	return rows
}

// selectARPTable turns the neighbour cache rows into IP -> MAC (pure).
//
// When one address is cached on several interfaces the entry of the ON-LINK
// interface wins: that is the adapter whose subnet contains the address, i.e.
// the one Windows routes through, so its MAC belongs to the device an HTTPS
// connection would actually talk to. Without a matching adapter (or with
// adapters == nil) the last entry of the table wins, which is what the raw table
// order suggests.
func selectARPTable(rows []arpRow, adapters []Adapter) map[string]string {
	table := make(map[string]string, len(rows))
	for _, row := range rows {
		table[row.IP] = row.MAC
	}
	routed := make(map[string]int, len(rows))
	for _, row := range rows {
		index, known := routed[row.IP]
		if !known {
			index = routedInterfaceIndex(adapters, row.IP)
			routed[row.IP] = index
		}
		if index <= 0 || uint32(index) != row.Index {
			continue
		}
		table[row.IP] = row.MAC
	}
	return table
}

// routedInterfaceIndex returns the interface index of the adapter that routes to
// ip - the adapter whose subnet contains the address - or 0 when none does.
func routedInterfaceIndex(adapters []Adapter, ip string) int {
	if len(adapters) == 0 {
		return 0
	}
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return 0
	}
	for _, adapter := range adapters {
		if adapter.Index <= 0 || len(adapter.Mask) != net.IPv4len || len(adapter.IP) != net.IPv4len {
			continue
		}
		same := true
		for i := 0; i < net.IPv4len; i++ {
			if adapter.IP[i]&adapter.Mask[i] != v4[i]&adapter.Mask[i] {
				same = false
				break
			}
		}
		if same {
			return adapter.Index
		}
	}
	return 0
}

// arpMAC returns the MAC the ARP table resolves for ip, or "".
//
// The text of the address is normalized through net.ParseIP so that a device
// address such as "192.168.100.253" matches the key of the table regardless of
// the textual form the protocol parser produced.
func arpMAC(arp map[string]string, ip string) string {
	if len(arp) == 0 || ip == "" {
		return ""
	}
	if mac, ok := arp[ip]; ok {
		return mac
	}
	if v4 := net.ParseIP(ip).To4(); v4 != nil {
		return arp[v4.String()]
	}
	return ""
}

// decideAXOMModel applies the ownership rule to one ubus answer (pure).
//
// The answered model is adopted only when
//   - the answer is a usable model string,
//   - the row has both an IP and a MAC,
//   - the local ARP table resolves that IP, and
//   - the resolved MAC is the MAC of this very row.
//
// A row that shares its IP with another device, or an address ARP has not
// resolved yet, therefore keeps its fallback value instead of being mislabelled
// with the model of a neighbour.
func decideAXOMModel(arp map[string]string, ip, mac, answered string) (string, bool) {
	model := sanitizeModel(answered)
	if model == "" || ip == "" || mac == "" {
		return "", false
	}
	owner := ParseMACString(arpMAC(arp, ip))
	deviceMAC := ParseMACString(mac)
	if owner == "" || deviceMAC == "" || !strings.EqualFold(owner, deviceMAC) {
		return "", false
	}
	return model, true
}

// pendingAXOMTargets groups the rows that still need a model by IP address.
//
// One device = one request: several rows of the same address (a dual IP host, or
// two devices behind one address) share the answer, and the ownership rule
// decides afterwards which of them may use it.
func pendingAXOMTargets(pending []Device) ([]string, map[string][]Device) {
	order := make([]string, 0, len(pending))
	byIP := make(map[string][]Device, len(pending))
	for _, row := range pending {
		if row.IP == "" {
			continue
		}
		if _, seen := byIP[row.IP]; !seen {
			order = append(order, row.IP)
		}
		byIP[row.IP] = append(byIP[row.IP], row)
	}
	return order, byIP
}

// enhanceAXOMModels replaces the host-name fallback of every AXOM row with the
// real model (including the regional suffix) answered by the device.
//
// Two channels, in this order (v1.3.1):
//
//  1. IPv6 LINK-LOCAL. The destination is derived from the device MAC (EUI-64)
//     and therefore identifies the device itself, so the answer needs no
//     ownership proof. This is the channel that works when several devices
//     share one IPv4 address.
//  2. IPv4 + ARP. Unchanged v1.3 behaviour: one request per address, and the
//     answer may only be used by the row whose MAC the ARP table resolves.
//     Reached only for rows the link-local channel could not resolve.
//
// The phase is deliberately quiet: it runs after the broadcast rounds and the
// 4800 detail queries, every query is bounded by timeout (TLS handshake
// included), the devices are queried in parallel (axomModelConcurrency) and any
// failure only produces a MOXA_DEBUG line. A device that does not answer keeps
// exactly the row it had before, and the rows of other protocols are never
// touched.
//
// Unlike the UDP queries - which are pinned to the adapter that saw the device
// with IP_UNICAST_IF - the IPv4 request follows the Windows routing table. That
// is intended: the device address is a normal unicast destination, and pinning
// it to the receiving adapter would break a device that answered a broadcast on
// a layer 2 segment the IP route does not use. The IPv6 channel is pinned by
// construction: its zone IS the interface that saw the device.
func enhanceAXOMModels(ctx context.Context, aggregator *aggregator, adapters []Adapter,
	timeout time.Duration) {

	if aggregator == nil || ctx == nil {
		return
	}
	if timeout <= 0 {
		timeout = axomModelTimeout
	}
	pending := aggregator.pendingAXOMRows()
	if len(pending) == 0 {
		return
	}

	unresolved := queryLinkLocalModels(ctx, adapters, pending, timeout, aggregator)
	if len(unresolved) == 0 {
		return
	}

	arp, err := readARPTable()
	if err != nil {
		debugf("读取本机 ARP 表失败，跳过 IPv4 回退: %v", err)
		return
	}
	if len(arp) == 0 {
		debugf("本机 ARP 表为空，跳过 IPv4 回退")
		return
	}
	queryAddressModels(ctx, arp, unresolved, timeout, aggregator)
	ubusHTTPClient.CloseIdleConnections()
}

// queryLinkLocalModels runs the IPv6 link-local query of every row, in parallel,
// and returns the rows it could not resolve.
func queryLinkLocalModels(ctx context.Context, adapters []Adapter, rows []Device,
	timeout time.Duration, aggregator *aggregator) []Device {

	unresolved := make([]Device, 0, len(rows))
	var mu sync.Mutex
	var wait sync.WaitGroup
	slots := make(chan struct{}, axomModelConcurrency)

	for _, row := range rows {
		wait.Add(1)
		go func(row Device) {
			defer wait.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			if queryOneLinkLocal(ctx, adapters, row, timeout, aggregator) {
				return
			}
			mu.Lock()
			unresolved = append(unresolved, row)
			mu.Unlock()
		}(row)
	}
	wait.Wait()
	return unresolved
}

// queryOneLinkLocal asks one row over its derived link-local address and
// reports whether the row is resolved (model stored, or nothing left to store).
func queryOneLinkLocal(ctx context.Context, adapters []Adapter, row Device,
	timeout time.Duration, aggregator *aggregator) bool {

	mac, err := net.ParseMAC(row.MAC)
	if err != nil {
		debugf("设备行 %s 的 MAC %q 无法解析，改用 IPv4 通道", row.IP, row.MAC)
		return false
	}
	linkLocal := eui64LinkLocal(mac)
	if linkLocal == "" {
		debugf("设备行 %s 的 MAC %q 无法派生链路本地地址，改用 IPv4 通道", row.IP, row.MAC)
		return false
	}
	zone := adapterIndexFor(adapters, row.Adapters)
	if zone <= 0 {
		debugf("设备 %s (MAC %s) 的网卡索引未知，改用 IPv4 通道", linkLocal, row.MAC)
		return false
	}
	model, err := ubusLinkLocalQuery(ctx, linkLocal, zone, timeout)
	if err != nil {
		debugf("设备 %s%%%d 链路本地查询失败（改用 IPv4 通道）: %v", linkLocal, zone, err)
		return false
	}
	if model == "" {
		debugf("设备 %s%%%d 未返回可用型号（改用 IPv4 通道）", linkLocal, zone)
		return false
	}
	if aggregator.setAXOMModel(row.IP, row.MAC, model) {
		debugf("设备 %s%%%d (MAC %s) 型号经链路本地地址确认为 %s", linkLocal, zone, row.MAC, model)
	}
	// The identity of a link-local answer is guaranteed by EUI-64, so this row
	// needs no further channel even when the model was already known.
	return true
}

// queryAddressModels is the IPv4 fallback of v1.3: one request per address and
// an ARP ownership check before anything is stored.
func queryAddressModels(ctx context.Context, arp map[string]string, rows []Device,
	timeout time.Duration, aggregator *aggregator) {

	order, byIP := pendingAXOMTargets(rows)
	var wait sync.WaitGroup
	slots := make(chan struct{}, axomModelConcurrency)

	for _, ip := range order {
		// Only a row whose MAC the ARP table resolves for this address could
		// ever adopt the answer (see decideAXOMModel). When no such row is left,
		// the request cannot change anything and is not sent at all.
		if !hasARPClaimant(arp, ip, byIP[ip]) {
			debugf("设备 %s 的 ARP 归属不在待查行中，跳过 IPv4 查询", ip)
			continue
		}
		wait.Add(1)
		go func(ip string) {
			defer wait.Done()
			slots <- struct{}{}
			defer func() { <-slots }()

			model, err := ubusAddressQuery(ctx, ip, timeout)
			if err != nil {
				debugf("设备 %s 型号查询失败（保持兜底值）: %v", ip, err)
				return
			}
			if model == "" {
				debugf("设备 %s 未返回可用型号（保持兜底值）", ip)
				return
			}
			for _, row := range byIP[ip] {
				adopted, ok := decideAXOMModel(arp, row.IP, row.MAC, model)
				if !ok {
					debugf("设备 %s 型号 %q 未采用：行 MAC %s 与本机 ARP 归属（%q）不符",
						ip, model, row.MAC, arpMAC(arp, row.IP))
					continue
				}
				if aggregator.setAXOMModel(row.IP, row.MAC, adopted) {
					debugf("设备 %s (MAC %s) 型号已增强为 %s", ip, row.MAC, adopted)
				}
			}
		}(ip)
	}
	wait.Wait()
}

// hasARPClaimant reports whether one of rows is the device the ARP table
// resolves for ip - i.e. whether an IPv4 answer could be attributed at all.
func hasARPClaimant(arp map[string]string, ip string, rows []Device) bool {
	owner := ParseMACString(arpMAC(arp, ip))
	if owner == "" {
		return false
	}
	for _, row := range rows {
		if strings.EqualFold(ParseMACString(row.MAC), owner) {
			return true
		}
	}
	return false
}
