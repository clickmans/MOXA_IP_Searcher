package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Adapter is one enabled IPv4 network interface of the local machine.
type Adapter struct {
	// Name is the Windows interface name, e.g. "WLAN".
	Name string
	// IP is the interface IPv4 address.
	IP net.IP
	// Mask is the interface subnet mask (4 bytes).
	Mask net.IPMask
	// MAC is the interface hardware address (may be nil).
	MAC net.HardwareAddr
	// Index is the Windows interface index (net.Interface.Index). It is needed
	// by IP_UNICAST_IF to pin unicast traffic to this very interface (v1.2).
	Index int
}

// PrefixLen returns the CIDR prefix length of the interface mask.
func (a Adapter) PrefixLen() int {
	if ones, bits := a.Mask.Size(); bits == 32 {
		return ones
	}
	return 24
}

// MaskString returns the dotted subnet mask.
func (a Adapter) MaskString() string {
	if len(a.Mask) == net.IPv4len {
		return net.IP(a.Mask).String()
	}
	return ""
}

// String renders "192.168.99.163/24 (WLAN)" for the header line of the GUI.
func (a Adapter) String() string {
	return fmt.Sprintf("%s/%d (%s)", a.IP.String(), a.PrefixLen(), a.Name)
}

// FormatAdapterList renders all adapters as one comma separated line.
func FormatAdapterList(adapters []Adapter) string {
	if len(adapters) == 0 {
		return "未找到已启用的 IPv4 网卡"
	}
	parts := make([]string, 0, len(adapters))
	for _, ad := range adapters {
		parts = append(parts, ad.String())
	}
	return strings.Join(parts, " · ")
}

// EnumerateAdapters returns every enabled, non loopback IPv4 interface.
//
// All of them are used for the broadcast (REQUIREMENTS.md R1): the search must
// not be limited to the default route adapter.
func EnumerateAdapters() ([]Adapter, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	adapters := make([]Adapter, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}
			if ip4.IsUnspecified() || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			mask := ipNet.Mask
			if len(mask) == net.IPv6len {
				mask = mask[12:]
			}
			adapters = append(adapters, Adapter{
				Name:  iface.Name,
				IP:    ip4,
				Mask:  mask,
				MAC:   iface.HardwareAddr,
				Index: iface.Index,
			})
		}
	}
	return adapters, nil
}

// broadcastTargets returns the destination addresses used for one adapter:
// the limited broadcast 255.255.255.255 plus the subnet directed broadcast
// (ip & mask) | ^mask, as required by PROTOCOL_SPEC.md §7.3.
func broadcastTargets(a Adapter) []net.IP {
	targets := []net.IP{net.IPv4bcast}
	if len(a.Mask) == net.IPv4len && len(a.IP) == net.IPv4len {
		directed := make(net.IP, net.IPv4len)
		for i := 0; i < net.IPv4len; i++ {
			directed[i] = a.IP[i] | ^a.Mask[i]
		}
		if !directed.Equal(net.IPv4bcast) && !directed.Equal(a.IP) && !directed.Equal(net.IPv4zero) {
			targets = append(targets, directed)
		}
	}
	return targets
}

// Options tunes one scan.
type Options struct {
	// Rounds is the number of broadcast rounds (default 3).
	Rounds int
	// RoundDuration is the pause between two rounds (default 400 ms).
	RoundDuration time.Duration
	// ModelQueryWait is the timeout of one detail query (0x03 / 0x10 / 0x16)
	// after the last round (default 400 ms, 0 disables the detail queries).
	ModelQueryWait time.Duration
}

// Bounds of one detail query timeout (v1.2).
//
// The devices of the reference network answer in a few milliseconds, but a
// device behind a slow WLAN bridge needs more; 300-400 ms is the window that
// measured reliable in the field and keeps the whole scan short.
const (
	detailQueryMin = 300 * time.Millisecond
	detailQueryMax = 400 * time.Millisecond
)

// detailTimeout returns the timeout of one detail query, clamped to the window
// that measured reliable on hardware. 0 means "detail queries disabled".
func (o Options) detailTimeout() time.Duration {
	if o.ModelQueryWait <= 0 {
		return 0
	}
	timeout := o.ModelQueryWait
	if timeout < detailQueryMin {
		timeout = detailQueryMin
	}
	if timeout > detailQueryMax {
		timeout = detailQueryMax
	}
	return timeout
}

// DefaultOptions mirrors the timing measured on the official tools:
// 3 rounds x 400 ms plus 400 ms for the model query.
func DefaultOptions() Options {
	return Options{
		Rounds:         3,
		RoundDuration:  400 * time.Millisecond,
		ModelQueryWait: 400 * time.Millisecond,
	}
}

// OptionsFromTimeout builds options from the --timeout command line value in
// milliseconds. The whole search (rounds + model query) stays inside the
// budget.
func OptionsFromTimeout(milliseconds int) Options {
	options := DefaultOptions()
	if milliseconds <= 0 {
		return options
	}
	budget := time.Duration(milliseconds) * time.Millisecond
	modelWait := budget / 4
	if modelWait > 500*time.Millisecond {
		modelWait = 500 * time.Millisecond
	}
	if modelWait < 150*time.Millisecond {
		modelWait = 150 * time.Millisecond
	}
	round := (budget - modelWait) / time.Duration(options.Rounds)
	if round < 100*time.Millisecond {
		round = 100 * time.Millisecond
	}
	options.RoundDuration = round
	options.ModelQueryWait = modelWait
	return options
}

// Phase identifies the stage of a scan (v1.3).
//
// The broadcast rounds report a round counter, the model enhancement that runs
// afterwards reports no round at all - it is a single extra step, and inventing
// a fourth round for it would make the count lie.
type Phase int

const (
	// PhaseBroadcast is the broadcast round loop (the default phase).
	PhaseBroadcast Phase = iota
	// PhaseModels is the AXOM model enhancement that follows the rounds.
	PhaseModels
)

// Progress is reported after every broadcast round.
type Progress struct {
	// Round is the 1-based index of the round that just finished sending.
	Round int
	// TotalRounds is the configured round count.
	TotalRounds int
	// Found is the number of distinct devices collected so far.
	Found int
	// Phase tells which stage produced this message (v1.3). The zero value is
	// PhaseBroadcast, so every existing caller keeps working unchanged.
	Phase Phase
}

// Result is the outcome of one scan.
type Result struct {
	// StartedAt is when the scan begun.
	StartedAt time.Time
	// Elapsed is the total scan duration.
	Elapsed time.Duration
	// Adapters are the interfaces that took part in the scan.
	Adapters []Adapter
	// Devices are the discovered devices, sorted by IP then MAC.
	Devices []Device
	// Errors holds non fatal problems (port binding failures, ...).
	Errors []string
	// Stats holds one counter row per (adapter, protocol) socket. It exists so
	// that a machine that finds fewer fields than another one can be diagnosed
	// locally: "0 received" is a delivery problem, "received but not decoded"
	// is a parsing problem.
	Stats []ProtocolStat
}

// Scan performs one complete discovery run.
//
// Every adapter gets its own UDP socket bound to the adapter address, so the
// broadcast replies (which the devices send back to the source port) are
// received by that very socket - this is the mechanism that also makes devices
// outside the local subnet visible (REQUIREMENTS.md R3, PROTOCOL_SPEC.md §7).
func Scan(ctx context.Context, options Options, onProgress func(Progress)) *Result {
	if options.Rounds <= 0 {
		options.Rounds = 3
	}
	if options.RoundDuration <= 0 {
		options.RoundDuration = 400 * time.Millisecond
	}

	result := &Result{
		StartedAt: time.Now(),
		Adapters:  []Adapter{},
		Devices:   []Device{},
		Errors:    []string{},
	}
	started := time.Now()
	defer func() { result.Elapsed = time.Since(started) }()

	var errMu sync.Mutex
	seenErr := make(map[string]bool, 8)
	addErr := func(message string) {
		errMu.Lock()
		defer errMu.Unlock()
		if seenErr[message] {
			return
		}
		seenErr[message] = true
		result.Errors = append(result.Errors, message)
	}

	adapters, err := EnumerateAdapters()
	if err != nil {
		addErr("枚举网卡失败: " + err.Error())
		return result
	}
	result.Adapters = adapters
	if len(adapters) == 0 {
		addErr("未找到已启用的 IPv4 网卡，无法发送广播")
		return result
	}

	aggregator := newAggregator()
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	endpoints := openEndpoints(adapters, addErr)
	if len(endpoints) == 0 {
		addErr("没有可用的 UDP 套接字，搜索无法进行")
		return result
	}

	var readers sync.WaitGroup
	for _, ep := range endpoints {
		readers.Add(1)
		go func(ep *endpoint) {
			defer readers.Done()
			readLoop(scanCtx, ep, aggregator)
		}(ep)
	}

	// shutdown stops the readers and waits for them, so that the counters they
	// maintain can be read without a race. Calling it twice is harmless: cancel
	// is idempotent, Close errors are ignored and Wait returns immediately, so
	// the same closure serves both the normal path and the deferred cleanup.
	shutdown := func() {
		cancel()
		for _, ep := range endpoints {
			_ = ep.conn.Close()
		}
		readers.Wait()
	}
	defer shutdown()

	if onProgress != nil {
		onProgress(Progress{Round: 0, TotalRounds: options.Rounds, Found: 0})
	}

rounds:
	for round := 1; round <= options.Rounds; round++ {
		if scanCtx.Err() != nil {
			break
		}
		sendRound(endpoints, addErr)
		if onProgress != nil {
			onProgress(Progress{Round: round, TotalRounds: options.Rounds, Found: aggregator.count()})
		}
		select {
		case <-time.After(options.RoundDuration):
		case <-scanCtx.Done():
			break rounds
		}
	}

	// v1.2: model, name and firmware of every 4800 device, three short queries
	// per device, devices in parallel (see queryDetails).
	if scanCtx.Err() == nil {
		queryDetails(scanCtx, endpoints, aggregator, options.detailTimeout())
	}

	// v1.3: real model (with regional suffix) of every AXOM row, asked from the
	// read-only ubus interface of the device and gated by the local ARP table so
	// that a device sharing its address with another one is never mislabelled
	// (see enhanceAXOMModels).
	if scanCtx.Err() == nil {
		if onProgress != nil {
			onProgress(Progress{
				Round:       options.Rounds,
				TotalRounds: options.Rounds,
				Found:       aggregator.count(),
				Phase:       PhaseModels,
			})
		}
		enhanceAXOMModels(scanCtx, aggregator, adapters, axomModelTimeout)
	}

	// Stop the readers first: the counters are only safe to read once the
	// goroutines that increment them are gone.
	shutdown()
	result.Stats = collectStats(endpoints)
	result.Devices = aggregator.snapshot()
	return result
}

// endpoint is one (adapter, protocol) pair together with its socket.
type endpoint struct {
	adapter  Adapter
	spec     *protocolSpec
	conn     *net.UDPConn
	requests [][]byte
	targets  []net.IP

	// loggedReadError makes the "non fatal read error" notice appear once per
	// socket instead of once per datagram. Only touched by readLoop, which runs
	// in a single goroutine per endpoint.
	loggedReadError bool

	// received counts the datagrams that arrived on this socket, whatever the
	// decoder makes of them, and decoded counts those that produced a device.
	//
	// The pair is the diagnostic that separates the two failure modes seen in
	// the field: received == 0 means the reply never reached this machine
	// (firewall, wrong adapter, another program holding the port), while
	// received > 0 with decoded == 0 means the frame arrived but did not match
	// any known layout (unknown magic, unknown firmware revision).
	//
	// Only touched by readLoop, so no lock is needed.
	received int
	decoded  int
}

// ProtocolStat is one row of Result.Stats.
type ProtocolStat struct {
	// Name is the protocol label, e.g. "WSU/5800".
	Name string
	// Port is the UDP destination port of the protocol.
	Port int
	// LocalPort is the port the replies had to arrive on. For WSU/5800 this is
	// 15802 unless another program already owned it, in which case the scanner
	// fell back to an ephemeral port.
	LocalPort int
	// Adapter is the adapter the socket belongs to.
	Adapter string
	// Received counts every datagram that arrived on the socket.
	Received int
	// Decoded counts the datagrams that were recognised as a device.
	Decoded int
}

// collectStats snapshots the per socket counters. It must run after the reader
// goroutines stopped, otherwise the numbers race with readLoop.
func collectStats(endpoints []*endpoint) []ProtocolStat {
	stats := make([]ProtocolStat, 0, len(endpoints))
	for _, ep := range endpoints {
		localPort := 0
		if local, ok := ep.conn.LocalAddr().(*net.UDPAddr); ok {
			localPort = local.Port
		}
		stats = append(stats, ProtocolStat{
			Name:      ep.spec.Name,
			Port:      ep.spec.Port,
			LocalPort: localPort,
			Adapter:   ep.adapter.Name,
			Received:  ep.received,
			Decoded:   ep.decoded,
		})
	}
	return stats
}

// isTimeoutError reports whether err is the read deadline expiring.
func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// isClosedError reports whether err means the socket was closed on purpose.
// Everything else (WSAECONNRESET from an ICMP port-unreachable,
// WSAECONNABORTED, WSAENETRESET, WSAETIMEDOUT, ...) is treated as a transient,
// per-datagram condition and must not stop the reader.
func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EBADF)
}

// debugEnabled turns the one-shot diagnostic logging on. It is off by default
// so that the normal run stays silent; set MOXA_DEBUG=1 when troubleshooting.
var debugEnabled = os.Getenv("MOXA_DEBUG") != ""

// debugf writes a diagnostic line to stderr when MOXA_DEBUG is set.
func debugf(format string, args ...any) {
	if !debugEnabled {
		return
	}
	fmt.Fprintf(os.Stderr, "[discovery] "+format+"\n", args...)
}

// msgListenPortBusy is reported once when a fixed receive port belongs to
// another program.
//
// The official MOXA Wireless Search Utility binds 0.0.0.0:15802 while it runs,
// which is the same port the WSW/WSU family (WIFI4, e.g. AWK-1132C) answers to.
// The scanner then uses an ephemeral port and advertises that one inside the
// request frame - the devices honour the advertised port (measured on an
// AWK-1132C with a random port 62603), so the search keeps working.
const msgListenPortBusy = "检测到 UDP 端口 %d 已被其它程序占用（可能是 MOXA Wireless Search Utility），" +
	"已改用临时端口，WIFI4 设备仍可搜索"

// openEndpoints creates one receiving socket per adapter and protocol.
//
// Every socket is also pinned to its own adapter with IP_UNICAST_IF so that the
// unicast detail queries of v1.2 leave through the interface that saw the
// device (see setUnicastInterface). A socket that refuses the option is kept:
// broadcasts keep working, only the unicast queries may take the default route.
func openEndpoints(adapters []Adapter, addErr func(string)) []*endpoint {
	specs := allProtocols()
	endpoints := make([]*endpoint, 0, len(adapters)*len(specs))
	unicastFailures := make([]string, 0, len(adapters))

	// reservedPort reports, per fixed receive port, whether this process may
	// take it. The check has to bind the *wildcard* address: a socket bound to
	// <adapter ip>:15802 is accepted by Windows even while another program owns
	// 0.0.0.0:15802 (measured with SO_REUSEADDR and with SO_EXCLUSIVEADDRUSE),
	// so a per adapter bind can never tell that the port is taken. Binding
	// 0.0.0.0:15802 exclusively fails with WSAEADDRINUSE (foreign socket) or
	// WSAEACCES (foreign socket set SO_REUSEADDR) - that is the detection.
	reservedPort := make(map[int]bool, len(specs))
	for _, spec := range specs {
		if spec.ListenPort == 0 {
			continue
		}
		if _, decided := reservedPort[spec.ListenPort]; decided {
			continue
		}
		usable := listenPortFree(spec.ListenPort)
		reservedPort[spec.ListenPort] = usable
		if !usable {
			addErr(fmt.Sprintf(msgListenPortBusy, spec.ListenPort))
		}
		debugf("固定接收端口 %d 可用=%v", spec.ListenPort, usable)
	}

	for _, ad := range adapters {
		for _, spec := range specs {
			conn, err := bindEndpointSocket(ad, spec, reservedPort[spec.ListenPort])
			if err != nil {
				addErr(fmt.Sprintf("网卡 %s 创建 UDP/%d 套接字失败: %v", ad.Name, spec.Port, err))
				continue
			}
			if err := setUnicastInterface(conn, ad.Index); err != nil {
				unicastFailures = append(unicastFailures,
					fmt.Sprintf("%s(#%d): %v", ad.Name, ad.Index, err))
			}
			localPort := 0
			if local, ok := conn.LocalAddr().(*net.UDPAddr); ok {
				localPort = local.Port
			}
			ctx := adapterCtx{
				Name:       ad.Name,
				IP:         ad.IP,
				Mask:       ad.Mask,
				MAC:        ad.MAC,
				ListenPort: localPort,
			}
			endpoints = append(endpoints, &endpoint{
				adapter:  ad,
				spec:     spec,
				conn:     conn,
				requests: spec.Build(ctx),
				targets:  broadcastTargets(ad),
			})
		}
	}
	if len(unicastFailures) > 0 {
		addErr("部分网卡不支持 IP_UNICAST_IF（" + strings.Join(unicastFailures, "; ") +
			"），单播查询可能走默认网卡")
	}
	return endpoints
}

// bindEndpointSocket binds the receive socket of one (adapter, protocol) pair.
//
// A protocol with a fixed ListenPort (WSU/5800 -> 15802) prefers that port, so
// the scanner behaves like the official tools. When the port is owned by
// another program the callers pass fixedPortUsable=false and every adapter gets
// an ephemeral port instead; the WSU request frame then advertises that very
// port (see buildWSURequests / adapterCtx.ListenPort), which the devices accept.
//
// An adapter whose exclusive bind still fails falls back to an ephemeral port
// on its own: four adapters keep four sockets on the same fixed port only as
// long as Windows allows it, and a short lived fallback is far better than
// losing a whole network card.
func bindEndpointSocket(ad Adapter, spec *protocolSpec, fixedPortUsable bool) (*net.UDPConn, error) {
	if spec.ListenPort == 0 {
		return listenUDP(ad.IP, 0)
	}
	if fixedPortUsable {
		conn, err := listenUDPExclusive(ad.IP, spec.ListenPort)
		if err == nil {
			return conn, nil
		}
		debugf("网卡 %s 独占绑定 UDP 端口 %d 失败（%v），该网卡改用临时端口",
			ad.Name, spec.ListenPort, err)
	}
	return listenUDP(ad.IP, 0)
}

// listenPortFree reports whether this process can take the given UDP port on
// the wildcard address for its own exclusive use.
//
// The socket is closed again immediately; it only answers the question "does
// somebody else already listen on <any address>:port?". The wildcard address is
// essential: binding <adapter ip>:port succeeds even while a foreign socket
// owns 0.0.0.0:port (measured on Windows with both SO_REUSEADDR and
// SO_EXCLUSIVEADDRUSE), so only the wildcard bind reveals the conflict.
//
// A probe that cannot bind at all (permission problems, address family issues)
// is reported as "not free" - the scanner then simply uses ephemeral ports,
// which always work.
func listenPortFree(port int) bool {
	if port <= 0 {
		return true
	}
	conn, err := listenUDPExclusive(net.IPv4zero, port)
	if err != nil {
		if isAddressInUseError(err) {
			debugf("固定接收端口 %d 已被其它程序占用: %v", port, err)
		} else {
			debugf("固定接收端口 %d 探测失败: %v", port, err)
		}
		return false
	}
	_ = conn.Close()
	return true
}

// isAddressInUseError reports whether a bind failed because the address/port
// pair belongs to somebody else.
//
// Windows answers WSAEADDRINUSE (10048, "Only one usage of each socket
// address") when the existing owner did not set SO_REUSEADDR, and WSAEACCES
// (10013, "access permissions") when it did. Both mean "occupied"; the message
// text is checked as a last resort because net wraps the Winsock error in a
// syscall.Errno that older Go releases stringify differently.
func isAddressInUseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, wsaEAddrInUse) || errors.Is(err, syscall.EADDRINUSE) ||
		errors.Is(err, wsaEAcces) || errors.Is(err, syscall.EACCES) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "only one usage") ||
		strings.Contains(text, "forbidden by its access permissions")
}

// soExclusiveAddrUse is Winsock's SO_EXCLUSIVEADDRUSE.
//
// Winsock2.h defines it as (int)(~SO_REUSEADDR), i.e. -5, and the Go syscall
// package does not export it for Windows (it only exports SO_REUSEADDR = 4), so
// the value is spelled out here. On Windows SO_EXCLUSIVEADDRUSE and
// SO_REUSEADDR are mutually exclusive: setting both makes the bind fail, which
// is why listenUDPOption sets exactly one of them.
const soExclusiveAddrUse = -5

// Winsock error codes used to recognise a bind conflict.
//
// syscall exports WSAEACCES but not WSAEADDRINUSE (the EADDRINUSE of the Windows
// port of syscall is an APPLICATION_ERROR pseudo errno, not the Winsock value),
// so both numbers are declared here.
const (
	// wsaEAddrInUse is WSAEADDRINUSE (10048).
	wsaEAddrInUse = syscall.Errno(10048)
	// wsaEAcces is WSAEACCES (10013), the code Windows returns when the port is
	// held by a socket that enabled SO_REUSEADDR.
	wsaEAcces = syscall.WSAEACCES
)

// listenUDP binds a UDP socket to one specific adapter address with
// SO_REUSEADDR - the tolerant variant used for ephemeral ports.
//
// SO_BROADCAST is mandatory to send to 255.255.255.255. Both options have to be
// set before bind, hence the ListenConfig hook.
func listenUDP(localIP net.IP, port int) (*net.UDPConn, error) {
	return listenUDPOption(localIP, port, false)
}

// listenUDPExclusive binds a UDP socket with SO_EXCLUSIVEADDRUSE instead of
// SO_REUSEADDR.
//
// Exclusive binding is what keeps a foreign process from quietly taking the
// port later on: while such a socket holds <adapter ip>:15802, a program that
// binds 0.0.0.0:15802 gets WSAEACCES instead of silently sharing the address
// and stealing the unicast replies of the devices.
func listenUDPExclusive(localIP net.IP, port int) (*net.UDPConn, error) {
	return listenUDPOption(localIP, port, true)
}

// listenUDPOption binds a UDP socket to one specific local address.
//
// exclusive selects the address sharing model: SO_EXCLUSIVEADDRUSE (the port is
// ours alone, binding may fail when somebody else owns it) or SO_REUSEADDR (the
// historical, tolerant behaviour). SO_BROADCAST is always enabled, and no other
// socket option is touched.
func listenUDPOption(localIP net.IP, port int, exclusive bool) (*net.UDPConn, error) {
	var optionErr error
	listenConfig := net.ListenConfig{
		Control: func(_, _ string, raw syscall.RawConn) error {
			controlErr := raw.Control(func(fd uintptr) {
				handle := syscall.Handle(fd)
				if err := syscall.SetsockoptInt(handle, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil && optionErr == nil {
					optionErr = err
				}
				if exclusive {
					if err := syscall.SetsockoptInt(handle, syscall.SOL_SOCKET, soExclusiveAddrUse, 1); err != nil && optionErr == nil {
						optionErr = err
					}
					return
				}
				if err := syscall.SetsockoptInt(handle, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil && optionErr == nil {
					optionErr = err
				}
			})
			if controlErr != nil {
				return controlErr
			}
			return optionErr
		},
	}
	address := net.JoinHostPort(localIP.String(), strconv.Itoa(port))
	packetConn, err := listenConfig.ListenPacket(context.Background(), "udp4", address)
	if err != nil {
		return nil, err
	}
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, errors.New("套接字类型断言失败")
	}
	return udpConn, nil
}

// Windows socket options used to pin unicast traffic to one adapter (v1.2).
const (
	// ipProtoIP is IPPROTO_IP.
	ipProtoIP = 0
	// ipUnicastIF is IP_UNICAST_IF (31) on Windows: it overrides the routing
	// table for the unicast destination of this socket only.
	ipUnicastIF = 31
)

// procSetsockopt is ws2_32!setsockopt.
//
// The stdlib exposes Syscall.SetsockoptInt (which would transmit the interface
// index in HOST byte order - wrong, see unicastIFValue) and Syscall.Setsockopt
// variants for addresses and timeouts only; SetsockoptString exists on the Unix
// ports of syscall but not on Windows. Calling the Winsock function directly is
// therefore the only standard-library way to hand over the four raw bytes in
// network order. ws2_32.dll is already loaded by package net.
var procSetsockopt = syscall.NewLazyDLL("ws2_32.dll").NewProc("setsockopt")

// unicastIFValue encodes an interface index for IP_UNICAST_IF.
//
// Windows expects the index as a 4 byte integer in NETWORK byte order. The
// obvious call, syscall.SetsockoptInt, transmits the value in host order, so on
// a little endian machine Windows would read a byte swapped index, pin the
// socket to an interface that does not exist and silently drop every packet.
// Encoding the four bytes by hand and passing them verbatim avoids that trap.
func unicastIFValue(index int) []byte {
	value := uint32(index)
	return []byte{
		byte(value >> 24),
		byte(value >> 16),
		byte(value >> 8),
		byte(value),
	}
}

// setUnicastInterface pins the unicast traffic of conn to the adapter with the
// given interface index (v1.2).
//
// Why this is required: every socket is bound to one adapter address, but a
// bound source address does not select the outgoing interface - Windows routes
// by destination. A device that answers the broadcast of the WLAN adapter while
// its own subnet is reached over the Ethernet adapter would therefore get every
// unicast query (model / name / firmware) sent out of the wrong NIC, where it is
// dropped, and its model column stayed empty. IP_UNICAST_IF removes the routing
// decision for those queries (broadcasts are unaffected).
//
// A failure is not fatal: older Windows versions may not know the option, and
// the scan still works for devices reachable over the default route. The caller
// reports one warning and carries on.
func setUnicastInterface(conn *net.UDPConn, index int) error {
	if conn == nil {
		return errors.New("UDP 套接字为空")
	}
	if index <= 0 {
		return fmt.Errorf("网卡接口索引无效: %d", index)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	value := unicastIFValue(index)
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		// A non zero return value is SOCKET_ERROR; the last error is meaningful.
		if result, _, callErr := procSetsockopt.Call(fd,
			uintptr(ipProtoIP), uintptr(ipUnicastIF),
			uintptr(unsafe.Pointer(&value[0])), uintptr(len(value))); result != 0 {
			optionErr = fmt.Errorf("setsockopt(IP_UNICAST_IF, %d) 失败: %v", index, callErr)
		}
	})
	runtime.KeepAlive(value)
	if controlErr != nil {
		return controlErr
	}
	return optionErr
}

// readLoop receives replies on one socket until the scan context is cancelled.
//
// The reader is deliberately tolerant: a UDP socket on Windows reports an
// inbound ICMP port-unreachable as WSAECONNRESET (this happens for real as soon
// as a unicast - e.g. the 0x03 model query - is sent to an address nobody
// listens on). That is a per-datagram condition, not a dead socket, so the
// loop keeps going. Only a socket that was closed on purpose ends the loop,
// otherwise one stray ICMP would silently stop collecting a whole protocol for
// the rest of the scan.
func readLoop(ctx context.Context, ep *endpoint, aggregator *aggregator) {
	buffer := make([]byte, 4096)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = ep.conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, source, err := ep.conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil || isClosedError(err) {
				return
			}
			if !isTimeoutError(err) {
				if !ep.loggedReadError {
					ep.loggedReadError = true
					debugf("网卡 %s UDP/%d 读错误已忽略并继续收包: %v",
						ep.adapter.Name, ep.spec.Port, err)
				}
				// Back off a little so a permanently failing socket cannot
				// spin this goroutine at 100% CPU.
				select {
				case <-time.After(5 * time.Millisecond):
				case <-ctx.Done():
					return
				}
			}
			continue
		}
		if n <= 0 {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buffer[:n])
		var sourceIP net.IP
		if source != nil {
			sourceIP = source.IP
		}
		// The counters are deliberately updated here, next to the receive path:
		// received counts every datagram, decoded only the ones that produced a
		// row (see Result.Stats for the diagnostic reading).
		ep.received++
		if handleReply(ep, payload, sourceIP, aggregator) {
			ep.decoded++
		}
	}
}

// handleReply dispatches one datagram to the right decoder.
//
// It reports whether the datagram turned into a device row. The caller uses that
// only for the diagnostic counters (Result.Stats): a protocol whose socket
// received frames but decoded none is a layout problem, not a delivery problem.
// The 0x83 property answer returns false on purpose - it fills fields of an
// existing row instead of creating one.
func handleReply(ep *endpoint, payload []byte, sourceIP net.IP, aggregator *aggregator) bool {
	if debugEnabled {
		localPort := 0
		if local, ok := ep.conn.LocalAddr().(*net.UDPAddr); ok {
			localPort = local.Port
		}
		debugf("收到 %s 回包 %d 字节，来源 %v，本地端口 %d",
			ep.spec.Name, len(payload), sourceIP, localPort)
	}
	// A 0x83 model / firmware answer can arrive on any of the UDP/4800 sockets.
	if len(payload) >= 20 && payload[0] == replyHeader4800Model {
		deviceID, model, firmware, ok := ParseModelReplyFull(payload)
		if ok {
			source := ""
			if sourceIP != nil {
				source = sourceIP.String()
			}
			if model != "" {
				aggregator.setModel(deviceID, source, model)
			}
			if firmware != "" {
				aggregator.setFirmware(deviceID, source, firmware)
			}
		}
		return false
	}

	device, ok := ep.spec.Parse(payload, sourceIP)
	if !ok || device == nil || device.IP == "" {
		return false
	}
	device.Adapters = appendUnique(nil, ep.adapter.Name)
	aggregator.add(device)
	return true
}

// sendRound sends every request of every endpoint to both broadcast targets.
func sendRound(endpoints []*endpoint, addErr func(string)) {
	for _, ep := range endpoints {
		var firstErr error
		for _, request := range ep.requests {
			for _, target := range ep.targets {
				if _, err := ep.conn.WriteToUDP(request, &net.UDPAddr{IP: target, Port: ep.spec.Port}); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
		if firstErr != nil {
			addErr(fmt.Sprintf("网卡 %s 发送 %s 广播失败: %v", ep.adapter.Name, ep.spec.Name, firstErr))
		}
	}
}

// queryDetails asks every 4800 device for its model, name and firmware (v1.2).
//
// One goroutine per device - devices are independent, so two devices take as
// long as one - and inside a goroutine the three queries run one after the
// other, each with its own short timeout, because every answer tells a
// different field of the same row.
//
// The queries are sent from a dedicated socket bound to the adapter that saw the
// device (and pinned to it with IP_UNICAST_IF), never from the default adapter:
// a device that answered the broadcast of the WLAN adapter is not necessarily
// reachable over the Ethernet route (REQUIREMENTS.md R3).
func queryDetails(ctx context.Context, endpoints []*endpoint, aggregator *aggregator, timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	pending := aggregator.pendingDetailQueries()
	if len(pending) == 0 {
		return
	}
	var group sync.WaitGroup
	for index := range pending {
		device := pending[index]
		adapter := pick4800Adapter(endpoints, device.Adapters)
		if adapter == nil {
			continue
		}
		group.Add(1)
		go func(device Device, adapter Adapter) {
			defer group.Done()
			queryOneDevice(ctx, adapter, device, timeout, aggregator)
		}(device, *adapter)
	}
	group.Wait()
}

// detailSequence numbers the detail queries of one device. The devices echo the
// sequence number they were asked with, and keeping it unique per command keeps
// a stray late answer distinguishable in a packet capture.
const (
	seqModelBase   uint32 = 0x100
	seqNameBase    uint32 = 0x200
	seqVersionBase uint32 = 0x300
)

// queryOneDevice runs the three detail queries of a single device.
func queryOneDevice(ctx context.Context, adapter Adapter, device Device, timeout time.Duration,
	aggregator *aggregator) {

	deviceID := device.DeviceID()
	if len(deviceID) != 12 {
		return
	}
	conn, err := listenUDP(adapter.IP, 0)
	if err != nil {
		debugf("网卡 %s 创建详情查询套接字失败: %v", adapter.Name, err)
		return
	}
	defer func() { _ = conn.Close() }()
	if err := setUnicastInterface(conn, adapter.Index); err != nil {
		debugf("网卡 %s 详情查询套接字无法设置 IP_UNICAST_IF: %v", adapter.Name, err)
	}

	// 0x03: property list ("Model\t<value>\n", optional "Firmware\t").
	if payload := ask4800(ctx, conn, adapter, device, BuildModelRequest(deviceID, seqModelBase), replyHeader4800Model, timeout); payload != nil {
		id, model, firmware, ok := ParseModelReplyFull(payload)
		if ok {
			if model != "" {
				aggregator.setModel(id, device.IP, model)
			}
			if firmware != "" {
				aggregator.setFirmware(id, device.IP, firmware)
			}
		}
	}

	// 0x10: plain device name, e.g. "NP6450_0001".
	if payload := ask4800(ctx, conn, adapter, device, BuildNameRequest(deviceID, seqNameBase), replyHeader4800Name, timeout); payload != nil {
		if id, name, ok := ParseNameReply(payload); ok {
			aggregator.setName(id, device.IP, name)
		}
	}

	// 0x16: firmware version (and the short serial number of the same answer).
	if payload := ask4800(ctx, conn, adapter, device, BuildVersionRequest(deviceID, seqVersionBase), replyHeader4800Version, timeout); payload != nil {
		id, version, shortSerial, ok := ParseVersionReply(payload)
		if ok {
			aggregator.setVersion(id, device.IP, version, shortSerial)
		} else {
			aggregator.setVersion(id, device.IP, "", shortSerial)
		}
	}
}

// ask4800 sends one detail request and waits for the matching answer.
//
// The frame is sent twice: as a unicast to the device address (the layout the
// official tools use) and to the broadcast targets of the same adapter. The
// unicast is the fast path now that IP_UNICAST_IF pins it to the right
// interface; the broadcast keeps working for a device that sits in another
// subnet on the same layer 2 segment, exactly as in v1.1. Devices ignore a frame
// that does not carry their own identity, so broadcasting one query per device
// is safe.
//
// Returns the answer payload, or nil on timeout / cancellation / no matching
// answer. A "no data" answer (flag 0x04) is returned as is: the caller decides
// that the field stays empty - it is a valid answer, not an error.
func ask4800(ctx context.Context, conn *net.UDPConn, adapter Adapter, device Device,
	request []byte, expect byte, timeout time.Duration) []byte {

	if request == nil || conn == nil {
		return nil
	}
	deviceID := device.DeviceID()
	deviceIP := net.ParseIP(device.IP).To4()

	if deviceIP != nil {
		_, _ = conn.WriteToUDP(request, &net.UDPAddr{IP: deviceIP, Port: port4800})
	}
	for _, target := range broadcastTargets(adapter) {
		_, _ = conn.WriteToUDP(request, &net.UDPAddr{IP: target, Port: port4800})
	}

	deadline := time.Now().Add(timeout)
	buffer := make([]byte, 4096)
	for {
		if ctx.Err() != nil {
			return nil
		}
		if !time.Now().Before(deadline) {
			return nil
		}
		_ = conn.SetReadDeadline(deadline)
		n, source, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if isTimeoutError(err) || ctx.Err() != nil || isClosedError(err) {
				return nil
			}
			// WSAECONNRESET from an inbound ICMP port-unreachable is a
			// per-datagram condition: keep waiting for the real answer.
			continue
		}
		if n < queryLen4800 || buffer[0] != expect {
			continue
		}
		payload := append([]byte(nil), buffer[:n]...)
		if !answerMatchesDevice(payload, source, deviceID, deviceIP) {
			continue
		}
		return payload
	}
}

// answerMatchesDevice reports whether an answer belongs to the device we asked.
//
// The 12 byte identity echoed in the header is authoritative; the source address
// is accepted as well, because a device behind a NAT-like bridge may answer from
// the address we talked to with a slightly different id.
func answerMatchesDevice(payload []byte, source *net.UDPAddr, deviceID []byte, deviceIP net.IP) bool {
	if len(payload) >= queryLen4800 && len(deviceID) == 12 {
		if string(payload[8:20]) == string(deviceID) {
			return true
		}
	}
	if source != nil && deviceIP != nil && source.IP.To4() != nil {
		return source.IP.To4().Equal(deviceIP)
	}
	return false
}

// pick4800Adapter returns the adapter of the UDP/4800 socket that saw the
// device, so that the detail queries leave through the right interface.
func pick4800Adapter(endpoints []*endpoint, adapterNames []string) *Adapter {
	for _, ep := range endpoints {
		if ep.spec.Port != port4800 {
			continue
		}
		for _, name := range adapterNames {
			if ep.adapter.Name == name {
				adapter := ep.adapter
				return &adapter
			}
		}
	}
	for _, ep := range endpoints {
		if ep.spec.Port == port4800 {
			adapter := ep.adapter
			return &adapter
		}
	}
	return nil
}
