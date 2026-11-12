package discovery

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Port handling tests for the WIFI4 (WSU/5800) receive port.
//
// Background (measured on the reference machine): while the official MOXA
// Wireless Search Utility runs it owns 0.0.0.0:15802. A bind to
// <adapter ip>:15802 is nevertheless accepted by Windows - with SO_REUSEADDR
// *and* with SO_EXCLUSIVEADDRUSE - so a per adapter bind cannot detect the
// conflict and the device replies never reach this tool. Only a bind to the
// wildcard address reveals the foreign socket, which is what listenPortFree
// does; the scanner then switches to an ephemeral port and advertises that one
// inside the request frame.

// loopbackAdapter builds an Adapter for 127.0.0.1 carrying the real interface
// index, so openEndpoints exercises the same code path as with a physical NIC.
func loopbackAdapter(t *testing.T) Adapter {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		return Adapter{
			Name:  iface.Name,
			IP:    net.IPv4(127, 0, 0, 1),
			Mask:  net.CIDRMask(8, 32),
			MAC:   iface.HardwareAddr,
			Index: iface.Index,
		}
	}
	t.Skip("no loopback interface available")
	return Adapter{}
}

// findEndpoint returns the endpoint of the given destination port.
func findEndpoint(endpoints []*endpoint, port int) *endpoint {
	for _, ep := range endpoints {
		if ep.spec.Port == port {
			return ep
		}
	}
	return nil
}

// closeEndpoints releases every socket of a scan result.
func closeEndpoints(endpoints []*endpoint) {
	for _, ep := range endpoints {
		if ep != nil && ep.conn != nil {
			_ = ep.conn.Close()
		}
	}
}

// TestListenUDPExclusiveRejectsOccupiedPort locks the core of the fix: an
// exclusive bind must fail (and be recognised as an address conflict) when the
// address/port pair is already held.
func TestListenUDPExclusiveRejectsOccupiedPort(t *testing.T) {
	holder, err := listenUDPExclusive(net.IPv4(127, 0, 0, 1), 0)
	if err != nil {
		t.Skipf("cannot bind a loopback socket: %v", err)
	}
	defer func() { _ = holder.Close() }()
	port := holder.LocalAddr().(*net.UDPAddr).Port

	conn, err := listenUDPExclusive(net.IPv4(127, 0, 0, 1), port)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("exclusive bind on the busy port %d succeeded, want an error", port)
	}
	if !isAddressInUseError(err) {
		t.Errorf("isAddressInUseError(%v) = false, want true", err)
	}

	// Documented, not enforced: the tolerant variant (SO_REUSEADDR) is what the
	// scanner used before the fix and it does not report the conflict. Some
	// Windows builds refuse the bind instead; both outcomes are fine here, the
	// detection itself is done by listenPortFree.
	if tolerant, tolerantErr := listenUDP(net.IPv4(127, 0, 0, 1), port); tolerantErr != nil {
		t.Logf("SO_REUSEADDR bind refused as well (%v)", tolerantErr)
	} else {
		_ = tolerant.Close()
	}
}

// TestListenPortFreeDetectsForeignHolder proves that the wildcard probe sees a
// process that owns the port on every address - the situation the official
// Wireless Search Utility creates.
func TestListenPortFreeDetectsForeignHolder(t *testing.T) {
	holder, err := listenUDPExclusive(net.IPv4zero, 0)
	if err != nil {
		t.Skipf("cannot bind a wildcard socket: %v", err)
	}
	defer func() { _ = holder.Close() }()
	port := holder.LocalAddr().(*net.UDPAddr).Port

	if listenPortFree(port) {
		t.Errorf("listenPortFree(%d) = true although 0.0.0.0:%d is held", port, port)
	}

	// A port that was just released is reported free again.
	released, err := listenUDPExclusive(net.IPv4zero, 0)
	if err != nil {
		t.Fatalf("cannot bind a second wildcard socket: %v", err)
	}
	freePort := released.LocalAddr().(*net.UDPAddr).Port
	_ = released.Close()
	if !listenPortFree(freePort) {
		t.Errorf("listenPortFree(%d) = false right after the socket was closed", freePort)
	}

	if !listenPortFree(0) {
		t.Error("listenPortFree(0) must report a free (ephemeral) port")
	}
}

// TestIsAddressInUseError covers the Winsock codes Windows uses for a bind
// conflict: WSAEADDRINUSE when the owner did not share, WSAEACCES when it did.
func TestIsAddressInUseError(t *testing.T) {
	if isAddressInUseError(nil) {
		t.Error("nil must not be an address conflict")
	}
	inUse := &net.OpError{Op: "listen", Net: "udp4", Err: wsaEAddrInUse}
	if !isAddressInUseError(inUse) {
		t.Errorf("isAddressInUseError(%v) = false, want true", inUse)
	}
	if !isAddressInUseError(&net.OpError{Op: "listen", Net: "udp4", Err: wsaEAcces}) {
		t.Error("WSAEACCES must be treated as a conflict")
	}
	if !isAddressInUseError(fmt.Errorf("wrap: %w", wsaEAddrInUse)) {
		t.Error("a wrapped WSAEADDRINUSE must be treated as a conflict")
	}
	if isAddressInUseError(errors.New("some unrelated failure")) {
		t.Error("an unrelated error was reported as a conflict")
	}
	if isAddressInUseError(syscall.EINVAL) {
		t.Error("EINVAL was reported as a conflict")
	}

	// Real bind error, not a synthetic one.
	holder, err := listenUDPExclusive(net.IPv4zero, 0)
	if err != nil {
		t.Skipf("cannot bind a wildcard socket: %v", err)
	}
	defer func() { _ = holder.Close() }()
	port := holder.LocalAddr().(*net.UDPAddr).Port
	if _, err := listenUDPExclusive(net.IPv4zero, port); err == nil {
		t.Fatal("the real bind conflict produced no error")
	} else if !isAddressInUseError(err) {
		t.Errorf("isAddressInUseError(%v) = false for a real bind conflict", err)
	}
}

// TestOpenEndpointsFallsBackWhenFixedPortBusy is the end to end test of the fix
// in code: with 0.0.0.0:15802 occupied, every WSU socket must come up on an
// ephemeral port, the request must advertise it, the hint must appear exactly
// once - and the socket must really receive a WSU reply addressed to that port.
func TestOpenEndpointsFallsBackWhenFixedPortBusy(t *testing.T) {
	holder, err := listenUDPExclusive(net.IPv4zero, wsuListenPort)
	if err != nil {
		t.Skipf("cannot occupy 0.0.0.0:%d for the test (already taken?): %v", wsuListenPort, err)
	}
	defer func() { _ = holder.Close() }()

	var messages []string
	endpoints := openEndpoints([]Adapter{loopbackAdapter(t)}, func(message string) {
		messages = append(messages, message)
	})
	defer closeEndpoints(endpoints)

	if len(endpoints) != len(allProtocols()) {
		t.Fatalf("len(endpoints) = %d, want %d (one per protocol)", len(endpoints), len(allProtocols()))
	}

	want := fmt.Sprintf(msgListenPortBusy, wsuListenPort)
	occurrences := 0
	for _, message := range messages {
		if message == want {
			occurrences++
		}
	}
	if occurrences != 1 {
		t.Errorf("端口占用提示出现 %d 次，want 1; messages = %v", occurrences, messages)
	}

	wsu := findEndpoint(endpoints, portWSU)
	if wsu == nil {
		t.Fatalf("no UDP/%d endpoint was created", portWSU)
	}
	bound := wsu.conn.LocalAddr().(*net.UDPAddr).Port
	if bound == wsuListenPort {
		t.Fatalf("the scanner still uses the busy port %d", wsuListenPort)
	}
	if len(wsu.requests) != 1 {
		t.Fatalf("len(requests) = %d, want 1", len(wsu.requests))
	}
	if advertised := fixedString(wsu.requests[0][62:68]); advertised != strconv.Itoa(bound) {
		t.Errorf("报文广告端口 = %q, want %d (the port actually bound)", advertised, bound)
	}

	// The device answers the advertised port, so a reply sent there must arrive.
	device := net.ParseIP("192.168.100.253")
	if device == nil {
		t.Fatal("cannot parse the device address")
	}
	sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: bound})
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer func() { _ = sender.Close() }()
	reply := mustHex(t, fixtureWSUReplyAWK1132C)
	if _, err := sender.Write(reply); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := wsu.conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, 4096)
	n, _, err := wsu.conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("the fallback socket received nothing: %v", err)
	}
	if n != len(reply) {
		t.Errorf("received %d bytes, want %d", n, len(reply))
	}
	parsed, ok := wsu.spec.Parse(buffer[:n], net.IPv4(127, 0, 0, 1))
	if !ok || parsed == nil {
		t.Fatal("the received reply was not parsed")
	}
	if parsed.Model != "AWK-1132C-US" {
		t.Errorf("Model = %q, want AWK-1132C-US", parsed.Model)
	}
}

// TestOpenEndpointsKeepsFixedPortWhenFree is the counterpart: a free port is
// used (behaviour identical to the official tool) and no hint is produced.
func TestOpenEndpointsKeepsFixedPortWhenFree(t *testing.T) {
	if !listenPortFree(wsuListenPort) {
		t.Skipf("UDP port %d is already occupied on this machine", wsuListenPort)
	}

	var messages []string
	endpoints := openEndpoints([]Adapter{loopbackAdapter(t)}, func(message string) {
		messages = append(messages, message)
	})
	defer closeEndpoints(endpoints)

	wsu := findEndpoint(endpoints, portWSU)
	if wsu == nil {
		t.Fatalf("no UDP/%d endpoint was created", portWSU)
	}
	if bound := wsu.conn.LocalAddr().(*net.UDPAddr).Port; bound != wsuListenPort {
		t.Errorf("bound port = %d, want the fixed %d", bound, wsuListenPort)
	}
	advertised := fixedString(wsu.requests[0][62:68])
	if advertised != strconv.Itoa(wsuListenPort) {
		t.Errorf("报文广告端口 = %q, want %d", advertised, wsuListenPort)
	}
	busy := fmt.Sprintf(msgListenPortBusy, wsuListenPort)
	for _, message := range messages {
		if message == busy {
			t.Errorf("端口占用提示不该出现（端口本来是空的）: %v", messages)
		}
	}
}

// TestBuildWSURequestsAdvertisesGivenPort pins rule 3 of the fix: the frame
// carries the port that was actually bound, never a hard coded 15802.
func TestBuildWSURequestsAdvertisesGivenPort(t *testing.T) {
	ac := adapterCtx{
		Name: "WLAN",
		IP:   net.IPv4(192, 168, 100, 10),
		Mask: net.CIDRMask(24, 32),
		MAC:  net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
	}
	for _, port := range []int{1024, 12345, 15802, 62603, 65535} {
		ac.ListenPort = port
		requests := buildWSURequests(ac)
		if len(requests) != 1 {
			t.Fatalf("len(requests) = %d, want 1", len(requests))
		}
		if got := fixedString(requests[0][62:68]); got != strconv.Itoa(port) {
			t.Errorf("[62:68] = %q, want %q", got, strconv.Itoa(port))
		}
	}

	// ListenPort == 0 cannot happen in a scan (the socket is bound before the
	// frame is built); the documented last resort stays the official default.
	ac.ListenPort = 0
	if got := fixedString(buildWSURequests(ac)[0][62:68]); got != strconv.Itoa(wsuListenPort) {
		t.Errorf("[62:68] = %q, want the default %d", got, wsuListenPort)
	}
}
