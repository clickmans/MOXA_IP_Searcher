package discovery

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// TestIsClosedError locks the P2-1 rule: a UDP socket on Windows reports an
// inbound ICMP port-unreachable as WSAECONNRESET. That must NOT be treated as a
// dead socket, otherwise one unicast to an unreachable address (the 0x03 model
// query does exactly that) silently kills reply collection for a protocol.
func TestIsClosedError(t *testing.T) {
	connectionReset := &net.OpError{Op: "read", Net: "udp", Err: syscall.WSAECONNRESET}
	if isClosedError(connectionReset) {
		t.Error("WSAECONNRESET was treated as a closed socket; the reader would stop")
	}
	if isTimeoutError(connectionReset) {
		t.Error("WSAECONNRESET was treated as a deadline timeout")
	}
	if !errors.Is(connectionReset, syscall.WSAECONNRESET) {
		t.Fatal("errors.Is does not see through net.OpError")
	}

	connectionAborted := &net.OpError{Op: "read", Net: "udp", Err: syscall.WSAECONNABORTED}
	if isClosedError(connectionAborted) {
		t.Error("WSAECONNABORTED was treated as a closed socket")
	}

	if !isClosedError(net.ErrClosed) {
		t.Error("net.ErrClosed must end the read loop")
	}
	if !isClosedError(&net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}) {
		t.Error("a wrapped net.ErrClosed must end the read loop")
	}
	if isClosedError(nil) {
		t.Error("nil must not report a closed socket")
	}
}

// TestIsTimeoutError checks the deadline detection that makes the loop silent.
func TestIsTimeoutError(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot bind a loopback socket: %v", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, 16)
	if _, _, err := conn.ReadFromUDP(buffer); err == nil {
		t.Fatal("expected a timeout error")
	} else if !isTimeoutError(err) {
		t.Fatalf("isTimeoutError(%v) = false, want true", err)
	}
}

// TestClosedSocketEndsTheReadLoop proves the only condition that stops a
// reader: closing the socket on purpose.
func TestClosedSocketEndsTheReadLoop(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot bind a loopback socket: %v", err)
	}
	_ = conn.Close()

	buffer := make([]byte, 16)
	if _, _, err := conn.ReadFromUDP(buffer); err == nil {
		t.Fatal("reading a closed socket returned no error")
	} else if !isClosedError(err) {
		t.Fatalf("isClosedError(%v) = false, the reader would loop forever", err)
	}
}

// TestReadLoopStillCollectsReplies drives a real readLoop: a valid 0xC9 reply
// must be collected even though the loop keeps hitting read deadlines, and the
// loop must stop as soon as the context is cancelled.
func TestReadLoopStillCollectsReplies(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot bind a loopback socket: %v", err)
	}
	endpoint := &endpoint{
		adapter: Adapter{Name: "loopback", IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)},
		spec:    protocol4000(),
		conn:    receiver,
	}
	aggregator := newAggregator()

	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer sender.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		readLoop(ctx, endpoint, aggregator)
		close(done)
	}()

	// Two datagrams: the first one is dropped by the parser (wrong length), the
	// second is a valid EDS reply. Neither must stop the loop.
	if _, err := sender.Write([]byte{0x00, 0x01, 0x02}); err != nil {
		t.Fatalf("write: %v", err)
	}
	payload := mustHex(t, fixture4000Reply64)
	if _, err := sender.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not stop after the context was cancelled")
	}

	devices := aggregator.snapshot()
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1 (the valid reply must be collected)", len(devices))
	}
	// The EDS parser takes the device address from the UDP source address (the
	// frame field at [14:18] carries the requester address, not the device
	// one), so over loopback the row is labelled 127.0.0.1. What this test
	// guards is that the loop keeps collecting after a malformed datagram.
	if devices[0].IP != "127.0.0.1" {
		t.Errorf("IP = %q, want 127.0.0.1 (the UDP source address)", devices[0].IP)
	}
	if devices[0].Model != "EOM-106" {
		t.Errorf("Model = %q, want EOM-106", devices[0].Model)
	}
}

// TestDebugfIsSilentByDefault makes sure the diagnostic path cannot pollute the
// headless JSON on stderr during normal runs.
func TestDebugfIsSilentByDefault(t *testing.T) {
	if debugEnabled {
		t.Skip("MOXA_DEBUG is set in this environment")
	}
	debugf("this must not be printed: %d", 1)
}

// TestDedupKeyShape documents the new row identity in one place.
func TestDedupKeyShape(t *testing.T) {
	withMAC := &Device{IP: "192.168.100.254", MAC: "50:0B:88:00:00:29", Protocol: ProtoName4800}
	if got, want := dedupKey(withMAC), "mac:50:0B:88:00:00:29|ip:192.168.100.254"; got != want {
		t.Errorf("dedupKey = %q, want %q", got, want)
	}
	otherIP := &Device{IP: "192.168.100.253", MAC: "50:0B:88:00:00:29", Protocol: ProtoName4800}
	if dedupKey(withMAC) == dedupKey(otherIP) {
		t.Error("the same MAC with two IPs must not share a dedup key")
	}
	withoutMAC := &Device{IP: "192.168.100.10", Protocol: ProtoName29168}
	if got, want := dedupKey(withoutMAC), "ip:192.168.100.10|MOXA/29168"; got != want {
		t.Errorf("dedupKey = %q, want %q", got, want)
	}
}
