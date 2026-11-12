package discovery

import (
	"net"
	"testing"
)

// TestCollectStatsShape pins the diagnostic counters: one row per socket, with
// the local port actually bound and the two counters copied verbatim.
//
// The counters are what tells a "no reply reached this PC" problem apart from a
// "reply reached the PC but was rejected by the decoder" problem, so the shape
// of the snapshot is part of the contract.
func TestCollectStatsShape(t *testing.T) {
	conn, err := listenUDP(net.IPv4(127, 0, 0, 1), 0)
	if err != nil {
		t.Skipf("cannot bind a loopback UDP socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	bound := conn.LocalAddr().(*net.UDPAddr).Port
	ep := &endpoint{
		adapter:  Adapter{Name: "回环", IP: net.IPv4(127, 0, 0, 1)},
		spec:     &protocolSpec{Name: "TEST/9999", Port: 9999},
		conn:     conn,
		received: 5,
		decoded:  2,
	}
	stats := collectStats([]*endpoint{ep})
	if len(stats) != 1 {
		t.Fatalf("len(stats) = %d, want 1", len(stats))
	}
	got := stats[0]
	if got.Name != "TEST/9999" || got.Port != 9999 {
		t.Errorf("name/port = %q/%d, want TEST/9999/9999", got.Name, got.Port)
	}
	if got.LocalPort != bound {
		t.Errorf("LocalPort = %d, want the bound port %d", got.LocalPort, bound)
	}
	if got.Adapter != "回环" {
		t.Errorf("Adapter = %q, want 回环", got.Adapter)
	}
	if got.Received != 5 || got.Decoded != 2 {
		t.Errorf("counters = %d/%d, want 5/2", got.Received, got.Decoded)
	}
}

// TestCollectStatsEmpty keeps the JSON array free of nil entries: the headless
// report must always contain "stats": [] rather than null.
func TestCollectStatsEmpty(t *testing.T) {
	stats := collectStats(nil)
	if stats == nil {
		t.Fatal("collectStats(nil) returned nil, want an empty slice")
	}
	if len(stats) != 0 {
		t.Fatalf("len(stats) = %d, want 0", len(stats))
	}
}
