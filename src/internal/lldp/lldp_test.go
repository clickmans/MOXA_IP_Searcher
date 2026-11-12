package lldp

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Pure functions: index parsing and column merging
// ---------------------------------------------------------------------------

// TestParseIndex pins the index layout TimeMark.LocalPortNum.RemIndex.
//
// The middle segment is the local port number - the value of the 端口 column -
// and the first segment (the time mark) changes with every LLDP update, so it
// must never be mistaken for the port (PROTOCOL_SPEC.md §10.3).
func TestParseIndex(t *testing.T) {
	tests := []struct {
		index    string
		port     int
		remIndex int
		ok       bool
	}{
		// Measured pairs (index, port) from 192.168.100.4.
		{index: "0.4.1", port: 4, remIndex: 1, ok: true},
		{index: "396.2.5", port: 2, remIndex: 5, ok: true},
		{index: "866.3.1", port: 3, remIndex: 1, ok: true},
		{index: "197.3.3", port: 3, remIndex: 3, ok: true},
		{index: "269.5.4", port: 5, remIndex: 4, ok: true},
		// The time mark is irrelevant, the port stays the second segment.
		{index: "0.12.1", port: 12, remIndex: 1, ok: true},
		// Malformed indexes are dropped, never guessed.
		{index: "abc", ok: false},
		{index: "1.2", ok: false},
		{index: "1.2.3.4", ok: false},
		{index: "", ok: false},
		{index: "1..3", ok: false},
		{index: "1.-2.3", ok: false},
		{index: "1.0.3", ok: false}, // port 0 does not exist
		{index: "1.x.3", ok: false},
	}
	for _, test := range tests {
		t.Run(test.index, func(t *testing.T) {
			port, remIndex, ok := parseIndex(test.index)
			if ok != test.ok {
				t.Fatalf("parseIndex(%q) ok = %v, want %v", test.index, ok, test.ok)
			}
			if !ok {
				return
			}
			if port != test.port {
				t.Errorf("port = %d, want %d", port, test.port)
			}
			if remIndex != test.remIndex {
				t.Errorf("remIndex = %d, want %d", remIndex, test.remIndex)
			}
		})
	}
}

// TestNextColumnValue verifies the walk step guard: exception values and
// foreign OIDs end the column instead of becoming table rows.
func TestNextColumnValue(t *testing.T) {
	base := oidRemBase + ".5"
	text := snmpValue{tag: tagOctetString, raw: []byte("0090e8000285")}

	if value, ok := nextColumnValue(columnChassisID, base, base+".0.4.1", text); !ok {
		t.Fatal("a varbind inside the subtree must be accepted")
	} else if value.Index != "0.4.1" || value.Column != columnChassisID || value.Value != "0090e8000285" {
		t.Fatalf("value = %+v", value)
	}

	rejected := map[string]struct {
		oid   string
		value snmpValue
	}{
		"noSuchObject":    {oid: base + ".0.4.1", value: snmpValue{tag: tagNoSuchObject}},
		"noSuchInstance":  {oid: base + ".0.4.1", value: snmpValue{tag: tagNoSuchInstance}},
		"endOfMibView":    {oid: base + ".0.4.1", value: snmpValue{tag: tagEndOfMibView}},
		"null":            {oid: base + ".0.4.1", value: snmpValue{tag: tagNull}},
		"next column":     {oid: oidRemBase + ".9.0.4.1", value: text},
		"column prefix":   {oid: oidRemBase + ".50.1.1", value: text},
		"outside the MIB": {oid: "1.3.6.1.2.1.1.5.0", value: text},
		"no index at all": {oid: base, value: text},
	}
	for name, test := range rejected {
		t.Run(name, func(t *testing.T) {
			if _, ok := nextColumnValue(columnChassisID, base, test.oid, test.value); ok {
				t.Fatalf("%s must end the column", name)
			}
		})
	}
}

// TestBuildNeighborsMergesColumns covers the merge of the four column walks:
// one row per index, missing columns stay empty, and the result is sorted by
// port.
func TestBuildNeighborsMergesColumns(t *testing.T) {
	values := []columnValue{
		{Column: columnChassisID, Index: "396.2.5", Value: "c85b7600004a"},
		{Column: columnPortID, Index: "396.2.5", Value: "c85b7600004a"},
		{Column: columnSystemName, Index: "396.2.5", Value: "Managed Redundant Switch 00004"},
		{Column: columnChassisID, Index: "0.4.1", Value: "0090e8000285"},
		{Column: columnPortID, Index: "0.4.1", Value: "7"},
		{Column: columnPortDesc, Index: "0.4.1", Value: "100FX,SC,Single,40."},
		{Column: columnSystemName, Index: "0.4.1", Value: "Managed Redundant Switch 00003"},
		{Column: columnChassisID, Index: "197.3.3", Value: "0090e8000032"},
		// Port 3 without port id / description: those columns stay empty.
	}

	neighbors := buildNeighbors(values)
	want := []Neighbor{
		{
			Port:       2,
			ChassisID:  "c85b7600004a",
			PortID:     "c85b7600004a",
			PortDesc:   "",
			SystemName: "Managed Redundant Switch 00004",
		},
		{
			Port:       3,
			ChassisID:  "0090e8000032",
			PortID:     "",
			PortDesc:   "",
			SystemName: "",
		},
		{
			Port:       4,
			ChassisID:  "0090e8000285",
			PortID:     "7",
			PortDesc:   "100FX,SC,Single,40.",
			SystemName: "Managed Redundant Switch 00003",
		},
	}
	if len(neighbors) != len(want) {
		t.Fatalf("len(neighbors) = %d, want %d: %+v", len(neighbors), len(want), neighbors)
	}
	for index := range want {
		if neighbors[index] != want[index] {
			t.Errorf("neighbors[%d] = %+v, want %+v", index, neighbors[index], want[index])
		}
	}
}

// TestBuildNeighborsKeepsSmallestRemIndex covers the "several neighbours on one
// local port" rule: the row with the smallest RemIndex survives, the others are
// dropped, and malformed indexes never panic.
func TestBuildNeighborsKeepsSmallestRemIndex(t *testing.T) {
	values := []columnValue{
		{Column: columnChassisID, Index: "197.3.3", Value: "second"},
		{Column: columnChassisID, Index: "866.3.1", Value: "first"},
		{Column: columnChassisID, Index: "10.3.2", Value: "third"},
		{Column: columnChassisID, Index: "abc", Value: "junk"},
		{Column: columnChassisID, Index: "1.2", Value: "junk"},
		{Column: columnPortID, Index: "866.3.1", Value: "1"},
	}
	neighbors := buildNeighbors(values)
	if len(neighbors) != 1 {
		t.Fatalf("len(neighbors) = %d, want 1: %+v", len(neighbors), neighbors)
	}
	if neighbors[0].Port != 3 || neighbors[0].ChassisID != "first" || neighbors[0].PortID != "1" {
		t.Fatalf("neighbors[0] = %+v, want the RemIndex 1 row of port 3", neighbors[0])
	}

	if empty := buildNeighbors(nil); len(empty) != 0 {
		t.Fatalf("buildNeighbors(nil) = %+v, want empty", empty)
	}
	if junk := buildNeighbors([]columnValue{{Index: "abc", Column: 5, Value: "x"}}); len(junk) != 0 {
		t.Fatalf("buildNeighbors(junk) = %+v, want empty", junk)
	}
}

// ---------------------------------------------------------------------------
// A tiny fake SNMP agent, so the client loop is tested without a device
// ---------------------------------------------------------------------------

// fakeEntry is one row of the fake MIB.
type fakeEntry struct {
	oid string
	tag byte
	raw []byte
}

// fakeAgent answers GET / GETNEXT requests from a canned MIB or from a custom
// function, so the whole client loop (encoding, request id matching, walk,
// merge) is exercised without network access to a device.
type fakeAgent struct {
	conn     *net.UDPConn
	entries  []fakeEntry
	answerFn func(pduTag byte, oid string) (nextOID string, tag byte, raw []byte)
	// wrongIDFirst makes the agent answer the first request of every exchange
	// with a foreign request id, which the client must ignore.
	wrongIDFirst bool
	requests     int64
}

// startFakeAgent binds a loopback UDP socket and serves until the test ends.
func startFakeAgent(t *testing.T, entries []fakeEntry) *fakeAgent {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot bind a loopback UDP socket: %v", err)
	}
	agent := &fakeAgent{conn: conn, entries: entries}
	go agent.serve()
	t.Cleanup(func() { _ = conn.Close() })
	return agent
}

// port returns the port the agent listens on.
func (a *fakeAgent) port() int {
	address, ok := a.conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0
	}
	return address.Port
}

// serve runs the request/reply loop.
func (a *fakeAgent) serve() {
	buffer := make([]byte, maxPacketSize)
	for {
		read, address, err := a.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		atomic.AddInt64(&a.requests, 1)
		requestID, pduTag, oid, ok := parseTestRequest(buffer[:read])
		if !ok {
			continue
		}
		nextOID, tag, raw := a.answer(pduTag, oid)
		if a.wrongIDFirst {
			// A stale datagram of an earlier request must be ignored by the
			// client, so send it first.
			_, _ = a.conn.WriteToUDP(buildTestResponse(requestID+1000, nextOID, tag, raw), address)
		}
		_, _ = a.conn.WriteToUDP(buildTestResponse(requestID, nextOID, tag, raw), address)
	}
}

// answer decides the reply of one request.
func (a *fakeAgent) answer(pduTag byte, oid string) (string, byte, []byte) {
	if a.answerFn != nil {
		return a.answerFn(pduTag, oid)
	}
	if pduTag == pduGetRequest {
		for _, entry := range a.entries {
			if entry.oid == oid {
				return entry.oid, entry.tag, entry.raw
			}
		}
		return oid, tagNoSuchObject, nil
	}
	// GETNEXT: the numerically next OID of the canned MIB.
	best := ""
	found := false
	for _, entry := range a.entries {
		if compareOID(entry.oid, oid) <= 0 {
			continue
		}
		if !found || compareOID(entry.oid, best) < 0 {
			best = entry.oid
			found = true
		}
	}
	if !found {
		return oid, tagEndOfMibView, nil
	}
	for _, entry := range a.entries {
		if entry.oid == best {
			return entry.oid, entry.tag, entry.raw
		}
	}
	return oid, tagEndOfMibView, nil
}

// parseTestRequest decodes just enough of a request to answer it.
func parseTestRequest(packet []byte) (requestID int64, pduTag byte, oid string, ok bool) {
	message, _, err := readTLV(packet, 0)
	if err != nil {
		return 0, 0, "", false
	}
	_, offset, err := readTLV(message.content, 0) // version
	if err != nil {
		return 0, 0, "", false
	}
	_, offset, err = readTLV(message.content, offset) // community
	if err != nil {
		return 0, 0, "", false
	}
	pdu, _, err := readTLV(message.content, offset)
	if err != nil {
		return 0, 0, "", false
	}
	id, pduOffset, err := readTLV(pdu.content, 0)
	if err != nil {
		return 0, 0, "", false
	}
	_, pduOffset, err = readTLV(pdu.content, pduOffset) // error-status
	if err != nil {
		return 0, 0, "", false
	}
	_, pduOffset, err = readTLV(pdu.content, pduOffset) // error-index
	if err != nil {
		return 0, 0, "", false
	}
	varBindList, _, err := readTLV(pdu.content, pduOffset)
	if err != nil {
		return 0, 0, "", false
	}
	varbind, _, err := readTLV(varBindList.content, 0)
	if err != nil {
		return 0, 0, "", false
	}
	oidTLV, _, err := readTLV(varbind.content, 0)
	if err != nil {
		return 0, 0, "", false
	}
	return signedInteger(id.content), pdu.tag, decodeOID(oidTLV.content), true
}

// buildTestResponse renders one GetResponse with a single varbind.
func buildTestResponse(requestID int64, oid string, tag byte, raw []byte) []byte {
	encodedOID, err := encodeOID(oid)
	if err != nil {
		return nil
	}
	varbind := append(append([]byte{}, encodedOID...), encodeTLV(tag, raw)...)
	varBindList := encodeTLV(tagSequence, encodeTLV(tagSequence, varbind))
	pduBody := append(encodeInteger(requestID), encodeInteger(0)...)
	pduBody = append(pduBody, encodeInteger(0)...)
	pduBody = append(pduBody, varBindList...)
	body := append(encodeInteger(snmpVersion2c), encodeTLV(tagOctetString, []byte(DefaultCommunity))...)
	body = append(body, encodeTLV(pduGetResponse, pduBody)...)
	return encodeTLV(tagSequence, body)
}

// compareOID orders two dotted OIDs segment by segment, numerically.
func compareOID(left, right string) int {
	leftFields := strings.Split(left, ".")
	rightFields := strings.Split(right, ".")
	limit := len(leftFields)
	if len(rightFields) < limit {
		limit = len(rightFields)
	}
	for index := 0; index < limit; index++ {
		leftValue, leftErr := strconv.Atoi(leftFields[index])
		rightValue, rightErr := strconv.Atoi(rightFields[index])
		if leftErr != nil || rightErr != nil {
			if leftFields[index] == rightFields[index] {
				continue
			}
			if leftFields[index] < rightFields[index] {
				return -1
			}
			return 1
		}
		if leftValue != rightValue {
			if leftValue < rightValue {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(leftFields) < len(rightFields):
		return -1
	case len(leftFields) > len(rightFields):
		return 1
	default:
		return 0
	}
}

// referenceMIB is the LLDP table measured on 192.168.100.4 (PROTOCOL_SPEC.md
// §10.4), including a column that the device does not publish (portDesc).
func referenceMIB() []fakeEntry {
	return []fakeEntry{
		{oid: oidChassisID, tag: tagOctetString, raw: mustHex("0090e80000d0")},
		{oid: oidSystemName, tag: tagOctetString, raw: []byte("Managed Redundant Switch 00001")},
		{oid: oidSystemDesc, tag: tagOctetString, raw: []byte("EOM-106")},
		// Column 5: lldpRemChassisId.
		{oid: oidRemBase + ".5.0.4.1", tag: tagOctetString, raw: mustHex("0090e8000285")},
		{oid: oidRemBase + ".5.197.3.3", tag: tagOctetString, raw: mustHex("0090e8000032")},
		{oid: oidRemBase + ".5.269.5.4", tag: tagOctetString, raw: mustHex("500b88000067")},
		{oid: oidRemBase + ".5.396.2.5", tag: tagOctetString, raw: mustHex("c85b7600004a")},
		// Column 7: lldpRemPortId.
		{oid: oidRemBase + ".7.0.4.1", tag: tagOctetString, raw: []byte("7")},
		{oid: oidRemBase + ".7.197.3.3", tag: tagOctetString, raw: []byte("3")},
		{oid: oidRemBase + ".7.269.5.4", tag: tagOctetString, raw: []byte("4")},
		{oid: oidRemBase + ".7.396.2.5", tag: tagOctetString, raw: mustHex("c85b7600004a")},
		// Column 9: lldpRemSysName.
		{oid: oidRemBase + ".9.0.4.1", tag: tagOctetString, raw: []byte("Managed Redundant Switch 00003")},
		{oid: oidRemBase + ".9.197.3.3", tag: tagOctetString, raw: []byte("Managed Redundant Switch 00001")},
		{oid: oidRemBase + ".9.269.5.4", tag: tagOctetString, raw: []byte("Managed Redundant Switch 00004")},
		// Port 2 has no system name, exactly like the measured device.
	}
}

// mustHex decodes a hex fixture or panics (test only).
func mustHex(raw string) []byte {
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		panic(err)
	}
	return decoded
}

// TestFetchAgainstFakeAgent runs the complete Fetch against the reference table.
func TestFetchAgainstFakeAgent(t *testing.T) {
	agent := startFakeAgent(t, referenceMIB())

	table, err := Fetch(context.Background(), "127.0.0.1", Options{
		Timeout: 300 * time.Millisecond,
		port:    agent.port(),
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if table.ChassisID != "0090e80000d0" {
		t.Errorf("ChassisID = %q", table.ChassisID)
	}
	if table.SystemName != "Managed Redundant Switch 00001" {
		t.Errorf("SystemName = %q", table.SystemName)
	}
	if table.SystemDesc != "EOM-106" {
		t.Errorf("SystemDesc = %q", table.SystemDesc)
	}

	// Sorted by Port ascending: 2, 3, 4, 5.
	want := []Neighbor{
		{Port: 2, ChassisID: "c85b7600004a", PortID: "c85b7600004a", PortDesc: "", SystemName: ""},
		{Port: 3, ChassisID: "0090e8000032", PortID: "3", PortDesc: "", SystemName: "Managed Redundant Switch 00001"},
		{Port: 4, ChassisID: "0090e8000285", PortID: "7", PortDesc: "", SystemName: "Managed Redundant Switch 00003"},
		{Port: 5, ChassisID: "500b88000067", PortID: "4", PortDesc: "", SystemName: "Managed Redundant Switch 00004"},
	}
	if len(table.Neighbors) != len(want) {
		t.Fatalf("len(Neighbors) = %d, want %d: %+v", len(table.Neighbors), len(want), table.Neighbors)
	}
	for index := range want {
		if table.Neighbors[index] != want[index] {
			t.Errorf("Neighbors[%d] = %+v, want %+v", index, table.Neighbors[index], want[index])
		}
	}
}

// TestFetchSkipsStaleRequestIDs makes the agent answer with a foreign request id
// first: the client must ignore that datagram and use the second one.
func TestFetchSkipsStaleRequestIDs(t *testing.T) {
	agent := startFakeAgent(t, referenceMIB())
	agent.wrongIDFirst = true

	table, err := Fetch(context.Background(), "127.0.0.1", Options{
		Timeout: 500 * time.Millisecond,
		port:    agent.port(),
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if table.ChassisID != "0090e80000d0" {
		t.Errorf("ChassisID = %q, want the value of the matching reply", table.ChassisID)
	}
	if len(table.Neighbors) != 4 {
		t.Errorf("len(Neighbors) = %d, want 4", len(table.Neighbors))
	}
}

// TestFetchWithoutNeighborsAcceptsEmptyTable covers a device that answers SNMP
// but has no LLDP neighbour: an empty table, no error.
func TestFetchWithoutNeighborsAcceptsEmptyTable(t *testing.T) {
	agent := startFakeAgent(t, []fakeEntry{
		{oid: oidChassisID, tag: tagOctetString, raw: mustHex("0090e80000d0")},
	})
	table, err := Fetch(context.Background(), "127.0.0.1", Options{
		Timeout: 300 * time.Millisecond,
		port:    agent.port(),
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if table == nil {
		t.Fatal("table must not be nil when the device answers SNMP")
	}
	if len(table.Neighbors) != 0 {
		t.Fatalf("Neighbors = %+v, want empty", table.Neighbors)
	}
	if table.SystemName != "" || table.SystemDesc != "" {
		t.Errorf("unanswered local fields must stay empty: %+v", table)
	}
}

// TestWalkStopsAtRowCap feeds an endless column and checks the 64 row budget.
func TestWalkStopsAtRowCap(t *testing.T) {
	agent := startFakeAgent(t, nil)
	base := oidRemBase + ".5"
	agent.answerFn = func(pduTag byte, oid string) (string, byte, []byte) {
		if pduTag == pduGetRequest {
			return oid, tagNoSuchObject, nil
		}
		if oid == base || !strings.HasPrefix(oid, base+".") {
			return base + ".0.1.1", tagOctetString, []byte("row")
		}
		timeMark, _, remIndex := splitIndex(strings.TrimPrefix(oid, base+"."))
		return fmt.Sprintf("%s.%d.1.%d", base, timeMark+1, remIndex+1), tagOctetString, []byte("row")
	}

	conn, err := dial(context.Background(), net.JoinHostPort("127.0.0.1", strconv.Itoa(agent.port())))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	session := &client{conn: conn, community: DefaultCommunity, timeout: 300 * time.Millisecond, retries: 0}
	values := session.walk(columnChassisID)
	if len(values) != maxWalkRows {
		t.Fatalf("len(values) = %d, want the %d row cap", len(values), maxWalkRows)
	}
	for _, value := range values {
		if value.Column != columnChassisID {
			t.Fatalf("value of column %d in column %d", value.Column, columnChassisID)
		}
		if value.Value != "row" {
			t.Fatalf("value = %q, want row", value.Value)
		}
	}
}

// splitIndex splits a three segment index; it tolerates damaged input because it
// is only a test helper.
func splitIndex(index string) (timeMark, port, remIndex int) {
	fields := strings.Split(index, ".")
	if len(fields) != 3 {
		return 0, 0, 0
	}
	timeMark, _ = strconv.Atoi(fields[0])
	port, _ = strconv.Atoi(fields[1])
	remIndex, _ = strconv.Atoi(fields[2])
	return timeMark, port, remIndex
}

// TestWalkStopsOnEndValue makes one column end with noSuchObject: the walk must
// stop there and produce no phantom neighbour.
func TestWalkStopsOnEndValue(t *testing.T) {
	agent := startFakeAgent(t, nil)
	base := oidRemBase + ".5"
	agent.answerFn = func(pduTag byte, oid string) (string, byte, []byte) {
		if pduTag == pduGetRequest {
			if oid == oidChassisID {
				return oid, tagOctetString, mustHex("0090e80000d0")
			}
			return oid, tagNoSuchObject, nil
		}
		// The column has one row, then the agent reports endOfMibView.
		if oid == base {
			return base + ".0.1.1", tagOctetString, []byte("only-row")
		}
		return oid, tagEndOfMibView, nil
	}

	table, err := Fetch(context.Background(), "127.0.0.1", Options{
		Timeout: 300 * time.Millisecond,
		port:    agent.port(),
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(table.Neighbors) != 1 {
		t.Fatalf("Neighbors = %+v, want exactly one row", table.Neighbors)
	}
	if table.Neighbors[0].Port != 1 || table.Neighbors[0].ChassisID != "only-row" {
		t.Fatalf("Neighbors[0] = %+v", table.Neighbors[0])
	}
	// The three exception values must never appear as text in the table.
	for _, neighbor := range table.Neighbors {
		for _, text := range []string{neighbor.ChassisID, neighbor.PortID, neighbor.PortDesc, neighbor.SystemName} {
			lowered := strings.ToLower(text)
			if strings.Contains(lowered, "nosuch") || strings.Contains(lowered, "endofmib") {
				t.Errorf("exception value leaked into the table: %q", text)
			}
		}
	}
}

// TestLocalFieldsUseTheProbeResult guards the single GET budget: the probe value
// is reused as the chassis id, so no second request is spent on it.
func TestLocalFieldsUseTheProbeResult(t *testing.T) {
	agent := startFakeAgent(t, referenceMIB())
	if _, err := Fetch(context.Background(), "127.0.0.1", Options{
		Timeout: 300 * time.Millisecond,
		port:    agent.port(),
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// 1 probe + 2 local fields + 4 columns (each column needs one request more
	// than it has rows: the closing GETNEXT).
	limit := int64(1 + 2 + 4 + len(referenceMIB()))
	if got := atomic.LoadInt64(&agent.requests); got > limit {
		t.Errorf("agent served %d requests, want <= %d", got, limit)
	}
}
