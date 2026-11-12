package lldp

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// OIDs of the standard LLDP MIB (IEEE 802.1AB, implemented as 1.0.8802.1.1.2).
//
// Every value below was read from a live device (192.168.127.4, an EOM-106) and
// compared row by row with the LLDP page of MXConfigCS; see
// docs/PROTOCOL_SPEC.md §10.1 and §10.2.
const (
	// oidChassisIDSubtype is lldpLocChassisIdSubtype. Its value is always 4
	// (macAddress) on the measured devices and is therefore only used as the
	// liveness probe, never displayed.
	oidChassisIDSubtype = "1.0.8802.1.1.2.1.3.1.0"
	// oidChassisID is lldpLocChassisId, e.g. "0090e80005d0".
	oidChassisID = "1.0.8802.1.1.2.1.3.2.0"
	// oidSystemName is lldpLocSysName, e.g. "Managed Redundant Switch 00007".
	oidSystemName = "1.0.8802.1.1.2.1.3.3.0"
	// oidSystemDesc is lldpLocSysDesc, e.g. "EOM-106".
	oidSystemDesc = "1.0.8802.1.1.2.1.3.4.0"
	// oidRemBase is lldpRemTable.1.1 - the column OID is oidRemBase + "." + col.
	oidRemBase = "1.0.8802.1.1.2.1.4.1.1"
)

// The four neighbour columns the panel shows (PROTOCOL_SPEC.md §10.2).
const (
	// columnChassisID is lldpRemChassisId -> 邻居 ID.
	columnChassisID = 5
	// columnPortID is lldpRemPortId -> 邻居端口.
	columnPortID = 7
	// columnPortDesc is lldpRemPortDesc -> 描述.
	columnPortDesc = 8
	// columnSystemName is lldpRemSysName -> 系统名.
	columnSystemName = 9
)

// neighborColumns is the walk order. The order only affects the request
// sequence, never the result.
var neighborColumns = []int{columnChassisID, columnPortID, columnPortDesc, columnSystemName}

// Neighbor is one row of the LLDP neighbour panel.
//
// Port is the LOCAL port of the queried switch, not the peer port: the index of
// lldpRemTable is TimeMark.LocalPortNum.RemIndex and the second segment is the
// port the neighbour is seen on (PROTOCOL_SPEC.md §10.3). Every text field may
// be empty when the device does not publish that column.
type Neighbor struct {
	// Port is the local port number, e.g. 4.
	Port int
	// ChassisID is the neighbour chassis id, e.g. "0090e8d65985".
	ChassisID string
	// PortID is the neighbour port id, e.g. "7" or "c85b76f2204a".
	PortID string
	// PortDesc is the neighbour port description, e.g. "100FX,SC,Single,40.".
	PortDesc string
	// SystemName is the neighbour system name, e.g. "Managed Redundant Switch".
	SystemName string
}

// Table is the LLDP view of one device: its own identity plus its neighbours.
type Table struct {
	// ChassisID is the local chassis id, e.g. "0090e80005d0".
	ChassisID string
	// SystemName is the local system name.
	SystemName string
	// SystemDesc is the local system description, which MOXA uses for the
	// model name, e.g. "EOM-106".
	SystemDesc string
	// Neighbors is sorted by Port ascending, one entry per local port.
	Neighbors []Neighbor
}

// columnValue is one decoded varbind of a column walk.
//
// Index is the raw OID suffix ("396.2.5") so that the merge step can decide
// itself whether the suffix is usable - a malformed index is dropped there
// instead of panicking in the walk.
type columnValue struct {
	Column int
	Index  string
	Value  string
}

// Fetch reads the LLDP table of one device over SNMPv2c.
//
// The call is bounded by two rules from PROTOCOL_SPEC.md §10.5:
//
//  1. It first GETs lldpLocChassisId. A device without an SNMP agent (an NPort
//     6450 for instance) silently drops the request, so the probe times out
//     after at most 2 x 500 ms and Fetch returns ErrNoSNMP. Only a device that
//     answered is walked - probing four OIDs plus seven columns first would
//     cost a dozen timeouts on such a device.
//  2. Every column walk stops after maxWalkRows rows.
//
// A device that answers SNMP without publishing any neighbour yields a Table
// with an empty Neighbors slice and a nil error.
func Fetch(ctx context.Context, ip string, opts Options) (*Table, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	settings := opts.normalized()
	address, err := agentAddress(ip, settings.port)
	if err != nil {
		return nil, err
	}
	conn, err := dial(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("%w：无法建立 UDP 连接（%v）", ErrNoSNMP, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	session := &client{
		conn:      conn,
		community: settings.Community,
		timeout:   settings.Timeout,
		retries:   defaultRetries,
	}

	table := &Table{}

	// Step 1: the liveness probe. Its result is also the local chassis id.
	chassis, answered, err := session.get(oidChassisID)
	if err != nil {
		// Nothing came back at all: no SNMP agent, or the community is wrong.
		return nil, ErrNoSNMP
	}
	if answered {
		table.ChassisID = chassis.String()
	}

	// Step 2: the remaining local fields. Each is best effort: a device that
	// answers the probe but not these OIDs simply leaves the field empty.
	if name, ok, err := session.get(oidSystemName); err == nil && ok {
		table.SystemName = name.String()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if desc, ok, err := session.get(oidSystemDesc); err == nil && ok {
		table.SystemDesc = desc.String()
	}

	// Step 3: the neighbour table, one walk per column.
	values := make([]columnValue, 0, 32)
	for _, column := range neighborColumns {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		values = append(values, session.walk(column)...)
	}
	table.Neighbors = buildNeighbors(values)
	return table, nil
}

// walk reads one column of lldpRemTable.
//
// The walk stops on the first condition that ends a column: an SNMPv2c
// exception value, an OID outside the column subtree, an OID that does not
// advance (defensive, a buggy agent could repeat itself) or the row cap. A
// timeout in the middle of a column keeps the rows collected so far, so a slow
// device still shows a partial table instead of nothing.
func (c *client) walk(column int) []columnValue {
	base := fmt.Sprintf("%s.%d", oidRemBase, column)
	current := base
	out := make([]columnValue, 0, 8)
	for len(out) < maxWalkRows {
		varbind, end, err := c.getNext(current)
		if err != nil || end {
			break
		}
		value, ok := nextColumnValue(column, base, varbind.OID, varbind.Value)
		if !ok {
			break
		}
		// A GETNEXT must advance. A repeated OID would loop forever, and an OID
		// that only looks "smaller" as a string (….10.1 after ….9.1) is a
		// perfectly valid next row, so only equality is treated as no advance.
		if varbind.OID == current {
			break
		}
		out = append(out, value)
		current = varbind.OID
	}
	return out
}

// nextColumnValue validates one walk step and renders it as a column value.
//
// It is a pure function so the unit tests can feed it every corner case: an
// exception value (0x80/0x81/0x82) or a NULL ends the column, and an OID that
// left the subtree belongs to the next column and therefore ends this one too
// (PROTOCOL_SPEC.md §10.5: "noSuch* must never be put into the table as text").
func nextColumnValue(column int, base, oid string, value snmpValue) (columnValue, bool) {
	if value.isEmpty() {
		return columnValue{}, false
	}
	prefix := base + "."
	if !strings.HasPrefix(oid, prefix) {
		return columnValue{}, false
	}
	suffix := oid[len(prefix):]
	if suffix == "" {
		return columnValue{}, false
	}
	return columnValue{Column: column, Index: suffix, Value: value.String()}, true
}

// parseIndex decodes the index of one lldpRemTable row.
//
// The index is TimeMark.LocalPortNum.RemIndex; the middle segment is the local
// port number shown in the 端口 column (PROTOCOL_SPEC.md §10.3). The first
// segment changes with every LLDP update and must never be used as a port.
//
// Anything but exactly three non negative segments - or a port number of zero -
// is rejected so that one damaged row cannot shift the whole table.
func parseIndex(index string) (port int, remIndex int, ok bool) {
	fields := strings.Split(index, ".")
	if len(fields) != 3 {
		return 0, 0, false
	}
	values := [3]int{}
	for position, field := range fields {
		if field == "" {
			return 0, 0, false
		}
		parsed, err := strconv.Atoi(field)
		if err != nil || parsed < 0 {
			return 0, 0, false
		}
		values[position] = parsed
	}
	if values[1] <= 0 {
		return 0, 0, false
	}
	return values[1], values[2], true
}

// buildNeighbors merges the per column walks into one neighbour per local port.
//
// Row identity inside lldpRemTable is the full index, but the panel shows one
// line per port, so rows of the same port are reduced to the one with the
// smallest RemIndex (PROTOCOL_SPEC.md §10.3). Rows whose index cannot be parsed
// are dropped, and a column that the device did not answer stays empty rather
// than borrowing a value from another row.
func buildNeighbors(values []columnValue) []Neighbor {
	// Group the values by index first: rows[ index ][ column ] = text.
	rows := make(map[string]map[int]string, len(values))
	indexes := make([]string, 0, len(values))
	for _, value := range values {
		if value.Index == "" {
			continue
		}
		cells, ok := rows[value.Index]
		if !ok {
			cells = make(map[int]string, len(neighborColumns))
			rows[value.Index] = cells
			indexes = append(indexes, value.Index)
		}
		cells[value.Column] = value.Value
	}
	// A deterministic order keeps the choice of the surviving row reproducible
	// (GOGC/GC order of map iteration must never show up in the table).
	sort.SliceStable(indexes, func(i, j int) bool { return indexLess(indexes[i], indexes[j]) })

	chosen := make(map[int]string, len(indexes))
	chosenRem := make(map[int]int, len(indexes))
	for _, index := range indexes {
		port, remIndex, ok := parseIndex(index)
		if !ok {
			continue
		}
		if previous, exists := chosenRem[port]; exists && previous <= remIndex {
			continue
		}
		chosen[port] = index
		chosenRem[port] = remIndex
	}

	neighbors := make([]Neighbor, 0, len(chosen))
	for port, index := range chosen {
		cells := rows[index]
		neighbors = append(neighbors, Neighbor{
			Port:       port,
			ChassisID:  cells[columnChassisID],
			PortID:     cells[columnPortID],
			PortDesc:   cells[columnPortDesc],
			SystemName: cells[columnSystemName],
		})
	}
	sort.SliceStable(neighbors, func(i, j int) bool { return neighbors[i].Port < neighbors[j].Port })
	return neighbors
}

// indexLess orders two OID index suffixes segment by segment.
//
// Both suffixes are validated by parseIndex before they are compared with the
// meaningful outcome, so this only has to be a total order that keeps the
// smallest RemIndex first for equal ports: numeric when possible, textual
// otherwise.
func indexLess(left, right string) bool {
	leftFields := strings.Split(left, ".")
	rightFields := strings.Split(right, ".")
	limit := len(leftFields)
	if len(rightFields) < limit {
		limit = len(rightFields)
	}
	for position := 0; position < limit; position++ {
		leftValue, leftErr := strconv.Atoi(leftFields[position])
		rightValue, rightErr := strconv.Atoi(rightFields[position])
		if leftErr == nil && rightErr == nil {
			if leftValue != rightValue {
				return leftValue < rightValue
			}
			continue
		}
		if leftFields[position] != rightFields[position] {
			return leftFields[position] < rightFields[position]
		}
	}
	return len(leftFields) < len(rightFields)
}
