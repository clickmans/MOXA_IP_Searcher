// Package lldp reads the LLDP neighbour table of a MOXA device over SNMPv2c.
//
// The transport was proven by the capture "lldp.pcapng" (the LLDP page of
// MXConfigCS): plain SNMPv2c, community "public", UDP/161 and the standard
// LLDP MIB 1.0.8802.1.1.2 - not a vendor private protocol. See
// docs/PROTOCOL_SPEC.md §10 for the OID table and the measured values.
//
// Only the standard library is used: the BER encoder is written by hand because
// encoding/asn1 cannot express an SNMP PDU (context specific tags, implicit
// tags, empty values) without fighting the package.
package lldp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Default transport parameters (PROTOCOL_SPEC.md §10.5).
const (
	// DefaultCommunity is the read-only community every MOXA switch ships with.
	DefaultCommunity = "public"
	// DefaultTimeout bounds one request/reply round trip.
	DefaultTimeout = 500 * time.Millisecond
	// defaultRetries is the number of retransmissions of one request. One retry
	// keeps the worst case of a device without an SNMP agent at
	// 500 ms x 2 = 1 s, well inside the 1.2 s budget of the UI.
	defaultRetries = 1
	// snmpPort is the standard SNMP agent port.
	snmpPort = 161
	// maxPacketSize is the receive buffer. The largest reply measured on a
	// MOXA switch carries one varbind and stays below 300 bytes.
	maxPacketSize = 4096
	// maxWalkRows caps one column walk so that a device answering an endless
	// subtree cannot stall the client (PROTOCOL_SPEC.md §10.5).
	maxWalkRows = 64
)

// ErrNoSNMP reports a device that does not answer SNMP at all.
//
// It is the expected answer of products without an SNMP agent - the NPort 6450
// serial server is one - and must be treated as "LLDP unavailable", never as a
// failure of the discovery result (PROTOCOL_SPEC.md §10.5).
var ErrNoSNMP = errors.New("设备未响应 SNMP")

// BER tags used by SNMPv2c (X.690 universal tags plus the SNMP exceptions).
const (
	tagInteger        = 0x02
	tagOctetString    = 0x04
	tagNull           = 0x05
	tagOID            = 0x06
	tagSequence       = 0x30
	tagIPAddress      = 0x40
	tagCounter32      = 0x41
	tagGauge32        = 0x42
	tagTimeTicks      = 0x43
	tagCounter64      = 0x46
	tagNoSuchObject   = 0x80
	tagNoSuchInstance = 0x81
	tagEndOfMibView   = 0x82
)

// SNMP PDU tags.
const (
	pduGetRequest     = 0xA0
	pduGetNextRequest = 0xA1
	pduGetResponse    = 0xA2
)

// snmpVersion2c is the version field value of SNMPv2c (0 = v1, 1 = v2c, 3 = v3).
const snmpVersion2c = 1

// Options tunes one Fetch call. The zero value means "500 ms, public, port 161".
type Options struct {
	// Timeout bounds one request/reply round trip (default DefaultTimeout).
	Timeout time.Duration
	// Community is the SNMP read community (default DefaultCommunity).
	Community string
	// port overrides the agent port. It stays unexported on purpose: it only
	// exists so the unit tests can point the client at a local sink instead of
	// a real device. Zero means the standard port 161.
	port int
}

// normalized fills in the documented defaults.
func (o Options) normalized() Options {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Community == "" {
		o.Community = DefaultCommunity
	}
	if o.port <= 0 || o.port > 0xFFFF {
		o.port = snmpPort
	}
	return o
}

// agentAddress validates ip and renders the "ip:port" dial target.
func agentAddress(ip string, port int) (string, error) {
	trimmed := strings.TrimSpace(ip)
	parsed := net.ParseIP(trimmed)
	if parsed == nil {
		return "", fmt.Errorf("无效的 IP 地址: %q", ip)
	}
	ipv4 := parsed.To4()
	if ipv4 == nil {
		return "", fmt.Errorf("不是 IPv4 地址: %q", ip)
	}
	return net.JoinHostPort(ipv4.String(), strconv.Itoa(port)), nil
}

// snmpValue is one decoded varbind value: its BER tag plus the raw content.
//
// Keeping the raw bytes instead of decoding eagerly means an unknown or large
// value costs nothing and an exception value (0x80/0x81/0x82) is never quoted
// as if it were text (PROTOCOL_SPEC.md §10.5).
type snmpValue struct {
	tag byte
	raw []byte
}

// isEnd reports whether the value terminates a walk: the three SNMPv2c
// exceptions noSuchObject(0x80) / noSuchInstance(0x81) / endOfMibView(0x82).
func (v snmpValue) isEnd() bool {
	return v.tag == tagNoSuchObject || v.tag == tagNoSuchInstance || v.tag == tagEndOfMibView
}

// isEmpty reports whether the value carries no data at all.
func (v snmpValue) isEmpty() bool {
	return v.isEnd() || v.tag == tagNull || len(v.raw) == 0
}

// String renders the value the way MXConfigCS shows it.
//
// An OCTET STRING is printed as text only when every byte is printable ASCII,
// otherwise as lower case hex on one line - which is what turns the six raw
// bytes 00 90 E8 D6 59 85 into the "0090e8d65985" that MXConfig displays for a
// MAC based chassis id, while "Managed Redundant Switch 00007" stays text.
func (v snmpValue) String() string {
	switch v.tag {
	case tagInteger:
		return strconv.FormatInt(signedInteger(v.raw), 10)
	case tagOctetString:
		if isPrintableASCII(v.raw) {
			return string(v.raw)
		}
		return hex.EncodeToString(v.raw)
	case tagOID:
		return decodeOID(v.raw)
	case tagIPAddress:
		if len(v.raw) == 4 {
			return net.IP(v.raw).String()
		}
		return hex.EncodeToString(v.raw)
	case tagCounter32, tagGauge32, tagTimeTicks, tagCounter64:
		return strconv.FormatUint(unsignedInteger(v.raw), 10)
	case tagNull, tagNoSuchObject, tagNoSuchInstance, tagEndOfMibView:
		return ""
	default:
		return hex.EncodeToString(v.raw)
	}
}

// snmpVarBind is one decoded OID/value pair.
type snmpVarBind struct {
	OID   string
	Value snmpValue
}

// snmpResponse is one decoded SNMP message.
type snmpResponse struct {
	Version     int64
	Community   string
	PDUTag      byte
	RequestID   int64
	ErrorStatus int64
	ErrorIndex  int64
	VarBinds    []snmpVarBind
}

// encodeLength renders a BER definite length (short form below 128, else the
// long form with the minimum number of length octets).
func encodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var raw []byte
	for value := length; value > 0; value >>= 8 {
		raw = append([]byte{byte(value & 0xFF)}, raw...)
	}
	out := make([]byte, 0, len(raw)+1)
	out = append(out, byte(0x80|len(raw)))
	return append(out, raw...)
}

// encodeTLV wraps content into a tag/length/value triple.
func encodeTLV(tag byte, content []byte) []byte {
	out := make([]byte, 0, len(content)+4)
	out = append(out, tag)
	out = append(out, encodeLength(len(content))...)
	return append(out, content...)
}

// encodeInteger renders a BER INTEGER with the minimal two's complement length.
func encodeInteger(value int64) []byte {
	var raw []byte
	if value >= 0 {
		raw = []byte{byte(value & 0xFF)}
		for shifted := value >> 8; shifted > 0; shifted >>= 8 {
			raw = append([]byte{byte(shifted & 0xFF)}, raw...)
		}
		if raw[0]&0x80 != 0 {
			raw = append([]byte{0x00}, raw...)
		}
	} else {
		raw = []byte{byte(value & 0xFF)}
		for shifted := value >> 8; shifted < -1; shifted >>= 8 {
			raw = append([]byte{byte(shifted & 0xFF)}, raw...)
		}
		if raw[0]&0x80 == 0 {
			raw = append([]byte{0xFF}, raw...)
		}
	}
	return encodeTLV(tagInteger, raw)
}

// encodeOID renders a dotted OID as BER OBJECT IDENTIFIER content.
//
// The first two arcs are folded into one octet (40*arc0 + arc1) and every
// remaining arc uses base-128 with the continuation bit. Example:
// 1.0.8802.1.1.2.1.3.2.0 -> 06 0a 28 c4 62 01 01 02 01 03 02 00.
func encodeOID(dotted string) ([]byte, error) {
	trimmed := strings.TrimSpace(dotted)
	if trimmed == "" {
		return nil, errors.New("空 OID")
	}
	fields := strings.Split(trimmed, ".")
	arcs := make([]uint64, 0, len(fields))
	for _, field := range fields {
		if field == "" {
			return nil, fmt.Errorf("非法 OID: %q", dotted)
		}
		value, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("非法 OID 段 %q: %w", field, err)
		}
		arcs = append(arcs, value)
	}
	if len(arcs) < 2 {
		return nil, fmt.Errorf("OID 至少需要两段: %q", dotted)
	}
	if arcs[0] > 2 {
		return nil, fmt.Errorf("非法 OID 首段 %d", arcs[0])
	}
	if arcs[0] < 2 && arcs[1] > 39 {
		return nil, fmt.Errorf("非法 OID 第二段 %d", arcs[1])
	}
	content := make([]byte, 0, 16)
	content = append(content, byte(arcs[0]*40+arcs[1]))
	for _, arc := range arcs[2:] {
		content = append(content, base128(arc)...)
	}
	return encodeTLV(tagOID, content), nil
}

// base128 renders one sub identifier in base 128 with continuation bits.
func base128(value uint64) []byte {
	chunk := []byte{byte(value & 0x7F)}
	value >>= 7
	for value > 0 {
		chunk = append([]byte{byte(value&0x7F) | 0x80}, chunk...)
		value >>= 7
	}
	return chunk
}

// encodeRequest builds one complete SNMPv2c message with one varbind.
//
// Shape (all lengths BER encoded):
//
//	SEQUENCE { INTEGER version=1, OCTET STRING community,
//	           PDU { INTEGER request-id, INTEGER error-status=0,
//	                 INTEGER error-index=0,
//	                 SEQUENCE { SEQUENCE { OID, NULL } } } }
func encodeRequest(pduTag byte, requestID int64, community string, oid string) ([]byte, error) {
	encodedOID, err := encodeOID(oid)
	if err != nil {
		return nil, err
	}
	varbind := append(encodedOID, encodeTLV(tagNull, nil)...)
	varBindList := encodeTLV(tagSequence, encodeTLV(tagSequence, varbind))

	pduBody := make([]byte, 0, 24+len(varBindList))
	pduBody = append(pduBody, encodeInteger(requestID)...)
	pduBody = append(pduBody, encodeInteger(0)...) // error-status
	pduBody = append(pduBody, encodeInteger(0)...) // error-index
	pduBody = append(pduBody, varBindList...)

	body := make([]byte, 0, 32+len(pduBody))
	body = append(body, encodeInteger(snmpVersion2c)...)
	body = append(body, encodeTLV(tagOctetString, []byte(community))...)
	body = append(body, encodeTLV(pduTag, pduBody)...)

	return encodeTLV(tagSequence, body), nil
}

// berTLV is one decoded tag/length/value triple.
type berTLV struct {
	tag     byte
	content []byte
}

// readTLV decodes one triple at offset and returns the offset behind it.
//
// The indefinite length form is rejected: SNMP uses definite lengths only, so a
// package that announces it is malformed rather than merely unusual.
func readTLV(data []byte, offset int) (berTLV, int, error) {
	if offset < 0 || offset+2 > len(data) {
		return berTLV{}, 0, errors.New("BER 数据不足")
	}
	tag := data[offset]
	offset++
	length := int(data[offset])
	offset++
	if length&0x80 != 0 {
		count := length & 0x7F
		if count == 0 {
			return berTLV{}, 0, errors.New("不支持 BER 不定长编码")
		}
		if count > 4 || offset+count > len(data) {
			return berTLV{}, 0, errors.New("BER 长度域非法")
		}
		length = 0
		for index := 0; index < count; index++ {
			length = length<<8 | int(data[offset+index])
		}
		offset += count
	}
	if length < 0 || offset+length > len(data) {
		return berTLV{}, 0, errors.New("BER 内容长度越界")
	}
	return berTLV{tag: tag, content: data[offset : offset+length]}, offset + length, nil
}

// signedInteger interprets raw as a big endian two's complement integer.
func signedInteger(raw []byte) int64 {
	if len(raw) == 0 {
		return 0
	}
	if len(raw) > 8 {
		raw = raw[len(raw)-8:]
	}
	value := int64(0)
	for _, b := range raw {
		value = value<<8 | int64(b)
	}
	// Sign extend from the top bit of the first octet: everything above the
	// value's own width becomes 1.
	if raw[0]&0x80 != 0 {
		if shift := uint(8 * len(raw)); shift < 64 {
			value |= ^int64(0) << shift
		}
	}
	return value
}

// unsignedInteger interprets raw as a big endian unsigned integer.
func unsignedInteger(raw []byte) uint64 {
	if len(raw) == 0 {
		return 0
	}
	if len(raw) > 8 {
		raw = raw[len(raw)-8:]
	}
	value := uint64(0)
	for _, b := range raw {
		value = value<<8 | uint64(b)
	}
	return value
}

// decodeOID renders BER OBJECT IDENTIFIER content as a dotted string.
func decodeOID(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	parts := []string{strconv.Itoa(int(raw[0]) / 40), strconv.Itoa(int(raw[0]) % 40)}
	value := uint64(0)
	for _, b := range raw[1:] {
		value = value<<7 | uint64(b&0x7F)
		if b&0x80 == 0 {
			parts = append(parts, strconv.FormatUint(value, 10))
			value = 0
		}
	}
	return strings.Join(parts, ".")
}

// isPrintableASCII reports whether every byte is a printable ASCII character.
func isPrintableASCII(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	for _, b := range raw {
		if b < 0x20 || b > 0x7E {
			return false
		}
	}
	return true
}

// decodeResponse decodes one complete SNMP message.
func decodeResponse(packet []byte) (snmpResponse, error) {
	message, _, err := readTLV(packet, 0)
	if err != nil {
		return snmpResponse{}, err
	}
	if message.tag != tagSequence {
		return snmpResponse{}, fmt.Errorf("顶层不是 SEQUENCE: %#x", message.tag)
	}
	version, next, err := readTLV(message.content, 0)
	if err != nil {
		return snmpResponse{}, err
	}
	if version.tag != tagInteger {
		return snmpResponse{}, fmt.Errorf("version 不是 INTEGER: %#x", version.tag)
	}
	community, next, err := readTLV(message.content, next)
	if err != nil {
		return snmpResponse{}, err
	}
	if community.tag != tagOctetString {
		return snmpResponse{}, fmt.Errorf("community 不是 OCTET STRING: %#x", community.tag)
	}
	pdu, _, err := readTLV(message.content, next)
	if err != nil {
		return snmpResponse{}, err
	}
	if pdu.tag != pduGetResponse {
		return snmpResponse{}, fmt.Errorf("不是 GetResponse: %#x", pdu.tag)
	}

	response := snmpResponse{
		Version:   signedInteger(version.content),
		Community: string(community.content),
		PDUTag:    pdu.tag,
	}

	requestID, pduOffset, err := readTLV(pdu.content, 0)
	if err != nil {
		return snmpResponse{}, err
	}
	errorStatus, pduOffset, err := readTLV(pdu.content, pduOffset)
	if err != nil {
		return snmpResponse{}, err
	}
	errorIndex, pduOffset, err := readTLV(pdu.content, pduOffset)
	if err != nil {
		return snmpResponse{}, err
	}
	varBindList, _, err := readTLV(pdu.content, pduOffset)
	if err != nil {
		return snmpResponse{}, err
	}
	if varBindList.tag != tagSequence {
		return snmpResponse{}, fmt.Errorf("varbind 列表不是 SEQUENCE: %#x", varBindList.tag)
	}
	response.RequestID = signedInteger(requestID.content)
	response.ErrorStatus = signedInteger(errorStatus.content)
	response.ErrorIndex = signedInteger(errorIndex.content)

	offset := 0
	for offset < len(varBindList.content) {
		varbind, nextOffset, err := readTLV(varBindList.content, offset)
		if err != nil {
			return snmpResponse{}, err
		}
		if varbind.tag != tagSequence {
			return snmpResponse{}, fmt.Errorf("varbind 不是 SEQUENCE: %#x", varbind.tag)
		}
		oidTLV, indexOffset, err := readTLV(varbind.content, 0)
		if err != nil {
			return snmpResponse{}, err
		}
		if oidTLV.tag != tagOID {
			return snmpResponse{}, fmt.Errorf("varbind 的 OID 非法: %#x", oidTLV.tag)
		}
		valueTLV, _, err := readTLV(varbind.content, indexOffset)
		if err != nil {
			return snmpResponse{}, err
		}
		response.VarBinds = append(response.VarBinds, snmpVarBind{
			OID:   decodeOID(oidTLV.content),
			Value: snmpValue{tag: valueTLV.tag, raw: valueTLV.content},
		})
		offset = nextOffset
	}
	return response, nil
}

// client is one SNMPv2c session bound to one agent address.
//
// The socket is connected, so the kernel drops replies from any other host -
// together with the request id check this makes a spoofed or stale datagram
// harmless.
type client struct {
	conn      *net.UDPConn
	community string
	timeout   time.Duration
	retries   int
	requestID int64
}

// nextRequestID returns a fresh request id, wrapped inside the 31 bit positive
// range SNMP uses.
func (c *client) nextRequestID() int64 {
	c.requestID++
	if c.requestID <= 0 || c.requestID > 0x7FFFFFFF {
		c.requestID = 1
	}
	return c.requestID
}

// single sends one request and returns the matching varbind.
//
// A reply is accepted only when its request id equals the one that was sent; a
// mismatch is skipped (not treated as a failure) because a datagram of an
// earlier, already timed out request may still be in flight.
func (c *client) single(pduTag byte, oid string) (snmpVarBind, error) {
	requestID := c.nextRequestID()
	packet, err := encodeRequest(pduTag, requestID, c.community, oid)
	if err != nil {
		return snmpVarBind{}, err
	}

	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if _, err := c.conn.Write(packet); err != nil {
			return snmpVarBind{}, err
		}
		if err := c.conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			return snmpVarBind{}, err
		}
		for {
			buffer := make([]byte, maxPacketSize)
			read, err := c.conn.Read(buffer)
			if err != nil {
				lastErr = err
				break
			}
			response, err := decodeResponse(buffer[:read])
			if err != nil {
				// Malformed datagram: ignore it and keep waiting for the answer
				// of this request.
				continue
			}
			if response.RequestID != requestID {
				continue
			}
			if response.ErrorStatus != 0 {
				return snmpVarBind{}, fmt.Errorf("SNMP 错误状态 %d（索引 %d）",
					response.ErrorStatus, response.ErrorIndex)
			}
			if len(response.VarBinds) == 0 {
				return snmpVarBind{}, errors.New("SNMP 应答不含 varbind")
			}
			return response.VarBinds[0], nil
		}
		// Only a timeout is worth retrying; a closed port or a routing error
		// answers immediately for every attempt.
		if netErr, ok := lastErr.(net.Error); !ok || !netErr.Timeout() {
			return snmpVarBind{}, lastErr
		}
	}
	if lastErr == nil {
		lastErr = errors.New("SNMP 请求超时")
	}
	return snmpVarBind{}, lastErr
}

// get performs one GET. The boolean reports whether the agent had a value.
func (c *client) get(oid string) (snmpValue, bool, error) {
	varbind, err := c.single(pduGetRequest, oid)
	if err != nil {
		return snmpValue{}, false, err
	}
	if varbind.Value.isEmpty() {
		return snmpValue{}, false, nil
	}
	return varbind.Value, true, nil
}

// getNext performs one GETNEXT. The boolean reports the end of the MIB view.
func (c *client) getNext(oid string) (snmpVarBind, bool, error) {
	varbind, err := c.single(pduGetNextRequest, oid)
	if err != nil {
		return snmpVarBind{}, false, err
	}
	return varbind, varbind.Value.isEnd(), nil
}

// dial opens the connected UDP socket of one session.
func dial(ctx context.Context, address string) (*net.UDPConn, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp4", address)
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("UDP 连接类型异常")
	}
	return udpConn, nil
}
