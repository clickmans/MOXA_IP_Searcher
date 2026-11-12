package discovery

// Fallback discovery ports.
//
// None of these ports produced a reply in the reference capture, but every
// official tool still sends the frames, so the tool sends them as well and
// accepts anything that answers (PROTOCOL_SPEC.md §6).
const (
	// port29168 is used by DSU and MXConfigCS with the same 8 byte frame as
	// UDP/4800.
	port29168 = 29168
	// port1029 is used by NPort Administrator and MXConfigCS with two
	// different 6 byte frames.
	port1029 = 1029
	// port22222 is used by EDSConfig for the older EDS family ("STR_BCAST").
	port22222 = 22222
)

// request29168 is byte identical to the 0x01 search frame of UDP/4800.
var request29168 = []byte{0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}

// request1029NPort is the NPort Administrator search frame (PROTOCOL_SPEC.md §6).
var request1029NPort = []byte{0x02, 0x00, 0x00, 0x06, 0x00, 0x00}

// request1029MXConfig is the MXConfigCS search frame (PROTOCOL_SPEC.md §6).
var request1029MXConfig = []byte{0x49, 0x00, 0x00, 0x06, 0x00, 0x00}

// request22222 is the 28 byte EDSConfig legacy broadcast frame:
// "STR_BCAST" + padding + "RQ1.0.0" + trailer, copied verbatim from the capture.
var request22222 = []byte{
	0x53, 0x54, 0x52, 0x5f, 0x42, 0x43, 0x41, 0x53, // "STR_BCAS"
	0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // "T" + padding
	0x52, 0x51, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x00, // "RQ1.0.0"
	0x00, 0x1c, 0x64, 0x31, // trailer
}

// protocol29168 is the DSU/MXConfigCS fallback port.
func protocol29168() *protocolSpec {
	return &protocolSpec{
		Port:       port29168,
		Name:       ProtoName29168,
		ListenPort: 0,
		Build:      staticRequest(request29168),
		Parse:      fallbackParser(ProtoName29168),
	}
}

// protocol1029 is the NPort Administrator / MXConfigCS fallback port. Both
// observed request variants are sent because the tools use whichever one their
// firmware family understands.
func protocol1029() *protocolSpec {
	return &protocolSpec{
		Port:       port1029,
		Name:       ProtoName1029,
		ListenPort: 0,
		Build: func(adapterCtx) [][]byte {
			out := make([][]byte, 0, 2)
			for _, frame := range [][]byte{request1029NPort, request1029MXConfig} {
				copied := make([]byte, len(frame))
				copy(copied, frame)
				out = append(out, copied)
			}
			return out
		},
		Parse: fallbackParser(ProtoName1029),
	}
}

// protocol22222 is the legacy EDS broadcast port. It is send only in practice;
// should a device answer, the reply is reported with the source IP.
func protocol22222() *protocolSpec {
	return &protocolSpec{
		Port:       port22222,
		Name:       ProtoName22222,
		ListenPort: 0,
		Build:      staticRequest(request22222),
		Parse:      fallbackParser(ProtoName22222),
	}
}
