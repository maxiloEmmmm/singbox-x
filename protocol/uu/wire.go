package uu

import "google.golang.org/protobuf/encoding/protowire"

const (
	wireSYN uint64 = iota
	wireFIN
	wireDATA
	wireSYNACK
	wireDATAACK
)

const mapMessage protowire.Number = 27

// mapFrame contains the UU labels and payload for one port-mapped TCP stream.
type mapFrame struct {
	// session and rule identify the controller's mapping.
	session uint64
	// rule is constant for the single configured local mapping.
	rule uint64
	// stream identifies one accepted TCP connection.
	stream uint64
	// kind is one of SYN, SYN_ACK, DATA, FIN or DATA_ACK.
	kind uint64
	// payload is JSON for SYN/SYN_ACK and bytes for DATA.
	payload []byte
}

// appendNumber writes a varint field, e.g. field 1 value 9 -> capture_type 9.
func appendNumber(buf []byte, field protowire.Number, value uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(buf, field, protowire.VarintType), value)
}

// appendBytes writes a length-delimited field, e.g. field 5 -> data bytes.
func appendBytes(buf []byte, field protowire.Number, value []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(buf, field, protowire.BytesType), value)
}

// connectOptions encodes the observed port-map request, e.g. field 1 -> capture type 9.
func connectOptions(deviceID string) []byte {
	buf := appendNumber(nil, 1, 9)
	buf = appendNumber(buf, 8, 3)
	buf = appendBytes(buf, 9, []byte(deviceID))
	buf = appendNumber(buf, 10, 1)
	return appendBytes(buf, 12, []byte(viewerVersion))
}

// encodeFrame wraps a flow message, e.g. stream 25 DATA -> UU message field 27.
func encodeFrame(frame mapFrame) []byte {
	// Put metadata in a stack-sized buffer, then copy the TCP payload only once.
	var prefix [64]byte
	payload := appendNumber(prefix[:0], 1, frame.session)
	payload = appendNumber(payload, 2, frame.rule)
	payload = appendNumber(payload, 3, frame.stream)
	payload = appendNumber(payload, 4, frame.kind)
	if len(frame.payload) > 0 {
		payload = protowire.AppendTag(payload, 5, protowire.BytesType)
		payload = protowire.AppendVarint(payload, uint64(len(frame.payload)))
	}
	out := protowire.AppendTag(make([]byte, 0, len(payload)+len(frame.payload)+8), mapMessage, protowire.BytesType)
	out = protowire.AppendVarint(out, uint64(len(payload)+len(frame.payload)))
	out = append(out, payload...)
	return append(out, frame.payload...)
}

// decodeFrame extracts a flow from field 27, e.g. other protobuf messages -> false.
func decodeFrame(data []byte) (mapFrame, bool) {
	raw, ok := wireBytes(data, mapMessage)
	if !ok {
		return mapFrame{}, false
	}
	var result mapFrame
	for len(raw) > 0 {
		number, typ, start := protowire.ConsumeTag(raw)
		if start < 0 {
			return mapFrame{}, false
		}
		count := protowire.ConsumeFieldValue(number, typ, raw[start:])
		if count < 0 {
			return mapFrame{}, false
		}
		if typ == protowire.VarintType {
			value, _ := protowire.ConsumeVarint(raw[start:])
			switch number {
			case 1:
				result.session = value
			case 2:
				result.rule = value
			case 3:
				result.stream = value
			case 4:
				result.kind = value
			}
		}
		if number == 5 && typ == protowire.BytesType {
			result.payload, _ = protowire.ConsumeBytes(raw[start:])
		}
		raw = raw[start+count:]
	}
	return result, result.session != 0 && result.rule != 0 && result.stream != 0
}

// wireBytes returns one length-delimited field, e.g. envelope field 3 -> SimpleAction.
func wireBytes(raw []byte, wanted protowire.Number) ([]byte, bool) {
	for len(raw) > 0 {
		number, kind, start := protowire.ConsumeTag(raw)
		if start < 0 {
			return nil, false
		}
		length := protowire.ConsumeFieldValue(number, kind, raw[start:])
		if length < 0 {
			return nil, false
		}
		if number == wanted && kind == protowire.BytesType {
			bytes, _ := protowire.ConsumeBytes(raw[start:])
			return bytes, true
		}
		raw = raw[start+length:]
	}
	return nil, false
}

// wireNumber returns one varint field, e.g. an omitted protobuf default -> 0.
func wireNumber(raw []byte, wanted protowire.Number) uint64 {
	for len(raw) > 0 {
		number, kind, start := protowire.ConsumeTag(raw)
		if start < 0 {
			return 0
		}
		length := protowire.ConsumeFieldValue(number, kind, raw[start:])
		if length < 0 {
			return 0
		}
		if number == wanted && kind == protowire.VarintType {
			value, _ := protowire.ConsumeVarint(raw[start:])
			return value
		}
		raw = raw[start+length:]
	}
	return 0
}
