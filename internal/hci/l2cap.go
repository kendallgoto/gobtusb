package hci

import "encoding/binary"

// L2CAP channel identifiers (3.A.2.1)
const (
	CIDATT      = 0x0004
	CIDLESignal = 0x0005
	CIDSecurity = 0x0006
)

// L2CAP LE command codes (3.A.4)
const (
	SigConnParamUpdateRequest  = 0x12
	SigConnParamUpdateResponse = 0x13
)

// ConnParamUpdateResponse builds an L2CAP Connection Parameter Update Response
func ConnParamUpdateResponse(identifier byte, result uint16) []byte {
	p := make([]byte, 6)
	p[0] = SigConnParamUpdateResponse
	p[1] = identifier
	binary.LittleEndian.PutUint16(p[2:4], 2) // payload length
	binary.LittleEndian.PutUint16(p[4:6], result)
	return p
}

// ACL packet boundary flags (3.A.3.3.2)
const (
	pbFirstNonFlushable = 0x00 // start of a non-automatically-flushable PDU
	pbContinuing        = 0x01 // continuation fragment
	pbFirstFlushable    = 0x02 // start of an automatically-flushable PDU
)

// EncodeACL frames an L2CAP payload as a single HCI ACL data packet, including
// the leading PacketTypeACLData indicator. Use FragmentACL for fragmentation.
func EncodeACL(handle uint16, cid uint16, payload []byte) []byte {
	out := make([]byte, 9+len(payload))
	out[0] = PacketTypeACLData
	binary.LittleEndian.PutUint16(out[1:3], (handle&0x0FFF)|(pbFirstNonFlushable<<12))
	binary.LittleEndian.PutUint16(out[3:5], uint16(4+len(payload))) // ACL data length
	binary.LittleEndian.PutUint16(out[5:7], uint16(len(payload)))   // L2CAP length
	binary.LittleEndian.PutUint16(out[7:9], cid)                    // L2CAP CID
	copy(out[9:], payload)
	return out
}

// FragmentACL frames an L2CAP payload as one or more HCI ACL data packets,
// fragmented with continuation headers as needed
func FragmentACL(handle uint16, cid uint16, payload []byte, maxData int) [][]byte {
	// The complete L2CAP frame: basic header (length, CID) + payload.
	frame := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint16(frame[0:2], uint16(len(payload)))
	binary.LittleEndian.PutUint16(frame[2:4], cid)
	copy(frame[4:], payload)

	if maxData <= 0 {
		maxData = len(frame)
	}
	var out [][]byte
	pb := uint16(pbFirstNonFlushable)
	for off := 0; off < len(frame); off += maxData {
		chunk := frame[off:min(off+maxData, len(frame))]
		pkt := make([]byte, 5+len(chunk))
		pkt[0] = PacketTypeACLData
		binary.LittleEndian.PutUint16(pkt[1:3], (handle&0x0FFF)|(pb<<12))
		binary.LittleEndian.PutUint16(pkt[3:5], uint16(len(chunk)))
		copy(pkt[5:], chunk)
		out = append(out, pkt)
		pb = pbContinuing
	}
	return out
}

// ACLFragment is a raw HCI ACL data packet before L2CAP reassembly.
type ACLFragment struct {
	Handle uint16
	PB     uint8
	Data   []byte // raw ACL data (a slice of the L2CAP frame)
}

// ParseACLFragment parses an HCI ACL data packet from buf into ACLFragments
func ParseACLFragment(buf []byte) (ACLFragment, error) {
	if len(buf) < 5 || buf[0] != PacketTypeACLData {
		return ACLFragment{}, ErrShortPacket
	}
	hf := binary.LittleEndian.Uint16(buf[1:3])
	aclLen := int(binary.LittleEndian.Uint16(buf[3:5]))
	if len(buf) < 5+aclLen {
		return ACLFragment{}, ErrShortPacket
	}
	return ACLFragment{
		Handle: hf & 0x0FFF,
		PB:     uint8((hf >> 12) & 0x3),
		Data:   buf[5 : 5+aclLen],
	}, nil
}

// Reassembler rebuilds L2CAP frames from a connection's ACL fragments.
type Reassembler struct {
	cid  uint16
	need int
	buf  []byte
}

// Push consumes one ACL fragment. When the fragment completes an L2CAP frame it
// returns the channel ID, the frame payload, and true.
func (r *Reassembler) Push(pb uint8, data []byte) (uint16, []byte, bool) {
	if pb == pbContinuing {
		if r.buf == nil {
			return 0, nil, false // continuation without a start; drop
		}
		r.buf = append(r.buf, data...)
	} else {
		if len(data) < 4 {
			r.reset()
			return 0, nil, false
		}
		r.need = int(binary.LittleEndian.Uint16(data[0:2]))
		r.cid = binary.LittleEndian.Uint16(data[2:4])
		r.buf = append([]byte{}, data[4:]...)
	}
	if len(r.buf) < r.need {
		return 0, nil, false
	}
	cid, payload := r.cid, r.buf[:r.need]
	r.reset()
	return cid, payload, true
}

func (r *Reassembler) reset() {
	r.cid, r.need, r.buf = 0, 0, nil
}

// ACLPacket is a parsed HCI ACL data packet.
type ACLPacket struct {
	Handle  uint16
	PB      uint8
	CID     uint16
	Payload []byte // L2CAP payload (or the ATT PDU when CID == CIDATT)
}

// ParseACL parses an HCI ACL data packet without fragment reassembly
func ParseACL(buf []byte) (ACLPacket, error) {
	if len(buf) < 9 || buf[0] != PacketTypeACLData {
		return ACLPacket{}, ErrShortPacket
	}
	hf := binary.LittleEndian.Uint16(buf[1:3])
	aclLen := int(binary.LittleEndian.Uint16(buf[3:5]))
	if len(buf) < 5+aclLen || aclLen < 4 {
		return ACLPacket{}, ErrShortPacket
	}
	l2capLen := int(binary.LittleEndian.Uint16(buf[5:7]))
	cid := binary.LittleEndian.Uint16(buf[7:9])
	if len(buf) < 9+l2capLen {
		return ACLPacket{}, ErrShortPacket
	}
	return ACLPacket{
		Handle:  hf & 0x0FFF,
		PB:      uint8((hf >> 12) & 0x3),
		CID:     cid,
		Payload: buf[9 : 9+l2capLen],
	}, nil
}
