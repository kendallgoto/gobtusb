package hci

import (
	"encoding/binary"
	"errors"
)

// ErrShortPacket is returned when a buffer is too small to hold the packet it
// claims to be.
var ErrShortPacket = errors.New("hci: short packet")

// HCI event codes (4.E.7.7)
const (
	EventDisconnectionComplete    = 0x05
	EventCommandComplete          = 0x0E
	EventCommandStatus            = 0x0F
	EventNumberOfCompletedPackets = 0x13
	EventLEMeta                   = 0x3E
)

// Subevent codes (4.E.7.7.65)
const (
	LEConnectionComplete = 0x01
	LEAdvertisingReport  = 0x02
)

// Event is a parsed HCI event packet (without the leading PacketTypeEvent
// indicator byte).
type Event struct {
	Code   uint8
	Params []byte
}

// ParseEvent parses an HCI event from buf, starting with the
// PacketTypeEvent indicator byte.
func ParseEvent(buf []byte) (*Event, error) {
	if len(buf) < 3 || buf[0] != PacketTypeEvent {
		return nil, ErrShortPacket
	}
	length := int(buf[2])
	if len(buf) < 3+length {
		return nil, ErrShortPacket
	}
	return &Event{Code: buf[1], Params: buf[3 : 3+length]}, nil
}

// CommandComplete holds the fields of a Command Complete event.
type CommandComplete struct {
	NumPackets uint8
	Opcode     uint16
	Status     uint8 // first return parameter for status-returning commands
	Return     []byte
}

// CommandComplete decodes the event as a Command Complete event.
func (e Event) CommandComplete() (*CommandComplete, error) {
	if e.Code != EventCommandComplete || len(e.Params) < 3 {
		return nil, ErrShortPacket
	}
	cc := &CommandComplete{
		NumPackets: e.Params[0],
		Opcode:     binary.LittleEndian.Uint16(e.Params[1:3]),
		Return:     e.Params[3:],
	}
	if len(cc.Return) > 0 {
		cc.Status = cc.Return[0]
	}
	return cc, nil
}

// CommandStatus holds the fields of a Command Status event.
type CommandStatus struct {
	Status     uint8
	NumPackets uint8
	Opcode     uint16
}

// CommandStatus decodes the event as a Command Status event.
func (e Event) CommandStatus() (CommandStatus, error) {
	if e.Code != EventCommandStatus || len(e.Params) < 4 {
		return CommandStatus{}, ErrShortPacket
	}
	return CommandStatus{
		Status:     e.Params[0],
		NumPackets: e.Params[1],
		Opcode:     binary.LittleEndian.Uint16(e.Params[2:4]),
	}, nil
}

// CompletedPackets reports how many ACL packets the controller has finished
// transmitting on one connection, freeing that many controller buffers.
type CompletedPackets struct {
	Handle uint16
	Count  uint16
}

// NumberOfCompletedPackets decodes a NumberOfCompletedPackets event (4.e.7.7.19)
func (e Event) NumberOfCompletedPackets() ([]CompletedPackets, error) {
	if e.Code != EventNumberOfCompletedPackets || len(e.Params) < 1 {
		return nil, ErrShortPacket
	}
	n := int(e.Params[0])
	if len(e.Params) < 1+4*n {
		return nil, ErrShortPacket
	}
	out := make([]CompletedPackets, n)
	for i := range n {
		out[i].Handle = binary.LittleEndian.Uint16(e.Params[1+2*i:]) & 0x0FFF
		out[i].Count = binary.LittleEndian.Uint16(e.Params[1+2*n+2*i:])
	}
	return out, nil
}

// LESubevent returns the subevent code of an LE meta event.
func (e Event) LESubevent() (uint8, error) {
	if e.Code != EventLEMeta || len(e.Params) < 1 {
		return 0, ErrShortPacket
	}
	return e.Params[0], nil
}

// Advertising report event types (4.E.7.7.65.2).
const (
	AdvInd        = 0x00 // connectable, scannable undirected
	AdvDirectInd  = 0x01
	AdvScanInd    = 0x02 // scannable undirected
	AdvNonconnInd = 0x03
	ScanRsp       = 0x04
)

// AdvertisingReport is a single report inside an LE Advertising Report event.
type AdvertisingReport struct {
	EventType uint8
	AddrType  uint8
	Addr      [6]byte // todo: use custom type?
	Data      []byte
	RSSI      int8
}

// AdvertisingReports decodes the event as an LE Advertising Report event,
// returning every report it contains.
func (e Event) AdvertisingReports() ([]AdvertisingReport, error) {
	sub, err := e.LESubevent()
	if err != nil || sub != LEAdvertisingReport {
		return nil, ErrShortPacket
	}
	p := e.Params
	if len(p) < 2 {
		return nil, ErrShortPacket
	}
	num := int(p[1])
	p = p[2:]
	reports := make([]AdvertisingReport, 0, num)
	for range num {
		// Each report: event type, addr type, addr[6], data len, data[len], rssi.
		if len(p) < 9 {
			return nil, ErrShortPacket
		}
		dataLen := int(p[8])
		if len(p) < 9+dataLen+1 {
			return nil, ErrShortPacket
		}
		var r AdvertisingReport
		r.EventType = p[0]
		r.AddrType = p[1]
		copy(r.Addr[:], p[2:8])
		r.Data = p[9 : 9+dataLen]
		r.RSSI = int8(p[9+dataLen])
		reports = append(reports, r)
		p = p[9+dataLen+1:]
	}
	return reports, nil
}

// ConnectionComplete holds the fields of an LE Connection Complete event.
type ConnectionComplete struct {
	Status   uint8
	Handle   uint16
	Role     uint8
	PeerType uint8
	Peer     [6]byte
}

// ConnectionComplete decodes the event as an LE Connection Complete event.
func (e Event) ConnectionComplete() (ConnectionComplete, error) {
	sub, err := e.LESubevent()
	if err != nil || sub != LEConnectionComplete {
		return ConnectionComplete{}, ErrShortPacket
	}
	p := e.Params
	if len(p) < 16 {
		return ConnectionComplete{}, ErrShortPacket
	}
	cc := ConnectionComplete{
		Status:   p[1],
		Handle:   binary.LittleEndian.Uint16(p[2:4]) & 0x0FFF,
		Role:     p[4],
		PeerType: p[5],
	}
	copy(cc.Peer[:], p[6:12])
	return cc, nil
}
