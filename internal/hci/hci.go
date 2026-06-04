// Package hci implements part of Bluetooth HCI, L2CAP, and ATT protocols needed
// as a central.
//
// It is transport-agnostic and would work over USB or UART for HCI.
//
// References: Bluetooth Core Specification 5.4, 3.A (L2CAP), 3.F (ATT), 4.E (HCI)
package hci

import "encoding/binary"

// HCI packet type indicators (4.A/4.B)
const (
	PacketTypeCommand = 0x01
	PacketTypeACLData = 0x02
	PacketTypeEvent   = 0x04
)

// HCI command opcodes (OGF<<10 | OCF) used by the central role (4.E.7)
const (
	OpDisconnect            = 0x0406
	OpReset                 = 0x0C03
	OpSetEventMask          = 0x0C01
	OpLESetEventMask        = 0x2001
	OpLEReadBufferSize      = 0x2002
	OpLESetRandomAddress    = 0x2005
	OpLESetScanParameters   = 0x200B
	OpLESetScanEnable       = 0x200C
	OpLECreateConnection    = 0x200D
	OpLECreateConnectionCxl = 0x200E
)

// LEReadBufferSize builds an HCI_LE_Read_Buffer_Size command, which reports the
// maximum ACL data length the controller accepts per packet and how many such
// packets it can buffer.
func LEReadBufferSize() Command { return Command{Opcode: OpLEReadBufferSize} }

// LEBufferSize is the decoded return of HCI_LE_Read_Buffer_Size.
type LEBufferSize struct {
	DataLength uint16 // max ACL data bytes per packet (0: use the BR/EDR buffer)
	NumPackets uint8  // how many ACL packets the controller can hold
}

// ParseLEReadBufferSize decodes the return parameters of an
// HCI_LE_Read_Buffer_Size Command Complete event (status, length, count).
func ParseLEReadBufferSize(ret []byte) (LEBufferSize, error) {
	if len(ret) < 4 {
		return LEBufferSize{}, ErrShortPacket
	}
	return LEBufferSize{
		DataLength: binary.LittleEndian.Uint16(ret[1:3]),
		NumPackets: ret[3],
	}, nil
}

// Disconnect builds an HCI_Disconnect command. The usual reason for a
// host-initiated disconnect is 0x13 (remote user terminated connection).
func Disconnect(handle uint16, reason uint8) Command {
	p := make([]byte, 3)
	binary.LittleEndian.PutUint16(p[0:2], handle)
	p[2] = reason
	return Command{Opcode: OpDisconnect, Params: p}
}

// SetRandomAddress builds an HCI_LE_Set_Random_Address command.
func SetRandomAddress(addr [6]byte) Command {
	return Command{Opcode: OpLESetRandomAddress, Params: addr[:]}
}

// SetEventMask builds an HCI_Set_Event_Mask command.
func SetEventMask(mask uint64) Command {
	p := make([]byte, 8)
	binary.LittleEndian.PutUint64(p, mask)
	return Command{Opcode: OpSetEventMask, Params: p}
}

// LESetEventMask builds an HCI_LE_Set_Event_Mask command
func LESetEventMask(mask uint64) Command {
	p := make([]byte, 8)
	binary.LittleEndian.PutUint64(p, mask)
	return Command{Opcode: OpLESetEventMask, Params: p}
}

// Command is an HCI command packet (without the leading PacketTypeCommand
// indicator byte).
type Command struct {
	Opcode uint16
	Params []byte
}

// Encode returns the command as transport bytes, including the leading
// PacketTypeCommand indicator.
func (c Command) Encode() []byte {
	out := make([]byte, 4+len(c.Params))
	out[0] = PacketTypeCommand
	binary.LittleEndian.PutUint16(out[1:3], c.Opcode)
	out[3] = byte(len(c.Params))
	copy(out[4:], c.Params)
	return out
}

// Reset builds an HCI_Reset command.
func Reset() Command { return Command{Opcode: OpReset} }

// ScanType values for SetScanParameters (4.e.7.8.10)
const (
	ScanTypePassive = 0x00
	ScanTypeActive  = 0x01
)

// Address types used across LE commands and events (4.e.7.8.10)
const (
	AddressPublic = 0x00
	AddressRandom = 0x01
)

// SetScanParameters builds an HCI_LE_Set_Scan_Parameters command. interval and
// window are in units of 0.625 ms.
func SetScanParameters(scanType uint8, interval, window uint16, ownAddrType uint8) Command {
	p := make([]byte, 7)
	p[0] = scanType
	binary.LittleEndian.PutUint16(p[1:3], interval)
	binary.LittleEndian.PutUint16(p[3:5], window)
	p[5] = ownAddrType
	p[6] = 0x00 // accept all advertisements (no filter list)
	return Command{Opcode: OpLESetScanParameters, Params: p}
}

// SetScanEnable builds an HCI_LE_Set_Scan_Enable command.
func SetScanEnable(enable, filterDuplicates bool) Command {
	return Command{
		Opcode: OpLESetScanEnable,
		Params: []byte{b2u(enable), b2u(filterDuplicates)},
	}
}

// CreateConnection builds an HCI_LE_Create_Connection command. The scan and
// connection-interval parameters are in their native HCI units (0.625 ms for
// scan, 1.25 ms for connection interval, 10 ms for supervision timeout). (4.e.7.8.12)
func CreateConnection(scanInterval, scanWindow uint16, peerType uint8, peer [6]byte, ownType uint8, connIntervalMin, connIntervalMax, latency, timeout uint16) Command {
	p := make([]byte, 25)
	binary.LittleEndian.PutUint16(p[0:2], scanInterval)
	binary.LittleEndian.PutUint16(p[2:4], scanWindow)
	p[4] = 0x00 // initiator filter policy: use peer address
	p[5] = peerType
	copy(p[6:12], peer[:])
	p[12] = ownType
	binary.LittleEndian.PutUint16(p[13:15], connIntervalMin)
	binary.LittleEndian.PutUint16(p[15:17], connIntervalMax)
	binary.LittleEndian.PutUint16(p[17:19], latency)
	binary.LittleEndian.PutUint16(p[19:21], timeout)
	// p[21:25] min/max CE length left at 0 (controller default).
	return Command{Opcode: OpLECreateConnection, Params: p}
}

func b2u(b bool) byte {
	if b {
		return 1
	}
	return 0
}
