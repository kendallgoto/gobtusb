package hci

import "encoding/binary"

// ATT protocol opcodes (Core Spec 3.F.3.4 Attribute Protocol PDUs)
const (
	ATTErrorResponse           = 0x01
	ATTExchangeMTURequest      = 0x02
	ATTExchangeMTUResponse     = 0x03
	ATTFindInformationRequest  = 0x04
	ATTFindInformationResponse = 0x05
	ATTReadByTypeRequest       = 0x08
	ATTReadByTypeResponse      = 0x09
	ATTReadRequest             = 0x0A
	ATTReadResponse            = 0x0B
	ATTReadByGroupTypeRequest  = 0x10
	ATTReadByGroupTypeResponse = 0x11
	ATTWriteRequest            = 0x12
	ATTWriteResponse           = 0x13
	ATTHandleValueNotification = 0x1B
	ATTHandleValueConfirmation = 0x1E
	ATTWriteCommand            = 0x52
	ATTHandleValueIndication   = 0x1D
)

// 3.F.3.4.1.1 Error response codes
const (
	ATTErrAttributeNotFound = 0x0A
)

// 3.G.3.4 GATT profile attributes
const (
	GATTPrimaryService = 0x2800
	GATTCharacteristic = 0x2803
	GATTCCCD           = 0x2902
)

// 3.G.3.3.3 CCC bit for notifications / indications
const (
	CCCDNotify   = 0x0001
	CCCDIndicate = 0x0002
)

// 3.F.3.2.8 MTU used before any negotiation
const DefaultMTU = 23

// WriteRequest forms the payload for an acknowledged write
func WriteRequest(handle uint16, value []byte) []byte {
	return attHandleValue(ATTWriteRequest, handle, value)
}

// WriteCommand forms the payload for an unacknowledged write
func WriteCommand(handle uint16, value []byte) []byte {
	return attHandleValue(ATTWriteCommand, handle, value)
}

// ExchangeMTURequest builds an ATT Exchange MTU Request (self initiated)
func ExchangeMTURequest(mtu uint16) []byte {
	p := make([]byte, 3)
	p[0] = ATTExchangeMTURequest
	binary.LittleEndian.PutUint16(p[1:3], mtu)
	return p
}

// ExchangeMTUResponse builds an ATT Exchange MTU Response PDU (remote initiated)
func ExchangeMTUResponse(mtu uint16) []byte {
	p := make([]byte, 3)
	p[0] = ATTExchangeMTUResponse
	binary.LittleEndian.PutUint16(p[1:3], mtu)
	return p
}

// HandleValueConfirmation builds an ATT Handle Value Confirmation for acknowledging indications
func HandleValueConfirmation() []byte {
	return []byte{ATTHandleValueConfirmation}
}

func attHandleValue(opcode byte, handle uint16, value []byte) []byte {
	p := make([]byte, 3+len(value))
	p[0] = opcode
	binary.LittleEndian.PutUint16(p[1:3], handle)
	copy(p[3:], value)
	return p
}

// ATTHandleValue is a decoded handle-value PDU
type ATTHandleValue struct {
	Opcode uint8
	Handle uint16
	Value  []byte
}

// ParseHandleValue decodes an ATT Handle Value Notification or Indication PDU.
func ParseHandleValue(pdu []byte) *ATTHandleValue {
	if len(pdu) < 3 {
		return nil
	}
	switch pdu[0] {
	case ATTHandleValueNotification, ATTHandleValueIndication:
		return &ATTHandleValue{
			Opcode: pdu[0],
			Handle: binary.LittleEndian.Uint16(pdu[1:3]),
			Value:  pdu[3:],
		}
	default:
		return nil
	}
}
