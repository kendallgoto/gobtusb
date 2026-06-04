package hci

import (
	"encoding/binary"
	"errors"
)

// ErrBadResponse is returned when an ATT response PDU is malformed or is not the
// expected type.
var ErrBadResponse = errors.New("hci: malformed ATT response")

// ReadByGroupTypeRequest builds an ATT Read By Group Type Request.
func ReadByGroupTypeRequest(start, end, groupType uint16) []byte {
	p := make([]byte, 7)
	p[0] = ATTReadByGroupTypeRequest
	binary.LittleEndian.PutUint16(p[1:3], start)
	binary.LittleEndian.PutUint16(p[3:5], end)
	binary.LittleEndian.PutUint16(p[5:7], groupType)
	return p
}

// ReadByTypeRequest builds an ATT Read By Type Request.
func ReadByTypeRequest(start, end, attType uint16) []byte {
	p := make([]byte, 7)
	p[0] = ATTReadByTypeRequest
	binary.LittleEndian.PutUint16(p[1:3], start)
	binary.LittleEndian.PutUint16(p[3:5], end)
	binary.LittleEndian.PutUint16(p[5:7], attType)
	return p
}

// FindInformationRequest builds an ATT Find Information Request.
func FindInformationRequest(start, end uint16) []byte {
	p := make([]byte, 5)
	p[0] = ATTFindInformationRequest
	binary.LittleEndian.PutUint16(p[1:3], start)
	binary.LittleEndian.PutUint16(p[3:5], end)
	return p
}

// GroupData is one element of a Read By Group Type Response containing
// an attribute group's handle range and UUID
type GroupData struct {
	Handle   uint16
	EndGroup uint16
	Value    []byte // raw UUID (2 or 16 bytes)
}

// ParseReadByGroupTypeResponse decodes a Read By Group Type Response PDU.
func ParseReadByGroupTypeResponse(pdu []byte) ([]GroupData, error) {
	if len(pdu) < 2 || pdu[0] != ATTReadByGroupTypeResponse {
		return nil, ErrBadResponse
	}
	each := int(pdu[1])
	if each < 4 {
		return nil, ErrBadResponse
	}
	var out []GroupData
	for i := 2; i+each <= len(pdu); i += each {
		out = append(out, GroupData{
			Handle:   binary.LittleEndian.Uint16(pdu[i : i+2]),
			EndGroup: binary.LittleEndian.Uint16(pdu[i+2 : i+4]),
			Value:    pdu[i+4 : i+each],
		})
	}
	return out, nil
}

// TypeData is one element of a Read By Type Response containing a handle and value
type TypeData struct {
	Handle uint16
	Value  []byte
}

// ParseReadByTypeResponse decodes a Read By Type Response PDU.
func ParseReadByTypeResponse(pdu []byte) ([]TypeData, error) {
	if len(pdu) < 2 || pdu[0] != ATTReadByTypeResponse {
		return nil, ErrBadResponse
	}
	each := int(pdu[1])
	if each < 2 {
		return nil, ErrBadResponse
	}
	var out []TypeData
	for i := 2; i+each <= len(pdu); i += each {
		out = append(out, TypeData{
			Handle: binary.LittleEndian.Uint16(pdu[i : i+2]),
			Value:  pdu[i+2 : i+each],
		})
	}
	return out, nil
}

// InfoData is one handle/UUID pair from a Find Information Response.
type InfoData struct {
	Handle uint16
	UUID   []byte
}

// ParseFindInformationResponse decodes a Find Information Response PDU.
func ParseFindInformationResponse(pdu []byte) ([]InfoData, error) {
	if len(pdu) < 2 || pdu[0] != ATTFindInformationResponse {
		return nil, ErrBadResponse
	}
	var uuidLen int
	switch pdu[1] {
	case 0x01:
		uuidLen = 2
	case 0x02:
		uuidLen = 16
	default:
		return nil, ErrBadResponse
	}
	each := 2 + uuidLen
	var out []InfoData
	for i := 2; i+each <= len(pdu); i += each {
		out = append(out, InfoData{
			Handle: binary.LittleEndian.Uint16(pdu[i : i+2]),
			UUID:   pdu[i+2 : i+each],
		})
	}
	return out, nil
}

// ErrorResponse holds the fields of an ATT Error Response PDU.
type ErrorResponse struct {
	ReqOpcode uint8
	Handle    uint16
	Code      uint8
}

// ParseErrorResponse decodes an ATT Error Response PDU, returning false if pdu
// is not one.
func ParseErrorResponse(pdu []byte) (ErrorResponse, bool) {
	if len(pdu) < 5 || pdu[0] != ATTErrorResponse {
		return ErrorResponse{}, false
	}
	return ErrorResponse{
		ReqOpcode: pdu[1],
		Handle:    binary.LittleEndian.Uint16(pdu[2:4]),
		Code:      pdu[4],
	}, true
}
