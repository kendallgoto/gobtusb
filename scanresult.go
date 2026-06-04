package gobtusb

import "slices"

// ScanResult is a single advertisement received during a scan.
type ScanResult struct {
	// Address is the address of the advertising peripheral.
	Address Address

	// RSSI is the received signal strength of the advertisement, in dBm.
	RSSI int8

	// payload is the raw advertising data (a sequence of length-type-value AD
	// structures).
	payload []byte
}

// AdvertisementData returns a copy of the raw advertising payload.
func (r ScanResult) AdvertisementData() []byte {
	return slices.Clone(r.payload)
}

// AD type identifiers from the BT SIG Assigned Numbers
const (
	adTypeShortLocalName    = 0x08
	adTypeCompleteLocalName = 0x09
	adTypeServiceData16     = 0x16
	adTypeServiceData32     = 0x20
	adTypeServiceData128    = 0x21
)

func (r ScanResult) LocalName() string {
	for _, ad := range r.adStructures() {
		switch ad.typ {
		case adTypeCompleteLocalName, adTypeShortLocalName:
			return string(ad.data)
		}
	}
	return ""
}

// HasServiceUUID reports whether the advertisement lists the given service UUID
func (r ScanResult) HasServiceUUID(uuid UUID) bool {
	for _, ad := range r.adStructures() {
		var width int
		switch ad.typ {
		case 0x02, 0x03: // incomplete/complete list of 16-bit UUIDs
			width = 2
		case 0x04, 0x05: // 32-bit UUIDs
			width = 4
		case 0x06, 0x07: // 128-bit UUIDs
			width = 16
		default:
			continue
		}
		for i := 0; i+width <= len(ad.data); i += width {
			if advUUID(ad.data[i:i+width]) == uuid {
				return true
			}
		}
	}
	return false
}

// ServiceDataElement is a single Service Data AD structure
type ServiceDataElement struct {
	// UUID of the service the data belongs to.
	UUID UUID

	// Data is the service data payload.
	Data []byte
}

// ServiceData returns the service data elements present in the advertisement
func (r ScanResult) ServiceData() []ServiceDataElement {
	var out []ServiceDataElement
	for _, ad := range r.adStructures() {
		var width int
		switch ad.typ {
		case adTypeServiceData16:
			width = 2
		case adTypeServiceData32:
			width = 4
		case adTypeServiceData128:
			width = 16
		default:
			continue
		}
		if len(ad.data) < width {
			continue
		}
		out = append(out, ServiceDataElement{
			UUID: advUUID(ad.data[:width]),
			Data: slices.Clone(ad.data[width:]),
		})
	}
	return out
}

type adStructure struct {
	typ  byte
	data []byte
}

// adStructures splits the payload into TLV AD structures
func (r ScanResult) adStructures() []adStructure {
	var out []adStructure
	for i := 0; i < len(r.payload); {
		length := int(r.payload[i])
		if length == 0 || i+1+length > len(r.payload) {
			break
		}
		out = append(out, adStructure{
			typ:  r.payload[i+1],
			data: r.payload[i+2 : i+1+length],
		})
		i += 1 + length
	}
	return out
}

func appendAD(dst []byte, typ byte, data []byte) []byte {
	dst = append(dst, byte(len(data)+1), typ)
	return append(dst, data...)
}

func appendServiceData(dst []byte, uuid UUID, data []byte) []byte {
	var value []byte
	typ := byte(adTypeServiceData128)
	if uuid.Is16Bit() {
		typ = adTypeServiceData16
		s := uuid.Get16Bit()
		value = append(value, byte(s), byte(s>>8))
	} else {
		for i := range 16 {
			value = append(value, uuid[15-i])
		}
	}
	return appendAD(dst, typ, append(value, data...))
}

// advUUID converts little-endian advertising UUID bytes (2, 4, or 16 wide) into
// a UUID.
func advUUID(b []byte) UUID {
	switch len(b) {
	case 2:
		return New16BitUUID(uint16(b[0]) | uint16(b[1])<<8)
	case 4:
		return New32BitUUID(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)
	case 16:
		var u UUID
		for i := range 16 {
			u[i] = b[15-i] // advertising data is little-endian
		}
		return u
	default:
		return UUID{}
	}
}
