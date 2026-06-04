package gobtusb

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// baseUUID is the Bluetooth Base UUID: 00000000-0000-1000-8000-00805F9B34FB.
// 16- and 32-bit UUIDs are shorthand for 128-bit UUIDs that share this base.
var baseUUID = UUID{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
	0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
}

// UUID is a 128-bit Bluetooth UUID stored in big-endian (network) byte order,
type UUID [16]byte

// NewUUID returns a UUID from 16 big-endian bytes
func NewUUID(b [16]byte) UUID {
	return UUID(b)
}

// New16BitUUID returns the 128-bit UUID for a 16-bit Bluetooth UUID.
func New16BitUUID(short uint16) UUID {
	return New32BitUUID(uint32(short))
}

// New32BitUUID returns the 128-bit UUID for a 32-bit Bluetooth UUID.
func New32BitUUID(short uint32) UUID {
	u := baseUUID
	u[0] = byte(short >> 24)
	u[1] = byte(short >> 16)
	u[2] = byte(short >> 8)
	u[3] = byte(short)
	return u
}

// Is16Bit reports whether the UUID is a 16-bit Bluetooth UUID
func (u UUID) Is16Bit() bool {
	return u.Is32Bit() && u[0] == 0 && u[1] == 0
}

// Is32Bit reports whether the UUID is a 32-bit Bluetooth UUID
func (u UUID) Is32Bit() bool {
	for i := 4; i < 16; i++ {
		if u[i] != baseUUID[i] {
			return false
		}
	}
	return true
}

// Get16Bit returns the 16-bit form of the UUID
func (u UUID) Get16Bit() uint16 {
	return uint16(u[2])<<8 | uint16(u[3])
}

// Get32Bit returns the 32-bit form of the UUID
func (u UUID) Get32Bit() uint32 {
	return uint32(u[0])<<24 | uint32(u[1])<<16 | uint32(u[2])<<8 | uint32(u[3])
}

// String returns the canonical lower-case 8-4-4-4-12 UUID
func (u UUID) String() string {
	var b [36]byte
	hex.Encode(b[0:8], u[0:4])
	b[8] = '-'
	hex.Encode(b[9:13], u[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], u[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], u[8:10])
	b[23] = '-'
	hex.Encode(b[24:36], u[10:16])
	return string(b[:])
}

// IsZero returns true if UUID is equal to the zero value.
func (u UUID) IsZero() bool {
	return u == UUID{}
}

func uuidSet(uuids []UUID) map[UUID]bool {
	if len(uuids) == 0 {
		return nil
	}
	m := make(map[UUID]bool, len(uuids))
	for _, u := range uuids {
		m[u] = true
	}
	return m
}

// ParseUUID parses a 16-bit, 32-bit ("0000180d"), or 128-bit BT UUID
func ParseUUID(s string) (UUID, error) {
	switch h := strings.ReplaceAll(s, "-", ""); len(h) {
	case 4:
		v, err := hex.DecodeString(h)
		if err != nil {
			return UUID{}, fmt.Errorf("%w: %q", ErrInvalidUUID, s)
		}
		return New16BitUUID(uint16(v[0])<<8 | uint16(v[1])), nil
	case 8:
		v, err := hex.DecodeString(h)
		if err != nil {
			return UUID{}, fmt.Errorf("%w: %q", ErrInvalidUUID, s)
		}
		return New32BitUUID(uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])), nil
	case 32:
		var u UUID
		if _, err := hex.Decode(u[:], []byte(h)); err != nil {
			return UUID{}, fmt.Errorf("%w: %q", ErrInvalidUUID, s)
		}
		return u, nil
	default:
		return UUID{}, fmt.Errorf("%w: %q", ErrInvalidUUID, s)
	}
}
