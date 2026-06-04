package gobtusb

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Address identifies a BLE peripheral - either its real 48 bit MAC address or
// an opaque UUID if obscured by the underlying stack (CoreBluetooth)
type Address struct {
	// MAC is the 48-bit Bluetooth device address, MAC[0] being the most
	// significant byte (as printed in "aa:bb:cc:dd:ee:ff" order).
	MAC [6]byte

	// IsRandom reports whether MAC is a random address rather than a public one.
	IsRandom bool

	// uuid is the reference in CoreBluetooth since MAC is obscured.
	// on other backends, it is unused.
	uuid UUID
}

// String formats the address as "aa:bb:cc:dd:ee:ff" (or the CoreBluetooth
// identifier UUID when no MAC is available). It uses a value receiver so both
// Address values and pointers satisfy fmt.Stringer.
func (a Address) String() string {
	if !a.uuid.IsZero() {
		return a.uuid.String()
	}
	var b [17]byte
	for i := range 6 {
		hex.Encode(b[i*3:i*3+2], a.MAC[i:i+1])
		if i < 5 {
			b[i*3+2] = ':'
		}
	}
	return string(b[:])
}

// ParseAddress parses an address of the form "aa:bb:cc:dd:ee:ff"
func ParseAddress(s string) (*Address, error) {
	h := strings.NewReplacer(":", "", "-", "").Replace(s)
	if len(h) != 12 {
		return nil, fmt.Errorf("%w: %q", ErrInvalidAddress, s)
	}
	var a Address
	if _, err := hex.Decode(a.MAC[:], []byte(h)); err != nil {
		return nil, fmt.Errorf("%w: %q", ErrInvalidAddress, s)
	}
	return &a, nil
}
