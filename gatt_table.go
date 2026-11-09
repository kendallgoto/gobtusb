package gobtusb

// GATTTabler is implemented by devices that can walk their peer's whole
// attribute table, with handles (the USB HCI backend). OS backends hide
// handles, so they don't.
type GATTTabler interface {
	GATTTable() ([]GATTService, error)
}

// Securer is implemented by devices whose link security the caller can drive
// (the USB HCI backend; OS backends pair on their own).
type Securer interface {
	// Secure encrypts the link: with the stored key if bonded to the peer,
	// otherwise by pairing (and bonding, when both sides want it). It is a
	// no-op when the link is already encrypted.
	Secure() error
}

// GATTService is a primary service and the handle range it spans.
type GATTService struct {
	UUID            UUID
	Start, End      uint16
	Characteristics []GATTCharacteristic
}

// GATTCharacteristic is a characteristic declaration (at Handle), its value
// attribute (at ValueHandle) and its descriptors.
type GATTCharacteristic struct {
	UUID        UUID
	Handle      uint16
	ValueHandle uint16
	Properties  uint8
	Value       []byte // when readable; at most ATT_MTU-1 bytes
	ReadErr     string // why reading Value failed, if it did
	Descriptors []GATTDescriptor
}

// GATTDescriptor is an attribute following a characteristic's value.
type GATTDescriptor struct {
	UUID    UUID
	Handle  uint16
	Value   []byte
	ReadErr string
}

// Characteristic properties (Core Vol 3 Part G 3.3.1.1).
const (
	PropBroadcast            = 0x01
	PropRead                 = 0x02
	PropWriteWithoutResponse = 0x04
	PropWrite                = 0x08
	PropNotify               = 0x10
	PropIndicate             = 0x20
	PropAuthenticatedWrites  = 0x40
	PropExtended             = 0x80
)

// PropertyNames lists the characteristic's properties.
func (c GATTCharacteristic) PropertyNames() []string {
	names := []string{"broadcast", "read", "write-without-response", "write", "notify", "indicate", "authenticated-writes", "extended"}
	var out []string
	for i, n := range names {
		if c.Properties&(1<<i) != 0 {
			out = append(out, n)
		}
	}
	return out
}
