package gobtusb

import "context"

// Adapter is a generic BLE controller as a central.
// Depending on the backend used, generate a specific one e.g. DefaultAdapter()
type Adapter interface {
	// Enable "powers on" the underlying controller and performs init, blocking
	// until the controller is ready or ctx is done. It must be called before
	// anything else.
	Enable(ctx context.Context) error

	// Scan starts scanning for advertising peripherals in the background and
	// returns once scanning is active, invoking callback for every
	// advertisement received until Adapter.StopScan. It returns ErrScanning
	// if a scan is already in progress.
	Scan(callback func(ScanResult)) error

	// StopScan stops a scan started by Adapter.Scan
	StopScan() error

	// Connect establishes a connection to the peripheral with the given
	// address blocking until connected or ctx is done.
	// When ctx carries no deadline, a backend default timeout applies.
	Connect(ctx context.Context, addr Address, params ConnectParams) (Device, error)
}

// Device is a connected BLE peripheral.
type Device interface {
	// Address returns the address of the peripheral.
	Address() Address

	// DiscoverServices discovers the GATT services on the peripheral. If uuids
	// is non-empty, only services with a matching UUID are returned; otherwise
	// all services are returned.
	DiscoverServices(uuids []UUID) ([]Service, error)

	// Disconnect closes the connection to the peripheral.
	Disconnect() error

	// Disconnected returns a channel that is closed when the connection to the
	// peripheral is lost.
	Disconnected() <-chan struct{}
}

// Service is a discovered GATT service on a connected Device.
type Service interface {
	// UUID returns the service's UUID.
	UUID() UUID

	// DiscoverCharacteristics discovers the characteristics of the service. If
	// uuids is non-empty, only characteristics with a matching UUID are
	// returned; otherwise all are returned.
	DiscoverCharacteristics(uuids []UUID) ([]Characteristic, error)
}

// Characteristic is a discovered GATT characteristic on a connected Device
type Characteristic interface {
	// UUID returns the characteristic's UUID.
	UUID() UUID

	// Write writes p to the characteristic and waits for the peripheral to
	// acknowledge it (ATT Write Request). It returns the number of bytes
	// written.
	Write(p []byte) (int, error)

	// WriteWithoutResponse writes p to the characteristic without waiting for an
	// acknowledgement (ATT Write Command). It returns the number of bytes
	// written.
	WriteWithoutResponse(p []byte) (int, error)

	// EnableNotifications subscribes to notifications from the characteristic,
	// invoking callback with the value of each notification received. callback
	// may be invoked from a background goroutine.
	EnableNotifications(callback func([]byte)) error

	// DisableNotifications unsubscribes from notifications previously enabled
	// with [Characteristic.EnableNotifications].
	DisableNotifications() error
}
