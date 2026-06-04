package gobtusb

// On Darwin, return CoreBluetooth backend as default
func DefaultAdapter() (Adapter, error) {
	return NewCoreBluetoothAdapter()
}
