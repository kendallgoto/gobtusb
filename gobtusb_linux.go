package gobtusb

// On Linux, return BlueZ backend as default
func DefaultAdapter() (Adapter, error) {
	return NewBlueZAdapter()
}
