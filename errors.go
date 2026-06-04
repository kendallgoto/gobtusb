package gobtusb

import "errors"

var (
	// ErrNotImplemented returned by operations that aren't supported on a specific backend
	ErrNotImplemented = errors.New("not implemented")

	// errNotEnabled returned when adapter.Enable is required
	ErrNotEnabled = errors.New("adapter not enabled")

	// ErrNotConnected is returned when an operation requires an active
	// connection to the peripheral.
	ErrNotConnected = errors.New("not connected")

	// ErrCharacteristicNotFound is returned when a characteristic does not
	// support the requested operation
	ErrCharacteristicNotFound = errors.New("characteristic not found")

	// ErrInvalidUUID is returned by ParseUUID for malformed input.
	ErrInvalidUUID = errors.New("invalid UUID")

	// ErrInvalidAddress is returned by ParseAddress for malformed input.
	ErrInvalidAddress = errors.New("invalid address")

	// ErrScanning is returned by Adapter.Scan when a scan is already in
	// progress.
	ErrScanning = errors.New("scan already in progress")
)
