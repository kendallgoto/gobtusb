package gobtusb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/tinygo-org/cbgo"
)

// cbOpTimeout bounds individual GATT operations (discovery, writes, CCCD
// updates) on the Darwin backend.
const cbOpTimeout = 10 * time.Second

// coreBluetoothDevice is a connected peripheral on the Darwin backend.
type coreBluetoothDevice struct {
	adapter *coreBluetoothAdapter
	prph    cbgo.Peripheral
	addr    Address

	opMu sync.Mutex // serializes blocking GATT operations

	pendMu  sync.Mutex
	pending chan error // completion channel for the in-flight operation

	notifyMu sync.Mutex
	notify   map[string]func([]byte) // notification callbacks, by characteristic UUID

	disc     chan struct{} // closed on disconnection
	discOnce sync.Once

	// wwrReady is signalled when CoreBluetooth can queue another write
	// without response (peripheralIsReadyToSendWriteWithoutResponse).
	wwrReady chan struct{}
}

func newCoreBluetoothDevice(a *coreBluetoothAdapter, prph cbgo.Peripheral, addr Address) *coreBluetoothDevice {
	return &coreBluetoothDevice{
		adapter:  a,
		prph:     prph,
		addr:     addr,
		notify:   make(map[string]func([]byte)),
		disc:     make(chan struct{}),
		wwrReady: make(chan struct{}, 1),
	}
}

func (d *coreBluetoothDevice) Address() Address { return d.addr }

func (d *coreBluetoothDevice) Disconnect() error {
	d.adapter.cm.CancelConnect(d.prph)
	d.adapter.mu.Lock()
	delete(d.adapter.devices, d.addr.String())
	d.adapter.mu.Unlock()
	// The device is no longer in the adapter's map, so DidDisconnectPeripheral
	// cannot reach it; mark the disconnection here.
	d.markDisconnected()
	return nil
}

func (d *coreBluetoothDevice) Disconnected() <-chan struct{} { return d.disc }

func (d *coreBluetoothDevice) DiscoverServices(uuids []UUID) ([]Service, error) {
	err := d.run(func() { d.prph.DiscoverServices(toCBUUIDs(uuids)) })
	if err != nil {
		return nil, err
	}
	want := uuidSet(uuids)
	var out []Service
	for _, s := range d.prph.Services() {
		if want == nil || want[fromCBUUID(s.UUID())] {
			out = append(out, &coreBluetoothService{dev: d, svc: s})
		}
	}
	return out, nil
}

// run executes fn (which kicks off an async CoreBluetooth operation) and blocks
// until the matching delegate callback calls complete, or the per-operation
// timeout elapses.
func (d *coreBluetoothDevice) run(fn func()) error {
	ctx, cancel := context.WithTimeout(context.Background(), cbOpTimeout)
	defer cancel()
	return d.runCtx(ctx, fn)
}

// runCtx is run with caller-controlled cancellation.
func (d *coreBluetoothDevice) runCtx(ctx context.Context, fn func()) error {
	d.opMu.Lock()
	defer d.opMu.Unlock()

	ch := make(chan error, 1)
	d.pendMu.Lock()
	d.pending = ch
	d.pendMu.Unlock()

	fn()

	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// complete delivers the result of the in-flight operation to a waiting run.
func (d *coreBluetoothDevice) complete(err error) {
	d.pendMu.Lock()
	ch := d.pending
	d.pendMu.Unlock()
	if ch != nil {
		select {
		case ch <- err:
		default:
		}
	}
}

func (d *coreBluetoothDevice) markDisconnected() {
	d.complete(ErrNotConnected)
	d.discOnce.Do(func() { close(d.disc) })
}

// coreBluetoothService is a discovered GATT service.
type coreBluetoothService struct {
	dev *coreBluetoothDevice
	svc cbgo.Service
}

func (s *coreBluetoothService) UUID() UUID { return fromCBUUID(s.svc.UUID()) }

func (s *coreBluetoothService) DiscoverCharacteristics(uuids []UUID) ([]Characteristic, error) {
	err := s.dev.run(func() { s.dev.prph.DiscoverCharacteristics(toCBUUIDs(uuids), s.svc) })
	if err != nil {
		return nil, err
	}
	want := uuidSet(uuids)
	var out []Characteristic
	for _, c := range s.svc.Characteristics() {
		if want == nil || want[fromCBUUID(c.UUID())] {
			out = append(out, &coreBluetoothCharacteristic{dev: s.dev, chr: c})
		}
	}
	return out, nil
}

// PeripheralDelegate
func (a *coreBluetoothAdapter) IsReadyToSendWriteWithoutResponse(prph cbgo.Peripheral) {
	if dev := a.device(prph); dev != nil {
		select {
		case dev.wwrReady <- struct{}{}:
		default:
		}
	}
}

func (a *coreBluetoothAdapter) DidDiscoverServices(prph cbgo.Peripheral, err error) {
	if dev := a.device(prph); dev != nil {
		dev.complete(err)
	}
}

func (a *coreBluetoothAdapter) DidDiscoverCharacteristics(prph cbgo.Peripheral, svc cbgo.Service, err error) {
	if dev := a.device(prph); dev != nil {
		dev.complete(err)
	}
}

func (a *coreBluetoothAdapter) DidWriteValueForCharacteristic(prph cbgo.Peripheral, chr cbgo.Characteristic, err error) {
	if dev := a.device(prph); dev != nil {
		dev.complete(err)
	}
}

func (a *coreBluetoothAdapter) DidUpdateNotificationState(prph cbgo.Peripheral, chr cbgo.Characteristic, err error) {
	if dev := a.device(prph); dev != nil {
		dev.complete(err)
	}
}

func (a *coreBluetoothAdapter) DidUpdateValueForCharacteristic(prph cbgo.Peripheral, chr cbgo.Characteristic, err error) {
	dev := a.device(prph)
	if dev == nil || err != nil {
		return
	}
	dev.notifyMu.Lock()
	cb := dev.notify[fromCBUUID(chr.UUID()).String()]
	dev.notifyMu.Unlock()
	if cb != nil {
		cb(chr.Value())
	}
}

// orErr returns err if non-nil, otherwise fallback.
func orErr(err, fallback error) error {
	if err != nil {
		return fmt.Errorf("%w: %v", fallback, err)
	}
	return fallback
}

// toCBUUIDs converts gobtusb UUIDs to cbgo UUIDs (nil for an empty slice, which
// CoreBluetooth treats as "discover everything").
func toCBUUIDs(uuids []UUID) []cbgo.UUID {
	if len(uuids) == 0 {
		return nil
	}
	out := make([]cbgo.UUID, len(uuids))
	for i, u := range uuids {
		out[i], _ = cbgo.ParseUUID(u.String())
	}
	return out
}

func fromCBUUID(u cbgo.UUID) UUID {
	g, _ := ParseUUID(u.String())
	return g
}
