package gobtusb

import (
	"context"
	"fmt"
	"sync"

	"github.com/tinygo-org/cbgo"
)

// coreBluetoothAdapter is the Darwin backend. It implements [Adapter] on top of
// CoreBluetooth
type coreBluetoothAdapter struct {
	cbgo.CentralManagerDelegateBase
	cbgo.PeripheralDelegateBase

	cm    cbgo.CentralManager
	state chan cbgo.ManagerState

	mu      sync.Mutex
	scanCb  func(ScanResult)
	found   map[string]cbgo.Peripheral      // discovered peripherals, by identifier
	devices map[string]*coreBluetoothDevice // connected devices, by identifier
}

// NewCoreBluetoothAdapter returns an [Adapter] backed by CoreBluetooth.
func NewCoreBluetoothAdapter() (Adapter, error) {
	a := &coreBluetoothAdapter{
		state:   make(chan cbgo.ManagerState, 4),
		found:   make(map[string]cbgo.Peripheral),
		devices: make(map[string]*coreBluetoothDevice),
	}
	a.cm = cbgo.NewCentralManager(nil)
	a.cm.SetDelegate(a)
	return a, nil
}

func (a *coreBluetoothAdapter) Enable(ctx context.Context) error {
	if a.cm.State() == cbgo.ManagerStatePoweredOn {
		return nil
	}
	for {
		select {
		case st := <-a.state:
			switch st {
			case cbgo.ManagerStatePoweredOn:
				return nil
			case cbgo.ManagerStateUnauthorized:
				return fmt.Errorf("%w: Bluetooth access not authorized", ErrNotEnabled)
			case cbgo.ManagerStateUnsupported:
				return fmt.Errorf("%w: Bluetooth not supported", ErrNotEnabled)
			}
			// unknown state; have to wait until it settles
		case <-ctx.Done():
			return fmt.Errorf("%w: waiting for power on: %w", ErrNotEnabled, ctx.Err())
		}
	}
}

func (a *coreBluetoothAdapter) Scan(callback func(ScanResult)) error {
	a.mu.Lock()
	if a.scanCb != nil {
		a.mu.Unlock()
		return ErrScanning
	}
	a.scanCb = callback
	a.mu.Unlock()

	a.cm.Scan(nil, nil)
	return nil
}

func (a *coreBluetoothAdapter) StopScan() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.scanCb == nil {
		return nil
	}
	a.cm.StopScan()
	a.scanCb = nil
	return nil
}

func (a *coreBluetoothAdapter) Connect(ctx context.Context, addr Address, params ConnectParams) (Device, error) {
	cctx, cancel := withConnectTimeout(ctx)
	defer cancel()

	id := addr.String()
	a.mu.Lock()
	prph, ok := a.found[id]
	a.mu.Unlock()
	if !ok { //NB: CoreBluetooth requires a scan since it uses UUIDs, so we can't connect directly to addresses
		return nil, fmt.Errorf("%w: peripheral %s not seen during scan", ErrNotConnected, id)
	}

	dev := newCoreBluetoothDevice(a, prph, addr)
	a.mu.Lock()
	a.devices[id] = dev
	a.mu.Unlock()

	err := dev.runCtx(cctx, func() { a.cm.Connect(prph, nil) })
	if err != nil {
		a.cm.CancelConnect(prph) // abort the pending attempt on timeout/cancel
		a.mu.Lock()
		delete(a.devices, id)
		a.mu.Unlock()
		return nil, fmt.Errorf("connect %s: %w", id, err)
	}
	return dev, nil
}

// device looks up the connected device for a peripheral, if any.
func (a *coreBluetoothAdapter) device(prph cbgo.Peripheral) *coreBluetoothDevice {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.devices[prph.Identifier().String()]
}

// Central Manager delegate
func (a *coreBluetoothAdapter) CentralManagerDidUpdateState(cmgr cbgo.CentralManager) {
	select {
	case a.state <- cmgr.State():
	default:
	}
}

func (a *coreBluetoothAdapter) DidDiscoverPeripheral(cmgr cbgo.CentralManager, prph cbgo.Peripheral, advFields cbgo.AdvFields, rssi int) {
	id := prph.Identifier().String()
	a.mu.Lock()
	a.found[id] = prph
	cb := a.scanCb
	a.mu.Unlock()
	if cb == nil {
		return
	}
	cb(ScanResult{
		Address: Address{uuid: fromCBUUID(prph.Identifier())},
		RSSI:    int8(rssi),
		payload: encodeAdvFields(advFields),
	})
}

func (a *coreBluetoothAdapter) DidConnectPeripheral(cmgr cbgo.CentralManager, prph cbgo.Peripheral) {
	prph.SetDelegate(a)
	if dev := a.device(prph); dev != nil {
		dev.complete(nil)
	}
}

func (a *coreBluetoothAdapter) DidFailToConnectPeripheral(cmgr cbgo.CentralManager, prph cbgo.Peripheral, err error) {
	if dev := a.device(prph); dev != nil {
		dev.complete(orErr(err, ErrNotConnected))
	}
}

func (a *coreBluetoothAdapter) DidDisconnectPeripheral(cmgr cbgo.CentralManager, prph cbgo.Peripheral, err error) {
	id := prph.Identifier().String()
	a.mu.Lock()
	dev := a.devices[id]
	delete(a.devices, id)
	a.mu.Unlock()
	if dev != nil {
		dev.markDisconnected()
	}
}
