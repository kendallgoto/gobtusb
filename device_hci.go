package gobtusb

import (
	"encoding/binary"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kendallgoto/gobtusb/internal/hci"
)

const attTimeout = 5 * time.Second

// hostRxMTU is the ATT MTU this host offers during the MTU exchange. Incoming
// frames are reassembled from ACL fragments, so anything the controller can
// receive is fine; 247 matches the LE data length extension payload and is
// widely supported.
const hostRxMTU = 247

// hciDevice is a connected peripheral on the USB HCI backend. GATT operations
// are implemented as ATT request/response transactions over the connection's
// ACL channel; the adapter's ACL reader delivers responses and notifications.
type hciDevice struct {
	adapter *hciAdapter
	handle  uint16
	addr    Address

	attMu   sync.Mutex  // serializes ATT transactions (one outstanding request)
	pendMu  sync.Mutex  // protects pending
	pending chan []byte // response delivery for the in-flight request

	notifyMu sync.Mutex
	notify   map[uint16]func([]byte) // callbacks by characteristic value handle

	disc     chan struct{} // closed on disconnection
	discOnce sync.Once

	mtu atomic.Uint32 // negotiated ATT MTU
}

func newHCIDevice(a *hciAdapter, handle uint16, addr Address) *hciDevice {
	d := &hciDevice{
		adapter: a,
		handle:  handle,
		addr:    addr,
		notify:  make(map[uint16]func([]byte)),
		disc:    make(chan struct{}),
	}
	d.mtu.Store(hci.DefaultMTU)
	return d
}

// setMTU records the negotiated ATT MTU for the connection.
func (d *hciDevice) setMTU(mtu uint16) { d.mtu.Store(uint32(mtu)) }

// attMTU returns the ATT MTU currently in effect.
func (d *hciDevice) attMTU() int { return int(d.mtu.Load()) }

// exchangeMTU performs the client-initiated ATT MTU exchange, offering rx as
// this host's receive MTU. Actual MTU becomes the minimum of the two sides,
// or falls back to default minimum if it fails to exchange.
func (d *hciDevice) exchangeMTU(rx uint16) {
	resp, err := d.attRequest(hci.ExchangeMTURequest(rx))
	if err != nil {
		return
	}
	if len(resp) >= 3 && resp[0] == hci.ATTExchangeMTUResponse {
		d.setMTU(min(rx, binary.LittleEndian.Uint16(resp[1:3])))
	}
}

func (d *hciDevice) Address() Address { return d.addr }

func (d *hciDevice) Disconnect() error { return d.adapter.disconnect(d.handle) }

func (d *hciDevice) Disconnected() <-chan struct{} { return d.disc }

// attRequest sends an ATT request PDU and waits for the matching response PDU.
func (d *hciDevice) attRequest(req []byte) ([]byte, error) {
	d.attMu.Lock()
	defer d.attMu.Unlock()

	ch := make(chan []byte, 1)
	d.pendMu.Lock()
	d.pending = ch
	d.pendMu.Unlock()
	defer func() {
		d.pendMu.Lock()
		d.pending = nil
		d.pendMu.Unlock()
	}()

	if err := d.adapter.sendACL(d.handle, req); err != nil {
		return nil, err
	}
	select {
	case resp := <-ch:
		if resp == nil {
			return nil, ErrNotConnected
		}
		return resp, nil
	case <-time.After(attTimeout):
		return nil, fmt.Errorf("%w: ATT request timed out", ErrNotConnected)
	}
}

// deliverResponse hands an ATT response PDU to a waiting attRequest.
func (d *hciDevice) deliverResponse(pdu []byte) {
	d.pendMu.Lock()
	ch := d.pending
	d.pendMu.Unlock()
	if ch != nil {
		select {
		case ch <- pdu:
		default:
		}
	}
}

// dispatchNotify delivers a notification value to the callback registered for a
// characteristic's value handle.
func (d *hciDevice) dispatchNotify(handle uint16, value []byte) {
	d.notifyMu.Lock()
	cb := d.notify[handle]
	d.notifyMu.Unlock()
	if cb != nil {
		cb(slices.Clone(value))
	}
}

// markDisconnected unblocks any in-flight request after a disconnection and
// closes the device's Disconnected channel.
func (d *hciDevice) markDisconnected() {
	d.deliverResponse(nil)
	d.discOnce.Do(func() { close(d.disc) })
}

func (d *hciDevice) DiscoverServices(uuids []UUID) ([]Service, error) {
	var services []*hciService
	start := uint16(0x0001)
	for {
		resp, err := d.attRequest(hci.ReadByGroupTypeRequest(start, 0xFFFF, hci.GATTPrimaryService))
		if err != nil {
			return nil, err
		}
		if e, ok := hci.ParseErrorResponse(resp); ok {
			if e.Code == hci.ATTErrAttributeNotFound {
				break
			}
			return nil, fmt.Errorf("discover services: ATT error %#x", e.Code)
		}
		groups, err := hci.ParseReadByGroupTypeResponse(resp)
		if err != nil {
			return nil, fmt.Errorf("discover services: %w", err)
		}
		if len(groups) == 0 {
			break
		}
		var last uint16
		for _, g := range groups {
			services = append(services, &hciService{
				dev:   d,
				uuid:  advUUID(g.Value),
				start: g.Handle,
				end:   g.EndGroup,
			})
			last = g.EndGroup
		}
		if last >= 0xFFFF {
			break
		}
		start = last + 1
	}

	want := uuidSet(uuids)
	var out []Service
	for _, s := range services {
		if want == nil || want[s.uuid] {
			out = append(out, s)
		}
	}
	return out, nil
}

// hciService is a discovered GATT service with its handle range.
type hciService struct {
	dev        *hciDevice
	uuid       UUID
	start, end uint16
}

func (s *hciService) UUID() UUID { return s.uuid }

func (s *hciService) DiscoverCharacteristics(uuids []UUID) ([]Characteristic, error) {
	var chars []*hciCharacteristic
	start := s.start
	for start <= s.end {
		resp, err := s.dev.attRequest(hci.ReadByTypeRequest(start, s.end, hci.GATTCharacteristic))
		if err != nil {
			return nil, err
		}
		if e, ok := hci.ParseErrorResponse(resp); ok {
			if e.Code == hci.ATTErrAttributeNotFound {
				break
			}
			return nil, fmt.Errorf("discover characteristics: ATT error %#x", e.Code)
		}
		items, err := hci.ParseReadByTypeResponse(resp)
		if err != nil {
			return nil, fmt.Errorf("discover characteristics: %w", err)
		}
		if len(items) == 0 {
			break
		}
		var lastDecl uint16
		for _, it := range items {
			// Characteristic declaration value: properties(1), value handle(2), UUID.
			if len(it.Value) < 3 {
				continue
			}
			chars = append(chars, &hciCharacteristic{
				dev:         s.dev,
				uuid:        advUUID(it.Value[3:]),
				declHandle:  it.Handle,
				valueHandle: binary.LittleEndian.Uint16(it.Value[1:3]),
				props:       it.Value[0],
			})
			lastDecl = it.Handle
		}
		if lastDecl >= s.end {
			break
		}
		start = lastDecl + 1
	}

	// Each characteristic's attributes (its descriptors) span from just after
	// its declaration up to just before the next characteristic, or the end of
	// the service for the last one.
	for i, c := range chars {
		if i+1 < len(chars) {
			c.endHandle = chars[i+1].declHandle - 1
		} else {
			c.endHandle = s.end
		}
	}

	want := uuidSet(uuids)
	var out []Characteristic
	for _, c := range chars {
		if want == nil || want[c.uuid] {
			out = append(out, c)
		}
	}
	return out, nil
}

// hciCharacteristic is a discovered GATT characteristic.
type hciCharacteristic struct {
	dev         *hciDevice
	uuid        UUID
	declHandle  uint16
	valueHandle uint16
	endHandle   uint16
	props       uint8
	cccdHandle  uint16 // resolved lazily by findCCCD
}

func (c *hciCharacteristic) UUID() UUID { return c.uuid }

func (c *hciCharacteristic) Write(p []byte) (int, error) {
	if err := c.checkWriteSize(p); err != nil {
		return 0, err
	}
	resp, err := c.dev.attRequest(hci.WriteRequest(c.valueHandle, p))
	if err != nil {
		return 0, err
	}
	if e, ok := hci.ParseErrorResponse(resp); ok {
		return 0, fmt.Errorf("write: ATT error %#x", e.Code)
	}
	if len(resp) == 0 || resp[0] != hci.ATTWriteResponse {
		return 0, fmt.Errorf("write: unexpected ATT response")
	}
	return len(p), nil
}

func (c *hciCharacteristic) WriteWithoutResponse(p []byte) (int, error) {
	if err := c.checkWriteSize(p); err != nil {
		return 0, err
	}
	if err := c.dev.adapter.sendACL(c.dev.handle, hci.WriteCommand(c.valueHandle, p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// checkWriteSize rejects values larger than the negotiated ATT MTU allows
// (MTU-3 for both write flavors); the server would silently drop or reject
// oversized PDUs otherwise.
func (c *hciCharacteristic) checkWriteSize(p []byte) error {
	if max := c.dev.attMTU() - 3; len(p) > max {
		return fmt.Errorf("write of %d bytes exceeds ATT_MTU-3 (%d) for characteristic %s", len(p), max, c.uuid)
	}
	return nil
}

func (c *hciCharacteristic) EnableNotifications(callback func([]byte)) error {
	cccd, err := c.findCCCD()
	if err != nil {
		return err
	}
	if err := c.writeDescriptor(cccd, []byte{hci.CCCDNotify, 0x00}); err != nil {
		return err
	}
	c.dev.notifyMu.Lock()
	c.dev.notify[c.valueHandle] = callback
	c.dev.notifyMu.Unlock()
	return nil
}

func (c *hciCharacteristic) DisableNotifications() error {
	cccd, err := c.findCCCD()
	if err != nil {
		return err
	}
	err = c.writeDescriptor(cccd, []byte{0x00, 0x00})
	c.dev.notifyMu.Lock()
	delete(c.dev.notify, c.valueHandle)
	c.dev.notifyMu.Unlock()
	return err
}

// findCCCD discovers the Client Characteristic Configuration descriptor for the
// characteristic, caching the handle.
func (c *hciCharacteristic) findCCCD() (uint16, error) {
	if c.cccdHandle != 0 {
		return c.cccdHandle, nil
	}
	cccdUUID := New16BitUUID(hci.GATTCCCD)
	start := c.valueHandle + 1
	for start != 0 && start <= c.endHandle {
		resp, err := c.dev.attRequest(hci.FindInformationRequest(start, c.endHandle))
		if err != nil {
			return 0, err
		}
		if e, ok := hci.ParseErrorResponse(resp); ok {
			if e.Code == hci.ATTErrAttributeNotFound {
				break
			}
			return 0, fmt.Errorf("find descriptors: ATT error %#x", e.Code)
		}
		infos, err := hci.ParseFindInformationResponse(resp)
		if err != nil {
			return 0, fmt.Errorf("find descriptors: %w", err)
		}
		if len(infos) == 0 {
			break
		}
		var last uint16
		for _, info := range infos {
			if advUUID(info.UUID) == cccdUUID {
				c.cccdHandle = info.Handle
				return info.Handle, nil
			}
			last = info.Handle
		}
		if last >= c.endHandle {
			break
		}
		start = last + 1
	}
	return 0, fmt.Errorf("%w: no CCCD for characteristic %s", ErrCharacteristicNotFound, c.uuid)
}

func (c *hciCharacteristic) writeDescriptor(handle uint16, value []byte) error {
	resp, err := c.dev.attRequest(hci.WriteRequest(handle, value))
	if err != nil {
		return err
	}
	if e, ok := hci.ParseErrorResponse(resp); ok {
		return fmt.Errorf("write descriptor: ATT error %#x", e.Code)
	}
	return nil
}
