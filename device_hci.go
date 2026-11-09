package gobtusb

import (
	"encoding/binary"
	"errors"
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

	addrMu sync.Mutex
	addr   Address // becomes the identity address once the peer distributes it

	// Over-the-air peer address from LE Connection Complete, as type ‖
	// address (most significant octet first), for pairing.
	peerAddr []byte

	secMu     sync.Mutex            // serializes pairing/encryption
	encrypted atomic.Bool           // link encryption is on
	smpRx     chan []byte           // inbound SMP PDUs
	encDone   chan encryptResult    // outcome of HCI_LE_Enable_Encryption
	secErr    atomic.Pointer[error] // last failure of a peer-requested pairing

	attMu   sync.Mutex  // serializes ATT transactions (one outstanding request)
	pendMu  sync.Mutex  // protects pending
	pending chan []byte // response delivery for the in-flight request

	notifyMu sync.Mutex
	notify   map[uint16]func([]byte) // callbacks by characteristic value handle

	disc     chan struct{} // closed on disconnection
	discOnce sync.Once

	mtu atomic.Uint32 // negotiated ATT MTU
}

func newHCIDevice(a *hciAdapter, handle uint16, addr Address, peerType uint8, peer [6]byte) *hciDevice {
	d := &hciDevice{
		adapter:  a,
		handle:   handle,
		addr:     addr,
		peerAddr: append([]byte{peerType & 0x01}, hci.Reverse(peer[:])...),
		smpRx:    make(chan []byte, 8),
		encDone:  make(chan encryptResult, 1),
		notify:   make(map[uint16]func([]byte)),
		disc:     make(chan struct{}),
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
		d.adapter.logf("ATT MTU exchange failed: %v; using %d", err, d.attMTU())
		return
	}
	if len(resp) >= 3 && resp[0] == hci.ATTExchangeMTUResponse {
		peer := binary.LittleEndian.Uint16(resp[1:3])
		d.setMTU(min(rx, peer))
		d.adapter.logf("ATT MTU exchange: ours %d, peer %d, using %d", rx, peer, d.attMTU())
	}
}

func (d *hciDevice) Address() Address {
	d.addrMu.Lock()
	defer d.addrMu.Unlock()
	return d.addr
}

func (d *hciDevice) Disconnect() error { return d.adapter.disconnect(d.handle) }

func (d *hciDevice) Disconnected() <-chan struct{} { return d.disc }

// attRequest sends an ATT request PDU and waits for the matching response PDU.
// If the peer refuses it for lack of security, the link is paired (or
// encrypted with an existing bond) and the request retried once, much as OS
// stacks do.
func (d *hciDevice) attRequest(req []byte) ([]byte, error) {
	resp, err := d.attTransact(req)
	if err != nil || d.encrypted.Load() {
		return resp, err
	}
	if e, ok := hci.ParseErrorResponse(resp); ok {
		switch e.Code {
		case hci.ATTErrInsufficientAuthentication, hci.ATTErrInsufficientEncryption, hci.ATTErrInsufficientEncKeySize:
			d.adapter.logf("ATT: request %#02x on handle %#04x refused (%s); securing link and retrying", e.ReqOpcode, e.Handle, hci.ATTErrorName(e.Code))
			if err := d.secure(); err != nil {
				return nil, fmt.Errorf("securing link: %w", err)
			}
			return d.attTransact(req)
		}
	}
	return resp, nil
}

// attTransact performs one ATT request/response transaction.
func (d *hciDevice) attTransact(req []byte) ([]byte, error) {
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
			return nil, d.notConnected()
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

var (
	_ GATTTabler = (*hciDevice)(nil)
	_ Securer    = (*hciDevice)(nil)
)

func (d *hciDevice) Secure() error { return d.secure() }

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
	descs, err := c.descriptors()
	if err != nil {
		return 0, err
	}
	cccdUUID := New16BitUUID(hci.GATTCCCD)
	for _, d := range descs {
		if d.UUID == cccdUUID {
			c.cccdHandle = d.Handle
			return d.Handle, nil
		}
	}
	return 0, fmt.Errorf("%w: no CCCD for characteristic %s", ErrCharacteristicNotFound, c.uuid)
}

// descriptors discovers the attributes after the characteristic's value, up
// to the next characteristic.
func (c *hciCharacteristic) descriptors() ([]GATTDescriptor, error) {
	var out []GATTDescriptor
	start := c.valueHandle + 1
	for start != 0 && start <= c.endHandle {
		resp, err := c.dev.attRequest(hci.FindInformationRequest(start, c.endHandle))
		if err != nil {
			return nil, err
		}
		if e, ok := hci.ParseErrorResponse(resp); ok {
			if e.Code == hci.ATTErrAttributeNotFound {
				break
			}
			return nil, fmt.Errorf("find descriptors: ATT error %#x (%s)", e.Code, hci.ATTErrorName(e.Code))
		}
		infos, err := hci.ParseFindInformationResponse(resp)
		if err != nil {
			return nil, fmt.Errorf("find descriptors: %w", err)
		}
		if len(infos) == 0 {
			break
		}
		for _, info := range infos {
			out = append(out, GATTDescriptor{UUID: advUUID(info.UUID), Handle: info.Handle})
		}
		last := infos[len(infos)-1].Handle
		if last >= c.endHandle {
			break
		}
		start = last + 1
	}
	return out, nil
}

// read reads an attribute's value with ATT Read Request, which returns at
// most ATT_MTU-1 bytes; longer values are truncated.
func (d *hciDevice) read(handle uint16) ([]byte, error) {
	resp, err := d.attRequest(hci.ReadRequest(handle))
	if err != nil {
		return nil, err
	}
	if e, ok := hci.ParseErrorResponse(resp); ok {
		return nil, fmt.Errorf("ATT error %#x (%s)", e.Code, hci.ATTErrorName(e.Code))
	}
	if len(resp) == 0 || resp[0] != hci.ATTReadResponse {
		return nil, fmt.Errorf("unexpected ATT response %x", resp)
	}
	return resp[1:], nil
}

// GATTTable discovers every primary service, characteristic and descriptor,
// reading each readable value along the way. A read that fails is recorded in
// the attribute's ReadErr rather than aborting the walk.
func (d *hciDevice) GATTTable() ([]GATTService, error) {
	services, err := d.DiscoverServices(nil)
	if err != nil {
		return nil, err
	}
	var out []GATTService
	for _, svc := range services {
		s := svc.(*hciService)
		gs := GATTService{UUID: s.uuid, Start: s.start, End: s.end}
		chars, err := s.DiscoverCharacteristics(nil)
		if err != nil {
			return nil, err
		}
		for _, ch := range chars {
			c := ch.(*hciCharacteristic)
			gc := GATTCharacteristic{UUID: c.uuid, Handle: c.declHandle, ValueHandle: c.valueHandle, Properties: c.props}
			if c.props&PropRead != 0 {
				gc.Value, gc.ReadErr = d.readForTable(c.valueHandle)
			}
			if gc.Descriptors, err = c.descriptors(); err != nil {
				return nil, err
			}
			for i := range gc.Descriptors {
				desc := &gc.Descriptors[i]
				desc.Value, desc.ReadErr = d.readForTable(desc.Handle)
			}
			gs.Characteristics = append(gs.Characteristics, gc)
		}
		out = append(out, gs)
	}
	return out, nil
}

func (d *hciDevice) readForTable(handle uint16) ([]byte, string) {
	v, err := d.read(handle)
	if err != nil {
		return nil, err.Error()
	}
	return v, ""
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

// errKeyMissing means the peer no longer has the LTK we hold for it.
var errKeyMissing = errors.New("peer has no key for this bond")

type encryptResult struct {
	status  uint8
	enabled bool
}

// encryptionChanged delivers the outcome of an encryption attempt.
func (d *hciDevice) encryptionChanged(status uint8, enabled bool) {
	select {
	case d.encDone <- encryptResult{status, enabled}:
	default:
	}
}

// secure encrypts the link: with the stored LTK if we are bonded to the peer,
// otherwise by pairing (and bonding, when both sides want it).
func (d *hciDevice) secure() error {
	d.secMu.Lock()
	defer d.secMu.Unlock()
	if d.encrypted.Load() {
		return nil
	}

	if b, ok := d.adapter.findBond(d.Address()); ok {
		d.adapter.logf("security: bonded to %s; encrypting with the stored LTK", b.Address)
		err := d.encrypt(b.LTK)
		if !errors.Is(err, errKeyMissing) {
			return err
		}
		// The peer has dropped our bond (e.g. after a factory reset); forget
		// it too and pair afresh.
		d.adapter.logf("security: peer has no key for our bond; deleting it and pairing again")
		if err := d.adapter.deleteBond(b.Address); err != nil {
			return err
		}
	}

	local := d.adapter.bonds.LocalAddress.MAC // fixed once the adapter is open
	d.adapter.logf("security: no bond; pairing")
	res, err := pair(smpLink{
		send:     func(pdu []byte) error { return d.adapter.sendL2CAP(d.handle, hci.CIDSecurity, pdu) },
		rx:       d.drainedSMP(),
		done:     d.disc,
		encrypt:  d.encrypt,
		confirm:  d.adapter.confirmPasskey,
		logf:     d.adapter.logf,
		initAddr: append([]byte{hci.AddressRandom}, local[:]...),
		respAddr: d.peerAddr,
	})
	if err != nil {
		d.adapter.logf("security: pairing failed: %v", err)
		return err
	}

	addr := d.Address()
	if res.identity != nil {
		id := *res.identity
		if isRPA(addr) {
			id.rpa = addr.MAC
		} else {
			id.rpa = addr.rpa
		}
		addr = id
		d.addrMu.Lock()
		d.addr = id
		d.addrMu.Unlock()
	}
	if !res.bonded {
		d.adapter.logf("security: paired without bonding; keys not stored")
		return nil
	}
	d.adapter.logf("security: bond saved for %s", addr)
	return d.adapter.saveBond(Bond{Address: addr, LTK: res.ltk, IRK: res.irk})
}

// notConnected reports a dropped link, with the reason if it followed a
// failed peer-requested pairing.
func (d *hciDevice) notConnected() error {
	if err := d.secErr.Load(); err != nil {
		return fmt.Errorf("%w (after pairing failed: %w)", ErrNotConnected, *err)
	}
	return ErrNotConnected
}

// drainedSMP discards stale SMP PDUs left from an earlier attempt and returns
// the channel for a new pairing.
func (d *hciDevice) drainedSMP() <-chan []byte {
	for {
		select {
		case <-d.smpRx:
		default:
			return d.smpRx
		}
	}
}

// encrypt starts link encryption with ltk (most significant octet first) and
// waits for the controller to report the outcome.
func (d *hciDevice) encrypt(ltk [16]byte) error {
	select {
	case <-d.encDone: // drop a stale result
	default:
	}
	cmd := hci.LEEnableEncryption(d.handle, 0, 0, [16]byte(hci.Reverse(ltk[:])))
	if err := d.adapter.sendCommand(cmd); err != nil {
		return fmt.Errorf("enable encryption: %w", err)
	}
	select {
	case r := <-d.encDone:
		switch {
		case r.status == hci.ErrPinOrKeyMissing:
			return errKeyMissing
		case r.status != 0 || !r.enabled:
			return fmt.Errorf("enable encryption: status %#x", r.status)
		}
		d.encrypted.Store(true)
		return nil
	case <-d.disc:
		return ErrNotConnected
	case <-time.After(smpTimeout):
		return errors.New("enable encryption: timed out")
	}
}
