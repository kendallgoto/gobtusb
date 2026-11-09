package gobtusb

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gousb"
	"github.com/kendallgoto/gobtusb/internal/hci"
)

// 4.B.2.2.2 RequestType for HCI control packets
const hciCtrlRequestType = 0x21

// HCIOptions describes what USB Bluetooth controller to select.
// By default, it will auto-pick by scanning.
type HCIOptions struct {
	// VendorID and ProductID restrict the scan to a specific USB VID:PID
	VendorID  uint16
	ProductID uint16

	// Serial selects the controller by its exact USB serial number
	Serial string

	// Interface will claim a specific USB interface number instead of
	// scanning and detecting which is a Wireless Controller interface
	Interface int
}

// hciAdapter is the raw USB HCI backend.
type hciAdapter struct {
	ctx      *gousb.Context
	dev      *gousb.Device
	intf     *gousb.Interface
	ifaceNum int    // bInterfaceNumber, used as wIndex for HCI command transfers
	done     func() // releases the claimed interface/config

	eventIn *gousb.InEndpoint  // HCI events (interrupt IN)
	aclIn   *gousb.InEndpoint  // ACL data from controller (bulk IN)
	aclOut  *gousb.OutEndpoint // ACL data to controller (bulk OUT)

	randomAddr [6]byte // random static address, in transmission (LE) order

	aclMaxData int           // controller's max ACL data bytes per packet
	aclSem     chan struct{} // in-flight ACL packets, capped at the controller's buffer count

	scanMu sync.Mutex
	scan   *hciScanSession // in-progress scan, if any

	mu         sync.Mutex            // protects the fields below
	devices    map[uint16]*hciDevice // connected devices, by connection handle
	readCancel context.CancelFunc    // cancels the background readers when set
}

// hciScanSession tracks a background scan's cancellation
type hciScanSession struct {
	cancel   context.CancelFunc
	stopped  atomic.Bool
	readDone chan struct{}
}

// newRandomStaticAddress returns a valid LE random static address in
// transmission (little-endian) order. The highest bits are set to identify it is random
// (6.B.1.3.2)
func newRandomStaticAddress() [6]byte {
	var a [6]byte
	_, _ = rand.Read(a[:])
	a[5] |= 0xC0
	return a
}

// NewHCIAdapter opens a USB Bluetooth controller and claims its HCI interface.
func NewHCIAdapter(opts HCIOptions) (Adapter, error) {
	ctx := gousb.NewContext()

	dev, ifaceNum, err := openController(ctx, opts)
	if err != nil {
		ctx.Close()
		return nil, err
	}

	a := &hciAdapter{
		ctx:        ctx,
		dev:        dev,
		randomAddr: newRandomStaticAddress(),
		devices:    make(map[uint16]*hciDevice),
	}
	if err := a.claim(ifaceNum); err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}

// Controller describes the USB Bluetooth controller this adapter opened.
func (a *hciAdapter) Controller() HCIControllerInfo {
	info := controllerInfo(a.dev)
	info.Interface = a.ifaceNum
	return info
}

// claim selects the controller's configuration, claims the HCI interface, and
// locates the event/ACL endpoints.
func (a *hciAdapter) claim(ifaceNum int) error {
	cfgNum, err := a.dev.ActiveConfigNum()
	if err != nil {
		cfgNum = 1
	}
	cfg, err := a.dev.Config(cfgNum)
	if err != nil {
		return fmt.Errorf("select config %d: %w", cfgNum, err)
	}
	intf, err := cfg.Interface(ifaceNum, 0)
	if err != nil {
		cfg.Close()
		return fmt.Errorf("claim interface %d: %w", ifaceNum, err)
	}
	a.intf = intf
	a.ifaceNum = ifaceNum
	a.done = func() { intf.Close(); cfg.Close() }

	if intf.Setting.Class != gousb.ClassWireless {
		return fmt.Errorf("%w: interface %d is class %#x, not Wireless Controller (0xe0)", ErrNotEnabled, ifaceNum, intf.Setting.Class)
	}
	return a.openEndpoints()
}

// openEndpoints finds the interrupt-IN (events) and bulk IN/OUT (ACL) endpoints
// of the claimed interface.
func (a *hciAdapter) openEndpoints() error {
	for _, ep := range a.intf.Setting.Endpoints {
		switch {
		case ep.TransferType == gousb.TransferTypeInterrupt && ep.Direction == gousb.EndpointDirectionIn:
			if a.eventIn, _ = a.intf.InEndpoint(ep.Number); a.eventIn == nil {
				return fmt.Errorf("%w: open event endpoint", ErrNotEnabled)
			}
		case ep.TransferType == gousb.TransferTypeBulk && ep.Direction == gousb.EndpointDirectionIn:
			a.aclIn, _ = a.intf.InEndpoint(ep.Number)
		case ep.TransferType == gousb.TransferTypeBulk && ep.Direction == gousb.EndpointDirectionOut:
			a.aclOut, _ = a.intf.OutEndpoint(ep.Number)
		}
	}
	if a.eventIn == nil {
		return fmt.Errorf("%w: controller has no interrupt-IN (event) endpoint", ErrNotEnabled)
	}
	return nil
}

// Close releases the USB interface and context.
func (a *hciAdapter) Close() error {
	a.mu.Lock()
	a.stopReadersLocked()
	a.mu.Unlock()
	if a.done != nil {
		a.done()
		a.done = nil
	}
	if a.dev != nil {
		a.dev.Close()
		a.dev = nil
	}
	if a.ctx != nil {
		a.ctx.Close()
		a.ctx = nil
	}
	return nil
}

// Enable resets the controller, enables the event masks a central needs
// (notably the LE Meta event that carries advertising reports), sets a random
// static address, and reads the controller's ACL buffer size so outgoing L2CAP
// frames can be fragmented to fit.
func (a *hciAdapter) Enable(ctx context.Context) error {
	cmds := []hci.Command{
		hci.Reset(),
		hci.SetEventMask(0x3FFFFFFFFFFFFFFF), // includes bit 61 (LE Meta event)
		hci.LESetEventMask(0x1F),             // LE subevents incl. advertising report
		hci.SetRandomAddress(a.randomAddr),
	}
	for _, cmd := range cmds {
		if err := a.command(ctx, cmd); err != nil {
			return fmt.Errorf("HCI enable: %w", err)
		}
	}

	// Learn how large each ACL packet to the controller may be and how many it
	// can buffer. Fall back to the spec minimum.
	a.aclMaxData = 27
	a.aclSem = make(chan struct{}, 2)
	if ret, err := a.commandReturn(ctx, hci.LEReadBufferSize()); err == nil {
		if bs, err := hci.ParseLEReadBufferSize(ret); err == nil && bs.DataLength >= 27 && bs.NumPackets > 0 {
			a.aclMaxData = int(bs.DataLength)
			a.aclSem = make(chan struct{}, bs.NumPackets)
		}
	}
	return nil
}

// command sends an HCI command and waits for its Command Complete (or Command
// Status) event, returning an error on a non-zero status, ctx cancellation, or
// timeout.
func (a *hciAdapter) command(ctx context.Context, cmd hci.Command) error {
	_, err := a.commandReturn(ctx, cmd)
	return err
}

// commandReturn sends an HCI command, waits for its Command Complete (or
// Command Status) event, and returns the event's return parameters. The wait is
// bounded by ctx and a per-command cap.
func (a *hciAdapter) commandReturn(ctx context.Context, cmd hci.Command) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second) // TODO: configurable?
	defer cancel()
	if err := a.sendCommand(cmd); err != nil {
		return nil, err
	}
	for {
		ev, err := a.readEventCtx(cctx)
		if err != nil {
			if cctx.Err() != nil {
				return nil, fmt.Errorf("%w: awaiting completion of command %#x: %w", ErrNotEnabled, cmd.Opcode, cctx.Err())
			}
			continue // transient read error; keep waiting
		}
		if cc, err := ev.CommandComplete(); err == nil && cc.Opcode == cmd.Opcode {
			if cc.Status != 0 {
				return nil, fmt.Errorf("command %#x failed with status %#x", cmd.Opcode, cc.Status)
			}
			return cc.Return, nil
		}
		if cs, err := ev.CommandStatus(); err == nil && cs.Opcode == cmd.Opcode {
			if cs.Status != 0 {
				return nil, fmt.Errorf("command %#x failed with status %#x", cmd.Opcode, cs.Status)
			}
			return nil, nil
		}
	}
}

// sendCommand writes an HCI command over the USB control endpoint. On the USB
// transport the command has no leading packet-type indicator (the transfer type
// implies it), so the indicator byte produced by Encode is stripped.
func (a *hciAdapter) sendCommand(cmd hci.Command) error {
	raw := cmd.Encode()[1:]
	_, err := a.dev.Control(hciCtrlRequestType, 0x00, 0, uint16(a.ifaceNum), raw)
	return err
}

// readEventCtx reads a single HCI event from the interrupt-IN endpoint. Events
// on the USB transport omit the packet-type indicator, so it is prepended
// before parsing.
func (a *hciAdapter) readEventCtx(ctx context.Context) (*hci.Event, error) {
	buf := make([]byte, 512)
	n, err := a.eventIn.ReadContext(ctx, buf)
	if err != nil {
		return nil, err
	}
	return hci.ParseEvent(append([]byte{hci.PacketTypeEvent}, buf[:n]...))
}

func (a *hciAdapter) Scan(callback func(ScanResult)) error {
	a.mu.Lock()
	connected := a.readCancel != nil
	a.mu.Unlock()
	if connected {
		return fmt.Errorf("%w: cannot scan while connected", ErrScanning)
	}

	a.scanMu.Lock()
	defer a.scanMu.Unlock()
	if a.scan != nil {
		return ErrScanning
	}

	// Active scan, 100 ms interval / 50 ms window (units of 0.625 ms). Use the
	// random static address set in Enable as the scanner's own address.
	// TODO: configurable?
	if err := a.command(context.Background(), hci.SetScanParameters(hci.ScanTypeActive, 0x00A0, 0x0050, hci.AddressRandom)); err != nil {
		return fmt.Errorf("set scan parameters: %w", err)
	}
	if err := a.command(context.Background(), hci.SetScanEnable(true, false)); err != nil {
		return fmt.Errorf("enable scan: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sess := &hciScanSession{cancel: cancel, readDone: make(chan struct{})}
	a.scan = sess
	results := make(chan ScanResult, 64)
	go a.scanReadLoop(ctx, sess, results)
	go scanDeliverLoop(sess, results, callback)
	return nil
}

// scanReadLoop reads advertising reports until the session is cancelled, then
// disables scanning at the controller and signals completion.
func (a *hciAdapter) scanReadLoop(ctx context.Context, sess *hciScanSession, results chan<- ScanResult) {
	defer close(sess.readDone)
	defer close(results)
	merged := advMerger{}
	for {
		ev, err := a.readEventCtx(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break // StopScan cancelled the scan
			}
			continue // transient read error or short packet; keep scanning
		}
		if reports, err := ev.AdvertisingReports(); err == nil {
			for _, r := range reports {
				select {
				case results <- scanResultFromReport(merged.merge(r)):
				default: // delivery backlog; drop rather than stall the reader
				}
			}
		}
	}
	// Disable scanning with a fresh context, since ctx is already cancelled.
	_ = a.command(context.Background(), hci.SetScanEnable(false, false))
}

// scanDeliverLoop invokes the callback for queued results from a dedicated
// goroutine, so a callback that itself calls StopScan cannot deadlock.
func scanDeliverLoop(sess *hciScanSession, results <-chan ScanResult, callback func(ScanResult)) {
	for r := range results {
		if sess.stopped.Load() {
			continue // drain without delivering once StopScan has been called
		}
		callback(r)
	}
}

func (a *hciAdapter) StopScan() error {
	a.scanMu.Lock()
	sess := a.scan
	a.scan = nil
	a.scanMu.Unlock()
	if sess == nil {
		return nil
	}
	sess.stopped.Store(true)
	sess.cancel()
	<-sess.readDone
	return nil
}

// advMerger joins each peer's advertisement with its scan response. The
// controller reports them separately, and peers commonly put the name in the
// scan response once the primary payload's 31 bytes are used up; CoreBluetooth
// delivers them merged, so we do the same.
type advMerger map[[7]byte]*advPair

type advPair struct{ adv, rsp []byte }

// maxMergedPeers bounds the cache in busy environments; it is simply reset
// when full, costing at most one unmerged report per peer.
const maxMergedPeers = 256

// mergedReport is an advertising report whose Data holds the advertisement
// followed by the scan response, the first advLen bytes being the former.
type mergedReport struct {
	hci.AdvertisingReport
	advLen int
}

// merge returns r with its payload extended by the peer's latest counterpart
// (scan response for an advertisement, or vice versa), if one has been seen.
func (m advMerger) merge(r hci.AdvertisingReport) mergedReport {
	if r.EventType != hci.AdvInd && r.EventType != hci.AdvScanInd && r.EventType != hci.ScanRsp {
		return mergedReport{r, len(r.Data)} // not scannable: there is no scan response to join
	}
	key := [7]byte{r.AddrType}
	copy(key[1:], r.Addr[:])
	p := m[key]
	if p == nil {
		if len(m) >= maxMergedPeers {
			clear(m)
		}
		p = &advPair{}
		m[key] = p
	}
	if r.EventType == hci.ScanRsp {
		p.rsp = r.Data
	} else {
		p.adv = r.Data
	}
	r.Data = slices.Concat(p.adv, p.rsp) // AD structures concatenate as-is
	return mergedReport{r, len(p.adv)}
}

// scanResultFromReport converts an HCI advertising report into a ScanResult.
func scanResultFromReport(r mergedReport) ScanResult {
	var addr Address
	for i := range 6 {
		addr.MAC[i] = r.Addr[5-i]
	}
	addr.IsRandom = r.AddrType == hci.AddressRandom
	return ScanResult{Address: addr, RSSI: r.RSSI, payload: r.Data, split: true, advLen: r.advLen}
}

// Connect establishes an LE connection to the peripheral at addr, then drives
// GATT over ATT/L2CAP on the ACL endpoints.
func (a *hciAdapter) Connect(ctx context.Context, addr Address, params ConnectParams) (Device, error) {
	a.scanMu.Lock()
	scanning := a.scan != nil
	a.scanMu.Unlock()
	if scanning {
		return nil, fmt.Errorf("%w: stop scanning before connecting", ErrScanning)
	}
	a.mu.Lock()
	connected := a.readCancel != nil
	a.mu.Unlock()
	if connected {
		return nil, fmt.Errorf("%w: a connection is already active", ErrNotConnected)
	}

	cctx, cancel := withConnectTimeout(ctx)
	defer cancel()

	var peer [6]byte
	for i := range 6 {
		peer[i] = addr.MAC[5-i] // MAC order -> transmission (little-endian) order
	}
	peerType := uint8(hci.AddressPublic)
	if addr.IsRandom {
		peerType = hci.AddressRandom
	}
	// scan interval/window 60/30 ms; connection interval 30-50 ms; no latency;
	// supervision timeout 4 s (units: 0.625 ms, 1.25 ms, 10 ms respectively).
	// TODO: configurable?
	cmd := hci.CreateConnection(0x0060, 0x0030, peerType, peer, hci.AddressRandom, 0x0018, 0x0028, 0, 0x0190)
	if err := a.command(cctx, cmd); err != nil { // returns on Command Status
		return nil, fmt.Errorf("create connection: %w", err)
	}

	// Wait synchronously for the LE Connection Complete event.
	var cc hci.ConnectionComplete
	got := false
	for !got {
		ev, err := a.readEventCtx(cctx)
		if err != nil {
			if cctx.Err() != nil {
				break // ctx cancelled or timed out
			}
			continue
		}
		if c, e := ev.ConnectionComplete(); e == nil {
			cc, got = c, true
		}
	}
	if !got {
		_ = a.command(context.Background(), hci.Command{Opcode: hci.OpLECreateConnectionCxl})
		return nil, fmt.Errorf("%w: awaiting connection: %w", ErrNotConnected, cctx.Err())
	}
	if cc.Status != 0 {
		return nil, fmt.Errorf("%w: connection failed with status %#x", ErrNotConnected, cc.Status)
	}

	dev := newHCIDevice(a, cc.Handle, addr)
	a.mu.Lock()
	a.devices[cc.Handle] = dev
	a.startReadersLocked()
	a.mu.Unlock()

	dev.exchangeMTU(hostRxMTU) // configurable?
	return dev, nil
}

// disconnect tears down the connection identified by handle. The HCI Disconnect
// command is sent without synchronously awaiting its completion event, since the
// background event reader owns the event endpoint while connected.
func (a *hciAdapter) disconnect(handle uint16) error {
	_ = a.sendCommand(hci.Disconnect(handle, 0x13)) // 0x13: remote user terminated
	a.handleDisconnect(handle)
	return nil
}

// startReadersLocked starts the background event and ACL readers if they are not
// already running. a.mu must be held.
func (a *hciAdapter) startReadersLocked() {
	if a.readCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.readCancel = cancel
	go a.eventLoop(ctx)
	go a.aclLoop(ctx)
}

// stopReadersLocked stops the background readers. a.mu must be held.
func (a *hciAdapter) stopReadersLocked() {
	if a.readCancel != nil {
		a.readCancel()
		a.readCancel = nil
	}
}

// eventLoop reads HCI events while connected, watching for disconnection and
// returning ACL flow-control credits as the controller completes transmissions.
func (a *hciAdapter) eventLoop(ctx context.Context) {
	for ctx.Err() == nil {
		ev, err := a.readEventCtx(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		switch ev.Code {
		case hci.EventDisconnectionComplete:
			if len(ev.Params) >= 3 {
				a.handleDisconnect(binary.LittleEndian.Uint16(ev.Params[1:3]))
			}
		case hci.EventNumberOfCompletedPackets:
			if pkts, err := ev.NumberOfCompletedPackets(); err == nil {
				for _, p := range pkts {
					a.releaseCredits(int(p.Count))
				}
			}
		}
	}
}

// aclLoop reads ACL data while connected, reassembles L2CAP frames from their
// fragments, and dispatches complete PDUs.
func (a *hciAdapter) aclLoop(ctx context.Context) {
	reassemblers := make(map[uint16]*hci.Reassembler)
	// Read with room for a full controller-to-host ACL packet (which can exceed
	// the endpoint's USB packet size; the transfer ends with a short packet).
	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		n, err := a.aclIn.ReadContext(ctx, buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		frag, err := hci.ParseACLFragment(append([]byte{hci.PacketTypeACLData}, buf[:n]...))
		if err != nil {
			continue
		}
		r := reassemblers[frag.Handle]
		if r == nil {
			r = &hci.Reassembler{}
			reassemblers[frag.Handle] = r
		}
		cid, payload, done := r.Push(frag.PB, frag.Data)
		if !done {
			continue
		}
		switch cid {
		case hci.CIDATT:
			a.dispatchATT(frag.Handle, payload)
		case hci.CIDLESignal:
			a.handleSignaling(frag.Handle, payload)
		}
	}
}

// acquireCredit reserves one controller ACL buffer before sending a packet. To
// avoid wedging forever if a Number Of Completed Packets event is lost, it
// gives up waiting after a second and proceeds best-effort.
func (a *hciAdapter) acquireCredit() {
	select {
	case a.aclSem <- struct{}{}:
	case <-time.After(time.Second):
	}
}

// releaseCredits returns n controller ACL buffers.
func (a *hciAdapter) releaseCredits(n int) {
	for range n {
		select {
		case <-a.aclSem:
		default:
			return
		}
	}
}

// handleSignaling answers L2CAP signaling the peripheral sends to a central,
// accepting connection-parameter-update requests.
func (a *hciAdapter) handleSignaling(handle uint16, pdu []byte) {
	if len(pdu) < 2 || pdu[0] != hci.SigConnParamUpdateRequest {
		return
	}
	identifier := pdu[1]
	_ = a.sendL2CAP(handle, hci.CIDLESignal, hci.ConnParamUpdateResponse(identifier, 0x0000))
}

// dispatchATT routes an inbound ATT PDU to a notification callback or to the
// device's in-flight request waiter.
func (a *hciAdapter) dispatchATT(handle uint16, pdu []byte) {
	a.mu.Lock()
	dev := a.devices[handle]
	a.mu.Unlock()
	if dev == nil || len(pdu) == 0 {
		return
	}
	if hv := hci.ParseHandleValue(pdu); hv != nil {
		if hv.Opcode == hci.ATTHandleValueIndication {
			_ = a.sendACL(handle, hci.HandleValueConfirmation())
		}
		dev.dispatchNotify(hv.Handle, hv.Value)
		return
	}
	// The peripheral may initiate an MTU exchange; answer it rather than
	// mistaking the request for a response to one of our GATT requests. The
	// bearer MTU becomes the minimum of the two sides' receive MTUs.
	if pdu[0] == hci.ATTExchangeMTURequest {
		if len(pdu) >= 3 {
			dev.setMTU(min(binary.LittleEndian.Uint16(pdu[1:3]), hostRxMTU))
		}
		_ = a.sendACL(handle, hci.ExchangeMTUResponse(hostRxMTU))
		return
	}
	dev.deliverResponse(pdu)
}

// handleDisconnect removes a device and stops the readers when none remain.
func (a *hciAdapter) handleDisconnect(handle uint16) {
	a.mu.Lock()
	dev := a.devices[handle]
	delete(a.devices, handle)
	if len(a.devices) == 0 {
		a.stopReadersLocked()
		// In-flight packets on the dropped connection will never report
		// completion; return their credits.
		a.releaseCredits(cap(a.aclSem))
	}
	a.mu.Unlock()
	if dev != nil {
		dev.markDisconnected()
	}
}

// sendACL frames an ATT PDU (L2CAP channel CIDATT) and writes it to the
// controller.
func (a *hciAdapter) sendACL(handle uint16, payload []byte) error {
	return a.sendL2CAP(handle, hci.CIDATT, payload)
}

// sendL2CAP frames an L2CAP payload on the given channel, fragments it to the
// controller's ACL buffer size, and writes the packets to the controller,
// honoring its buffer count. The USB bulk transport omits the packet-type
// indicator, so it is stripped.
func (a *hciAdapter) sendL2CAP(handle, cid uint16, payload []byte) error {
	for _, pkt := range hci.FragmentACL(handle, cid, payload, a.aclMaxData) {
		a.acquireCredit()
		if _, err := a.aclOut.Write(pkt[1:]); err != nil {
			return err
		}
	}
	return nil
}
