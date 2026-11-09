package gobtusb

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"slices"
	"testing"

	"github.com/kendallgoto/gobtusb/internal/hci"
)

var (
	testInitAddr = []byte{hci.AddressRandom, 0xC1, 0x22, 0x33, 0x44, 0x55, 0x66} // our static address
	testRespAddr = []byte{hci.AddressRandom, 0x4A, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF} // peer's RPA
	testPeerIRK  = [16]byte{0: 0x11, 15: 0xEE}
	testPeerID   = Address{MAC: [6]byte{0xC0, 0x01, 0x02, 0x03, 0x04, 0x05}, IsRandom: true}
)

// responder plays the peripheral side of LE Secure Connections Just Works /
// Numeric Comparison pairing (3.H.2.3.5.6), written from the responder's
// point of view.
type responder struct {
	t          *testing.T
	in, out    chan []byte
	ltk        chan []byte
	ioCap      uint8
	mitm       bool        // require MITM protection, like a security level 4 peer
	vb         chan uint32 // the number this side would display, for Numeric Comparison
	badConfirm bool        // send a confirm value that won't match
	stopAtNb   bool        // the initiator is expected to give up after Nb
}

func (r *responder) recv(code byte) []byte {
	pdu := <-r.in
	if pdu[0] != code {
		r.t.Errorf("responder: got PDU %x, want command %#x", pdu, code)
	}
	return pdu
}

func (r *responder) run() {
	req, _ := hci.ParsePairingFeatures(r.recv(hci.SMPPairingRequest))
	rsp := hci.PairingFeatures{
		IOCap:       r.ioCap,
		AuthReq:     hci.AuthReqBonding | hci.AuthReqSC,
		MaxKeySize:  16,
		RespKeyDist: req.RespKeyDist & hci.KeyDistIdKey,
	}
	if r.mitm {
		rsp.AuthReq |= hci.AuthReqMITM
	}
	r.out <- rsp.Encode(hci.SMPPairingResponse)

	ax, ay, _ := hci.ParsePairingPublicKey(r.recv(hci.SMPPairingPublicKey))
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	pkB := priv.PublicKey().Bytes()[1:]
	r.out <- hci.PairingPublicKey(pkB[:32], pkB[32:])
	peer, err := ecdh.P256().NewPublicKey(slices.Concat([]byte{0x04}, ax, ay))
	if err != nil {
		r.t.Error(err)
		return
	}
	dhKey, _ := priv.ECDH(peer)

	nb := make([]byte, 16)
	rand.Read(nb)
	cb := hci.F4(pkB[:32], ax, nb, 0)
	if r.badConfirm {
		cb[0] ^= 1
	}
	r.out <- hci.SMPValue(hci.SMPPairingConfirm, cb)
	na, _ := hci.ParseSMPValue(r.recv(hci.SMPPairingRandom), 16)
	r.out <- hci.SMPValue(hci.SMPPairingRandom, nb)
	if r.vb != nil {
		r.vb <- hci.G2(ax, pkB[:32], na, nb) % 1000000
	}
	if r.badConfirm || r.stopAtNb {
		return // the initiator gives up here
	}

	ea, _ := hci.ParseSMPValue(r.recv(hci.SMPPairingDHKeyCheck), 16)
	macKey, ltk := hci.F5(dhKey, na, nb, testInitAddr, testRespAddr)
	zero := make([]byte, 16)
	if !bytes.Equal(ea, hci.F6(macKey, na, nb, zero, req.IOCapField(), testInitAddr, testRespAddr)) {
		r.t.Error("responder: initiator DHKey check does not match")
	}
	r.out <- hci.SMPValue(hci.SMPPairingDHKeyCheck, hci.F6(macKey, nb, na, zero, rsp.IOCapField(), testRespAddr, testInitAddr))

	// Key distribution, sent once the link is encrypted.
	r.out <- hci.SMPValue(hci.SMPIdentityInformation, testPeerIRK[:])
	r.out <- slices.Concat([]byte{hci.SMPIdentityAddressInformation, hci.AddressRandom}, hci.Reverse(testPeerID.MAC[:]))
	r.ltk <- ltk
}

func newResponder(t *testing.T, ioCap uint8) *responder {
	return &responder{t: t, in: make(chan []byte, 8), out: make(chan []byte, 8), ltk: make(chan []byte, 1), vb: make(chan uint32, 1), ioCap: ioCap}
}

func newTestLink(r *responder, encryptedWith *[16]byte) smpLink {
	return smpLink{
		send:     func(pdu []byte) error { r.in <- pdu; return nil },
		rx:       r.out,
		done:     make(chan struct{}),
		encrypt:  func(ltk [16]byte) error { *encryptedWith = ltk; return nil },
		initAddr: testInitAddr,
		respAddr: testRespAddr,
	}
}

func TestPairJustWorks(t *testing.T) {
	r := newResponder(t, hci.IOCapNoInputNoOutput)
	go r.run()

	var encryptedWith [16]byte
	res, err := pair(newTestLink(r, &encryptedWith))
	if err != nil {
		t.Fatal(err)
	}
	ltk := <-r.ltk
	if !bytes.Equal(res.ltk[:], ltk) || encryptedWith != res.ltk {
		t.Errorf("LTK mismatch: ours %x, encrypted with %x, peer %x", res.ltk, encryptedWith, ltk)
	}
	if res.irk != testPeerIRK || res.identity == nil || !sameIdentity(*res.identity, testPeerID) || !res.bonded {
		t.Errorf("unexpected keys: %+v", res)
	}
	if res.authenticated {
		t.Error("Just Works key reported as authenticated")
	}
}

// A peer that can confirm a number and requires MITM protection (security
// level 4) gets Numeric Comparison, and both sides show the same value.
func TestPairNumericComparison(t *testing.T) {
	r := newResponder(t, hci.IOCapDisplayYesNo)
	r.mitm = true
	go r.run()

	var shown uint32
	var encryptedWith [16]byte
	l := newTestLink(r, &encryptedWith)
	l.confirm = func(v uint32) bool { shown = v; return true }
	res, err := pair(l)
	if err != nil {
		t.Fatal(err)
	}
	if vb := <-r.vb; shown != vb || shown >= 1000000 {
		t.Errorf("initiator showed %06d, responder %06d", shown, vb)
	}
	if ltk := <-r.ltk; !bytes.Equal(res.ltk[:], ltk) || !res.authenticated {
		t.Errorf("LTK %x (peer %x), authenticated %v", res.ltk, ltk, res.authenticated)
	}
}

func TestPairNumericComparisonRejected(t *testing.T) {
	r := newResponder(t, hci.IOCapKeyboardDisplay)
	r.stopAtNb = true
	go r.run()

	var encryptedWith [16]byte
	l := newTestLink(r, &encryptedWith)
	l.confirm = func(uint32) bool { return false }
	if _, err := pair(l); err == nil {
		t.Fatal("pairing succeeded after the user rejected the comparison")
	}
	if pdu := <-r.in; !bytes.Equal(pdu, hci.PairingFailed(hci.SMPErrNumericCompFailed)) {
		t.Errorf("sent %x, want Pairing Failed (numeric comparison failed)", pdu)
	}
	if encryptedWith != ([16]byte{}) {
		t.Error("link encrypted after failed pairing")
	}
}

func TestSCMethod(t *testing.T) {
	const (
		do  = hci.IOCapDisplayOnly
		dyn = hci.IOCapDisplayYesNo
		ko  = hci.IOCapKeyboardOnly
		nio = hci.IOCapNoInputNoOutput
		kd  = hci.IOCapKeyboardDisplay
	)
	const mitm = hci.AuthReqSC | hci.AuthReqMITM
	for _, c := range []struct {
		init, resp uint8
		authReq    uint8
		want       pairingMethod
	}{
		{dyn, dyn, mitm, numericComparison},
		{dyn, kd, mitm, numericComparison},
		{kd, kd, mitm, numericComparison},
		{dyn, nio, mitm, justWorks},
		{dyn, do, mitm, justWorks},
		{dyn, dyn, hci.AuthReqSC, justWorks}, // nobody asked for MITM
		{dyn, ko, mitm, passkeyEntry},
		{do, kd, mitm, passkeyEntry},
	} {
		init := hci.PairingFeatures{IOCap: c.init, AuthReq: c.authReq}
		resp := hci.PairingFeatures{IOCap: c.resp, AuthReq: c.authReq}
		if got := scMethod(init, resp); got != c.want {
			t.Errorf("scMethod(%#x, %#x, authReq %#x) = %d, want %d", c.init, c.resp, c.authReq, got, c.want)
		}
	}
}

func TestPairConfirmMismatch(t *testing.T) {
	r := newResponder(t, hci.IOCapNoInputNoOutput)
	r.badConfirm = true
	go r.run()

	var encryptedWith [16]byte
	if _, err := pair(newTestLink(r, &encryptedWith)); err == nil {
		t.Fatal("pairing succeeded with a bad confirm value")
	}
	// The responder consumed everything up to Na; next the initiator must
	// report the failure.
	if pdu := <-r.in; !bytes.Equal(pdu, hci.PairingFailed(hci.SMPErrConfirmValueFailed)) {
		t.Errorf("sent %x, want Pairing Failed (confirm value failed)", pdu)
	}
	if encryptedWith != ([16]byte{}) {
		t.Error("link encrypted after failed pairing")
	}
}

func TestResolvePrivateAddress(t *testing.T) {
	st := BondState{Bonds: []Bond{{Address: testPeerID, IRK: testPeerIRK}}}
	prand := []byte{0x4A, 0xBC, 0xDE} // top bits 0b01: resolvable private
	var rpa Address
	rpa.IsRandom = true
	copy(rpa.MAC[:3], prand)
	copy(rpa.MAC[3:], hci.Ah(testPeerIRK[:], prand))

	got := st.resolve(rpa)
	if !sameIdentity(got, testPeerID) || got.rpa != rpa.MAC {
		t.Errorf("resolve(%s) = %s (rpa %x), want %s", rpa, got, got.rpa, testPeerID)
	}

	rpa.MAC[5] ^= 1 // someone else's RPA
	if got := st.resolve(rpa); got != rpa {
		t.Errorf("resolve(%s) = %s, want unchanged", rpa, got)
	}
}
