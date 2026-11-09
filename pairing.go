package gobtusb

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/kendallgoto/gobtusb/internal/hci"
)

// smpTimeout bounds each step of pairing (3.H.3.4).
const smpTimeout = 30 * time.Second

// smpLink is what pairing needs from a connection.
type smpLink struct {
	send    func(pdu []byte) error
	rx      <-chan []byte            // inbound SMP PDUs
	done    <-chan struct{}          // closed on disconnection
	encrypt func(ltk [16]byte) error // starts link encryption with ltk

	// confirm shows the numeric comparison value and reports whether the
	// user accepted it; nil accepts every value.
	confirm func(passkey uint32) bool

	logf func(format string, args ...any) // optional trace of each step

	// The addresses used to establish the connection, as type ‖ address (most
	// significant octet first): the A and B inputs of f5 and f6.
	initAddr, respAddr []byte
}

// pairResult is what a successful pairing yields.
type pairResult struct {
	ltk      [16]byte
	irk      [16]byte
	identity *Address // the peer's identity address, if it distributed one
	bonded   bool     // both sides asked to bond

	// authenticated is true when the key is MITM-protected (Numeric
	// Comparison), which is what a peer requiring security level 4 needs.
	authenticated bool
}

// pairingMethod is the LE Secure Connections association model (3.H.2.3.5.1).
type pairingMethod int

const (
	justWorks pairingMethod = iota
	numericComparison
	passkeyEntry // not supported: we have no keyboard and show no passkey
)

// scMethod picks the association model from both sides' features: Just Works
// unless someone asked for MITM protection, otherwise by IO capabilities
// (3.H.2.3.5.1, Table 2.8, Secure Connections entries).
func scMethod(init, resp hci.PairingFeatures) pairingMethod {
	if (init.AuthReq|resp.AuthReq)&hci.AuthReqMITM == 0 {
		return justWorks
	}
	if init.IOCap == hci.IOCapNoInputNoOutput || resp.IOCap == hci.IOCapNoInputNoOutput {
		return justWorks
	}
	yesNo := func(c uint8) bool { return c == hci.IOCapDisplayYesNo || c == hci.IOCapKeyboardDisplay }
	keyboard := func(c uint8) bool { return c == hci.IOCapKeyboardOnly || c == hci.IOCapKeyboardDisplay }
	switch {
	case yesNo(init.IOCap) && yesNo(resp.IOCap):
		return numericComparison
	case keyboard(init.IOCap) || keyboard(resp.IOCap):
		return passkeyEntry
	}
	return justWorks
}

// pair runs LE Secure Connections pairing as the initiator (3.H.2.3.5.6),
// then starts encryption and receives the peer's identity key. We present
// DisplayYesNo and request MITM protection, so a peer that can confirm a
// number pairs with Numeric Comparison (authenticated, security level 4) and
// one without IO falls back to Just Works (unauthenticated, level 2).
func pair(l smpLink) (pairResult, error) {
	var res pairResult
	fail := func(reason byte, err error) (pairResult, error) {
		_ = l.send(hci.PairingFailed(reason))
		return pairResult{}, err
	}

	// -- Phase 1: feature exchange. We ask the peer for its identity key so
	// its private addresses can be resolved later, and distribute nothing:
	// our random static address is our identity.
	req := hci.PairingFeatures{
		IOCap:       hci.IOCapDisplayYesNo,
		AuthReq:     hci.AuthReqBonding | hci.AuthReqMITM | hci.AuthReqSC,
		MaxKeySize:  16,
		RespKeyDist: hci.KeyDistIdKey,
	}
	if err := l.send(req.Encode(hci.SMPPairingRequest)); err != nil {
		return res, err
	}
	pdu, err := l.expect(hci.SMPPairingResponse)
	if err != nil {
		return res, err
	}
	rsp, err := hci.ParsePairingFeatures(pdu)
	if err != nil {
		return fail(hci.SMPErrInvalidParameters, err)
	}
	if rsp.AuthReq&hci.AuthReqSC == 0 {
		return fail(hci.SMPErrAuthRequirements, errors.New("peer does not support LE Secure Connections"))
	}
	if rsp.MaxKeySize != 16 {
		return fail(hci.SMPErrEncryptionKeySize, fmt.Errorf("peer offers a %d-octet key, want 16", rsp.MaxKeySize))
	}
	method := scMethod(req, rsp)
	l.log("SMP: ours IOCap %#02x AuthReq %#02x; peer IOCap %#02x AuthReq %#02x, key size %d, keys init %#02x resp %#02x -> %s",
		req.IOCap, req.AuthReq, rsp.IOCap, rsp.AuthReq, rsp.MaxKeySize, rsp.InitKeyDist, rsp.RespKeyDist, method)
	if method == passkeyEntry {
		return fail(hci.SMPErrPasskeyEntryFailed, fmt.Errorf("peer IO capability %#x needs passkey entry, which is not supported", rsp.IOCap))
	}

	// -- Phase 2, public key exchange: DHKey is the x-coordinate of the shared point.
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return fail(hci.SMPErrUnspecified, err)
	}
	pkA := priv.PublicKey().Bytes()[1:] // X ‖ Y, big-endian
	if err := l.send(hci.PairingPublicKey(pkA[:32], pkA[32:])); err != nil {
		return res, err
	}
	if pdu, err = l.expect(hci.SMPPairingPublicKey); err != nil {
		return res, err
	}
	bx, by, err := hci.ParsePairingPublicKey(pdu)
	if err != nil {
		return fail(hci.SMPErrInvalidParameters, err)
	}
	pkB := slices.Concat(bx, by)
	peer, err := ecdh.P256().NewPublicKey(slices.Concat([]byte{0x04}, pkB)) // validates the point
	if err != nil || subtle.ConstantTimeCompare(pkA, pkB) == 1 {
		return fail(hci.SMPErrInvalidParameters, errors.New("invalid peer public key"))
	}
	dhKey, err := priv.ECDH(peer)
	if err != nil {
		return fail(hci.SMPErrInvalidParameters, err)
	}
	l.log("SMP: public keys exchanged, DHKey computed")

	// -- Phase 2, authentication stage 1 (Just Works / Numeric Comparison):
	// the responder commits to Nb, we reveal Na, then it reveals Nb and we
	// check its commitment.
	if pdu, err = l.expect(hci.SMPPairingConfirm); err != nil {
		return res, err
	}
	cb, err := hci.ParseSMPValue(pdu, 16)
	if err != nil {
		return fail(hci.SMPErrInvalidParameters, err)
	}
	na := make([]byte, 16)
	rand.Read(na)
	if err := l.send(hci.SMPValue(hci.SMPPairingRandom, na)); err != nil {
		return res, err
	}
	if pdu, err = l.expect(hci.SMPPairingRandom); err != nil {
		return res, err
	}
	nb, err := hci.ParseSMPValue(pdu, 16)
	if err != nil {
		return fail(hci.SMPErrInvalidParameters, err)
	}
	if subtle.ConstantTimeCompare(hci.F4(bx, pkA[:32], nb, 0), cb) != 1 {
		return fail(hci.SMPErrConfirmValueFailed, errors.New("peer confirm value does not match"))
	}
	if method == numericComparison {
		// Both sides display Va = g2(PKax, PKbx, Na, Nb) mod 10^6; a MITM
		// with its own keys can't make the two numbers match.
		va := hci.G2(pkA[:32], bx, na, nb) % 1000000
		if l.confirm != nil && !l.confirm(va) {
			return fail(hci.SMPErrNumericCompFailed, fmt.Errorf("numeric comparison %06d rejected", va))
		}
		res.authenticated = true
		l.log("SMP: numeric comparison %06d accepted", va)
	}

	// -- Phase 2, authentication stage 2: derive the LTK and exchange DHKey checks.
	macKey, ltk := hci.F5(dhKey, na, nb, l.initAddr, l.respAddr)
	zero := make([]byte, 16) // r is zero for Just Works and Numeric Comparison
	ea := hci.F6(macKey, na, nb, zero, req.IOCapField(), l.initAddr, l.respAddr)
	if err := l.send(hci.SMPValue(hci.SMPPairingDHKeyCheck, ea)); err != nil {
		return res, err
	}
	if pdu, err = l.expect(hci.SMPPairingDHKeyCheck); err != nil {
		return res, err
	}
	eb, err := hci.ParseSMPValue(pdu, 16)
	if err != nil {
		return fail(hci.SMPErrInvalidParameters, err)
	}
	if subtle.ConstantTimeCompare(hci.F6(macKey, nb, na, zero, rsp.IOCapField(), l.respAddr, l.initAddr), eb) != 1 {
		return fail(hci.SMPErrDHKeyCheckFailed, errors.New("peer DHKey check does not match"))
	}
	copy(res.ltk[:], ltk)
	l.log("SMP: DHKey checks match; encrypting with the new LTK")

	// -- Encrypt the link with the new LTK.
	if err := l.encrypt(res.ltk); err != nil {
		return pairResult{}, err
	}

	// -- Phase 3: key distribution over the encrypted link. With Secure
	// Connections the LTK is derived, not distributed, so only the keys both
	// sides agreed on arrive here.
	if rsp.RespKeyDist&hci.KeyDistIdKey != 0 {
		if pdu, err = l.expect(hci.SMPIdentityInformation); err != nil {
			return res, err
		}
		irk, err := hci.ParseSMPValue(pdu, 16)
		if err != nil {
			return fail(hci.SMPErrInvalidParameters, err)
		}
		copy(res.irk[:], irk)
		if pdu, err = l.expect(hci.SMPIdentityAddressInformation); err != nil {
			return res, err
		}
		typ, addr, err := hci.ParseIdentityAddress(pdu)
		if err != nil {
			return fail(hci.SMPErrInvalidParameters, err)
		}
		id := Address{IsRandom: typ == hci.AddressRandom}
		copy(id.MAC[:], addr)
		res.identity = &id
		l.log("SMP: peer distributed IRK and identity address %s", id)
	}
	res.bonded = req.AuthReq&rsp.AuthReq&hci.AuthReqBonding != 0
	return res, nil
}

func (l smpLink) log(format string, args ...any) {
	if l.logf != nil {
		l.logf(format, args...)
	}
}

func (m pairingMethod) String() string {
	return [...]string{"Just Works", "Numeric Comparison", "Passkey Entry"}[m]
}

// expect waits for the next SMP PDU and checks that it is the given command.
func (l smpLink) expect(code byte) ([]byte, error) {
	select {
	case pdu := <-l.rx:
		switch {
		case len(pdu) >= 2 && pdu[0] == hci.SMPPairingFailed:
			return nil, fmt.Errorf("peer rejected pairing: %s (%#x)", smpReason(pdu[1]), pdu[1])
		case len(pdu) == 0 || pdu[0] != code:
			_ = l.send(hci.PairingFailed(hci.SMPErrUnspecified))
			return nil, fmt.Errorf("unexpected SMP PDU %x, want command %#x", pdu, code)
		}
		return pdu, nil
	case <-l.done:
		return nil, ErrNotConnected
	case <-time.After(smpTimeout):
		return nil, errors.New("SMP timeout")
	}
}

// smpReason names a Pairing Failed reason code (3.H.3.5.5).
func smpReason(code byte) string {
	if s, ok := map[byte]string{
		0x01: "passkey entry failed",
		0x02: "OOB not available",
		0x03: "authentication requirements",
		0x04: "confirm value failed",
		0x05: "pairing not supported",
		0x06: "encryption key size",
		0x07: "command not supported",
		0x08: "unspecified reason",
		0x09: "repeated attempts",
		0x0A: "invalid parameters",
		0x0B: "DHKey check failed",
		0x0C: "numeric comparison failed",
		0x0D: "BR/EDR pairing in progress",
		0x0E: "cross-transport key derivation not allowed",
		0x0F: "key rejected",
	}[code]; ok {
		return s
	}
	return "unknown reason"
}
