package hci

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"slices"
)

// Security Manager Protocol (3.H), for a central pairing with LE Secure
// Connections. Values passed to the cryptographic functions (3.H.2.2) are most
// significant octet first, as the spec writes them; SMP PDUs carry them
// little-endian, so the PDU helpers here reverse them on the way in and out.

// SMP command codes (3.H.3.3)
const (
	SMPPairingRequest             = 0x01
	SMPPairingResponse            = 0x02
	SMPPairingConfirm             = 0x03
	SMPPairingRandom              = 0x04
	SMPPairingFailed              = 0x05
	SMPEncryptionInformation      = 0x06
	SMPCentralIdentification      = 0x07
	SMPIdentityInformation        = 0x08
	SMPIdentityAddressInformation = 0x09
	SMPSigningInformation         = 0x0A
	SMPSecurityRequest            = 0x0B
	SMPPairingPublicKey           = 0x0C
	SMPPairingDHKeyCheck          = 0x0D
)

// IO capabilities (3.H.3.5.1)
const (
	IOCapDisplayOnly     = 0x00
	IOCapDisplayYesNo    = 0x01
	IOCapKeyboardOnly    = 0x02
	IOCapNoInputNoOutput = 0x03
	IOCapKeyboardDisplay = 0x04
)

// AuthReq flags (3.H.3.5.1)
const (
	AuthReqBonding = 0x01
	AuthReqMITM    = 0x04
	AuthReqSC      = 0x08
)

// Key distribution flags (3.H.3.6.1)
const (
	KeyDistEncKey  = 0x01
	KeyDistIdKey   = 0x02
	KeyDistSignKey = 0x04
)

// Pairing Failed reason codes (3.H.3.5.5)
const (
	SMPErrPasskeyEntryFailed  = 0x01
	SMPErrAuthRequirements    = 0x03
	SMPErrConfirmValueFailed  = 0x04
	SMPErrPairingNotSupported = 0x05
	SMPErrEncryptionKeySize   = 0x06
	SMPErrUnspecified         = 0x08
	SMPErrInvalidParameters   = 0x0A
	SMPErrDHKeyCheckFailed    = 0x0B
	SMPErrNumericCompFailed   = 0x0C
)

// PairingFeatures is the body of a Pairing Request or Pairing Response
// (3.H.3.5.1-2).
type PairingFeatures struct {
	IOCap       uint8
	OOB         uint8
	AuthReq     uint8
	MaxKeySize  uint8
	InitKeyDist uint8
	RespKeyDist uint8
}

// Encode builds a Pairing Request or Response PDU, depending on code.
func (f PairingFeatures) Encode(code byte) []byte {
	return []byte{code, f.IOCap, f.OOB, f.AuthReq, f.MaxKeySize, f.InitKeyDist, f.RespKeyDist}
}

// IOCapField returns AuthReq ‖ OOB ‖ IO capability, the IOcap input to f6.
func (f PairingFeatures) IOCapField() []byte {
	return []byte{f.AuthReq, f.OOB, f.IOCap}
}

// ParsePairingFeatures decodes a Pairing Request or Response PDU.
func ParsePairingFeatures(pdu []byte) (PairingFeatures, error) {
	if len(pdu) < 7 {
		return PairingFeatures{}, ErrShortPacket
	}
	return PairingFeatures{
		IOCap: pdu[1], OOB: pdu[2], AuthReq: pdu[3],
		MaxKeySize: pdu[4], InitKeyDist: pdu[5], RespKeyDist: pdu[6],
	}, nil
}

// SMPValue builds an SMP PDU carrying a single value (Pairing Confirm, Pairing
// Random, DHKey Check, Identity Information), given most significant octet
// first.
func SMPValue(code byte, v []byte) []byte {
	return append([]byte{code}, Reverse(v)...)
}

// ParseSMPValue decodes a single-value SMP PDU of n octets, returning the value
// most significant octet first.
func ParseSMPValue(pdu []byte, n int) ([]byte, error) {
	if len(pdu) < 1+n {
		return nil, ErrShortPacket
	}
	return Reverse(pdu[1 : 1+n]), nil
}

// PairingPublicKey builds a Pairing Public Key PDU from big-endian P-256
// coordinates (3.H.3.5.6).
func PairingPublicKey(x, y []byte) []byte {
	return slices.Concat([]byte{SMPPairingPublicKey}, Reverse(x), Reverse(y))
}

// ParsePairingPublicKey decodes a Pairing Public Key PDU into big-endian
// coordinates.
func ParsePairingPublicKey(pdu []byte) (x, y []byte, err error) {
	if len(pdu) < 65 {
		return nil, nil, ErrShortPacket
	}
	return Reverse(pdu[1:33]), Reverse(pdu[33:65]), nil
}

// ParseIdentityAddress decodes an Identity Address Information PDU
// (3.H.3.6.5), returning the address type and the address most significant
// octet first.
func ParseIdentityAddress(pdu []byte) (addrType uint8, addr []byte, err error) {
	if len(pdu) < 8 {
		return 0, nil, ErrShortPacket
	}
	return pdu[1], Reverse(pdu[2:8]), nil
}

// PairingFailed builds a Pairing Failed PDU.
func PairingFailed(reason byte) []byte { return []byte{SMPPairingFailed, reason} }

// Reverse returns a reversed copy of b, converting between little-endian wire
// order and the spec's most-significant-first notation.
func Reverse(b []byte) []byte {
	r := slices.Clone(b)
	slices.Reverse(r)
	return r
}

// aesCMAC is AES-CMAC (RFC 4493) with a 128-bit key.
func aesCMAC(key, msg []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// Subkeys: K1 = dbl(AES_K(0)), K2 = dbl(K1).
	k1 := make([]byte, 16)
	c.Encrypt(k1, k1)
	k1 = dbl(k1)
	k2 := dbl(k1)

	n := max(1, (len(msg)+15)/16)
	last := make([]byte, 16)
	if rem := msg[(n-1)*16:]; len(rem) == 16 {
		subtle.XORBytes(last, rem, k1)
	} else {
		copy(last, rem)
		last[len(rem)] = 0x80
		subtle.XORBytes(last, last, k2)
	}
	x := make([]byte, 16)
	for i := range n - 1 {
		subtle.XORBytes(x, x, msg[i*16:(i+1)*16])
		c.Encrypt(x, x)
	}
	subtle.XORBytes(x, x, last)
	c.Encrypt(x, x)
	return x
}

// dbl is multiplication by x in GF(2^128), as used for CMAC subkeys.
func dbl(b []byte) []byte {
	out := make([]byte, 16)
	for i := range 15 {
		out[i] = b[i]<<1 | b[i+1]>>7
	}
	out[15] = b[15] << 1
	if b[0]&0x80 != 0 {
		out[15] ^= 0x87
	}
	return out
}

// F4 is the LE Secure Connections confirm value function (3.H.2.2.6):
// AES-CMAC_X(U ‖ V ‖ Z).
func F4(u, v, x []byte, z byte) []byte {
	return aesCMAC(x, slices.Concat(u, v, []byte{z}))
}

// G2 is the numeric comparison value generation function (3.H.2.2.9): the
// six-digit number both users compare is G2(PKax, PKbx, Na, Nb) mod 10^6.
func G2(u, v, x, y []byte) uint32 {
	return binary.BigEndian.Uint32(aesCMAC(x, slices.Concat(u, v, y))[12:])
}

// f5Salt is the SALT of f5 (3.H.2.2.7).
var f5Salt = []byte{
	0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38,
	0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60, 0x83, 0xBE,
}

// F5 is the LE Secure Connections key generation function (3.H.2.2.7). w is
// the DHKey; a1 and a2 are 7-octet addresses (type ‖ address).
func F5(w, n1, n2, a1, a2 []byte) (macKey, ltk []byte) {
	t := aesCMAC(f5Salt, w)
	gen := func(counter byte) []byte {
		return aesCMAC(t, slices.Concat([]byte{counter}, []byte("btle"), n1, n2, a1, a2, []byte{0x01, 0x00}))
	}
	return gen(0), gen(1)
}

// F6 is the LE Secure Connections check value function (3.H.2.2.8):
// AES-CMAC_W(N1 ‖ N2 ‖ R ‖ IOcap ‖ A1 ‖ A2).
func F6(w, n1, n2, r, iocap, a1, a2 []byte) []byte {
	return aesCMAC(w, slices.Concat(n1, n2, r, iocap, a1, a2))
}

// Ah is the random address hash function (3.H.2.2.2): the low 24 bits of
// AES_IRK(padding ‖ prand). prand and the result are 3 octets.
func Ah(irk, prand []byte) []byte {
	c, err := aes.NewCipher(irk)
	if err != nil {
		panic(err)
	}
	block := make([]byte, 16)
	copy(block[13:], prand)
	c.Encrypt(block, block)
	return block[13:]
}
