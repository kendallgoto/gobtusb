package gobtusb

import (
	"crypto/subtle"
	"slices"

	"github.com/kendallgoto/gobtusb/internal/hci"
)

// BondStore persists pairing state for the HCI backend, which talks to a bare
// controller and so has nowhere of its own to keep it. OS-managed backends
// (CoreBluetooth) keep their own bonds and don't use it.
type BondStore interface {
	// Load returns the saved state, or a zero BondState if nothing is saved.
	Load() (BondState, error)

	// Save replaces the saved state.
	Save(BondState) error
}

// BondState is everything the HCI backend needs to remember between runs.
type BondState struct {
	// LocalAddress is this host's random static address. Peers find their
	// bond with us by it, so it must stay the same across runs; the adapter
	// generates and saves one when it is zero.
	LocalAddress Address

	Bonds []Bond
}

// Bond is the pairing state shared with one peer, from LE Secure Connections
// pairing. Keys are 128-bit values, most significant octet first.
type Bond struct {
	// Address is the peer's identity address.
	Address Address

	// LTK encrypts the link on reconnection.
	LTK [16]byte

	// IRK resolves the peer's resolvable private addresses; zero if the peer
	// distributed none.
	IRK [16]byte
}

// sameIdentity reports whether a and b are the same identity address.
func sameIdentity(a, b Address) bool {
	return a.MAC == b.MAC && a.IsRandom == b.IsRandom
}

// isRPA reports whether addr is a resolvable private address (6.B.1.3.2.2).
func isRPA(addr Address) bool {
	return addr.IsRandom && addr.MAC[0]>>6 == 0b01
}

// resolve maps a resolvable private address to the identity address of the
// bonded peer that generated it, remembering the private address to connect
// to. Other addresses are returned unchanged.
func (s *BondState) resolve(addr Address) Address {
	if !isRPA(addr) {
		return addr
	}
	prand, hash := addr.MAC[0:3], addr.MAC[3:6]
	for _, b := range s.Bonds {
		if b.IRK == ([16]byte{}) {
			continue
		}
		if subtle.ConstantTimeCompare(hci.Ah(b.IRK[:], prand), hash) == 1 {
			id := b.Address
			id.rpa = addr.MAC
			return id
		}
	}
	return addr
}

func (s *BondState) find(addr Address) (Bond, bool) {
	i := slices.IndexFunc(s.Bonds, func(b Bond) bool { return sameIdentity(b.Address, addr) })
	if i < 0 {
		return Bond{}, false
	}
	return s.Bonds[i], true
}

// put adds b, replacing any bond with the same identity address.
func (s *BondState) put(b Bond) {
	b.Address.rpa = [6]byte{}
	s.remove(b.Address)
	s.Bonds = append(s.Bonds, b)
}

func (s *BondState) remove(addr Address) {
	s.Bonds = slices.DeleteFunc(s.Bonds, func(b Bond) bool { return sameIdentity(b.Address, addr) })
}
