package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/kendallgoto/gobtusb"
)

// fileBondStore is a gobtusb.BondStore kept in a JSON file. It holds link
// keys, so it is written owner-only.
type fileBondStore string

type bondFile struct {
	LocalAddress string     `json:"local_address,omitempty"`
	Bonds        []bondJSON `json:"bonds"`
}

type bondJSON struct {
	Address string `json:"address"`
	Random  bool   `json:"random"`
	LTK     string `json:"ltk"`
	IRK     string `json:"irk"`
}

func (p fileBondStore) Load() (gobtusb.BondState, error) {
	var st gobtusb.BondState
	b, err := os.ReadFile(string(p))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	var f bondFile
	if err := json.Unmarshal(b, &f); err != nil {
		return st, fmt.Errorf("%s: %w", p, err)
	}
	if f.LocalAddress != "" {
		a, err := gobtusb.ParseAddress(f.LocalAddress)
		if err != nil {
			return st, err
		}
		st.LocalAddress = *a
		st.LocalAddress.IsRandom = true // always a random static address
	}
	for _, e := range f.Bonds {
		a, err := gobtusb.ParseAddress(e.Address)
		if err != nil {
			return st, err
		}
		bond := gobtusb.Bond{Address: *a}
		bond.Address.IsRandom = e.Random
		if err := decodeKey(bond.LTK[:], e.LTK); err != nil {
			return st, fmt.Errorf("bond %s ltk: %w", e.Address, err)
		}
		if err := decodeKey(bond.IRK[:], e.IRK); err != nil {
			return st, fmt.Errorf("bond %s irk: %w", e.Address, err)
		}
		st.Bonds = append(st.Bonds, bond)
	}
	return st, nil
}

func (p fileBondStore) Save(st gobtusb.BondState) error {
	f := bondFile{LocalAddress: st.LocalAddress.String(), Bonds: []bondJSON{}}
	for _, b := range st.Bonds {
		f.Bonds = append(f.Bonds, bondJSON{
			Address: b.Address.String(),
			Random:  b.Address.IsRandom,
			LTK:     hex.EncodeToString(b.LTK[:]),
			IRK:     hex.EncodeToString(b.IRK[:]),
		})
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(string(p)), 0o700); err != nil {
		return err
	}
	return os.WriteFile(string(p), append(data, '\n'), 0o600)
}

func decodeKey(dst []byte, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(dst) {
		return fmt.Errorf("want %d hex bytes", len(dst))
	}
	copy(dst, b)
	return nil
}
