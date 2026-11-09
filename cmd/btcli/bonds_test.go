package main

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kendallgoto/gobtusb"
)

func TestFileBondStoreRoundTrip(t *testing.T) {
	store := fileBondStore(filepath.Join(t.TempDir(), "sub", "bonds.json"))
	if st, err := store.Load(); err != nil || len(st.Bonds) != 0 {
		t.Fatalf("empty load: %+v, %v", st, err)
	}

	local, _ := gobtusb.ParseAddress("c1:22:33:44:55:66")
	local.IsRandom = true
	peer, _ := gobtusb.ParseAddress("c0:01:02:03:04:05")
	peer.IsRandom = true
	want := gobtusb.BondState{
		LocalAddress: *local,
		Bonds:        []gobtusb.Bond{{Address: *peer, LTK: [16]byte{0: 1, 15: 2}, IRK: [16]byte{0: 3}}},
	}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("load = %+v, %v; want %+v", got, err, want)
	}

	want.Bonds = nil
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.Load(); len(got.Bonds) != 0 {
		t.Errorf("deleted bond came back: %+v", got.Bonds)
	}
}
