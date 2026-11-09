package gobtusb

import (
	"slices"
	"testing"

	"github.com/kendallgoto/gobtusb/internal/hci"
)

func TestAdvMergeScanResponse(t *testing.T) {
	peer := [6]byte{1, 2, 3, 4, 5, 0xC6}
	adv := []byte{0x03, 0x03, 0x0A, 0x18}         // 16-bit UUIDs: 0x180A
	rsp := []byte{0x05, 0x09, 'T', 'a', 'g', 's'} // complete local name
	dis := New16BitUUID(0x180A)
	m := advMerger{}
	get := func(typ uint8, data []byte) ScanResult {
		r := m.merge(hci.AdvertisingReport{EventType: typ, AddrType: hci.AddressRandom, Addr: peer, Data: data})
		return ScanResult{payload: r.Data, split: true, advLen: r.advLen}
	}

	if r := get(hci.AdvInd, adv); r.LocalName() != "" || !r.HasServiceUUID(dis) {
		t.Errorf("advertisement alone: name %q, payload %x", r.LocalName(), r.payload)
	}
	// The scan response alone has no service UUID; merged, it has both.
	if r := get(hci.ScanRsp, rsp); r.LocalName() != "Tags" || !r.HasServiceUUID(dis) {
		t.Errorf("scan response: name %q, payload %x", r.LocalName(), r.payload)
	}
	if r := get(hci.ScanRsp, rsp); !slices.EqualFunc(r.Structures(), []ADStructure{
		{Type: 0x03, Data: adv[2:], Source: SourceAdvertisement},
		{Type: 0x09, Data: rsp[2:], Source: SourceScanResponse},
	}, func(a, b ADStructure) bool {
		return a.Type == b.Type && a.Source == b.Source && slices.Equal(a.Data, b.Data)
	}) {
		t.Errorf("structures: %+v", r.Structures())
	}
	// Later advertisements carry the remembered scan response.
	if r := get(hci.AdvInd, adv); r.LocalName() != "Tags" {
		t.Errorf("repeat advertisement: name %q", r.LocalName())
	}
	// Non-scannable advertising is passed through untouched.
	if r := get(hci.AdvNonconnInd, adv); len(r.payload) != len(adv) {
		t.Errorf("non-connectable advertisement modified: %x", r.payload)
	}
}
