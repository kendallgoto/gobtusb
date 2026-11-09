package hci

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// RFC 4493 section 4 examples.
func TestAESCMAC(t *testing.T) {
	key := unhex("2b7e1516 28aed2a6 abf71588 09cf4f3c")
	msg := unhex("6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51" +
		"30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710")
	for _, v := range []struct {
		n    int
		want string
	}{
		{0, "bb1d6929 e9593728 7fa37d12 9b756746"},
		{16, "070a16b4 6b4d4144 f79bdd9d d04a287c"},
		{40, "dfa66747 de9ae630 30ca3261 1497c827"},
		{64, "51f0bebf 7e3b9d92 fc497417 79363cfe"},
	} {
		if got := aesCMAC(key, msg[:v.n]); !bytes.Equal(got, unhex(v.want)) {
			t.Errorf("CMAC(%d B) = %x, want %s", v.n, got, v.want)
		}
	}
}

// Sample data from Core 5.4 Vol 3 Part H Appendix D.
func TestSMPFunctions(t *testing.T) {
	u := unhex("20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6")
	v := unhex("55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd")
	x := unhex("d5cb8454 d177733e ffffb2ec 712baeab")
	if got, want := F4(u, v, x, 0), unhex("f2c916f1 07a9bd1c f1eda1be a974872d"); !bytes.Equal(got, want) {
		t.Errorf("f4 = %x, want %x", got, want)
	}

	y := unhex("a6e8e7cc 25a75f6e 216583f7 ff3dc4cf")
	if got := G2(u, v, x, y); got != 0x2f9ed5ba {
		t.Errorf("g2 = %#x, want 0x2f9ed5ba", got)
	}

	w := unhex("ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698")
	n1 := unhex("d5cb8454 d177733e ffffb2ec 712baeab")
	n2 := unhex("a6e8e7cc 25a75f6e 216583f7 ff3dc4cf")
	a1 := unhex("00561237 37bfce")
	a2 := unhex("00a71370 2dcfc1")
	macKey, ltk := F5(w, n1, n2, a1, a2)
	if want := unhex("2965f176 a1084a02 fd3f6a20 ce636e20"); !bytes.Equal(macKey, want) {
		t.Errorf("f5 MacKey = %x, want %x", macKey, want)
	}
	if want := unhex("69867911 69d7cd23 980522b5 94750a38"); !bytes.Equal(ltk, want) {
		t.Errorf("f5 LTK = %x, want %x", ltk, want)
	}

	r := unhex("12a3343b b453bb54 08da42d2 0c2d0fc8")
	if got, want := F6(macKey, n1, n2, r, unhex("010102"), a1, a2), unhex("e3c47398 9cd0e8c5 d26c0b09 da958f61"); !bytes.Equal(got, want) {
		t.Errorf("f6 = %x, want %x", got, want)
	}

	if got, want := Ah(unhex("ec0234a3 57c8ad05 341010a6 0a397d9b"), unhex("708194")), unhex("0dfbaa"); !bytes.Equal(got, want) {
		t.Errorf("ah = %x, want %x", got, want)
	}
}

func TestSMPValueByteOrder(t *testing.T) {
	v := unhex("000102030405060708090a0b0c0d0e0f")
	pdu := SMPValue(SMPPairingRandom, v)
	if pdu[0] != SMPPairingRandom || pdu[1] != 0x0f || pdu[16] != 0x00 {
		t.Fatalf("PDU not little-endian: %x", pdu)
	}
	got, err := ParseSMPValue(pdu, 16)
	if err != nil || !bytes.Equal(got, v) {
		t.Fatalf("round trip = %x, %v", got, err)
	}
}
