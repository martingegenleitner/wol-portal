package wol

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestMagicPacket(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	p, err := MagicPacket(mac)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 102 {
		t.Fatalf("len = %d, want 102", len(p))
	}
	if !bytes.Equal(p[:6], bytes.Repeat([]byte{0xFF}, 6)) {
		t.Errorf("bad header: % x", p[:6])
	}
	for i := 0; i < 16; i++ {
		if !bytes.Equal(p[6+i*6:12+i*6], mac) {
			t.Errorf("repetition %d wrong", i)
		}
	}
	if _, err := MagicPacket(net.HardwareAddr{1, 2}); err == nil {
		t.Error("expected error for short MAC")
	}
}

func TestSenderWake(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	mac, _ := net.ParseMAC("01:02:03:04:05:06")
	if err := (Sender{Addr: pc.LocalAddr().String()}).Wake(mac); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := MagicPacket(mac)
	if !bytes.Equal(buf[:n], want) {
		t.Errorf("received packet differs")
	}
}
