// Package wol sends Wake-on-LAN magic packets.
package wol

import (
	"fmt"
	"net"
	"time"
)

// MagicPacket builds the 102-byte payload: 6×0xFF followed by the MAC 16 times.
func MagicPacket(mac net.HardwareAddr) ([]byte, error) {
	if len(mac) != 6 {
		return nil, fmt.Errorf("wol: MAC must be 6 bytes, got %d", len(mac))
	}
	p := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		p = append(p, 0xFF)
	}
	for i := 0; i < 16; i++ {
		p = append(p, mac...)
	}
	return p, nil
}

// Sender sends magic packets over UDP to Addr (e.g. "192.168.1.255:9").
type Sender struct {
	Addr string
}

// Wake sends one magic packet for mac.
func (s Sender) Wake(mac net.HardwareAddr) error {
	p, err := MagicPacket(mac)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("udp", s.Addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("wol: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write(p); err != nil {
		return fmt.Errorf("wol: %w", err)
	}
	return nil
}
