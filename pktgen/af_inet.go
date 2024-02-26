// pkg/pktgen/af_inet.go
package pktgen

import (
	"context"
	"fmt"
	"net"
)

// AFInetSender is a Sender that uses the net package to send packets
type NetConnSender struct {
	dstIP       net.IP
	dstPort     uint16
	payloadSize int
}

// NewAFInetSender creates a new AFInetSender
func NewNetConnSender(dstIP net.IP, dstPort, payloadSize int) *NetConnSender {
	return &NetConnSender{
		dstIP:       dstIP,
		dstPort:     uint16(dstPort),
		payloadSize: payloadSize,
	}
}

// Send sends packets to the destination IP address
func (s *NetConnSender) Send(ctx context.Context) error {
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", s.dstIP, s.dstPort))
	if err != nil {
		return fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer conn.Close()

	payload := buildPayload(s.payloadSize)
	if err != nil {
		return fmt.Errorf("failed to build packet: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			_, _ = conn.Write(payload)
		}
	}
}
