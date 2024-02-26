// pkg/pktgen/af_packet.go
package pktgen

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// AFPacketSender implements the Sender interface using AF_PACKET
type AFPacketSender struct {
	iface          string
	srcIP          net.IP
	dstIP          net.IP
	srcPort        uint16
	dstPort        uint16
	payloadSize    int
	srcMAC, dstMAC net.HardwareAddr
}

// NewAFPacketSender creates a new AFPacketSender with specified parameters
func NewAFPacketSender(iface string, srcIP, dstIP net.IP, srcPort, dstPort, payloadSize int, srcMAC, dstMAC net.HardwareAddr) *AFPacketSender {
	return &AFPacketSender{
		srcMAC:      srcMAC,
		dstMAC:      dstMAC,
		iface:       iface,
		srcIP:       srcIP,
		dstIP:       dstIP,
		srcPort:     uint16(srcPort),
		dstPort:     uint16(dstPort),
		payloadSize: payloadSize,
	}
}

// Send sends packets using AF_PACKET
func (s *AFPacketSender) Send(ctx context.Context) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer syscall.Close(fd)

	ifi, err := net.InterfaceByName(s.iface)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", s.iface, err)
	}

	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  ifi.Index,
	}

	// Construct the packet once outside the loop
	// create a packet configuration
	config, err := NewPacketConfig(
		WithEthernetLayer(s.srcMAC, s.dstMAC),
		WithIpLayer(s.srcIP, s.dstIP),
		WithUdpLayer(int(s.srcPort), int(s.dstPort)),
		WithPayloadSize(s.payloadSize),
	)
	if err != nil {
		return fmt.Errorf("error configuring packet: %v", err)
	}
	// build the packet
	packet, err := BuildPacket(config)
	if err != nil {
		return fmt.Errorf("failed to build packet: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			if err := syscall.Sendto(fd, packet, 0, addr); err != nil {
				return fmt.Errorf("failed to send packet: %w", err)
			}
		}
	}

}

// htons converts a uint16 from host- to network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
