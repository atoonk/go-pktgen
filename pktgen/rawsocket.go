package pktgen

import (
	"context"
	"fmt"
	"log"
	"net"
	"syscall"
)

// RawSocketSender implements the Sender interface using raw sockets
type RawSocketSender struct {
	dstIP       net.IP
	srcIP       net.IP
	dstPort     uint16
	srcPort     uint16
	payloadSize int
}

// NewRawSocketSender creates a new RawSocketSender with specified parameters
func NewRawSocketSender(srcIP, dstIP net.IP, srcPort, dstPort, payloadSize int) *RawSocketSender {
	return &RawSocketSender{
		srcIP:       srcIP,
		dstIP:       dstIP,
		srcPort:     uint16(srcPort),
		dstPort:     uint16(dstPort),
		payloadSize: payloadSize,
	}
}

// Send sends packets using RawSocketSender
func (s *RawSocketSender) Send(ctx context.Context) error {
	// Create a raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("Failed to create raw socket: %v", err)
	}
	defer syscall.Close(fd)

	// Set options: here, we enable IP_HDRINCL to manually include the IP header
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		log.Fatalf("Failed to set IP_HDRINCL: %v", err)
	}

	// Assuming parsedDstIP is already an IPv4 address
	ipv4DstIP := s.dstIP.To4()
	if ipv4DstIP == nil {
		log.Fatalf("Destination IP address is not an IPv4 address: %s", s.dstIP)
	}

	dstAddr := &syscall.SockaddrInet4{
		Port: int(s.dstPort),
		Addr: [4]byte{ipv4DstIP[0], ipv4DstIP[1], ipv4DstIP[2], ipv4DstIP[3]},
	}

	// now create a packet configuration
	config, err := NewPacketConfig(
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
			if err := syscall.Sendto(fd, packet, 0, dstAddr); err != nil {
				log.Fatalf("Failed to send packet: %v", err)
			}
		}
	}
}
