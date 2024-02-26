// pkg/pktgen/af_inet.go
package pktgen

import (
	"context"
	"log"
	"net"
	"syscall"
)

// AFInetSyscallSender is a Sender that uses the syscall package to send packets
type AFInetSyscallSender struct {
	dstIP       net.IP
	dstPort     uint16
	payloadSize int
}

// NewAFInetSyscallSender creates a new AFInetSyscallSender
func NewAFInetSyscallSender(dstIP net.IP, dstPort, payloadSize int) *AFInetSyscallSender {
	return &AFInetSyscallSender{
		dstIP:       dstIP,
		dstPort:     uint16(dstPort),
		payloadSize: payloadSize,
	}
}

// Send sends packets to the destination IP address
func (s *AFInetSyscallSender) Send(ctx context.Context) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		log.Fatalf("Failed to create socket: %v", err)
	}
	defer syscall.Close(fd)

	// Assuming parsedDstIP is already an IPv4 address
	ipv4DstIP := s.dstIP.To4()
	if ipv4DstIP == nil {
		log.Fatalf("Destination IP address is not an IPv4 address: %s", s.dstIP)
	}

	dstAddr := &syscall.SockaddrInet4{
		Port: int(s.dstPort),
		Addr: [4]byte{ipv4DstIP[0], ipv4DstIP[1], ipv4DstIP[2], ipv4DstIP[3]},
	}

	payload := buildPayload(s.payloadSize)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			err = syscall.Sendto(fd, payload, 0, dstAddr)
			if err != nil {
				log.Fatalf("Failed to send packet: %v", err)
			}
		}
	}
}
