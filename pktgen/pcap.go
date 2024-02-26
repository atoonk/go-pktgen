// pkg/pktgen/af_packet.go
package pktgen

import (
	"context"
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

// AFPcapSender implements the Sender
type AFPcapSender struct {
	iface          string
	srcIP          net.IP
	dstIP          net.IP
	srcPort        uint16
	dstPort        uint16
	payloadSize    int
	srcMAC, dstMAC net.HardwareAddr
}

// NewAFPcapSender creates a new NewAFPcapSender with specified parameters
func NewAFPcapSender(iface string, srcIP, dstIP net.IP, srcPort, dstPort, payloadSize int, srcMAC, dstMAC net.HardwareAddr) *AFPcapSender {
	return &AFPcapSender{
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

// Send sends packets using PCAP handle
func (s *AFPcapSender) Send(ctx context.Context) error {

	// open the device for sending
	// we don't need to block, as we're not reading packets
	// snaplen is set to 1500, but it doesn't matter as we're not reading packets
	handle, err := pcap.OpenLive(s.iface, 1500, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("could not open device: %w", err)
	}
	defer handle.Close()

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
			// Send the packet
			if err := handle.WritePacketData(packet); err != nil {
				return fmt.Errorf("failed to send packet: %w", err)
			}
		}
	}

}
