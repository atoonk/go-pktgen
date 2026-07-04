package pktgen

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketOption is a function that applies a configuration to a PacketConfig.
type PacketOption func(*PacketConfig) error

// PacketConfig stores configuration for building a packet.
type PacketConfig struct {
	SrcIP, DstIP     net.IP
	SrcPort, DstPort layers.UDPPort
	SrcMAC, DstMAC   net.HardwareAddr
	PayloadSize      int
	VlanID           int // 0 = untagged; >0 inserts an 802.1Q tag
}

func buildPayload(payloadSize int) []byte {
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256) // Example payload; adjust as needed
	}
	return payload
}

// WithEthernetLayer enables the Ethernet layer in the packet.
func WithEthernetLayer(srcMAC, dstMAC net.HardwareAddr) PacketOption {
	return func(c *PacketConfig) error {
		c.SrcMAC = srcMAC
		c.DstMAC = dstMAC
		return nil
	}
}

// WithIpLayer enables the IP layer in the packet.
func WithIpLayer(srcIp, dstIp net.IP) PacketOption {
	return func(c *PacketConfig) error {
		c.SrcIP = srcIp
		c.DstIP = dstIp
		return nil
	}
}

// WithUdpLayer enables the UDP layer in the packet.
func WithUdpLayer(srcPort, dstPort int) PacketOption {
	return func(c *PacketConfig) error {
		c.SrcPort = layers.UDPPort(srcPort)
		c.DstPort = layers.UDPPort(dstPort)
		return nil
	}
}

// WithVlanLayer inserts an 802.1Q VLAN tag with the given ID (0 = untagged, no
// tag added). Only meaningful when an Ethernet layer is present.
func WithVlanLayer(vlanID int) PacketOption {
	return func(c *PacketConfig) error {
		c.VlanID = vlanID
		return nil
	}
}

// WithPayloadSize sets the payload size for the packet.
func WithPayloadSize(size int) PacketOption {
	return func(c *PacketConfig) error {
		c.PayloadSize = size
		return nil
	}
}

// NewPacketConfig creates a new PacketConfig with specified options.
func NewPacketConfig(opts ...PacketOption) (*PacketConfig, error) {
	config := &PacketConfig{}

	for _, opt := range opts {
		if err := opt(config); err != nil {
			return nil, err
		}
	}
	return config, nil
}

// BuildPacket constructs the packet based on the PacketConfig.
// It automatically includes the Ethernet layer if both SrcMAC and DstMAC are provided.
func BuildPacket(c *PacketConfig) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	var layersToSerialize []gopacket.SerializableLayer

	// Automatically include the Ethernet layer if MAC addresses are provided.
	// With a VLAN ID, the ethertype becomes 802.1Q and a Dot1Q tag carrying the
	// inner IPv4 ethertype is inserted between Ethernet and IP.
	if c.SrcMAC != nil && c.DstMAC != nil {
		ethLayer := &layers.Ethernet{
			SrcMAC:       c.SrcMAC,
			DstMAC:       c.DstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		if c.VlanID > 0 {
			ethLayer.EthernetType = layers.EthernetTypeDot1Q
			layersToSerialize = append(layersToSerialize, ethLayer, &layers.Dot1Q{
				VLANIdentifier: uint16(c.VlanID),
				Type:           layers.EthernetTypeIPv4,
			})
		} else {
			layersToSerialize = append(layersToSerialize, ethLayer)
		}
	}

	// Set IP layer
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    c.SrcIP,
		DstIP:    c.DstIP,
		Protocol: layers.IPProtocolUDP,
	}
	layersToSerialize = append(layersToSerialize, ipLayer)

	udpLayer := &layers.UDP{
		SrcPort: c.SrcPort,
		DstPort: c.DstPort,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer) // Important for checksum calculation
	layersToSerialize = append(layersToSerialize, udpLayer)

	payload := make([]byte, c.PayloadSize)
	// Optionally, fill the payload with data
	layersToSerialize = append(layersToSerialize, gopacket.Payload(payload))

	// Serialize the packet layers into the buffer
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layersToSerialize...); err != nil {
		return nil, fmt.Errorf("error serializing packet: %w", err)
	}

	return buf.Bytes(), nil
}
