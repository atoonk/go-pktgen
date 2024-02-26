package pktgen

import (
	"context"
	"fmt"
	"math"
	"net"

	"github.com/asavie/xdp"
	"github.com/vishvananda/netlink"
)

// AFXdpSender implements the Sender interface using AF_XDP
type AFXdpSender struct {
	queueID        int
	iface          string
	srcIP          net.IP
	dstIP          net.IP
	srcPort        uint16
	dstPort        uint16
	payloadSize    int
	srcMAC, dstMAC net.HardwareAddr
}

// NewAFXdpSender creates a new AFXdpSender with specified parameters
func NewAFXdpSender(iface string, srcIP, dstIP net.IP, srcPort, dstPort, payloadSize int, srcMAC, dstMAC net.HardwareAddr, queueID int) *AFXdpSender {
	return &AFXdpSender{
		queueID:     queueID,
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

// Send sends packets using AFXdpSender
func (s *AFXdpSender) Send(ctx context.Context) error {

	// Initialize the XDP socket.

	link, err := netlink.LinkByName(s.iface)
	if err != nil {
		panic(err)
	}

	xsk, err := xdp.NewSocket(link.Attrs().Index, s.queueID, nil)
	if err != nil {
		panic(err)
	}

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

	frameLen := len(packet)
	// Fill all the frames in UMEM with the pre-generated UDP packet.

	descs := xsk.GetDescs(math.MaxInt32, false)
	for i := range descs {
		frameLen = copy(xsk.GetFrame(descs[i]), packet)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			descs := xsk.GetDescs(xsk.NumFreeTxSlots(), false)
			for i := range descs {
				descs[i].Len = uint32(frameLen)
			}
			xsk.Transmit(descs)

			_, _, err = xsk.Poll(-1)
			if err != nil {
				panic(err)
			}
		}
	}

}
