//go:build linux

package pktgen

import (
	"context"
	"fmt"
	"net"

	"github.com/atoonk/go-pktgen/pktgen/afxdp"
)

// AFXdpZCSender implements the Sender interface using AF_XDP with zero-copy support
type AFXdpZCSender struct {
	queueID        int
	iface          string
	srcIP          net.IP
	dstIP          net.IP
	srcPort        uint16
	dstPort        uint16
	payloadSize    int
	srcMAC, dstMAC net.HardwareAddr
}

// NewAFXdpZCSender creates a new AFXdpZCSender with specified parameters
func NewAFXdpZCSender(iface string, srcIP, dstIP net.IP, srcPort, dstPort, payloadSize int, srcMAC, dstMAC net.HardwareAddr, queueID int) *AFXdpZCSender {
	return &AFXdpZCSender{
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

// Send sends packets using AFXdpZCSender with zero-copy support
func (s *AFXdpZCSender) Send(ctx context.Context) error {
	// Initialize the AF_XDP interface with zero-copy preference
	iface, err := afxdp.MakeInterface(s.iface, afxdp.InterfaceConfig{
		PreferZerocopy: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create AF_XDP interface: %w", err)
	}
	// Don't defer yet - we need to control the order

	// Open socket on the specified queue
	sock, err := iface.Open(afxdp.SocketConfig{
		QueueID:   uint32(s.queueID),
		FrameSize: 2048,
		NumFrames: 4096,
		TxSize:    2048,
		CqSize:    2048,
		RxSize:    2048,
		BatchSize: 64,
	})
	if err != nil {
		iface.Close() // Clean up interface if socket open fails
		return fmt.Errorf("failed to open AF_XDP socket: %w", err)
	}

	// Ensure cleanup happens in correct order: socket first, then interface
	defer func() {
		sock.Close()
		iface.Close()
	}()

	// Build the packet once
	config, err := NewPacketConfig(
		WithEthernetLayer(s.srcMAC, s.dstMAC),
		WithIpLayer(s.srcIP, s.dstIP),
		WithUdpLayer(int(s.srcPort), int(s.dstPort)),
		WithPayloadSize(s.payloadSize),
	)
	if err != nil {
		return fmt.Errorf("error configuring packet: %v", err)
	}

	packet, err := BuildPacket(config)
	if err != nil {
		return fmt.Errorf("failed to build packet: %w", err)
	}

	frameLen := uint32(len(packet))

	// Prepare batch submission buffers
	const batchSize = 64
	addrs := make([]uint64, 0, batchSize)
	lens := make([]uint32, 0, batchSize)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			// Build a batch of frames
			addrs = addrs[:0]
			lens = lens[:0]

			for i := 0; i < batchSize; i++ {
				frame := sock.NextFrame()
				if frame.Addr == 0 {
					// No more free frames available
					break
				}

				// Copy packet data to frame
				copy(frame.Buf, packet)
				addrs = append(addrs, frame.Addr)
				lens = append(lens, frameLen)
			}

			if len(addrs) == 0 {
				// No frames available, try to reclaim completions
				sock.PollCompletions(batchSize)
				continue
			}

			// Submit the batch
			_, err := sock.SubmitBatch(addrs, lens)
			if err != nil {
				return fmt.Errorf("failed to submit batch: %w", err)
			}

			// Flush TX ring to notify kernel
			if err := sock.FlushTx(); err != nil {
				return fmt.Errorf("failed to flush TX: %w", err)
			}

			// Poll for completions to reclaim frames
			sock.PollCompletions(batchSize)
		}
	}
}
