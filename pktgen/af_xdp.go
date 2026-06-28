//go:build linux

package pktgen

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/atoonk/go-afxdp"
	"github.com/vishvananda/netlink"
)

// AFXdpSender implements the Sender interface using the github.com/atoonk/go-afxdp
// library — the same one the library's blast example is built on. It attaches a
// no-op XDP program (afxdp.MatchNone) to enable the AF_XDP transmit datapath
// (zero-copy where the driver supports it, copy on veth) without stealing any
// receive traffic, then builds the UDP frame once and transmits it across its
// tx queue as fast as the ring will take it.
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

// Send sends packets using the go-afxdp library until the context is cancelled.
//
// Unlike the other senders, go-afxdp's model is a single Fleet that binds every
// rx/tx queue with one socket each, driven by one goroutine per queue — so this
// sender uses ALL queues at once. go-pktgen's "one stream per queue" model
// doesn't apply (and a second Open would attach a conflicting XDP program), so
// only the first stream does the work; any extra streams idle.
func (s *AFXdpSender) Send(ctx context.Context) error {
	if s.queueID != 0 {
		<-ctx.Done()
		return nil
	}

	// MatchNone attaches the XDP program (enabling the AF_XDP TX datapath) but
	// redirects nothing, so the host's receive traffic is untouched. With no
	// WithQueues it binds every queue; the mode is auto-selected (native
	// zero-copy on a capable NIC, copy on veth).
	fleet, err := afxdp.Open(s.iface, afxdp.WithFilter(afxdp.MatchNone()))
	if err != nil {
		return fmt.Errorf("afxdp open: %w", err)
	}
	defer fleet.Close()

	// Native XDP attach can relink the NIC for several seconds (instant on
	// veth); wait so we don't transmit into a down link.
	waitLinkUpAFXdp(s.iface, 15*time.Second)

	// Build the packet once, the same way the other senders do.
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

	// One transmit goroutine per queue.
	const batch = 256
	var wg sync.WaitGroup
	for _, xsk := range fleet.Sockets() {
		wg.Add(1)
		go func(xsk *afxdp.Socket) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				// SendFunc copies the packet into each frame and handles all the
				// ring bookkeeping (completions, kicking, full-ring draining).
				xsk.SendFunc(batch, func(i int, frame []byte) int {
					return copy(frame, packet)
				})
			}
		}(xsk)
	}
	wg.Wait()
	return nil
}

// waitLinkUpAFXdp polls until the interface is operationally up or the timeout
// elapses (native XDP attach can take the link down for several seconds on some
// drivers; it's instant on veth).
func waitLinkUpAFXdp(iface string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if l, err := netlink.LinkByName(iface); err == nil && l.Attrs().OperState == netlink.OperUp {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}
