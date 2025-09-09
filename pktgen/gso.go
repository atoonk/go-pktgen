//go:build linux

package pktgen

import (
    "context"
    "fmt"
    "net"
    "syscall"
    "unsafe"

    "golang.org/x/sys/unix"
)

// GSOSender implements UDP Generic Segmentation Offload (GSO) using UDP_SEGMENT
type GSOSender struct {
    dstIP        net.IP
    dstPort      uint16
    segmentSize  int
    numSegments  int
}

// NewGSOSender creates a new GSOSender.
// It interprets payloadSize as the per-segment size and uses a fixed batch of segments.
func NewGSOSender(dstIP net.IP, dstPort, segmentSize int) *GSOSender {
    return &GSOSender{
        dstIP:       dstIP,
        dstPort:     uint16(dstPort),
        segmentSize: segmentSize,
        numSegments: 8, // default number of segments per UDP frame
    }
}

// Some distributions ship older golang.org/x/sys without SOL_UDP/UDP_SEGMENT.
// Define the Linux values here to remain compatible.
// From include/uapi/linux/udp.h: UDP_SEGMENT = 103; SOL_UDP equals IPPROTO_UDP = 17.
const (
    solUDP     = 17  // SOL_UDP
    udpSegment = 103 // UDP_SEGMENT
)

// Send transmits UDP payloads using UDP_SEGMENT control message for GSO
func (s *GSOSender) Send(ctx context.Context) error {
    // Create UDP socket
    fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
    if err != nil {
        return fmt.Errorf("socket: %w", err)
    }
    defer syscall.Close(fd)

    // Prepare destination
    v4 := s.dstIP.To4()
    if v4 == nil {
        return fmt.Errorf("destination IP is not IPv4: %s", s.dstIP)
    }
    sa := &syscall.SockaddrInet4{Port: int(s.dstPort)}
    copy(sa.Addr[:], v4)

    // Prepare payload: total size = segmentSize * numSegments
    totalPayload := s.segmentSize * s.numSegments
    payload := buildPayload(totalPayload)

    // Build UDP_SEGMENT control message with the segment size (uint16)
    cmsgLen := unix.CmsgSpace(2)
    cmsgBuf := make([]byte, cmsgLen)
    hdr := (*unix.Cmsghdr)(unsafe.Pointer(&cmsgBuf[0]))
    hdr.Level = solUDP
    hdr.Type = udpSegment
    hdr.SetLen(unix.CmsgLen(2))
    *(*uint16)(unsafe.Pointer(&cmsgBuf[unix.CmsgLen(0)])) = uint16(s.segmentSize)

    for {
        select {
        case <-ctx.Done():
            return nil
        default:
            // Use destination address directly (unconnected UDP) to avoid ECONNREFUSED
            if _, err := syscall.SendmsgN(fd, payload, cmsgBuf, sa, 0); err != nil {
                return fmt.Errorf("SendmsgN failed: %w", err)
            }
        }
    }
}
