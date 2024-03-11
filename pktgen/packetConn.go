package pktgen

import (
	"context"
	"net"

	"golang.org/x/net/ipv4"
)

type BatchConnSender struct {
	pConn       *ipv4.PacketConn
	dstAddr     *net.UDPAddr
	payloadSize int
}

func NewBatchConnSender(dstIP net.IP, dstPort, payloadSize int) *BatchConnSender {
	// Create the underlying UDP connection
	udpAddr := &net.UDPAddr{IP: dstIP, Port: dstPort}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil
	}

	// Create an ipv4.PacketConn from the UDP connection
	pConn := ipv4.NewPacketConn(conn)

	return &BatchConnSender{
		pConn:       pConn,
		dstAddr:     udpAddr,
		payloadSize: payloadSize,
	}
}

// Send sends packets using WriteBatch
// func (s *BatchConnSender) Send(ctx context.Context, payloads [][]byte) error {
func (s *BatchConnSender) Send(ctx context.Context) error {

	payload := buildPayload(s.payloadSize)

	// let's create a slice of payloads
	var msgs []ipv4.Message

	// let's create 128 payloads, that we'll send in one batch
	for i := 0; i < 1; i++ {
		msgs = append(msgs, ipv4.Message{
			Buffers: [][]byte{payload},
			Addr:    s.dstAddr,
		})
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			// sendmmsg is not available in the ipv4.PacketConn
			// so we'll use WriteBatch instead, which is a wrapper around sendmmsg
			_, err := s.pConn.WriteBatch(msgs, 0)
			if err != nil {
				return err
			}
		}
	}
}
