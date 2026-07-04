package pktgen

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"sync/atomic"
)

// Counter is a concurrency-safe tally of packets actually put on the wire.
// Each sender increments it by the real number of packets a send produces — 1
// for a plain sendto, the batch size for batched senders, numSegments for GSO —
// so the reported rate reflects true wire packets.
//
// This replaces reading the netdev TxPackets counter, which miscounts whenever
// an offload sits between the app and the wire: UDP GSO bumps it once per
// pre-segmentation super-packet (undercounting by numSegments), and AF_XDP
// zero-copy may not bump it at all.
type Counter struct {
	packets atomic.Uint64
}

// Add records that n packets were sent.
func (c *Counter) Add(n uint64) { c.packets.Add(n) }

// Load returns the running packet total.
func (c *Counter) Load() uint64 { return c.packets.Load() }

type Sender interface {
	Send(ctx context.Context, c *Counter) error
}

// GetCurrentTXQueues returns the number of TX queues for the specified interface
func GetCurrentTXQueues(interfaceName string) (int, error) {
	cmd := exec.Command("ethtool", "-l", interfaceName)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return 0, err
	}

	// Adjusted regular expression to work across multiple lines
	rx := regexp.MustCompile(`(?s)Current hardware settings:.*?TX:\s+(\d+)`)
	matches := rx.FindStringSubmatch(out.String())
	if len(matches) < 2 {
		// If the TX queues are not found, try to find the combined queues
		rx = regexp.MustCompile(`(?s)Current hardware settings:.*?Combined:\s+(\d+)`)
		matches = rx.FindStringSubmatch(out.String())
		if len(matches) < 2 {
			fmt.Println("could not find TX queues in output")
			return 0, fmt.Errorf("could not find TX queues in output")
		}
	}
	var txQueues int
	fmt.Sscanf(matches[1], "%d", &txQueues)

	return txQueues, nil
}
