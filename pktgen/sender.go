package pktgen

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
)

type Sender interface {
	Send(ctx context.Context) error
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
		fmt.Println("could not find TX queues in output")
		return 0, fmt.Errorf("could not find TX queues in output")
	}
	var txQueues int
	fmt.Sscanf(matches[1], "%d", &txQueues)

	return txQueues, nil
}
