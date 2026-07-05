//go:build linux

// This implements a versatile packet generation tool designed for network performance
// and stress testing. It supports various methods of packet sending including direct AF_PACKET access,
// raw sockets, and high-level abstractions like net.Conn. Users can specify source and destination
// IPs, MAC addresses, payload size, and duration for the tests. This tool is useful for network
// administrators and developers looking to evaluate network equipment, protocols, or software
// under different conditions and loads.
// However it's main intent was to compare the performance of different packet sending methods.

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/atoonk/go-pktgen/pktgen"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

type resultItem struct {
	Method    string
	PacketsPS int // Packets per second
	Mbps      int
}

var (
	method      string
	iface       string
	srcIP       string
	dstIP       string
	srcPort     int
	dstPort     int
	payloadSize int
	srcMAC      string
	dstMAC      string
	duration    int
	streams     int
	gsoSegments int
	vlan        int
)

// Define global or package-level variables if needed
var rootCmd = &cobra.Command{
	Use:   "pktgen",
	Short: "Packet generator tool",
	Long:  `A versatile packet generation tool designed for network performance and stress testing.`,
	Run:   runPacketGenerator,
}

// this starts the packet generator, using the method specified by the user
func runPacketGenerator(cmd *cobra.Command, args []string) {

	// Unless the user set --srcmac explicitly, use the interface's real MAC.
	// Frame-building methods (af_packet/af_pcap/af_xdp) then send with a real,
	// consistent source MAC, so the switch's MAC learning stays sane — a bogus
	// placeholder source can stall L2 delivery for the first seconds of a run.
	if !cmd.Flags().Changed("srcmac") {
		if ifi, err := net.InterfaceByName(iface); err == nil && len(ifi.HardwareAddr) == 6 {
			srcMAC = ifi.HardwareAddr.String()
		}
	}

	srcMACAddr, err := net.ParseMAC(srcMAC)
	if err != nil {
		log.Fatalf("Invalid source MAC address: %v", err)
	}
	dstMACAddr, err := net.ParseMAC(dstMAC)
	if err != nil {
		log.Fatalf("Invalid destination MAC address: %v", err)
	}

	dstIPParsed := net.ParseIP(dstIP)
	// check if the destination  IP is a valid IP address
	if dstIPParsed == nil {
		log.Fatalf("Invalid destination IP address: %s", dstIP)
	}

	srcIPParsed := net.ParseIP(srcIP)
	// check if the source  IP is a valid IP address
	if srcIPParsed == nil {
		log.Fatalf("Invalid source IP address: %s", srcIP)
	}

	// This is the check if the number of TX queues
	// No real benefit to have more streams than TX queues
	// Will also break AF_XDP so need a check
	txQueues, err := pktgen.GetCurrentTXQueues(iface)
	if err == nil && txQueues < streams {
		fmt.Printf("Error: Number of TX queues (%d) is less than the number of streams (%d)\n", txQueues, streams)
		fmt.Printf("Pleease increase the number of TX queues using ethtool -L %s [tx|combined] %d or lower the number of streams to %d\n", iface, streams, txQueues)
		os.Exit(1)
	}

	// Handling multiple streams
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setupSignalHandler(cancel)

	// Warm the L2 path before sending: a quick kernel UDP send ARP-resolves the
	// destination, which makes the receiver reply (transmit) so the switch learns
	// its MAC. Frame-building methods (af_packet/af_pcap/af_xdp) craft frames with
	// an explicit --dstmac and never ARP, so against a silent receiver (e.g. a
	// drop sink that never transmits) the switch has no forwarding entry and drops
	// the traffic. Kernel methods self-warm via ARP; this makes every method work.
	log.Println("warming up the path (ARP + switch learning)...")
	warmupPath(dstIPParsed, dstPort, payloadSize)

	if method == "benchmark" {
		runBenchmark(ctx, iface, srcIPParsed, dstIPParsed, srcPort, dstPort, payloadSize, duration, srcMACAddr, dstMACAddr, streams)

	} else {
		// One shared counter tallies packets across all streams; each sender
		// increments it with real wire-packet counts and printStats reports it.
		counter := &pktgen.Counter{}
		go printStats(counter, payloadSize, ctx)

		// run the streams, that will know what method to start
		wg := &sync.WaitGroup{}
		for i := 0; i < streams; i++ {
			wg.Add(1)
			go func(streamNum int) {
				defer wg.Done()
				runStream(ctx, method, iface, srcIPParsed, dstIPParsed, srcPort, dstPort, payloadSize, srcMACAddr, dstMACAddr, duration, streamNum, counter)
			}(i + 1)
		}

		wg.Wait()
	}
}

// runBenchmark executes a series of packet sending tests using different methods
// specified in the methods map. It collects and displays the results in terms of packets
// per second and Mbps. The function gracefully handles interrupts, allowing for a clean
// shutdown and accurate results reporting.
//
// Parameters:
// - ifaceName: The network interface name for sending packets.
// - srcIPParsed, dstIPParsed: Source and destination IP addresses for the packets.
// - srcPort, dstPort: Source and destination ports for UDP/TCP packets.
// - payloadSize: The size of the packet payload in bytes.
// - duration: The duration of each test in seconds.
// - dstMACAddr, srcMACAddr: Destination and source MAC addresses for packet crafting.
//
// The function sorts and displays the results in a table, highlighting the method's performance.func runBenchmark(ifaceName string, srcIPParsed, dstIPParsed net.IP, srcPort, dstPort, payloadSize, duration *int, dstMACAddr, srcMACAddr net.HardwareAddr) {

func runBenchmark(ctx context.Context, ifaceName string, srcIPParsed, dstIPParsed net.IP, srcPort, dstPort, payloadSize, duration int, srcMACAddr, dstMACAddr net.HardwareAddr, streams int) {

	var resultsSlice []resultItem
	// define the methods as a slice
	// af_xdp runs LAST: it attaches/detaches an XDP program (churning the queue
	// binding), so keeping it at the end avoids that disturbing the methods that
	// follow it.
	methods := []string{"af_packet", "net_conn", "udp_syscall", "raw_socket", "af_pcap", "pkt_conn", "gso", "af_xdp"}

	// Iterate over methods, run test and collect results
	for _, TestType := range methods {
		log.Printf("=== benchmark method: %s ===", TestType)
		counter := &pktgen.Counter{}
		wg := &sync.WaitGroup{}
		for i := 0; i < streams; i++ {
			wg.Add(1)
			go func(streamNum int) {
				// stream i is a distinct flow: source port srcPort+i (see runStream).
				streamSrcPort := srcPort + (streamNum - 1)
				var sender pktgen.Sender
				switch TestType {
				case "af_xdp":
					sender = pktgen.NewAFXdpSender(ifaceName, srcIPParsed, dstIPParsed, srcPort, dstPort, payloadSize, srcMACAddr, dstMACAddr, streamNum-1, vlan, streams)
				case "af_packet":
					sender = pktgen.NewAFPacketSender(ifaceName, srcIPParsed, dstIPParsed, streamSrcPort, dstPort, payloadSize, srcMACAddr, dstMACAddr, vlan)
				case "net_conn":
					sender = pktgen.NewNetConnSender(dstIPParsed, dstPort, payloadSize)
				case "udp_syscall":
					sender = pktgen.NewAFInetSyscallSender(dstIPParsed, dstPort, payloadSize)
				case "raw_socket":
					sender = pktgen.NewRawSocketSender(srcIPParsed, dstIPParsed, streamSrcPort, dstPort, payloadSize)
				case "af_pcap":
					sender = pktgen.NewAFPcapSender(ifaceName, srcIPParsed, dstIPParsed, streamSrcPort, dstPort, payloadSize, srcMACAddr, dstMACAddr, vlan)
				case "pkt_conn":
					sender = pktgen.NewBatchConnSender(dstIPParsed, dstPort, payloadSize)
				case "gso":
					sender = pktgen.NewGSOSender(dstIPParsed, dstPort, payloadSize, gsoSegments)
				}
				runTest(sender, duration, counter)
				defer wg.Done()

			}(i + 1)
		}

		wg.Wait()

		// Brief pause after each test to ensure clean transition
		time.Sleep(100 * time.Millisecond)

		packetsPS := int(counter.Load()) / duration
		mbps := (packetsPS * (payloadSize + 42) * 8) / (1000 * 1000)
		resultsSlice = append(resultsSlice, resultItem{Method: TestType, PacketsPS: packetsPS, Mbps: mbps})

		if ctx.Err() != nil {
			break
		}
	}

	// Sort results by Packets per second, highest first
	sort.Slice(resultsSlice, func(i, j int) bool {
		return resultsSlice[i].PacketsPS > resultsSlice[j].PacketsPS
	})

	// Create and print the table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Method", "Packets/s", "Mb/s"})
	table.SetAutoFormatHeaders(false) // Prevents automatic capitalization

	for _, item := range resultsSlice {
		table.Append([]string{item.Method, fmt.Sprintf("%d", item.PacketsPS), fmt.Sprintf("%d", item.Mbps)})
	}
	table.Render()
}

// warmupPath sends real UDP to the destination for a moment so ARP resolves and
// the switch learns the MAC path before the timed methods run. Without it, the
// first method's packets can be dropped while L2 settles (variable, a few to
// ~20 seconds), which looks like the early methods "not working".
func warmupPath(dstIP net.IP, dstPort, payloadSize int) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_ = pktgen.NewNetConnSender(dstIP, dstPort, payloadSize).Send(ctx, &pktgen.Counter{})
}

// runTest runs a test with the given sender, tallying packets into counter.
func runTest(sender pktgen.Sender, duration int, counter *pktgen.Counter) {

	// Create a context that will be canceled when the timeout is reached or an interrupt signal is received
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()

	// Apply timeout if duration is not -1
	if duration >= 0 {
		var cancelFunc context.CancelFunc
		ctx, cancelFunc = context.WithTimeout(ctx, time.Duration(duration)*time.Second)
		defer cancelFunc()
	}

	// Start sending packets in a goroutine
	errChan := make(chan error, 1)
	go func() {
		err := sender.Send(ctx, counter)
		errChan <- err
	}()

	// Wait for sending to finish or be cancelled
	select {
	case err := <-errChan:
		if err != nil {
			log.Fatalf("Error sending packet: %v", err)
		}
	case <-ctx.Done():
		// Context cancelled, but we MUST wait for Send() to return
		// so that all defers (especially XDP cleanup) have executed
		<-errChan
	}

}

// printStats prints the packet rate once a second, read from the shared
// application counter (which reflects real wire packets across all offloads).
func printStats(counter *pktgen.Counter, frameLen int, ctx context.Context) {

	var prev, numPkts uint64
	for {
		select {
		case <-ctx.Done():
			return // Exit the goroutine when the context is cancelled
		default:
			time.Sleep(time.Duration(1) * time.Second)

			cur := counter.Load()

			// skip the first loop so the first printed value is a full-second
			// delta (and misses any link-settling ramp on AF_XDP attach)
			if prev == 0 {
				prev = cur
				continue
			}

			// Calculate the packets sent in the last second
			numPkts = cur - prev
			prev = cur

			// Approximate on-wire bytes: payload + eth 14 + ipv4 20 + udp 8 = +42.
			bps := (numPkts * uint64(frameLen+42) * 8)
			fmt.Printf("%d packets/s (%d Mb/s)\n", numPkts, bps/(1000*1000))
		}
	}
}

func runStream(ctx context.Context, method, iface string, srcIP, dstIP net.IP, srcPort, dstPort, payloadSize int, srcMAC, dstMAC net.HardwareAddr, duration, streamNum int, counter *pktgen.Counter) {
	// Each stream is a distinct flow: stream i gets source port srcPort+i, so the
	// receiver's RSS spreads streams across rx queues (destination port stays
	// fixed so a dst-port filter still matches). The socket methods
	// (net_conn/udp_syscall/pkt_conn/gso) already get a distinct kernel-assigned
	// ephemeral source port per stream, so this only applies to the methods that
	// stamp the port into a crafted frame. af_xdp drives all TX queues from one
	// worker and varies the port per queue itself, so it takes the base srcPort.
	streamSrcPort := srcPort + (streamNum - 1)
	var sender pktgen.Sender
	switch method {
	case "af_pcap":
		sender = pktgen.NewAFPcapSender(iface, srcIP, dstIP, streamSrcPort, dstPort, payloadSize, srcMAC, dstMAC, vlan)
	case "af_packet":
		sender = pktgen.NewAFPacketSender(iface, srcIP, dstIP, streamSrcPort, dstPort, payloadSize, srcMAC, dstMAC, vlan)
	case "af_xdp":
		sender = pktgen.NewAFXdpSender(iface, srcIP, dstIP, srcPort, dstPort, payloadSize, srcMAC, dstMAC, streamNum-1, vlan, streams)
	case "net_conn":
		sender = pktgen.NewNetConnSender(dstIP, dstPort, payloadSize)
	case "udp_syscall":
		sender = pktgen.NewAFInetSyscallSender(dstIP, dstPort, payloadSize)
	case "raw_socket":
		sender = pktgen.NewRawSocketSender(srcIP, dstIP, streamSrcPort, dstPort, payloadSize)
	case "pkt_conn":
		sender = pktgen.NewBatchConnSender(dstIP, dstPort, payloadSize)
	case "gso":
		sender = pktgen.NewGSOSender(dstIP, dstPort, payloadSize, gsoSegments)
	default:
		log.Fatalf("Unsupported method: %s", method)
	}
	runTest(sender, duration, counter)

}

func setupSignalHandler(cancelFunc context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nReceived interrupt signal, stopping all streams...")
		cancelFunc()
	}()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&method, "method", "af_packet", "method to use for sending packets [af_xdp, af_packet, net_conn, udp_syscall, raw_socket, af_pcap, pkt_conn, gso, benchmark]")
	rootCmd.PersistentFlags().StringVar(&iface, "iface", "eth0", "Interface to use")
	rootCmd.PersistentFlags().StringVar(&srcIP, "srcip", "192.168.64.1", "Source IP address")
	rootCmd.PersistentFlags().StringVar(&dstIP, "dstip", "192.168.64.2", "Destination IP address")
	rootCmd.PersistentFlags().IntVar(&srcPort, "srcport", 12345, "Base source UDP port; with --streams, stream i uses srcport+i so each stream is a distinct flow (af_xdp varies it per TX queue; socket methods use kernel ephemeral ports)")
	rootCmd.PersistentFlags().IntVar(&dstPort, "dstport", 12345, "Destination UDP port")
	rootCmd.PersistentFlags().IntVar(&payloadSize, "payloadsize", 100, "Size of the payload in bytes")
	rootCmd.PersistentFlags().StringVar(&srcMAC, "srcmac", "de:ad:be:ef:ca:fe", "Source MAC address (default: the --iface interface's real MAC)")
	rootCmd.PersistentFlags().StringVar(&dstMAC, "dstmac", "c0:ff:ee:00:00:00", "Destination MAC address")
	rootCmd.PersistentFlags().IntVar(&duration, "duration", 5, "Duration of the benchmark in seconds")
	rootCmd.PersistentFlags().IntVar(&streams, "streams", 1, "Number of concurrent streams for sending packets")
	rootCmd.PersistentFlags().IntVar(&gsoSegments, "segments", 8, "GSO only: segments the kernel slices each sendmsg into (payloadsize*segments must be <= 65507)")
	rootCmd.PersistentFlags().IntVar(&vlan, "vlan", 0, "802.1Q VLAN ID to tag frames with (0 = untagged; frame-building methods af_packet/af_pcap/af_xdp only). Use with --iface <physical> to run AF_XDP native instead of generic-on-vlan.")

}

func main() {
	// should only run on linux
	if runtime.GOOS != "linux" {
		fmt.Println("This tool only runs on Linux")
		os.Exit(1)
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
