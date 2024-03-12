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
	"github.com/vishvananda/netlink"
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

	if method == "benchmark" {
		runBenchmark(ctx, iface, srcIPParsed, dstIPParsed, srcPort, dstPort, payloadSize, duration, srcMACAddr, dstMACAddr, streams)

	} else {
		// start the printStats goroutine
		go printStats(iface, payloadSize, ctx)

		// run the streams, that will know what method to start
		wg := &sync.WaitGroup{}
		for i := 0; i < streams; i++ {
			wg.Add(1)
			go func(streamNum int) {
				defer wg.Done()
				runStream(ctx, method, iface, srcIPParsed, dstIPParsed, srcPort, dstPort, payloadSize, srcMACAddr, dstMACAddr, duration, streamNum)
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
	methods := []string{"af_xdp", "af_packet", "net_conn", "udp_syscall", "raw_socket", "af_pcap", "pkt_conn"}

	// Iterate over methods, run test and collect results
	for _, TestType := range methods {

		counterT0 := counterStats(ifaceName)
		wg := &sync.WaitGroup{}
		for i := 0; i < streams; i++ {
			wg.Add(1)
			go func(streamNum int) {
				var sender pktgen.Sender
				switch TestType {
				case "af_xdp":
					sender = pktgen.NewAFXdpSender(ifaceName, srcIPParsed, dstIPParsed, srcPort, dstPort, payloadSize, dstMACAddr, srcMACAddr, streamNum-1)
				case "af_packet":
					sender = pktgen.NewAFPacketSender(ifaceName, srcIPParsed, dstIPParsed, srcPort, dstPort, payloadSize, dstMACAddr, srcMACAddr)
				case "net_conn":
					sender = pktgen.NewNetConnSender(dstIPParsed, dstPort, payloadSize)
				case "udp_syscall":
					sender = pktgen.NewAFInetSyscallSender(dstIPParsed, dstPort, payloadSize)
				case "raw_socket":
					sender = pktgen.NewRawSocketSender(srcIPParsed, dstIPParsed, srcPort, dstPort, payloadSize)
				case "af_pcap":
					sender = pktgen.NewAFPcapSender(ifaceName, srcIPParsed, dstIPParsed, srcPort, dstPort, payloadSize, srcMACAddr, dstMACAddr)
				case "pkt_conn":
					sender = pktgen.NewBatchConnSender(dstIPParsed, dstPort, payloadSize)
				}
				runTest(sender, duration, ifaceName, payloadSize) // Assume runTest is modified to not print directly
				defer wg.Done()

			}(i + 1)
		}

		wg.Wait()
		counterT1 := counterStats(ifaceName)
		packetsPS := int(counterT1-counterT0) / duration
		mbps := (packetsPS * payloadSize * 8) / (1000 * 1000)
		resultsSlice = append(resultsSlice, resultItem{Method: TestType, PacketsPS: packetsPS, Mbps: mbps})
		// Check if the context has been cancelled before continuing to the next method
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

// runTest runs a test with the given sender and prints the results
func runTest(sender pktgen.Sender, duration int, ifaceName string, payloadSize int) {

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
		err := sender.Send(ctx)
		errChan <- err
	}()

	// Wait for sending to finish or be cancelled
	select {
	case err := <-errChan:
		if err != nil {
			log.Fatalf("Error sending packet: %v", err)
		}
	case <-ctx.Done():
		// Wait for the sending process to finish or be cancelled
	}

}

// counterStats returns the number of transmitted packets per second
func counterStats(ifaceName string) uint64 {
	// Fetch the link by name
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		fmt.Printf("Error fetching link: %v\n", err)
		return 0
	}

	// Accessing the statistics from the link attributes
	attrs := link.Attrs()
	if attrs == nil || attrs.Statistics == nil {
		fmt.Println("Failed to get link attributes or statistics")
		return 0 // Skip this iteration if stats are unavailable
	}

	// Print the number of packets transmitted per second
	return attrs.Statistics.TxPackets

}

// printStats prints the number of transmitted packets per second
func printStats(ifaceName string, frameLen int, ctx context.Context) {

	var prevTxPackets, numPkts uint64
	for {
		select {
		case <-ctx.Done():
			return // Exit the goroutine when the context is cancelled
		default:
			time.Sleep(time.Duration(1) * time.Second)

			pktCounter := counterStats(ifaceName)

			// skip the first loop, when prevTxPackets is 0
			if prevTxPackets == 0 {
				prevTxPackets = pktCounter
				continue
			}

			// Calculate the difference in transmitted packets
			numPkts = pktCounter - prevTxPackets
			prevTxPackets = pktCounter

			// Print the number of packets transmitted per second
			// also account for thernet, ipv4 and udp header
			// ethernet header = 14 bytes
			// ipv4 header = 20 bytes
			// udp header = 8 bytes
			// total = 42 bytes
			bps := (numPkts * uint64(frameLen+42) * 8)
			//fmt.Printf("%d packets/s (%d Mb/s)\n", numPkts, (numPkts*uint64(frameLen)*8)/(1000*1000))
			fmt.Printf("%d packets/s (%d Mb/s)\n", numPkts, bps/(1000*1000))
		}
	}
}

func runStream(ctx context.Context, method, iface string, srcIP, dstIP net.IP, srcPort, dstPort, payloadSize int, srcMAC, dstMAC net.HardwareAddr, duration, streamNum int) {
	// Replicate the switch logic from your existing `main()`
	// For example:
	var sender pktgen.Sender
	switch method {
	case "af_pcap":
		sender = pktgen.NewAFPacketSender(iface, srcIP, dstIP, srcPort, dstPort, payloadSize, srcMAC, dstMAC)
	case "af_packet":
		sender = pktgen.NewAFPacketSender(iface, srcIP, dstIP, srcPort, dstPort, payloadSize, srcMAC, dstMAC)
	case "af_xdp":
		sender = pktgen.NewAFXdpSender(iface, srcIP, dstIP, srcPort, dstPort, payloadSize, srcMAC, dstMAC, streamNum-1)
	case "net_conn":
		sender = pktgen.NewNetConnSender(dstIP, dstPort, payloadSize)
	case "udp_syscall":
		sender = pktgen.NewAFInetSyscallSender(dstIP, dstPort, payloadSize)
	case "raw_socket":
		sender = pktgen.NewRawSocketSender(srcIP, dstIP, srcPort, dstPort, payloadSize)
	case "pkt_conn":
		sender = pktgen.NewBatchConnSender(dstIP, dstPort, payloadSize)
	default:
		log.Fatalf("Unsupported method: %s", method)
	}
	runTest(sender, duration, iface, payloadSize)

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
	rootCmd.PersistentFlags().StringVar(&method, "method", "af_packet", "method to use for sending packets [af_packet, net_conn, udp_syscall, raw_socket, af_pcap, pkt_conn, benchmark]")
	rootCmd.PersistentFlags().StringVar(&iface, "iface", "eth0", "Interface to use")
	rootCmd.PersistentFlags().StringVar(&srcIP, "srcip", "192.168.64.1", "Source IP address")
	rootCmd.PersistentFlags().StringVar(&dstIP, "dstip", "192.168.64.2", "Destination IP address")
	rootCmd.PersistentFlags().IntVar(&srcPort, "srcport", 12345, "Source UDP port")
	rootCmd.PersistentFlags().IntVar(&dstPort, "dstport", 12345, "Destination UDP port")
	rootCmd.PersistentFlags().IntVar(&payloadSize, "payloadsize", 100, "Size of the payload in bytes")
	rootCmd.PersistentFlags().StringVar(&srcMAC, "srcmac", "de:ad:be:ef:ca:fe", "Source MAC address")
	rootCmd.PersistentFlags().StringVar(&dstMAC, "dstmac", "c0:ff:ee:00:00:00", "Destination MAC address")
	rootCmd.PersistentFlags().IntVar(&duration, "duration", 5, "Duration of the benchmark in seconds")
	rootCmd.PersistentFlags().IntVar(&streams, "streams", 1, "Number of concurrent streams for sending packets")

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
