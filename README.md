[![Go Report Card](https://goreportcard.com/badge/github.com/atoonk/go-pktgen)](https://goreportcard.com/report/github.com/atoonk/go-pktgen)
[![Documentation](https://godoc.org/github.com/atoonk/go-pktgen?status.svg)](https://godoc.org/github.com/atoonk/go-pktgen)
[![GitHub issues](https://img.shields.io/github/issues/atoonk/go-pktgen.svg)](https://github.com/atoonk/go-pktgen/issues)
[![license](https://img.shields.io/github/license/atoonk/go-pktgen.svg)](https://github.com/atoonk/go-pktgen/blob/master/LICENSE)
[![Stargazers over time](https://starchart.cc/atoonk/go-pktgen.svg?variant=adaptive)](https://starchart.cc/atoonk/go-pktgen)

# Go Packet Generator (go-pktgen)

For more information, also see my blog here: [High-Speed Packet Transmission in Go: From net.Dial to AF_XDP](https://toonk.io/sending-network-packets-in-go/)

The Go Packet Generator (`go-pktgen`) is a tool designed for network performance testing and stress testing. It demonstrates various methods of generating and sending packets in Go, allowing users to compare the performance differences between these methods. This tool supports direct `AF_PACKET` access, `AF_XDP` (via [go-afxdp](https://github.com/atoonk/go-afxdp)), UDP GSO (`UDP_SEGMENT`), raw sockets, high-level abstractions like `net.Conn`, and more.

## Goal
The primary goal of `go-pktgen` is to showcase different packet generation techniques in Go and to facilitate performance comparisons among these methods under various conditions.

Below is an example benchmark result comparing the methods over a veth pair
(AMD EPYC 4244P @ 3.8GHz, 6 cores). It uses `--payloadsize 18`: 18 bytes of UDP
payload + 14 (Ethernet) + 20 (IPv4) + 8 (UDP) is a 60-byte frame, which with the
4-byte FCS is the classic 64-byte minimum-size Ethernet packet — the standard
worst case for packets-per-second.

```
./go-pktgen --dstip 192.168.64.2 --method benchmark --duration 5 --payloadsize 18 --iface veth0
+-------------+-----------+------+
|   Method    | Packets/s | Mb/s |
+-------------+-----------+------+
| gso         |   1396318 |  670 |
| af_xdp      |    736512 |  353 |
| af_pcap     |    477484 |  229 |
| af_packet   |    374134 |  179 |
| raw_socket  |    191189 |   91 |
| udp_syscall |    183244 |   87 |
| pkt_conn    |    182323 |   87 |
| net_conn    |    145383 |   69 |
+-------------+-----------+------+
```

On a veth pair everything is a software path, so the winner is whoever spends
the fewest CPU cycles per packet in the kernel — `gso` (one sendmsg carries 8
packets), while `af_xdp` runs in copy mode and can't shine.

**On a physical NIC, af_xdp is in a different league.** With a NIC that supports
native XDP and zero-copy, af_xdp transmits straight from user-space memory into
all TX queues, bypassing the kernel network stack entirely. Here is a 15-second
run on a 10G ixgbe interface (the network is a VLAN, so we tag with `--vlan`
and keep `--iface` on the physical NIC — that's what keeps XDP native):

```
./go-pktgen --method af_xdp --iface eno2 --vlan 2131 --srcip 192.168.0.1 --dstip 192.168.0.2 \
  --dstmac 3c:ec:ef:b4:c2:dc --dstport 9999 --payloadsize 18 --streams 12 --duration 15
13302952 packets/s (6385 Mb/s)
13329780 packets/s (6398 Mb/s)
13205180 packets/s (6338 Mb/s)
13269492 packets/s (6369 Mb/s)
```

That's **13.3 million packets per second** — 18x the veth number, and the limit
is the 10G wire, not the CPU. (For comparison on the same NIC: gso ~7.4M pps,
af_packet ~5.1M pps.)

**Why 13.3M pps shows as only ~6.4 Gb/s.** The Mb/s column counts
application-level bytes: the frame go-pktgen builds (60 bytes here). The wire
carries more per packet: +4 VLAN tag, +4 FCS, +8 preamble/SFD, +12 interframe
gap = 88 bytes per packet on the wire. 13.3M pps x 88B x 8 = ~9.4 Gb/s of wire
time — within ~7% of the 14.2M pps theoretical maximum for minimum-size tagged
frames on 10G — even though the app-level figure reads 6.4 Gb/s. The smaller
the packet, the bigger that gap; at 1500-byte frames the two numbers nearly
converge.

Note for benchmarking on such NICs: attaching an XDP program on ixgbe retrains
the link for ~10 seconds, and the af_xdp method waits for link-up *inside* its
measured window — short `--method benchmark` runs therefore understate af_xdp
(a 5s run reports 0). Use a long `--duration`, or measure af_xdp standalone as
above.

If you're not interested in comparing methods and just want to send packets as
fast as possible, have a look at the
[blast example](https://github.com/atoonk/go-afxdp/tree/main/examples/blast) in
the [go-afxdp](https://github.com/atoonk/go-afxdp) library: a minimal AF_XDP
UDP flooder that drives every TX queue at line rate, sweeping the source port
per packet so the traffic spreads across many flows (and the receiver's RSS
queues). It's a good, small example of using the library directly.

## Getting Started

### Prerequisites
This tool is designed to run on Linux. Running on other platforms will not work for certain packet sending methods like `AF_PACKET` and `AF_XDP`. 
you need libpcap-dev and build-essential
`sudo apt-get install build-essential libpcap-dev`

### Compilation
Note this tool for now only works on Linux. 
To compile the tool, navigate to the root of the repository and run:

```sh
go build -o go-pktgen main.go
```
This command compiles the source code into an executable named go-pktgen.


## Usage
To run the packet generator, you can use the following command:
```
./go-pktgen -h
A versatile packet generation tool designed for network performance and stress testing.

Usage:
  pktgen [flags]

Flags:
      --dstip string      Destination IP address (default "192.168.64.2")
      --dstmac string     Destination MAC address (default "c0:ff:ee:00:00:00")
      --dstport int       Destination UDP port (default 12345)
      --duration int      Duration of the benchmark in seconds (default 5)
  -h, --help              help for pktgen
      --iface string      Interface to use (default "eth0")
      --method string     method to use for sending packets [af_xdp, af_packet, net_conn, udp_syscall, raw_socket, af_pcap, pkt_conn, gso, benchmark] (default "af_packet")
      --payloadsize int   Size of the payload in bytes (default 100)
      --segments int      GSO only: segments the kernel slices each sendmsg into (payloadsize*segments must be <= 65507) (default 8)
      --srcip string      Source IP address (default "192.168.64.1")
      --srcmac string     Source MAC address (default: the --iface interface's real MAC)
      --srcport int       Base source UDP port; with --streams, stream i uses srcport+i so each stream is a distinct flow (af_xdp varies it per TX queue; socket methods use kernel ephemeral ports) (default 12345)
      --streams int       Number of concurrent streams for sending packets (default 1)
      --vlan int          802.1Q VLAN ID to tag frames with (0 = untagged; frame-building methods af_packet/af_pcap/af_xdp only). Use with --iface <physical> to run AF_XDP native instead of generic-on-vlan.
```

Note that pktgen requires root privileges to run, as it needs to access raw sockets and network interfaces. 
It also checks that the number of streams is less than or equal to the number of available TX queues on the specified interface.

*example*
packet generator sending UDP packets using `af_packet`
```
./go-pktgen --dstip 192.168.64.2 --method af_packet --duration 5 --payloadsize 1200 --streams 1  --iface veth0
```

packet generator sending UDP packets using `af_xdp`
```
./go-pktgen --dstip 192.168.64.2 --method af_xdp --duration 5 --payloadsize 1200 --streams 1  --iface veth0
```

`af_xdp` is built on [go-afxdp](https://github.com/atoonk/go-afxdp): it attaches
a no-op XDP program (enabling the driver's zero-copy TX path on capable NICs)
and drives **all** TX queues from one worker, so `--streams` doesn't apply;
instead it stamps `--streams` distinct source ports across its queues so the
receiver's RSS spreads the load over its rx queues. On a physical NIC give it
real addressing — for example, 10G line rate at 64-byte frames on ixgbe:
```
./go-pktgen --method af_xdp --iface eno2 --srcip 192.168.0.1 --dstip 192.168.0.2 \
  --dstmac 3c:ec:ef:b4:c2:dc --dstport 9999 --payloadsize 64 --streams 12 --duration 30
```
To send on a VLAN, add `--vlan <id>` and keep `--iface` on the physical NIC:
running on the `vlan.X` subinterface itself forces generic (slow) XDP.

packet generator sending UDP packets using `gso` (UDP_SEGMENT: the kernel slices
one 8·payloadsize sendmsg into 8 wire packets, cutting per-packet syscall cost)
```
./go-pktgen --dstip 192.168.64.2 --method gso --duration 5 --payloadsize 1200 --segments 8
```
`gso` goes through a normal UDP socket, so it needs no interface/MAC flags and
the receiver must be reachable via the routing table.

## Benchmarking
To compare the performance of different packet sending methods, use the benchmark method:

```
./go-pktgen --dstip 192.168.64.2 --method benchmark --duration 5 --payloadsize 64 --streams 1 --iface veth0
```
This will run a series of tests using all available methods and print the results in terms of packets per second and Mbps.

## Multiple streams
To use multiple streams, you need to have multiple TX queues. You can check the number of TX queues on your system like this:
```
ethtool -l veth0
Channel parameters for veth0:
Pre-set maximums:
RX:		16
TX:		16
Other:		n/a
Combined:	n/a
Current hardware settings:
RX:		1
TX:		10
Other:		n/a
Combined:	n/a
```

Take note of the Current hardware settings for the TX queue. 
You can change it like this to the maximum, in this example 16
```
ethtool -L veth0 tx 16
```

## Contributing
Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.

