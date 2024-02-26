# Go Packet Generator (go-pktgen)

The Go Packet Generator (`go-pktgen`) is a tool designed for network performance testing and stress testing. It demonstrates various methods of generating and sending packets in Go, allowing users to compare the performance differences between these methods. This tool supports direct `AF_PACKET` access, `AF_XDP`, raw sockets, high-level abstractions like `net.Conn`, and more.

## Goal
The primary goal of `go-pktgen` is to showcase different packet generation techniques in Go and to facilitate performance comparisons among these methods under various conditions. 
Below is an example benchmark result comparing the performance of different packet sending methods:

```
./go-pktgen --dstip 192.168.64.2 --method benchmark --duration 5 --payloadsize 64 --streams 2 --iface veth0
+-------------+-----------+------+
|   Method    | Packets/s | Mb/s |
+-------------+-----------+------+
| af_xdp      |   5191321 | 2657 |
| af_packet   |   2644950 | 1354 |
| af_pcap     |   2229470 | 1141 |
| udp_syscall |   1646761 |  843 |
| raw_socket  |   1571420 |  804 |
| net_conn    |   1480660 |  758 |
+-------------+-----------+------+
```


## Getting Started

### Prerequisites
This tool is designed to run on Linux. Running on other platforms will not work for certain packet sending methods like `AF_PACKET` and `AF_XDP`. 

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
      --method string     method to use for sending packets [af_packet, net_conn, udp_syscall, raw_socket, af_pcap, benchmark] (default "af_packet")
      --payloadsize int   Size of the payload in bytes (default 100)
      --srcip string      Source IP address (default "192.168.64.1")
      --srcmac string     Source MAC address (default "de:ad:be:ef:ca:fe")
      --srcport int       Source UDP port (default 12345)
      --streams int       Number of concurrent streams for sending packets (default 1)
```

Note that pktgen requires root privileges to run, as it needs to access raw sockets and network interfaces. 
It also checks that the number of streams is less than or equal to the number of available TX queues on the specified interface.

## Benchmarking
To compare the performance of different packet sending methods, use the benchmark method:

```
./go-pktgen --dstip 192.168.64.2 --method benchmark --duration 5 --payloadsize 64 --streams 2 --iface veth0
```
This will run a series of tests using all available methods and print the results in terms of packets per second and Mbps.

## Contributing
Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.


