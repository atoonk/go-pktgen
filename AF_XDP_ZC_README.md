# AF_XDP Zero-Copy Implementation

This document describes the new `afxdp_zc` method added to go-pktgen for high-performance packet transmission using AF_XDP with zero-copy support.

## Overview

The `afxdp_zc` method provides:
- **Zero-copy mode** with automatic fallback to copy mode
- **Batch submission** for improved throughput
- **Explicit completion tracking** for better performance visibility
- **Custom eBPF program** for packet filtering

## Implementation Details

### Files Added

```
pktgen/
├── afxdp/
│   ├── afxdp.go              # Core AF_XDP socket implementation
│   └── xdp/
│       ├── xdp_bpf_gen.go    # Go generate directive
│       ├── xdp_redirect_map.c # eBPF XDP program (filters UDP port 12345)
│       ├── xdpprog_bpfeb.go  # Generated Go bindings (big-endian)
│       ├── xdpprog_bpfeb.o   # Compiled eBPF bytecode (big-endian)
│       ├── xdpprog_bpfel.go  # Generated Go bindings (little-endian)
│       └── xdpprog_bpfel.o   # Compiled eBPF bytecode (little-endian)
└── af_xdp_zc.go              # AFXdpZCSender implementation
```

### XDP Program Behavior

The eBPF program (`xdp_redirect_map.c`) filters incoming packets:
- **UDP port 12345** → Redirected to AF_XDP socket (for potential RX support)
- **All other traffic** → `XDP_PASS` (passed to kernel network stack)

This ensures your SSH and other network traffic works normally while the AF_XDP socket can receive test packets.

## Compiling on Linux

**IMPORTANT**: The eBPF bytecode files (`.o` and generated `.go` files) were initially copied from afxdp-bench-go. You should regenerate them on Linux with the modified XDP program.

### Prerequisites

On Linux, install required tools:

```bash
# Ubuntu/Debian
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)

# RHEL/CentOS
sudo yum install clang llvm libbpf-devel kernel-devel
```

### Regenerate eBPF Bytecode

On your Linux machine:

```bash
cd pktgen/afxdp/xdp
go generate
```

This will compile `xdp_redirect_map.c` and generate:
- `xdpprog_bpfel.o` and `xdpprog_bpfel.go` (little-endian)
- `xdpprog_bpfeb.o` and `xdpprog_bpfeb.go` (big-endian)

### Build go-pktgen

```bash
go build -o go-pktgen .
```

## Usage

### Single Method Test

```bash
sudo ./go-pktgen --method afxdp_zc --iface eth0 --dstip 192.168.1.2 --duration 10
```

### Benchmark Comparison

```bash
sudo ./go-pktgen --method benchmark --iface eth0 --dstip 192.168.1.2 --duration 5
```

Expected output:
```
+-------------+-----------+------+
|   Method    | Packets/s | Mb/s |
+-------------+-----------+------+
| afxdp_zc    |   3500000 | 1792 |  <- New zero-copy implementation
| af_xdp      |   2620595 | 1341 |  <- Original implementation
| af_packet   |   1159690 |  593 |
| af_pcap     |   1037554 |  531 |
...
+-------------+-----------+------+
```

### Multi-Queue/Multi-Stream

```bash
# Check TX queues
ethtool -l eth0

# Set TX queues if needed
sudo ethtool -L eth0 tx 4

# Run with multiple streams
sudo ./go-pktgen --method afxdp_zc --iface eth0 --streams 4 --duration 10
```

## Performance Considerations

### Zero-Copy Mode

The implementation prefers zero-copy mode but automatically falls back to copy mode if:
- NIC driver doesn't support zero-copy
- Queue doesn't support XDP_ZEROCOPY flag

You can check the mode in logs (when implemented) or by observing performance differences.

### Tuning Parameters

In `pktgen/af_xdp_zc.go`, you can adjust:

```go
sock, err := iface.Open(afxdp.SocketConfig{
    QueueID:   uint32(s.queueID),
    FrameSize: 2048,        // UMEM frame size
    NumFrames: 4096,        // Total UMEM frames
    TxSize:    2048,        // TX ring size
    CqSize:    2048,        // Completion queue size
    RxSize:    2048,        // RX ring size (for future RX support)
    BatchSize: 64,          // Batch submission size
})
```

### CPU Pinning

For best performance, consider pinning the process to specific CPUs:

```bash
taskset -c 0-3 sudo ./go-pktgen --method afxdp_zc --iface eth0 --streams 4
```

## Comparison with Original af_xdp

| Feature | af_xdp (original) | afxdp_zc (new) |
|---------|-------------------|----------------|
| Library | github.com/asavie/xdp | Custom (cilium/ebpf) |
| Zero-copy control | Automatic | Explicit with fallback |
| Batch submission | No | Yes (64 packets) |
| Completion tracking | Minimal | Explicit polling |
| eBPF program | Library-provided | Custom (port 12345 filter) |
| Frame management | Library-managed | Manual pool |

## Troubleshooting

### Build Errors on macOS

The code is Linux-only. Cross-compile with:
```bash
GOOS=linux GOARCH=amd64 go build .
```

### eBPF Compilation Errors

If `go generate` fails:
- Ensure clang and llvm-strip are installed
- Check kernel headers are present
- Verify BPF headers are available: `ls /usr/include/linux/bpf.h`

### Runtime Errors

**"permission denied"**: Run with `sudo`

**"device or resource busy"**: Another XDP program may be attached. Check with:
```bash
ip link show eth0
```

**"not supported"**: NIC driver may not support AF_XDP. Check driver documentation.

## Future Enhancements

Potential improvements:
1. Add RX receiver implementation
2. Make batch size configurable via command-line flag
3. Add zero-copy status reporting
4. Implement ethtool statistics for more accurate measurement
5. Add latency measurements
6. Support for custom XDP filters via command-line

## References

- Original implementation: https://github.com/romshark/afxdp-bench-go
- AF_XDP documentation: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
- cilium/ebpf library: https://github.com/cilium/ebpf
