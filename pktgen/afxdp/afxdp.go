//go:build linux

// Package afxdp implements AF_XDP zero-copy capable sockets.
// Interface owns XDP program + eBPF objects.
// Socket is an AF_XDP socket bound to a specific RX/TX queue.
//
// Adapted from github.com/romshark/afxdp-bench-go
//
// Terminology mapping (kernel ↔ userspace):
//
//   - RX ring: raw packets delivered from NIC to userspace.
//   - FQ ring: UMEM addresses userspace provides to kernel for RX.
//   - TX ring: descriptors userspace sends to NIC.
//   - CQ ring: completed TX buffers returned by kernel.
package afxdp

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/atoonk/go-pktgen/pktgen/afxdp/xdp"
)

var (
	ErrXSKSMapNotFound     = errors.New("xsks_map not found")
	ErrXDPSockProgNotFound = errors.New("xdp_sock_prog not found")
	ErrTXRegionIsEmpty     = errors.New("tx region is empty")
	ErrCQRegionIsEmpty     = errors.New("cq region is empty")
	ErrNumFramesTooSmall   = errors.New("NumFrames must be >= TxSize + RxSize")
)

// InterfaceConfig controls how AF_XDP is attached to a network interface.
type InterfaceConfig struct {
	PreferZerocopy bool
}

type SocketConfig struct {
	// QueueID identifies the NIC RX/TX queue to bind to.
	QueueID uint32
	// NumFrames is the total number of UMEM frames allocated.
	NumFrames uint32
	// FrameSize defines the size of each UMEM frame in bytes.
	FrameSize uint32
	// RxSize sets the number of descriptors in the RX ring.
	RxSize uint32
	// TxSize sets the number of descriptors in the TX ring.
	TxSize uint32
	// CqSize sets the number of entries in the completion ring.
	CqSize uint32
	// BatchSize controls TX and completion processing batch size.
	// Very large values do not help and can hurt copy-mode performance,
	// so we clamp them in ValidateAndSetDefaults.
	BatchSize uint32
}

func (c *SocketConfig) ValidateAndSetDefaults() error {
	if c.NumFrames == 0 {
		c.NumFrames = DefaultNumFrames
	}
	if c.FrameSize == 0 {
		c.FrameSize = DefaultFrameSize
	}
	if c.RxSize == 0 {
		c.RxSize = DefaultRxQueueSize
	}
	if c.TxSize == 0 {
		c.TxSize = DefaultTxQueueSize
	}
	if c.CqSize == 0 {
		c.CqSize = DefaultCompletionRingSize
	}
	if c.BatchSize == 0 {
		c.BatchSize = DefaultBatchSize
	}
	// Hard upper bound: larger batches cause latency spikes and bad behavior
	// in copy-mode; AF_XDP works best with modest batches.
	if c.BatchSize > 256 {
		c.BatchSize = 256
	}
	if c.NumFrames < c.TxSize+c.RxSize {
		return ErrNumFramesTooSmall
	}
	return nil
}

// Interface represents a NIC with an XDP program attached for AF_XDP use.
// It owns the XDP program and eBPF objects and can create AF_XDP sockets
// bound to individual hardware queues.
type Interface struct {
	ifaceName      string
	ifaceIndex     int
	preferZerocopy bool

	link link.Link
	objs *xdp.XdpProgObjects
}

func (i *Interface) Info() (name string, index int) {
	return i.ifaceName, i.ifaceIndex
}

// MakeInterface attaches the XDP program to the given interface name
// and returns an Interface handle that can open AF_XDP sockets on its queues.
// The XDP program is attached once per Interface.
func MakeInterface(iface string, conf InterfaceConfig) (*Interface, error) {
	netIf, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("getting interface: %w", err)
	}

	// prefer driver mode always; zerocopy is decided per-socket
	l, objs, err := attachXDP(iface)
	if err != nil {
		return nil, fmt.Errorf("attaching XDP program: %w", err)
	}

	return &Interface{
		ifaceName:      iface,
		preferZerocopy: conf.PreferZerocopy,
		ifaceIndex:     netIf.Index,
		link:           l,
		objs:           objs,
	}, nil
}

// RXQueueIDs returns the list of RX queue IDs available on the interface,
// sorted in ascending order inspecting /sys/class/net/<iface>/queues.
func (i *Interface) RXQueueIDs() (ids []uint32, err error) {
	path := "/sys/class/net/" + i.ifaceName + "/queues"
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "rx-") {
			idStr := e.Name()[3:]
			id, err := strconv.Atoi(idStr)
			if err != nil {
				return nil, fmt.Errorf("parsing entry %q: %w", idStr, err)
			}
			ids = append(ids, uint32(id))
		}
	}
	slices.Sort(ids)
	return ids, nil
}

// Close detaches the XDP program from the interface and frees the underlying
// eBPF resources owned by this Interface. It does not close any Socket instances;
// those must be closed separately before closing the Interface.
func (i *Interface) Close() error {
	var errs []error
	if i.link != nil {
		if err := i.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing XDP link: %w", err))
		}
		i.link = nil
	}

	if i.objs != nil {
		if err := i.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing XDP objs: %w", err))
		}
		i.objs = nil
	}
	return errors.Join(errs...)
}

// registerXSK registers the socket FD in the xsks_map for the given queue.
// This allows the XDP program to redirect packets to the correct AF_XDP socket.
func registerXSK(objs *xdp.XdpProgObjects, fd int, queue uint32) error {
	if objs.XsksMap == nil {
		return ErrXSKSMapNotFound
	}
	return objs.XsksMap.Update(queue, uint32(fd), ebpf.UpdateAny)
}

// attachXDP loads and attaches the XDP program to the interface.
// When zerocopy is true, driver mode is requested to enable AF_XDP zero-copy.
func attachXDP(ifaceName string) (link.Link, *xdp.XdpProgObjects, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, nil, fmt.Errorf("getting interface index by name: %w", err)
	}

	var objs xdp.XdpProgObjects
	if err := xdp.LoadXdpProgObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("loading XDP BPF: %w", err)
	}

	prog := objs.XdpSockProg
	if prog == nil {
		objs.Close()
		return nil, nil, ErrXDPSockProgNotFound
	}

	opts := link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode, // always try driver mode
	}

	l, err := link.AttachXDP(opts)
	if err != nil {
		// fallback: generic mode (slower, but works)
		opts.Flags = 0
		l, err = link.AttachXDP(opts)
		if err != nil {
			objs.Close()
			return nil, nil, fmt.Errorf("attaching XDP: %w", err)
		}
	}

	return l, &objs, nil
}

const (
	DefaultNumFrames          = 4096
	DefaultFrameSize          = 2048
	DefaultTxQueueSize        = 2048
	DefaultRxQueueSize        = DefaultTxQueueSize
	DefaultCompletionRingSize = 2048
	DefaultBatchSize          = 64 // TX batching
)

/*---- Kernel structs ----*/

// sockaddr_xdp is defined in linux/if_xdp.h
// See https://elixir.bootlin.com/linux/v5.15.77/source/include/uapi/linux/if_xdp.h#L32
type sockaddr_xdp struct {
	Family       uint16
	Flags        uint16
	Ifindex      uint32
	QueueID      uint32
	SharedUmemFD uint32
}

// xdp_ring_offset is defined in linux/if_xdp.h
// See https://elixir.bootlin.com/linux/v5.15.77/source/include/uapi/linux/if_xdp.h#L43
type xdp_ring_offset struct {
	Producer uint64
	Consumer uint64
	Desc     uint64
	Flags    uint64
}

// xdp_mmap_offsets is defined in linux/if_xdp.h
// https://elixir.bootlin.com/linux/v5.15.77/source/include/uapi/linux/if_xdp.h#L50
type xdp_mmap_offsets struct {
	Rx xdp_ring_offset
	Tx xdp_ring_offset
	Fr xdp_ring_offset
	Cr xdp_ring_offset
}

// xdp_umem_reg is defined in linux/if_xdp.h
// See https://elixir.bootlin.com/linux/v5.15.77/source/include/uapi/linux/if_xdp.h#L67
type xdp_umem_reg struct {
	Addr      uint64
	Len       uint64
	ChunkSize uint32
	Headroom  uint32
}

// xdp_desc is defined in linux/if_xdp.h
// See https://elixir.bootlin.com/linux/v5.15.77/source/include/uapi/linux/if_xdp.h#L103
type xdp_desc struct {
	Addr uint64
	Len  uint32
	Opts uint32
}

/*---- Queue wrappers ----*/

// xdpUQueue represents a userspace ring queue backed by shared memory.
// It mirrors the kernel ring structure and maintains cached producer/consumer
// indices to reduce atomic traffic.
type xdpUQueue struct {
	cachedProd uint32
	cachedCons uint32
	mask       uint32
	size       uint32
	prod       *uint32
	cons       *uint32
	descs      []xdp_desc
}

// xdpUMemQueue represents a UMEM address ring (FQ or CQ).
// Entries are raw UMEM offsets managed by kernel and userspace.
type xdpUMemQueue struct {
	cachedProd uint32
	cachedCons uint32
	mask       uint32
	size       uint32
	prod       *uint32
	cons       *uint32
	addrs      []uint64
}

func rawBind(fd int, sa *sockaddr_xdp) error {
	_, _, e := unix.Syscall(unix.SYS_BIND,
		uintptr(fd),
		uintptr(unsafe.Pointer(sa)),
		unsafe.Sizeof(*sa),
	)
	if e != 0 {
		return e
	}
	return nil
}

func setsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	_, _, e := unix.Syscall6(unix.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(name),
		uintptr(val), vallen, 0)
	if e != 0 {
		return e
	}
	return nil
}

func getsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	l := uint32(vallen) // socklen_t
	_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(val),
		uintptr(unsafe.Pointer(&l)),
		0,
	)
	if e != 0 {
		return e
	}
	return nil
}

// mmapRegion maps RX/TX/FQ/CQ rings on the AF_XDP socket.
func mmapRegion(fd int, length uintptr, offset uintptr) ([]byte, error) {
	addr, _, errno := unix.Syscall6(unix.SYS_MMAP,
		0,
		length,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
		uintptr(fd),
		offset,
	)
	if errno != 0 {
		return nil, errno
	}
	sh := &struct {
		Addr uintptr
		Len  int
		Cap  int
	}{addr, int(length), int(length)}
	return *(*[]byte)(unsafe.Pointer(sh)), nil
}

// mmapUmem maps an anonymous, page-backed region for UMEM.
func mmapUmem(length uintptr) ([]byte, error) {
	addr, _, errno := unix.Syscall6(unix.SYS_MMAP,
		0,
		length,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE,
		^uintptr(0), // fd = -1
		0,
	)
	if errno != 0 {
		return nil, errno
	}
	sh := &struct {
		Addr uintptr
		Len  int
		Cap  int
	}{addr, int(length), int(length)}
	return *(*[]byte)(unsafe.Pointer(sh)), nil
}

// makeQueue builds RX/TX user queue from mmap + offsets.
func makeQueue(
	region []byte, off xdp_ring_offset, size uint32, isTx bool,
) (*xdpUQueue, error) {
	if len(region) == 0 {
		return nil, ErrTXRegionIsEmpty
	}
	base := unsafe.Pointer(&region[0])

	prod := (*uint32)(unsafe.Add(base, off.Producer))
	cons := (*uint32)(unsafe.Add(base, off.Consumer))

	descPtr := unsafe.Add(base, off.Desc)
	descs := unsafe.Slice((*xdp_desc)(descPtr), size)

	cachedCons := uint32(0)
	if isTx {
		cachedCons = size
	}

	return &xdpUQueue{
		mask:       size - 1,
		size:       size,
		prod:       prod,
		cons:       cons,
		descs:      descs,
		cachedProd: 0,
		cachedCons: cachedCons,
	}, nil
}

// makeUMemQueue builds UMEM completion queue from mmap + offsets.
func makeUMemQueue(
	region []byte, off xdp_ring_offset, size uint32,
) (*xdpUMemQueue, error) {
	if len(region) == 0 {
		return nil, ErrCQRegionIsEmpty
	}
	base := unsafe.Pointer(&region[0])

	prod := (*uint32)(unsafe.Add(base, off.Producer))
	cons := (*uint32)(unsafe.Add(base, off.Consumer))

	addrPtr := unsafe.Add(base, off.Desc)
	addrs := unsafe.Slice((*uint64)(addrPtr), size)

	return &xdpUMemQueue{
		mask:       size - 1,
		size:       size,
		prod:       prod,
		cons:       cons,
		addrs:      addrs,
		cachedProd: 0,
		cachedCons: 0,
	}, nil
}

/*---- Queue operations ----*/

// rxAvailable returns the number of RX descriptors available to consume.
func rxAvailable(q *xdpUQueue) uint32 {
	avail := q.cachedProd - q.cachedCons
	if avail > 0 {
		return avail
	}

	q.cachedProd = atomic.LoadUint32(q.prod)
	return q.cachedProd - q.cachedCons
}

// reserveTx reserves nDescs TX descriptors if space is available.
// Returns zero if the ring is full.
func reserveTx(q *xdpUQueue, nDescs uint32, idx *uint32) int {
	free := q.cachedCons - q.cachedProd
	if free < nDescs {
		cons := atomic.LoadUint32(q.cons)
		q.cachedCons = cons + q.size
		if q.cachedCons-q.cachedProd < nDescs {
			return 0
		}
	}

	*idx = q.cachedProd
	q.cachedProd += nDescs
	return int(nDescs)
}

// commitTxDescriptors publishes TX descriptors to the kernel
// by updating the producer index.
func commitTxDescriptors(queueProd *uint32, queueCachedProd uint32) {
	// Descriptors are written; now publish producer index.
	atomic.StoreUint32(queueProd, queueCachedProd)
}

// umemNbAvail returns the number of UMEM entries available to consume, capped by nb.
func umemNbAvail(q *xdpUMemQueue, nb uint32) uint32 {
	entries := q.cachedProd - q.cachedCons
	if entries == 0 {
		prod := atomic.LoadUint32(q.prod)
		q.cachedProd = prod
		entries = q.cachedProd - q.cachedCons
	}
	if entries > nb {
		return nb
	}
	return entries
}

// umemCompleteFromKernel copies completed UMEM addresses into dst
// and advances the consumer index.
func umemCompleteFromKernel(q *xdpUMemQueue, dst []uint64, nb uint32) uint32 {
	entries := umemNbAvail(q, nb)
	for i := range entries {
		idx := q.cachedCons & q.mask
		dst[i] = q.addrs[idx]
		q.cachedCons++
	}
	if entries > 0 {
		atomic.StoreUint32(q.cons, q.cachedCons)
	}
	return entries
}

var zeroBuf []byte

// wakeupTxQueue notifies the kernel/NIC that new TX descriptors are ready.
// AF_XDP interprets a zero-length sendto() as a doorbell signal to process
// the TX ring. This is required when XDP_USE_NEED_WAKEUP is enabled.
func wakeupTxQueue(fd int) error {
	// zero-length wakeup; AF_XDP treats this as a "kick"
	err := unix.Sendto(fd, zeroBuf, unix.MSG_DONTWAIT, nil)
	if err == unix.EAGAIN || err == unix.EBUSY {
		// Treat EAGAIN (and optionally EBUSY) as non-fatal backpressure.
		return nil
	}
	return err
}

// Socket is an AF_XDP bidirectional socket.
//
// WARNING: Socket is not safe for concurrent use.
type Socket struct {
	conf       SocketConfig
	isZerocopy bool

	fd int

	umem []byte
	tx   *xdpUQueue
	cq   *xdpUMemQueue
	rx   *xdpUQueue
	fq   *xdpUMemQueue

	txRegion []byte
	rxRegion []byte
	cqRegion []byte
	fqRegion []byte

	freeFrames []uint64
	freeCount  uint32

	compBuf []uint64

	iface *Interface
}

// TxFree returns the number of free TX descriptors in the TX ring.
func (s *Socket) TxFree() uint32 {
	// cons = kernel consumer index
	cons := atomic.LoadUint32(s.tx.cons) + s.tx.size
	return cons - s.tx.cachedProd
}

// FreeFrames returns number of free UMEM frames available for TX.
func (s *Socket) FreeFrames() uint32 {
	return s.freeCount
}

// Open creates and initializes an AF_XDP socket.
// It allocates UMEM, maps rings, configures kernel structures,
// binds to the target NIC queue and registers the socket in xsks_map.
func (i *Interface) Open(conf SocketConfig) (*Socket, error) {
	// Apply defaults if necessary.
	if err := conf.ValidateAndSetDefaults(); err != nil {
		return nil, err
	}

	// TODO: currently, Open would leak memory if some of the following
	// operations fail.

	iface, err := net.InterfaceByName(i.ifaceName)
	if err != nil {
		return nil, fmt.Errorf("fetching iface info by name: %w", err)
	}

	// AF_XDP socket.
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("opening AF_XDP socket: %w", err)
	}

	// UMEM registration.
	umemLen := uintptr(conf.NumFrames) * uintptr(conf.FrameSize)
	umem, err := mmapUmem(umemLen)
	if err != nil {
		return nil, fmt.Errorf("mmap UMEM: %w", err)
	}

	reg := xdp_umem_reg{
		Addr:      uint64(uintptr(unsafe.Pointer(&umem[0]))),
		Len:       uint64(len(umem)),
		ChunkSize: conf.FrameSize,
		Headroom:  0,
	}
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_UMEM_REG,
		unsafe.Pointer(&reg), unsafe.Sizeof(reg),
	); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("setsockopt XDP_UMEM_REG: %w", err)
	}

	// UMEM ring sizes.
	fillSize := conf.RxSize
	compSize := conf.CqSize
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING,
		unsafe.Pointer(&fillSize), unsafe.Sizeof(fillSize),
	); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("setsockopt XDP_UMEM_FILL_RING: %w", err)
	}
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING,
		unsafe.Pointer(&compSize), unsafe.Sizeof(compSize),
	); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("setsockopt XDP_UMEM_COMPLETION_RING: %w", err)
	}

	// TX ring size on socket.
	txSize := conf.TxSize
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_TX_RING,
		unsafe.Pointer(&txSize), unsafe.Sizeof(txSize),
	); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("setsockopt XDP_TX_RING: %w", err)
	}

	// RX ring size on socket.
	rxSize := conf.RxSize
	if err := setsockopt(
		fd, unix.SOL_XDP, unix.XDP_RX_RING,
		unsafe.Pointer(&rxSize), unsafe.Sizeof(rxSize),
	); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("setsockopt XDP_RX_RING: %w", err)
	}

	// Query mmap offsets for all rings.
	var offs xdp_mmap_offsets
	if err := getsockopt(
		fd, unix.SOL_XDP, unix.XDP_MMAP_OFFSETS,
		unsafe.Pointer(&offs), unsafe.Sizeof(offs),
	); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("setsockopt XDP_MMAP_OFFSETS: %w", err)
	}

	// Map TX ring (descriptors).
	txRegionLen := uintptr(offs.Tx.Desc) + uintptr(conf.TxSize)*unsafe.Sizeof(xdp_desc{})
	txRegion, err := mmapRegion(fd, txRegionLen, unix.XDP_PGOFF_TX_RING)
	if err != nil {
		return nil, fmt.Errorf("mmap TX ring: %w", err)
	}

	// Map CQ ring (UMEM completion ring, uint64 addresses).
	cqRegionLen := uintptr(offs.Cr.Desc) + uintptr(conf.CqSize)*unsafe.Sizeof(uint64(0))
	cqRegion, err := mmapRegion(fd, cqRegionLen, unix.XDP_UMEM_PGOFF_COMPLETION_RING)
	if err != nil {
		return nil, fmt.Errorf("mmap CQ ring: %w", err)
	}

	// Map RX ring
	rxRegionLen := uintptr(offs.Rx.Desc) + uintptr(conf.RxSize)*unsafe.Sizeof(xdp_desc{})
	rxRegion, err := mmapRegion(fd, rxRegionLen, unix.XDP_PGOFF_RX_RING)
	if err != nil {
		return nil, fmt.Errorf("mmap RX ring: %w", err)
	}

	// Map FQ ring (UMEM fill ring, uint64 addresses)
	fqRegionLen := uintptr(offs.Fr.Desc) + uintptr(conf.RxSize)*unsafe.Sizeof(uint64(0))
	fqRegion, err := mmapRegion(fd, fqRegionLen, unix.XDP_UMEM_PGOFF_FILL_RING)
	if err != nil {
		return nil, fmt.Errorf("mmap FQ ring: %w", err)
	}

	// Build queues.
	txQ, err := makeQueue(txRegion, offs.Tx, conf.TxSize, true)
	if err != nil {
		return nil, fmt.Errorf("making TX queue: %w", err)
	}
	cqQ, err := makeUMemQueue(cqRegion, offs.Cr, conf.CqSize)
	if err != nil {
		return nil, fmt.Errorf("making CQ queue: %w", err)
	}
	rxQ, err := makeQueue(rxRegion, offs.Rx, conf.RxSize, false)
	if err != nil {
		return nil, fmt.Errorf("making RX queue: %w", err)
	}
	fqQ, err := makeUMemQueue(fqRegion, offs.Fr, conf.RxSize)
	if err != nil {
		return nil, fmt.Errorf("making FQ queue: %w", err)
	}

	{ // Populate FQ with initial UMEM frames.
		ringSize := fqQ.size
		prod := atomic.LoadUint32(fqQ.prod)

		// Use the first ringSize frames from UMEM for RX.
		for i := range ringSize {
			idx := (prod + i) & fqQ.mask
			fqQ.addrs[idx] = uint64(i) * uint64(conf.FrameSize)
		}

		atomic.StoreUint32(fqQ.prod, prod+ringSize)
		// cached indices are not used for FQ anymore
		fqQ.cachedProd = atomic.LoadUint32(fqQ.prod)
		fqQ.cachedCons = atomic.LoadUint32(fqQ.cons)
	}

	// Bind AF_XDP socket to iface:queue.
	sa := &sockaddr_xdp{
		Family:  unix.AF_XDP,
		Ifindex: uint32(iface.Index),
		QueueID: conf.QueueID,
	}

	zerocopy := i.preferZerocopy
	if zerocopy {
		sa.Flags = unix.XDP_ZEROCOPY | unix.XDP_USE_NEED_WAKEUP
	} else {
		sa.Flags = unix.XDP_COPY | unix.XDP_USE_NEED_WAKEUP
	}

	err = rawBind(fd, sa)
	if err != nil && zerocopy {
		// If zerocopy is not supported for this queue, fall back to copy mode.
		// veth and many virtual interfaces don't support zero-copy.
		sa.Flags = unix.XDP_COPY | unix.XDP_USE_NEED_WAKEUP
		zerocopy = false
		err = rawBind(fd, sa)
	}
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("binding socket: %w", err)
	}

	if err := registerXSK(i.objs, fd, conf.QueueID); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("registering XSK: %w", err)
	}

	// Local free-frame pool.
	freeFrames := make([]uint64, conf.NumFrames)
	for i := range conf.NumFrames {
		freeFrames[i] = uint64(i) * uint64(conf.FrameSize)
	}

	s := &Socket{
		conf:       conf,
		isZerocopy: zerocopy,
		fd:         fd,
		umem:       umem,
		tx:         txQ,
		cq:         cqQ,
		rx:         rxQ,
		fq:         fqQ,
		txRegion:   txRegion,
		rxRegion:   rxRegion,
		cqRegion:   cqRegion,
		fqRegion:   fqRegion,
		freeFrames: freeFrames,
		freeCount:  conf.NumFrames,
		compBuf:    make([]uint64, conf.BatchSize),
		iface:      i,
	}

	return s, nil
}

// IsZerocopy reports whether the socket is operating in zero-copy mode.
// May return false even if PreferZerocopy was true because the corresponding queue
// may not support XDP_ZEROCOPY mode and the socket fall back to XDP_COPY automatically.
func (s *Socket) IsZerocopy() bool { return s.isZerocopy }

// Close releases the socket, UMEM and kernel resources.
// The kernel automatically unmaps mmap'd regions when the FD is closed,
// so we only need to close the FD.
func (s *Socket) Close() error {
	if s.fd != 0 {
		err := unix.Close(s.fd)
		s.fd = 0
		if err != nil {
			return fmt.Errorf("closing fd: %w", err)
		}
	}
	return nil
}

// Wait blocks until the AF_XDP socket becomes readable or the timeout expires.
// Returns nil when the socket becomes readable OR when the timeout expires.
// Returns a non-nil error only for real system call failures.
func (s *Socket) Wait(timeoutMS int) error {
	for {
		_, err := unix.Poll([]unix.PollFd{{
			Fd:     int32(s.fd),
			Events: unix.POLLIN,
		}}, timeoutMS)

		if err == nil {
			return nil
		}

		// EINTR is not treated as an error and will never be surfaced to the caller.
		// This ensures stable behavior in environments where signals are delivered
		// (profilers, debuggers, timers, SIGCHLD, etc.).
		if err == unix.EINTR {
			continue // Retry on signal interruption.
		}

		return err
	}
}

// Receive retrieves up to len(buffer) frames from the RX ring.
// Returned frames reference UMEM and must be returned via Release.
func (s *Socket) Receive(buffer []Frame) []Frame {
	avail := rxAvailable(s.rx)
	if avail == 0 {
		return nil
	}

	if max := uint32(len(buffer)); avail > max {
		avail = max
	}
	n := int(avail)
	buffer = buffer[:n]

	for i := range avail {
		idx := s.rx.cachedCons & s.rx.mask
		d := s.rx.descs[idx]

		start := int(d.Addr)
		end := start + int(d.Len)

		buffer[i].Buf = s.umem[start:end]
		buffer[i].Addr = d.Addr

		s.rx.cachedCons++
	}

	atomic.StoreUint32(s.rx.cons, s.rx.cachedCons)
	return buffer
}

// Release returns a received frame to the fill queue for reuse.
func (s *Socket) Release(frame Frame) error {
	// Single producer: for every packet we receive, we return one buffer.
	// This keeps FQ occupancy bounded without fancy accounting.
	prod := atomic.LoadUint32(s.fq.prod)
	idx := prod & s.fq.mask

	s.fq.addrs[idx] = frame.Addr
	atomic.StoreUint32(s.fq.prod, prod+1)

	return nil
}

// ReleaseBatch returns a batch of received frames to the fill queue for reuse.
func (s *Socket) ReleaseBatch(frames []Frame) {
	prod := atomic.LoadUint32(s.fq.prod)
	for _, fr := range frames {
		idx := prod & s.fq.mask
		s.fq.addrs[idx] = fr.Addr
		prod++
	}
	atomic.StoreUint32(s.fq.prod, prod)
}

// Frame represents a borrowed UMEM frame from an AF_XDP socket.
type Frame struct {
	// Buf points directly into the UMEM region and can be written to
	// without additional copying.
	Buf []byte

	// Addr is the UMEM address that must be passed
	// back to Submit() after the frame has been filled.
	Addr uint64
}

// NextFrame returns a writable UMEM buffer and its address.
// A zero-value frame indicates that no frame is currently available and the
// caller should retry after PollCompletions().
func (s *Socket) NextFrame() Frame {
	if s.freeCount == 0 {
		// Try to reclaim some completions.
		s.PollCompletions(uint32(len(s.compBuf)))
		if s.freeCount == 0 {
			return Frame{}
		}
	}

	s.freeCount--
	addr := s.freeFrames[s.freeCount]

	frameSize := s.conf.FrameSize
	if frameSize == 0 {
		frameSize = DefaultFrameSize
	}

	start := int(addr)
	end := start + int(frameSize)

	return Frame{
		Buf:  s.umem[start:end],
		Addr: addr,
	}
}

// Submit publishes the frame to the TX ring.
func (s *Socket) Submit(addr uint64, length uint32) error {
	var idx uint32

	// Reserve one descriptor; spin until we get space.
	for {
		if reserveTx(s.tx, 1, &idx) > 0 {
			break
		}
		// Ring full: try to reclaim and wake up the NIC.
		if s.PollCompletions(s.conf.BatchSize) == 0 {
			if err := wakeupTxQueue(s.fd); err != nil {
				return err
			}
		}
	}

	d := &s.tx.descs[idx&s.tx.mask]
	d.Addr = addr
	d.Len = length
	d.Opts = 0
	return nil
}

// SubmitBatch publishes a batch of frames to the TX ring.
func (s *Socket) SubmitBatch(addrs []uint64, lens []uint32) (int, error) {
	n := len(addrs)
	if n == 0 {
		return 0, nil
	}

	var idx uint32
retry:
	if reserveTx(s.tx, uint32(n), &idx) == 0 {
		if s.PollCompletions(s.conf.BatchSize) == 0 {
			if err := wakeupTxQueue(s.fd); err != nil {
				return 0, err
			}
		}
		goto retry
	}

	base := idx & s.tx.mask
	for i := range n {
		d := &s.tx.descs[(base+uint32(i))&s.tx.mask]
		d.Addr = addrs[i]
		d.Len = lens[i]
		d.Opts = 0
	}

	return n, nil
}

// FlushTx notifies the kernel/NIC that TX descriptors are available.
// Required when XDP_USE_NEED_WAKEUP is enabled.
func (s *Socket) FlushTx() error {
	// Commit all pending descriptors and ring the doorbell.
	commitTxDescriptors(s.tx.prod, s.tx.cachedProd)
	return wakeupTxQueue(s.fd)
}

// PollCompletions reclaims completed frames from the kernel.
// maxFrames specifies the maximum number of completed frames the caller wishes
// to reclaim in this call. The actual number processed may be lower if
// fewer completions are available. The value is also capped internally
// by the size of the completion buffer.
func (s *Socket) PollCompletions(maxFrames uint32) uint32 {
	if maxFrames == 0 {
		return 0
	}
	maxFrames = min(maxFrames, uint32(len(s.compBuf)))

	n := umemCompleteFromKernel(s.cq, s.compBuf, maxFrames)
	for i := range n {
		s.freeFrames[s.freeCount] = s.compBuf[i]
		s.freeCount++
	}
	return n
}
