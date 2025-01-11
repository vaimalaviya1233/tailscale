// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/mem"
	"tailscale.com/disco"
	tsmetrics "tailscale.com/metrics"
	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
	"tailscale.com/net/tsaddr"
	"tailscale.com/syncs"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/wgcfg"
)

const maxBufferSize = device.MaxMessageSize

// PacketStartOffset is the minimal amount of leading space that must exist
// before &packet[offset] in a packet passed to Read, Write, or InjectInboundDirect.
// This is necessary to avoid reallocation in wireguard-go internals.
const PacketStartOffset = device.MessageTransportHeaderSize

// MaxPacketSize is the maximum size (in bytes)
// of a packet that can be injected into a tstun.Wrapper.
const MaxPacketSize = device.MaxContentSize

const tapDebug = false // for super verbose TAP debugging

var (
	// ErrClosed is returned when attempting an operation on a closed Wrapper.
	ErrClosed = errors.New("device closed")
	// ErrFiltered is returned when the acted-on packet is rejected by a filter.
	ErrFiltered = errors.New("packet dropped by filter")
)

var (
	errPacketTooBig   = errors.New("packet too big")
	errOffsetTooBig   = errors.New("offset larger than buffer length")
	errOffsetTooSmall = errors.New("offset smaller than PacketStartOffset")
)

// parsedPacketPool holds a pool of Parsed structs for use in filtering.
// This is needed because escape analysis cannot see that parsed packets
// do not escape through {Pre,Post}Filter{In,Out}.
var parsedPacketPool = sync.Pool{New: func() any { return new(packet.Parsed) }}

// FilterFunc is a packet-filtering function with access to the Wrapper device.
// It must not hold onto the packet struct, as its backing storage will be reused.
type FilterFunc func(*packet.Parsed, *Wrapper) filter.Response

// Wrapper augments a tun.Device with packet filtering and injection.
//
// A Wrapper starts in a "corked" mode where Read calls are blocked
// until the Wrapper's Start method is called.
type Wrapper struct {
	logf        logger.Logf
	limitedLogf logger.Logf // aggressively rate-limited logf used for potentially high volume errors
	// tdev is the underlying Wrapper device.
	tdev  tun.Device
	isTAP bool // whether tdev is a TAP device

	started atomic.Bool   // whether Start has been called
	startCh chan struct{} // closed in Start

	closeOnce sync.Once

	// lastActivityAtomic is read/written atomically.
	// On 32 bit systems, if the fields above change,
	// you might need to add an align64 field here.
	lastActivityAtomic mono.Time // time of last send or receive

	destIPActivity syncs.AtomicValue[map[netip.Addr]func()]
	discoKey       syncs.AtomicValue[key.DiscoPublic]

	// timeNow, if non-nil, will be used to obtain the current time.
	timeNow func() time.Time

	// peerConfig stores the current NAT configuration.
	peerConfig atomic.Pointer[peerConfigTable]

	// vectorBuffer stores the oldest unconsumed packet vector from tdev. It is
	// allocated in wrap() and the underlying arrays should never grow.
	vectorBuffer [][]byte
	// bufferConsumedMu protects bufferConsumed from concurrent sends, closes,
	// and send-after-close (by way of bufferConsumedClosed).
	bufferConsumedMu sync.Mutex
	// bufferConsumedClosed is true when bufferConsumed has been closed. This is
	// read by bufferConsumed writers to prevent send-after-close.
	bufferConsumedClosed bool
	// bufferConsumed synchronizes access to vectorBuffer (shared by Read() and
	// pollVector()).
	//
	// Close closes bufferConsumed and sets bufferConsumedClosed to true.
	bufferConsumed chan struct{}

	// closed signals poll (by closing) when the device is closed.
	closed chan struct{}
	// outboundMu protects outbound and vectorOutbound from concurrent sends,
	// closes, and send-after-close (by way of outboundClosed).
	outboundMu sync.Mutex
	// outboundClosed is true when outbound or vectorOutbound have been closed.
	// This is read by outbound and vectorOutbound writers to prevent
	// send-after-close.
	outboundClosed bool
	// vectorOutbound is the queue by which packets leave the TUN device.
	//
	// The directions are relative to the network, not the device:
	// inbound packets arrive via UDP and are written into the TUN device;
	// outbound packets are read from the TUN device and sent out via UDP.
	// This queue is needed because although inbound writes are synchronous,
	// the other direction must wait on a WireGuard goroutine to poll it.
	//
	// Empty reads are skipped by WireGuard, so it is always legal
	// to discard an empty packet instead of sending it through vectorOutbound.
	//
	// Close closes vectorOutbound and sets outboundClosed to true.
	vectorOutbound chan tunVectorReadResult

	// eventsUpDown yields up and down tun.Events that arrive on a Wrapper's events channel.
	eventsUpDown chan tun.Event
	// eventsOther yields non-up-and-down tun.Events that arrive on a Wrapper's events channel.
	eventsOther chan tun.Event

	// filter atomically stores the currently active packet filter
	filter atomic.Pointer[filter.Filter]
	// filterFlags control the verbosity of logging packet drops/accepts.
	filterFlags filter.RunFlags
	// jailedFilter is the packet filter for jailed nodes.
	// Can be nil, which means drop all packets.
	jailedFilter atomic.Pointer[filter.Filter]

	// PreFilterPacketInboundFromWireGuard is the inbound filter function that runs before the main filter
	// and therefore sees the packets that may be later dropped by it.
	PreFilterPacketInboundFromWireGuard FilterFunc

	// PreFilterPacketOutboundToWireGuardEngineIntercept is a filter function that runs before the main filter
	// for packets from the local system. This filter is populated by wgengine to hook
	// packets which it handles internally. If both this and PreFilterFromTunToNetstack
	// filter functions are non-nil, this filter runs second.
	PreFilterPacketOutboundToWireGuardEngineIntercept FilterFunc
	// PostFilterPacketOutboundToWireGuard is the outbound filter function that runs after the main filter.
	PostFilterPacketOutboundToWireGuard FilterFunc

	// OnTSMPPongReceived, if non-nil, is called whenever a TSMP pong arrives.
	OnTSMPPongReceived func(packet.TSMPPongReply)

	// OnICMPEchoResponseReceived, if non-nil, is called whenever a ICMP echo response
	// arrives. If the packet is to be handled internally this returns true,
	// false otherwise.
	OnICMPEchoResponseReceived func(*packet.Parsed) bool

	// PeerAPIPort, if non-nil, returns the peerapi port that's
	// running for the given IP address.
	PeerAPIPort func(netip.Addr) (port uint16, ok bool)

	// disableFilter disables all filtering when set. This should only be used in tests.
	disableFilter bool

	// disableTSMPRejected disables TSMP rejected responses. For tests.
	disableTSMPRejected bool

	metrics *metrics
}

type metrics struct {
	inboundDroppedPacketsTotal  *tsmetrics.MultiLabelMap[usermetric.DropLabels]
	outboundDroppedPacketsTotal *tsmetrics.MultiLabelMap[usermetric.DropLabels]
}

func registerMetrics(reg *usermetric.Registry) *metrics {
	return &metrics{
		inboundDroppedPacketsTotal:  reg.DroppedPacketsInbound(),
		outboundDroppedPacketsTotal: reg.DroppedPacketsOutbound(),
	}
}

// tunInjectedRead is an injected packet pretending to be a tun.Read().
type tunInjectedRead struct {
	data []byte
}

// tunVectorReadResult is the result of a tun.Read(), or an injected packet
// pretending to be a tun.Read().
type tunVectorReadResult struct {
	// When err AND data are nil, injected will be set with meaningful data
	// (injected packet). If either err OR data is non-nil, injected should be
	// ignored (a "real" tun.Read).
	err      error
	data     [][]byte
	injected tunInjectedRead

	dataOffset int
}

// Start unblocks any Wrapper.Read calls that have already started
// and makes the Wrapper functional.
//
// Start must be called exactly once after the various Tailscale
// subsystems have been wired up to each other.
func (w *Wrapper) Start() {
	w.started.Store(true)
	close(w.startCh)
}

func WrapTAP(logf logger.Logf, tdev tun.Device, m *usermetric.Registry) *Wrapper {
	return wrap(logf, tdev, true, m)
}

func Wrap(logf logger.Logf, tdev tun.Device, m *usermetric.Registry) *Wrapper {
	return wrap(logf, tdev, false, m)
}

func wrap(logf logger.Logf, tdev tun.Device, isTAP bool, m *usermetric.Registry) *Wrapper {
	logf = logger.WithPrefix(logf, "tstun: ")
	w := &Wrapper{
		disableFilter: true, // lanscaping
		logf:          logf,
		limitedLogf:   logger.RateLimitedFn(logf, 1*time.Minute, 2, 10),
		isTAP:         isTAP,
		tdev:          tdev,
		// bufferConsumed is conceptually a condition variable:
		// a goroutine should not block when setting it, even with no listeners.
		bufferConsumed: make(chan struct{}, 1),
		closed:         make(chan struct{}),
		// vectorOutbound can be unbuffered; the buffer is an optimization.
		vectorOutbound: make(chan tunVectorReadResult, 1),
		eventsUpDown:   make(chan tun.Event),
		eventsOther:    make(chan tun.Event),
		// TODO(dmytro): (highly rate-limited) hexdumps should happen on unknown packets.
		filterFlags: filter.LogAccepts | filter.LogDrops,
		startCh:     make(chan struct{}),
		metrics:     registerMetrics(m),
	}

	w.vectorBuffer = make([][]byte, tdev.BatchSize())
	for i := range w.vectorBuffer {
		w.vectorBuffer[i] = make([]byte, maxBufferSize)
	}
	go w.pollVector()

	go w.pumpEvents()
	// The buffer starts out consumed.
	w.bufferConsumed <- struct{}{}
	w.noteActivity()

	return w
}

// now returns the current time, either by calling t.timeNow if set or time.Now
// if not.
func (t *Wrapper) now() time.Time {
	if t.timeNow != nil {
		return t.timeNow()
	}
	return time.Now()
}

// SetDestIPActivityFuncs sets a map of funcs to run per packet
// destination (the map keys).
//
// The map ownership passes to the Wrapper. It must be non-nil.
func (t *Wrapper) SetDestIPActivityFuncs(m map[netip.Addr]func()) {
	t.destIPActivity.Store(m)
}

// SetDiscoKey sets the current discovery key.
//
// It is only used for filtering out bogus traffic when network
// stack(s) get confused; see Issue 1526.
func (t *Wrapper) SetDiscoKey(k key.DiscoPublic) {
	t.discoKey.Store(k)
}

// isSelfDisco reports whether packet p
// looks like a Disco packet from ourselves.
// See Issue 1526.
func (t *Wrapper) isSelfDisco(p *packet.Parsed) bool {
	if p.IPProto != ipproto.UDP {
		return false
	}
	pkt := p.Payload()
	discobs, ok := disco.Source(pkt)
	if !ok {
		return false
	}
	discoSrc := key.DiscoPublicFromRaw32(mem.B(discobs))
	selfDiscoPub := t.discoKey.Load()
	return selfDiscoPub == discoSrc
}

func (t *Wrapper) Close() error {
	var err error
	t.closeOnce.Do(func() {
		if t.started.CompareAndSwap(false, true) {
			close(t.startCh)
		}
		close(t.closed)
		t.bufferConsumedMu.Lock()
		t.bufferConsumedClosed = true
		close(t.bufferConsumed)
		t.bufferConsumedMu.Unlock()
		t.outboundMu.Lock()
		t.outboundClosed = true
		close(t.vectorOutbound)
		t.outboundMu.Unlock()
		err = t.tdev.Close()
	})
	return err
}

// isClosed reports whether t is closed.
func (t *Wrapper) isClosed() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}

// pumpEvents copies events from t.tdev to t.eventsUpDown and t.eventsOther.
// pumpEvents exits when t.tdev.events or t.closed is closed.
// pumpEvents closes t.eventsUpDown and t.eventsOther when it exits.
func (t *Wrapper) pumpEvents() {
	defer close(t.eventsUpDown)
	defer close(t.eventsOther)
	src := t.tdev.Events()
	for {
		// Retrieve an event from the TUN device.
		var event tun.Event
		var ok bool
		select {
		case <-t.closed:
			return
		case event, ok = <-src:
			if !ok {
				return
			}
		}

		// Pass along event to the correct recipient.
		// Though event is a bitmask, in practice there is only ever one bit set at a time.
		dst := t.eventsOther
		if event&(tun.EventUp|tun.EventDown) != 0 {
			dst = t.eventsUpDown
		}
		select {
		case <-t.closed:
			return
		case dst <- event:
		}
	}
}

// EventsUpDown returns a TUN event channel that contains all Up and Down events.
func (t *Wrapper) EventsUpDown() chan tun.Event {
	return t.eventsUpDown
}

// Events returns a TUN event channel that contains all non-Up, non-Down events.
// It is named Events because it is the set of events that we want to expose to wireguard-go,
// and Events is the name specified by the wireguard-go tun.Device interface.
func (t *Wrapper) Events() <-chan tun.Event {
	return t.eventsOther
}

func (t *Wrapper) File() *os.File {
	return t.tdev.File()
}

func (t *Wrapper) MTU() (int, error) {
	return t.tdev.MTU()
}

func (t *Wrapper) Name() (string, error) {
	return t.tdev.Name()
}

const ethernetFrameSize = 14 // 2 six byte MACs, 2 bytes ethertype

// pollVector polls t.tdev.Read(), placing the oldest unconsumed packet vector
// into t.vectorBuffer. This is needed because t.tdev.Read() in general may
// block (it does on Windows), so packets may be stuck in t.vectorOutbound if
// t.Read() called t.tdev.Read() directly.
func (t *Wrapper) pollVector() {
	sizes := make([]int, len(t.vectorBuffer))
	readOffset := PacketStartOffset
	reader := t.tdev.Read
	if t.isTAP {
		type tapReader interface {
			ReadEthernet(buffs [][]byte, sizes []int, offset int) (int, error)
		}
		if r, ok := t.tdev.(tapReader); ok {
			readOffset = PacketStartOffset - ethernetFrameSize
			reader = r.ReadEthernet
		}
	}

	for range t.bufferConsumed {
		for i := range t.vectorBuffer {
			t.vectorBuffer[i] = t.vectorBuffer[i][:cap(t.vectorBuffer[i])]
		}
		var n int
		var err error
		for n == 0 && err == nil {
			if t.isClosed() {
				return
			}
			n, err = reader(t.vectorBuffer[:], sizes, readOffset)
			if t.isTAP && tapDebug {
				s := fmt.Sprintf("% x", t.vectorBuffer[0][:])
				for strings.HasSuffix(s, " 00") {
					s = strings.TrimSuffix(s, " 00")
				}
				t.logf("TAP read %v, %v: %s", n, err, s)
			}
		}
		for i := range sizes[:n] {
			t.vectorBuffer[i] = t.vectorBuffer[i][:readOffset+sizes[i]]
		}
		t.sendVectorOutbound(tunVectorReadResult{
			data:       t.vectorBuffer[:n],
			dataOffset: PacketStartOffset,
			err:        err,
		})
	}
}

// sendBufferConsumed does t.bufferConsumed <- struct{}{}.
func (t *Wrapper) sendBufferConsumed() {
	t.bufferConsumedMu.Lock()
	defer t.bufferConsumedMu.Unlock()
	if t.bufferConsumedClosed {
		return
	}
	t.bufferConsumed <- struct{}{}
}

// injectOutbound does t.vectorOutbound <- r
func (t *Wrapper) injectOutbound(r tunInjectedRead) {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	if t.outboundClosed {
		return
	}
	t.vectorOutbound <- tunVectorReadResult{
		injected: r,
	}
}

// sendVectorOutbound does t.vectorOutbound <- r.
func (t *Wrapper) sendVectorOutbound(r tunVectorReadResult) {
	t.outboundMu.Lock()
	defer t.outboundMu.Unlock()
	if t.outboundClosed {
		return
	}
	t.vectorOutbound <- r
}

// snat does SNAT on p if the destination address requires a different source address.
func (pc *peerConfigTable) snat(p *packet.Parsed) {
	oldSrc := p.Src.Addr()
	newSrc := pc.selectSrcIP(oldSrc, p.Dst.Addr())
	if oldSrc != newSrc {
		checksum.UpdateSrcAddr(p, newSrc)
	}
}

// dnat does destination NAT on p.
func (pc *peerConfigTable) dnat(p *packet.Parsed) {
	oldDst := p.Dst.Addr()
	newDst := pc.mapDstIP(p.Src.Addr(), oldDst)
	if newDst != oldDst {
		checksum.UpdateDstAddr(p, newDst)
	}
}

// findV4 returns the first Tailscale IPv4 address in addrs.
func findV4(addrs []netip.Prefix) netip.Addr {
	for _, ap := range addrs {
		a := ap.Addr()
		if a.Is4() && tsaddr.IsTailscaleIP(a) {
			return a
		}
	}
	return netip.Addr{}
}

// findV6 returns the first Tailscale IPv6 address in addrs.
func findV6(addrs []netip.Prefix) netip.Addr {
	for _, ap := range addrs {
		a := ap.Addr()
		if a.Is6() && tsaddr.IsTailscaleIP(a) {
			return a
		}
	}
	return netip.Addr{}
}

// peerConfigTable contains configuration for individual peers and related
// information necessary to perform peer-specific operations.  It should be
// treated as immutable.
//
// The nil value is a valid configuration.
type peerConfigTable struct {
	// nativeAddr4 and nativeAddr6 are the IPv4/IPv6 Tailscale Addresses of
	// the current node.
	//
	// These are implicitly used as the address to rewrite to in the DNAT
	// path (as configured by listenAddrs, below). The IPv4 address will be
	// used if the inbound packet is IPv4, and the IPv6 address if the
	// inbound packet is IPv6.
	nativeAddr4, nativeAddr6 netip.Addr

	// byIP contains configuration for each peer, indexed by a peer's IP
	// address(es).
	byIP bart.Table[*peerConfig]

	// masqAddrCounts is a count of peers by MasqueradeAsIP.
	// TODO? for logging
	masqAddrCounts map[netip.Addr]int
}

// peerConfig is the configuration for a single peer.
type peerConfig struct {
	// dstMasqAddr{4,6} are the addresses that should be used as the
	// source address when masquerading packets to this peer (i.e.
	// SNAT). If an address is not valid, the packet should not be
	// masqueraded for that address family.
	dstMasqAddr4 netip.Addr
	dstMasqAddr6 netip.Addr

	// jailed is whether this peer is "jailed" (i.e. is restricted from being
	// able to initiate connections to this node). This is the case for shared
	// nodes.
	jailed bool
}

func (c *peerConfigTable) String() string {
	if c == nil {
		return "peerConfigTable(nil)"
	}
	var b strings.Builder
	b.WriteString("peerConfigTable{")
	fmt.Fprintf(&b, "nativeAddr4: %v, ", c.nativeAddr4)
	fmt.Fprintf(&b, "nativeAddr6: %v, ", c.nativeAddr6)

	// TODO: figure out how to iterate/debug/print c.byIP

	b.WriteString("}")

	return b.String()
}

func (c *peerConfig) String() string {
	if c == nil {
		return "peerConfig(nil)"
	}
	var b strings.Builder
	b.WriteString("peerConfig{")
	fmt.Fprintf(&b, "dstMasqAddr4: %v, ", c.dstMasqAddr4)
	fmt.Fprintf(&b, "dstMasqAddr6: %v, ", c.dstMasqAddr6)
	fmt.Fprintf(&b, "jailed: %v}", c.jailed)

	return b.String()
}

// mapDstIP returns the destination IP to use for a packet to dst.
// If dst is not one of the listen addresses, it is returned as-is,
// otherwise the native address is returned.
func (pc *peerConfigTable) mapDstIP(src, oldDst netip.Addr) netip.Addr {
	if pc == nil {
		return oldDst
	}

	// The packet we're processing is inbound from WireGuard, received from
	// a peer. The 'src' of the packet is the remote peer's IP address,
	// possibly the masqueraded address (if the peer is shared/etc.).
	//
	// The 'dst' of the packet is the address for this local node. It could
	// be a masquerade address that we told other nodes to use, or one of
	// our local node's Addresses.
	c, ok := pc.byIP.Lookup(src)
	if !ok {
		return oldDst
	}

	if oldDst.Is4() && pc.nativeAddr4.IsValid() && c.dstMasqAddr4 == oldDst {
		return pc.nativeAddr4
	}
	if oldDst.Is6() && pc.nativeAddr6.IsValid() && c.dstMasqAddr6 == oldDst {
		return pc.nativeAddr6
	}
	return oldDst
}

// selectSrcIP returns the source IP to use for a packet to dst.
// If the packet is not from the native address, it is returned as-is.
func (pc *peerConfigTable) selectSrcIP(oldSrc, dst netip.Addr) netip.Addr {
	if pc == nil {
		return oldSrc
	}

	// If this packet doesn't originate from this Tailscale node, don't
	// SNAT it (e.g. if we're a subnet router).
	if oldSrc.Is4() && oldSrc != pc.nativeAddr4 {
		return oldSrc
	}
	if oldSrc.Is6() && oldSrc != pc.nativeAddr6 {
		return oldSrc
	}

	// Look up the configuration for the destination
	c, ok := pc.byIP.Lookup(dst)
	if !ok {
		return oldSrc
	}

	// Perform SNAT based on the address family and whether we have a valid
	// addr.
	if oldSrc.Is4() && c.dstMasqAddr4.IsValid() {
		return c.dstMasqAddr4
	}
	if oldSrc.Is6() && c.dstMasqAddr6.IsValid() {
		return c.dstMasqAddr6
	}

	// No SNAT; use old src
	return oldSrc
}

// peerConfigTableFromWGConfig generates a peerConfigTable from nm. If NAT is
// not required, and no additional configuration is present, it returns nil.
func peerConfigTableFromWGConfig(wcfg *wgcfg.Config) *peerConfigTable {
	if wcfg == nil {
		return nil
	}

	nativeAddr4 := findV4(wcfg.Addresses)
	nativeAddr6 := findV6(wcfg.Addresses)
	if !nativeAddr4.IsValid() && !nativeAddr6.IsValid() {
		return nil
	}

	ret := &peerConfigTable{
		nativeAddr4:    nativeAddr4,
		nativeAddr6:    nativeAddr6,
		masqAddrCounts: make(map[netip.Addr]int),
	}

	// When using an exit node that requires masquerading, we need to
	// fill out the routing table with all peers not just the ones that
	// require masquerading.
	exitNodeRequiresMasq := false // true if using an exit node and it requires masquerading
	for _, p := range wcfg.Peers {
		isExitNode := slices.Contains(p.AllowedIPs, tsaddr.AllIPv4()) || slices.Contains(p.AllowedIPs, tsaddr.AllIPv6())
		if isExitNode {
			hasMasqAddr := false ||
				(p.V4MasqAddr != nil && p.V4MasqAddr.IsValid()) ||
				(p.V6MasqAddr != nil && p.V6MasqAddr.IsValid())
			if hasMasqAddr {
				exitNodeRequiresMasq = true
			}
			break
		}
	}

	byIPSize := 0
	for i := range wcfg.Peers {
		p := &wcfg.Peers[i]

		// Build a routing table that configures DNAT (i.e. changing
		// the V4MasqAddr/V6MasqAddr for a given peer to the current
		// peer's v4/v6 IP).
		var addrToUse4, addrToUse6 netip.Addr
		if p.V4MasqAddr != nil && p.V4MasqAddr.IsValid() {
			addrToUse4 = *p.V4MasqAddr
			ret.masqAddrCounts[addrToUse4]++
		}
		if p.V6MasqAddr != nil && p.V6MasqAddr.IsValid() {
			addrToUse6 = *p.V6MasqAddr
			ret.masqAddrCounts[addrToUse6]++
		}

		// If the exit node requires masquerading, set the masquerade
		// addresses to our native addresses.
		if exitNodeRequiresMasq {
			if !addrToUse4.IsValid() && nativeAddr4.IsValid() {
				addrToUse4 = nativeAddr4
			}
			if !addrToUse6.IsValid() && nativeAddr6.IsValid() {
				addrToUse6 = nativeAddr6
			}
		}

		if !addrToUse4.IsValid() && !addrToUse6.IsValid() && !p.IsJailed {
			// NAT not required for this peer.
			continue
		}

		// Use the same peer configuration for each address of the peer.
		pc := &peerConfig{
			dstMasqAddr4: addrToUse4,
			dstMasqAddr6: addrToUse6,
			jailed:       p.IsJailed,
		}

		// Insert an entry into our routing table for each allowed IP.
		for _, ip := range p.AllowedIPs {
			ret.byIP.Insert(ip, pc)
			byIPSize++
		}
	}
	if byIPSize == 0 && len(ret.masqAddrCounts) == 0 {
		return nil
	}
	return ret
}

func (pc *peerConfigTable) inboundPacketIsJailed(p *packet.Parsed) bool {
	if pc == nil {
		return false
	}
	c, ok := pc.byIP.Lookup(p.Src.Addr())
	if !ok {
		return false
	}
	return c.jailed
}

func (pc *peerConfigTable) outboundPacketIsJailed(p *packet.Parsed) bool {
	if pc == nil {
		return false
	}
	c, ok := pc.byIP.Lookup(p.Dst.Addr())
	if !ok {
		return false
	}
	return c.jailed
}

type setIPer interface {
	// SetIP sets the IP addresses of the TAP device.
	SetIP(ipV4, ipV6 netip.Addr) error
}

// SetWGConfig is called when a new NetworkMap is received.
func (t *Wrapper) SetWGConfig(wcfg *wgcfg.Config) {
	if t.isTAP {
		if sip, ok := t.tdev.(setIPer); ok {
			sip.SetIP(findV4(wcfg.Addresses), findV6(wcfg.Addresses))
		}
	}
	cfg := peerConfigTableFromWGConfig(wcfg)
	old := t.peerConfig.Swap(cfg)
	if !reflect.DeepEqual(old, cfg) {
		t.logf("peer config: %v", cfg)
	}
}

var (
	magicDNSIPPort   = netip.AddrPortFrom(tsaddr.TailscaleServiceIP(), 0) // 100.100.100.100:0
	magicDNSIPPortv6 = netip.AddrPortFrom(tsaddr.TailscaleServiceIPv6(), 0)
)

// noteActivity records that there was a read or write at the current time.
func (t *Wrapper) noteActivity() {
	t.lastActivityAtomic.StoreAtomic(mono.Now())
}

// IdleDuration reports how long it's been since the last read or write to this device.
//
// Its value should only be presumed accurate to roughly 10ms granularity.
// If there's never been activity, the duration is since the wrapper was created.
func (t *Wrapper) IdleDuration() time.Duration {
	return mono.Since(t.lastActivityAtomic.LoadAtomic())
}

func (t *Wrapper) Read(buffs [][]byte, sizes []int, offset int) (int, error) {
	if !t.started.Load() {
		<-t.startCh
	}
	// packet from OS read and sent to WG
	res, ok := <-t.vectorOutbound
	if !ok {
		return 0, io.EOF
	}
	if res.err != nil && len(res.data) == 0 {
		return 0, res.err
	}
	if res.data == nil {
		panic("unreachable; lanscaping")
	}

	metricPacketOut.Add(int64(len(res.data)))

	var buffsPos int
	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	pc := t.peerConfig.Load()
	for _, data := range res.data {
		p.Decode(data[res.dataOffset:])

		if m := t.destIPActivity.Load(); m != nil {
			if fn := m[p.Dst.Addr()]; fn != nil {
				fn()
			}
		}

		// Make sure to do SNAT after filtering, so that any flow tracking in
		// the filter sees the original source address. See #12133.
		pc.snat(p)
		n := copy(buffs[buffsPos][offset:], p.Buffer())
		if n != len(data)-res.dataOffset {
			panic(fmt.Sprintf("short copy: %d != %d", n, len(data)-res.dataOffset))
		}
		sizes[buffsPos] = n
		buffsPos++
	}

	// t.vectorBuffer has a fixed location in memory.
	// TODO(raggi): add an explicit field and possibly method to the tunVectorReadResult
	// to signal when sendBufferConsumed should be called.
	if &res.data[0] == &t.vectorBuffer[0] {
		// We are done with t.buffer. Let poll() re-use it.
		t.sendBufferConsumed()
	}

	t.noteActivity()
	return buffsPos, res.err
}

const (
	minTCPHeaderSize = 20
)

// Write accepts incoming packets. The packets begin at buffs[:][offset:],
// like wireguard-go/tun.Device.Write. Write is called per-peer via
// wireguard-go/device.Peer.RoutineSequentialReceiver, so it MUST be
// thread-safe.
func (t *Wrapper) Write(buffs [][]byte, offset int) (int, error) {
	metricPacketIn.Add(int64(len(buffs)))
	i := 0
	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)
	pc := t.peerConfig.Load()
	for _, buff := range buffs {
		p.Decode(buff[offset:])
		pc.dnat(p)
	}
	if t.disableFilter {
		i = len(buffs)
	}
	buffs = buffs[:i]

	if len(buffs) > 0 {
		t.noteActivity()
		_, err := t.tdevWrite(buffs, offset)
		if err != nil {
			t.metrics.inboundDroppedPacketsTotal.Add(usermetric.DropLabels{
				Reason: usermetric.ReasonError,
			}, int64(len(buffs)))
		}
		return len(buffs), err
	}
	return 0, nil
}

func (t *Wrapper) tdevWrite(buffs [][]byte, offset int) (int, error) {
	return t.tdev.Write(buffs, offset)
}

func (t *Wrapper) GetFilter() *filter.Filter {
	return t.filter.Load()
}

func (t *Wrapper) SetFilter(filt *filter.Filter) {
	t.filter.Store(filt)
}

func (t *Wrapper) GetJailedFilter() *filter.Filter {
	return t.jailedFilter.Load()
}

func (t *Wrapper) SetJailedFilter(filt *filter.Filter) {
	t.jailedFilter.Store(filt)
}

// InjectInboundDirect makes the Wrapper device behave as if a packet
// with the given contents was received from the network.
// It blocks and does not take ownership of the packet.
// The injected packet will not pass through inbound filters.
//
// The packet contents are to start at &buf[offset].
// offset must be greater or equal to PacketStartOffset.
// The space before &buf[offset] will be used by WireGuard.
func (t *Wrapper) InjectInboundDirect(buf []byte, offset int) error {
	if len(buf) > MaxPacketSize {
		return errPacketTooBig
	}
	if len(buf) < offset {
		return errOffsetTooBig
	}
	if offset < PacketStartOffset {
		return errOffsetTooSmall
	}

	// Write to the underlying device to skip filters.
	_, err := t.tdevWrite([][]byte{buf}, offset) // TODO(jwhited): alloc?
	return err
}

func (t *Wrapper) injectOutboundPong(pp *packet.Parsed, req packet.TSMPPingRequest) {
	pong := packet.TSMPPongReply{
		Data: req.Data,
	}
	if t.PeerAPIPort != nil {
		pong.PeerAPIPort, _ = t.PeerAPIPort(pp.Dst.Addr())
	}
	switch pp.IPVersion {
	case 4:
		h4 := pp.IP4Header()
		h4.ToResponse()
		pong.IPHeader = h4
	case 6:
		h6 := pp.IP6Header()
		h6.ToResponse()
		pong.IPHeader = h6
	default:
		return
	}

	t.InjectOutbound(packet.Generate(pong, nil))
}

// InjectOutbound makes the Wrapper device behave as if a packet
// with the given contents was sent to the network.
// It does not block, but takes ownership of the packet.
// The injected packet will not pass through outbound filters.
// Injecting an empty packet is a no-op.
func (t *Wrapper) InjectOutbound(pkt []byte) error {
	if len(pkt) > MaxPacketSize {
		return errPacketTooBig
	}
	if len(pkt) == 0 {
		return nil
	}
	t.injectOutbound(tunInjectedRead{data: pkt})
	return nil
}

func (t *Wrapper) BatchSize() int {
	if runtime.GOOS == "linux" {
		// Always setup Linux to handle vectors, even in the very rare case that
		// the underlying t.tdev returns 1. gVisor GSO is always enabled for
		// Linux, and we cannot make a determination on gVisor usage at
		// wireguard-go.Device startup, which is when this value matters for
		// packet memory init.
		return conn.IdealBatchSize
	}
	return t.tdev.BatchSize()
}

// Unwrap returns the underlying tun.Device.
func (t *Wrapper) Unwrap() tun.Device {
	return t.tdev
}

var (
	metricPacketIn              = clientmetric.NewCounter("tstun_in_from_wg")
	metricPacketInDrop          = clientmetric.NewCounter("tstun_in_from_wg_drop")
	metricPacketInDropFilter    = clientmetric.NewCounter("tstun_in_from_wg_drop_filter")
	metricPacketInDropSelfDisco = clientmetric.NewCounter("tstun_in_from_wg_drop_self_disco")

	metricPacketOut              = clientmetric.NewCounter("tstun_out_to_wg")
	metricPacketOutDrop          = clientmetric.NewCounter("tstun_out_to_wg_drop")
	metricPacketOutDropFilter    = clientmetric.NewCounter("tstun_out_to_wg_drop_filter")
	metricPacketOutDropSelfDisco = clientmetric.NewCounter("tstun_out_to_wg_drop_self_disco")
)
