package magicsock

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/yixinin/iroh-go/crypto"
	"github.com/yixinin/iroh-go/relay"
)

const (
	holepunchPacketType = 0x01
	holepunchMaxAge     = 30 * time.Second
)

type CustomPacketConn struct {
	mu sync.RWMutex

	endpointId *crypto.EndpointId

	ipv4Conn  *net.UDPConn
	ipv6Conn  *net.UDPConn
	relayConn *relay.Client

	paths        map[string]*Path
	selectedPath *Path

	holepuncher *Holepuncher

	readChan  chan []byte
	writeChan chan *Packet

	ctx    context.Context
	cancel context.CancelFunc
}

type Path struct {
	addr      net.Addr
	conn      net.PacketConn
	relayConn *relay.Client
	rtt       time.Duration
	active    bool
	lastSeen  time.Time
}

type Packet struct {
	data []byte
	addr net.Addr
	path *Path
}

type Candidate struct {
	addr     net.Addr
	source   string
	priority int
}

func NewCustomPacketConn(endpointId *crypto.EndpointId) *CustomPacketConn {
	ctx, cancel := context.WithCancel(context.Background())

	return &CustomPacketConn{
		endpointId: endpointId,
		paths:      make(map[string]*Path),
		readChan:   make(chan []byte, 1024),
		writeChan:  make(chan *Packet, 1024),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (c *CustomPacketConn) SetIPv4Conn(conn *net.UDPConn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.ipv4Conn = conn
	if conn != nil {
		path := &Path{
			addr:     conn.LocalAddr(),
			conn:     conn,
			active:   true,
			lastSeen: time.Now(),
		}
		c.paths[conn.LocalAddr().String()] = path
		if c.selectedPath == nil {
			c.selectedPath = path
		}
	}
}

func (c *CustomPacketConn) SetIPv6Conn(conn *net.UDPConn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.ipv6Conn = conn
	if conn != nil {
		path := &Path{
			addr:     conn.LocalAddr(),
			conn:     conn,
			active:   true,
			lastSeen: time.Now(),
		}
		c.paths[conn.LocalAddr().String()] = path
		if c.selectedPath == nil {
			c.selectedPath = path
		}
	}
}

func (c *CustomPacketConn) SetRelayConn(conn *relay.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.relayConn = conn
	if conn != nil {
		relayPacketConn := NewRelayPacketConn(conn)
		localAddr, _ := net.ResolveUDPAddr("udp", conn.LocalAddr())
		path := &Path{
			addr:      localAddr,
			conn:      relayPacketConn,
			relayConn: conn,
			active:    true,
			lastSeen:  time.Now(),
		}
		c.paths[localAddr.String()] = path
	}
}

func (c *CustomPacketConn) Start() {
	c.startPacketLoop()
	c.startHolepuncher()
}

func (c *CustomPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case data := <-c.readChan:
		n = copy(p, data)
		c.mu.RLock()
		if c.selectedPath != nil {
			addr = c.selectedPath.addr
		}
		c.mu.RUnlock()
		return n, addr, nil
	case <-c.ctx.Done():
		return 0, nil, c.ctx.Err()
	}
}

func (c *CustomPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	packet := &Packet{
		data: p,
		addr: addr,
	}

	path := c.selectPath(addr)
	if path == nil {
		return 0, fmt.Errorf("no available path")
	}

	packet.path = path

	select {
	case c.writeChan <- packet:
		return len(p), nil
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}
}

func (c *CustomPacketConn) Close() error {
	c.cancel()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ipv4Conn != nil {
		c.ipv4Conn.Close()
	}
	if c.ipv6Conn != nil {
		c.ipv6Conn.Close()
	}
	if c.relayConn != nil {
		c.relayConn.Close()
	}

	close(c.readChan)
	close(c.writeChan)

	return nil
}

func (c *CustomPacketConn) LocalAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.selectedPath != nil {
		return c.selectedPath.conn.LocalAddr()
	}
	return nil
}

func (c *CustomPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *CustomPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *CustomPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *CustomPacketConn) selectPath(addr net.Addr) *Path {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.selectedPath != nil && c.selectedPath.active {
		return c.selectedPath
	}

	var bestPath *Path
	var bestRTT time.Duration

	for _, path := range c.paths {
		if !path.active {
			continue
		}

		if bestPath == nil || path.rtt < bestRTT {
			bestPath = path
			bestRTT = path.rtt
		}
	}

	return bestPath
}

func (c *CustomPacketConn) updatePathRTT(path *Path, rtt time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	path.rtt = rtt
	path.lastSeen = time.Now()

	if c.selectedPath == nil || rtt < c.selectedPath.rtt {
		c.selectedPath = path
	}
}

func (c *CustomPacketConn) addPath(addr net.Addr, conn net.PacketConn) *Path {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := addr.String()
	if path, exists := c.paths[key]; exists {
		return path
	}

	path := &Path{
		addr:     addr,
		conn:     conn,
		active:   false,
		lastSeen: time.Now(),
	}

	c.paths[key] = path
	return path
}

func (c *CustomPacketConn) startPacketLoop() {
	go c.readFromIPv4()
	go c.readFromIPv6()
	go c.readFromRelay()
	go c.processPackets()
}

func (c *CustomPacketConn) readFromIPv4() {
	if c.ipv4Conn == nil {
		return
	}

	buf := make([]byte, 65535)
	for {
		n, addr, err := c.ipv4Conn.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				fmt.Printf("IPv4 read error: %v\n", err)
			}
			return
		}

		c.handlePacket(buf[:n], addr, c.ipv4Conn)
	}
}

func (c *CustomPacketConn) readFromIPv6() {
	if c.ipv6Conn == nil {
		return
	}

	buf := make([]byte, 65535)
	for {
		n, addr, err := c.ipv6Conn.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				fmt.Printf("IPv6 read error: %v\n", err)
			}
			return
		}

		c.handlePacket(buf[:n], addr, c.ipv6Conn)
	}
}

func (c *CustomPacketConn) readFromRelay() {
	for {
		c.mu.RLock()
		relayConn := c.relayConn
		var relayPacketConn net.PacketConn
		for _, path := range c.paths {
			if path.relayConn == relayConn {
				relayPacketConn = path.conn
				break
			}
		}
		c.mu.RUnlock()

		if relayConn == nil || relayPacketConn == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		buf := make([]byte, 65535)
		n, err := relayConn.Read(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				fmt.Printf("Relay read error: %v\n", err)
			}
			return
		}

		localAddr, _ := net.ResolveUDPAddr("udp", relayConn.LocalAddr())
		c.handlePacket(buf[:n], localAddr, relayPacketConn)
	}
}

func (c *CustomPacketConn) handlePacket(data []byte, addr net.Addr, conn net.PacketConn) {
	if c.holepuncher != nil && c.holepuncher.isHolepunchPacket(data) {
		c.holepuncher.handleHolepunchPacket(data, addr)
		return
	}

	path := c.addPath(addr, conn)
	path.active = true
	path.lastSeen = time.Now()

	select {
	case c.readChan <- data:
	default:
		fmt.Printf("Read channel full, dropping packet\n")
	}
}

func (c *CustomPacketConn) processPackets() {
	for {
		select {
		case packet := <-c.writeChan:
			_, err := packet.path.conn.WriteTo(packet.data, packet.addr)
			if err != nil {
				fmt.Printf("Write error: %v\n", err)
				packet.path.active = false
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *CustomPacketConn) startHolepuncher() {
	c.holepuncher = NewHolepuncher(c)
	c.holepuncher.Start()
}

type Holepuncher struct {
	conn        *CustomPacketConn
	candidates  []*Candidate
	attempts    int
	lastAttempt time.Time
}

func NewHolepuncher(conn *CustomPacketConn) *Holepuncher {
	return &Holepuncher{
		conn:       conn,
		candidates: make([]*Candidate, 0),
	}
}

func (h *Holepuncher) Start() {
	go h.run()
}

func (h *Holepuncher) run() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.attemptHolepunch()
		case <-h.conn.ctx.Done():
			return
		}
	}
}

func (h *Holepuncher) attemptHolepunch() {
	h.attempts++
	h.lastAttempt = time.Now()

	for _, candidate := range h.candidates {
		h.sendHolepunchPacket(candidate.addr)
	}
}

func (h *Holepuncher) sendHolepunchPacket(addr net.Addr) {
	packet := h.createHolepunchPacket()
	h.conn.WriteTo(packet, addr)
}

func (h *Holepuncher) createHolepunchPacket() []byte {
	buf := make([]byte, 41)
	buf[0] = holepunchPacketType
	copy(buf[1:33], h.conn.endpointId.Bytes())
	binary.BigEndian.PutUint64(buf[33:41], uint64(time.Now().UnixNano()))
	return buf
}

func (h *Holepuncher) isHolepunchPacket(data []byte) bool {
	if len(data) < 41 {
		return false
	}
	return data[0] == holepunchPacketType
}

func (h *Holepuncher) handleHolepunchPacket(data []byte, addr net.Addr) {
	if len(data) < 41 || data[0] != holepunchPacketType {
		return
	}

	var endpointId [32]byte
	copy(endpointId[:], data[1:33])
	timestamp := time.Unix(0, int64(binary.BigEndian.Uint64(data[33:41])))

	if time.Since(timestamp) > holepunchMaxAge {
		return
	}

	h.addCandidate(addr, "holepunch", 10)
}

func (h *Holepuncher) addCandidate(addr net.Addr, source string, priority int) {
	candidate := &Candidate{
		addr:     addr,
		source:   source,
		priority: priority,
	}

	h.candidates = append(h.candidates, candidate)
}
