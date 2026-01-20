package magicsock

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/yixinin/iroh-go/crypto"
)

type RemoteStateMessage interface {
	Handle(actor *RemoteStateActor)
}

type RemoteStateActor struct {
	endpointId       *crypto.EndpointId
	localEndpointId  *crypto.EndpointId
	localDirectAddrs *LocalDirectAddrs
	relayMappedAddrs *AddrMap
	discovery        Discovery

	connections   map[uint64]*ConnectionState
	connectionsMu sync.RWMutex

	relayConnection interface{}

	paths              *RemotePathState
	lastHolepunch      *HolepunchAttempt
	selectedPath       *Addr
	scheduledHolepunch time.Time
	scheduledOpenPath  time.Time
	pendingOpenPaths   []Addr

	discoveryStream DiscoveryStream

	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
}

type ConnectionState struct {
	conn      interface{}
	paths     map[PathId]Addr
	openPaths []Addr
	pathIds   map[string]PathId
	mu        sync.RWMutex
}

type PathId uint64

const PathIdZero PathId = 0

type HolepunchAttempt struct {
	time     time.Time
	addrs    []Addr
	attempts int
}

type DiscoveryStream interface {
	Next(ctx context.Context) (*DiscoveryItem, error)
}

type DiscoveryItem struct {
	Addrs []Addr
}

type Discovery interface {
	Resolve(ctx context.Context, id *crypto.EndpointId) (<-chan *DiscoveryItem, error)
}

type LocalDirectAddrs struct {
	addrs []net.Addr
	mu    sync.RWMutex
}

func NewLocalDirectAddrs() *LocalDirectAddrs {
	return &LocalDirectAddrs{
		addrs: make([]net.Addr, 0),
	}
}

func (lda *LocalDirectAddrs) Get() []net.Addr {
	lda.mu.RLock()
	defer lda.mu.RUnlock()
	return lda.addrs
}

func (lda *LocalDirectAddrs) Set(addrs []net.Addr) {
	lda.mu.Lock()
	defer lda.mu.Unlock()
	lda.addrs = addrs
}

func NewRemoteStateActor(
	endpointId *crypto.EndpointId,
	localEndpointId *crypto.EndpointId,
	localDirectAddrs *LocalDirectAddrs,
	relayMappedAddrs *AddrMap,
	discovery Discovery,
) *RemoteStateActor {
	ctx, cancel := context.WithCancel(context.Background())

	return &RemoteStateActor{
		endpointId:       endpointId,
		localEndpointId:  localEndpointId,
		localDirectAddrs: localDirectAddrs,
		relayMappedAddrs: relayMappedAddrs,
		discovery:        discovery,
		connections:      make(map[uint64]*ConnectionState),
		paths:            NewRemotePathState(),
		pendingOpenPaths: make([]Addr, 0),
		ctx:              ctx,
		cancel:           cancel,
	}
}

func (rsa *RemoteStateActor) Start() {
	go rsa.run()
}

func (rsa *RemoteStateActor) Stop() {
	rsa.cancel()
}

func (rsa *RemoteStateActor) run() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	idleTimer := time.NewTimer(60 * time.Second)
	defer idleTimer.Stop()

	for {
		select {
		case <-rsa.ctx.Done():
			return

		case <-ticker.C:
			rsa.checkConnections()

		case <-idleTimer.C:
			if rsa.isIdle() {
				return
			}
			idleTimer.Reset(60 * time.Second)

		case now := <-rsa.waitForScheduledHolepunch():
			if now.After(rsa.scheduledHolepunch) {
				rsa.triggerHolepunching()
			}

		case now := <-rsa.waitForScheduledOpenPath():
			if now.After(rsa.scheduledOpenPath) {
				rsa.openPendingPaths()
			}
		}
	}
}

func (rsa *RemoteStateActor) isIdle() bool {
	rsa.connectionsMu.RLock()
	defer rsa.connectionsMu.RUnlock()
	return len(rsa.connections) == 0
}

func (rsa *RemoteStateActor) checkConnections() {
	rsa.connectionsMu.RLock()
	defer rsa.connectionsMu.RUnlock()

	for _, conn := range rsa.connections {
		conn.mu.RLock()
		hasNonRelayPath := false
		for _, addr := range conn.openPaths {
			if addr.IsIP() {
				hasNonRelayPath = true
				break
			}
		}
		conn.mu.RUnlock()

		if !hasNonRelayPath {
			rsa.triggerHolepunching()
		}
	}
}

func (rsa *RemoteStateActor) triggerHolepunching() {
	now := time.Now()

	if rsa.lastHolepunch != nil && now.Sub(rsa.lastHolepunch.time) < 5*time.Second {
		return
	}

	rsa.mu.Lock()
	defer rsa.mu.Unlock()

	rsa.scheduledHolepunch = now
	rsa.lastHolepunch = &HolepunchAttempt{
		time:     now,
		attempts: 0,
	}

	rsa.doHolepunching()
}

func (rsa *RemoteStateActor) doHolepunching() {
	paths := rsa.paths.GetCandidatePaths()

	for _, path := range paths {
		if rsa.shouldHolepunchPath(&path) {
			rsa.holepunchPath(&path)
		}
	}
}

func (rsa *RemoteStateActor) shouldHolepunchPath(path *Addr) bool {
	if rsa.selectedPath != nil && rsa.selectedPath.Equals(path) {
		return false
	}

	if path.IsRelay() {
		return false
	}

	return true
}

func (rsa *RemoteStateActor) holepunchPath(path *Addr) {
	if rsa.lastHolepunch != nil {
		rsa.lastHolepunch.attempts++
		rsa.lastHolepunch.addrs = append(rsa.lastHolepunch.addrs, *path)
	}

	if !path.IsIP() {
		return
	}

	udpAddr := path.ToSocketAddr()
	if udpAddr == nil {
		return
	}

	rsa.sendHolepunchPackets(udpAddr)
}

func (rsa *RemoteStateActor) sendHolepunchPackets(addr *net.UDPAddr) {
	holepunchData := rsa.createHolepunchPacket()

	for i := 0; i < 3; i++ {
		rsa.sendHolepunchPacket(addr, holepunchData)
		time.Sleep(time.Duration(50) * time.Millisecond)
	}
}

func (rsa *RemoteStateActor) createHolepunchPacket() []byte {
	packet := make([]byte, 32)
	copy(packet, rsa.localEndpointId.Bytes())
	return packet
}

func (rsa *RemoteStateActor) sendHolepunchPacket(addr *net.UDPAddr, data []byte) error {
	udpConn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	_, err = udpConn.Write(data)
	return err
}

func (rsa *RemoteStateActor) openPendingPaths() {
	rsa.mu.Lock()
	defer rsa.mu.Unlock()

	for _, addr := range rsa.pendingOpenPaths {
		rsa.openPath(&addr)
	}
	rsa.pendingOpenPaths = make([]Addr, 0)
}

func (rsa *RemoteStateActor) openPath(addr *Addr) {
	rsa.paths.AddPath(addr)
}

func (rsa *RemoteStateActor) waitForScheduledHolepunch() <-chan time.Time {
	rsa.mu.RLock()
	defer rsa.mu.RUnlock()

	if rsa.scheduledHolepunch.IsZero() {
		return nil
	}

	duration := time.Until(rsa.scheduledHolepunch)
	if duration <= 0 {
		return time.After(0)
	}

	return time.After(duration)
}

func (rsa *RemoteStateActor) waitForScheduledOpenPath() <-chan time.Time {
	rsa.mu.RLock()
	defer rsa.mu.RUnlock()

	if rsa.scheduledOpenPath.IsZero() {
		return nil
	}

	duration := time.Until(rsa.scheduledOpenPath)
	if duration <= 0 {
		return time.After(0)
	}

	return time.After(duration)
}

func (rsa *RemoteStateActor) AddConnection(conn interface{}, connId uint64) {
	rsa.connectionsMu.Lock()
	defer rsa.connectionsMu.Unlock()

	connState := &ConnectionState{
		conn:      conn,
		paths:     make(map[PathId]Addr),
		openPaths: make([]Addr, 0),
		pathIds:   make(map[string]PathId),
	}
	rsa.connections[connId] = connState

	rsa.triggerHolepunching()
}

func (rsa *RemoteStateActor) RemoveConnection(connId uint64) {
	rsa.connectionsMu.Lock()
	defer rsa.connectionsMu.Unlock()

	delete(rsa.connections, connId)
}

func (rsa *RemoteStateActor) SetRelayConnection(relayConn interface{}) {
	rsa.mu.Lock()
	defer rsa.mu.Unlock()

	rsa.relayConnection = relayConn
}

func (rsa *RemoteStateActor) GetRelayConnection() interface{} {
	rsa.mu.RLock()
	defer rsa.mu.RUnlock()

	return rsa.relayConnection
}

func (rsa *RemoteStateActor) AddPath(connId uint64, pathId PathId, addr Addr) {
	rsa.connectionsMu.Lock()
	defer rsa.connectionsMu.Unlock()

	conn, ok := rsa.connections[connId]
	if !ok {
		return
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.paths[pathId] = addr
	conn.openPaths = append(conn.openPaths, addr)
	conn.pathIds[addr.String()] = pathId

	rsa.selectBestPath()
}

func (rsa *RemoteStateActor) RemovePath(connId uint64, pathId PathId) {
	rsa.connectionsMu.Lock()
	defer rsa.connectionsMu.Unlock()

	conn, ok := rsa.connections[connId]
	if !ok {
		return
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	addr, ok := conn.paths[pathId]
	if !ok {
		return
	}

	delete(conn.paths, pathId)
	delete(conn.pathIds, addr.String())

	for i, a := range conn.openPaths {
		if a.Equals(&addr) {
			conn.openPaths = append(conn.openPaths[:i], conn.openPaths[i+1:]...)
			break
		}
	}

	rsa.selectBestPath()
}

func (rsa *RemoteStateActor) selectBestPath() {
	rsa.connectionsMu.RLock()
	defer rsa.connectionsMu.RUnlock()

	var bestPath *Addr
	var bestScore float64

	for _, conn := range rsa.connections {
		conn.mu.RLock()
		for _, addr := range conn.openPaths {
			score := rsa.scorePath(&addr)
			if score > bestScore {
				bestScore = score
				bestPath = &addr
			}
		}
		conn.mu.RUnlock()
	}

	rsa.mu.Lock()
	defer rsa.mu.Unlock()

	if bestPath != nil {
		rsa.selectedPath = bestPath
	} else {
		rsa.selectedPath = nil
	}
}

func (rsa *RemoteStateActor) scorePath(addr *Addr) float64 {
	score := 0.0

	if addr.IsIP() {
		score += 100.0
	} else if addr.IsRelay() {
		score += 10.0
	}

	return score
}

func (rsa *RemoteStateActor) GetSelectedPath() *Addr {
	rsa.mu.RLock()
	defer rsa.mu.RUnlock()

	return rsa.selectedPath
}

func (rsa *RemoteStateActor) GetRemoteInfo() *RemoteStateInfo {
	return &RemoteStateInfo{
		Id:        rsa.endpointId,
		Addresses: rsa.paths.GetAddresses(),
	}
}

type RemoteStateInfo struct {
	Id        *crypto.EndpointId
	Addresses []string
}

type RemotePathState struct {
	paths map[string]*PathInfo
	mu    sync.RWMutex
}

type PathInfo struct {
	Addr     Addr
	Status   PathStatus
	LastUsed time.Time
	RTT      time.Duration
}

type PathStatus int

const (
	PathStatusAvailable PathStatus = iota
	PathStatusBackup
	PathStatusFailed
)

func NewRemotePathState() *RemotePathState {
	return &RemotePathState{
		paths: make(map[string]*PathInfo),
	}
}

func (rps *RemotePathState) AddPath(addr *Addr) {
	rps.mu.Lock()
	defer rps.mu.Unlock()

	addrStr := addr.String()
	if _, ok := rps.paths[addrStr]; !ok {
		rps.paths[addrStr] = &PathInfo{
			Addr:     *addr,
			Status:   PathStatusAvailable,
			LastUsed: time.Now(),
		}
	}
}

func (rps *RemotePathState) RemovePath(addr *Addr) {
	rps.mu.Lock()
	defer rps.mu.Unlock()

	addrStr := addr.String()
	delete(rps.paths, addrStr)
}

func (rps *RemotePathState) GetPath(addr *Addr) *PathInfo {
	rps.mu.RLock()
	defer rps.mu.RUnlock()

	addrStr := addr.String()
	return rps.paths[addrStr]
}

func (rps *RemotePathState) GetCandidatePaths() []Addr {
	rps.mu.RLock()
	defer rps.mu.RUnlock()

	paths := make([]Addr, 0, len(rps.paths))
	for _, info := range rps.paths {
		if info.Status == PathStatusAvailable {
			paths = append(paths, info.Addr)
		}
	}

	return paths
}

func (rps *RemotePathState) GetAddresses() []string {
	rps.mu.RLock()
	defer rps.mu.RUnlock()

	addrs := make([]string, 0, len(rps.paths))
	for _, info := range rps.paths {
		addrs = append(addrs, info.Addr.String())
	}

	return addrs
}

func (rps *RemotePathState) IsEmpty() bool {
	rps.mu.RLock()
	defer rps.mu.RUnlock()

	return len(rps.paths) == 0
}

func (rps *RemotePathState) GetPaths() map[string]*PathInfo {
	rps.mu.RLock()
	defer rps.mu.RUnlock()

	result := make(map[string]*PathInfo, len(rps.paths))
	for k, v := range rps.paths {
		result[k] = v
	}

	return result
}
