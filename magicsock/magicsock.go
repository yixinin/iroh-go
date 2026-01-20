package magicsock

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/yixinin/iroh-go/common"
	"github.com/yixinin/iroh-go/crypto"
	"github.com/yixinin/iroh-go/discovery"
	"github.com/yixinin/iroh-go/relay"

	"github.com/quic-go/quic-go"
)

const (
	defaultDialTimeout = 30 * time.Second
	defaultKeepAlive   = 30 * time.Second
	holepunchInterval  = 5 * time.Second
	pathCheckInterval  = 10 * time.Second

	// DefaultRelayMode 默认中继模式
	DefaultRelayMode = common.RelayModeDefault
	// DefaultALPN 默认 ALPN 协议
	DefaultALPN = "h3"
)

type Options struct {
	RelayMode common.RelayMode
	SecretKey *crypto.SecretKey
	ALPNs     [][]byte
	Discovery discovery.Discovery
}

type EndpointAddr struct {
	Id    *crypto.EndpointId
	Addrs []common.TransportAddr
}

type Connection struct {
	quicConn  quic.Connection
	relayConn *relay.RelayConnection
	remoteId  *crypto.EndpointId
	alpn      []byte
}

func (c *Connection) Conn() quic.Connection {
	if c.quicConn != nil {
		return c.quicConn
	}
	return c.relayConn
}

func (c *Connection) Relay() *relay.RelayConnection {
	return c.relayConn
}

func (c *Connection) RemoteId() *crypto.EndpointId {
	return c.remoteId
}

func (c *Connection) ALPN() []byte {
	return c.alpn
}

type Incoming struct {
	conn     quic.Connection
	remoteId *crypto.EndpointId
	alpn     []byte
}

func (i *Incoming) Conn() quic.Connection {
	return i.conn
}

func (i *Incoming) RemoteId() *crypto.EndpointId {
	return i.remoteId
}

func (i *Incoming) ALPN() []byte {
	return i.alpn
}

type MagicSock struct {
	endpoint     *quic.Listener
	remoteMap    *RemoteMap
	transports   *Transports
	relayMap     *RelayMap
	relayClients []*relay.Client
	id           *crypto.EndpointId
	secretKey    *crypto.SecretKey
	discovery    discovery.Discovery

	customPacketConn *CustomPacketConn

	remoteStates   map[string]*RemoteStateActor
	remoteStatesMu sync.RWMutex

	localDirectAddrs *LocalDirectAddrs
	relayMappedAddrs *AddrMap

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewMagicSock(opts Options) (*MagicSock, error) {
	// 应用默认值
	if opts.RelayMode == 0 {
		opts.RelayMode = DefaultRelayMode
	}
	if opts.SecretKey == nil {
		opts.SecretKey = crypto.NewSecretKey()
	}
	if len(opts.ALPNs) == 0 {
		opts.ALPNs = [][]byte{[]byte(DefaultALPN)}
	}
	if opts.Discovery == nil {
		opts.Discovery = discovery.DefaultDiscovery()
	}

	ctx, cancel := context.WithCancel(context.Background())

	remoteMap := NewRemoteMap()
	relayMap := NewRelayMap(opts.RelayMode)

	transports, err := initTransports(opts.RelayMode, relayMap)
	if err != nil {
		cancel()
		return nil, err
	}

	var relayClients []*relay.Client
	if opts.RelayMode != common.RelayModeDisabled {
		log.Printf("[MagicSock] Initializing relay connections (mode: %v)", opts.RelayMode)

		relayURLs := relayMap.Relays()
		if len(relayURLs) == 0 {
			log.Printf("[MagicSock] Warning: No relay URLs configured")
		}

		for _, relayURL := range relayURLs {
			log.Printf("[MagicSock] Attempting to connect to relay: %s", relayURL)

			config := relay.NewConfig([]string{relayURL}, opts.SecretKey)
			client, err := relay.NewClient(config)
			if err != nil {
				log.Printf("[MagicSock] Failed to create relay client for %s: %v", relayURL, err)
				continue
			}

			if err := client.Connect(); err != nil {
				log.Printf("[MagicSock] Failed to connect to relay %s: %v", relayURL, err)
				continue
			}

			relayClients = append(relayClients, client)
			log.Printf("[MagicSock] Successfully connected to relay: %s", relayURL)
		}

		if len(relayClients) == 0 {
			log.Printf("[MagicSock] Warning: No relay connections established")
		} else {
			log.Printf("[MagicSock] Successfully connected to %d relay(s)", len(relayClients))
		}
	} else {
		log.Printf("[MagicSock] Relay mode disabled")
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:  defaultKeepAlive,
		KeepAlivePeriod: defaultKeepAlive,
	}
	log.Printf("[MagicSock] Starting QUIC listener on 0.0.0.0:0")
	listener, err := quic.ListenAddr("0.0.0.0:0", generateTLSConfig(opts.SecretKey, opts.ALPNs), quicConfig)
	if err != nil {
		log.Printf("[MagicSock] Failed to start QUIC listener: %v", err)
		cancel()
		return nil, err
	}
	log.Printf("[MagicSock] QUIC listener started successfully on %s", listener.Addr())

	id := crypto.EndpointIdFromPublicKey(opts.SecretKey.Public())
	log.Printf("[MagicSock] Endpoint ID: %s", id.String())

	localDirectAddrs := NewLocalDirectAddrs()
	localAddrStrings := transports.LocalAddrs()
	localAddrs := make([]net.Addr, 0, len(localAddrStrings))
	for _, addrStr := range localAddrStrings {
		if udpAddr, err := net.ResolveUDPAddr("udp", addrStr); err == nil {
			localAddrs = append(localAddrs, udpAddr)
		}
	}
	localDirectAddrs.Set(localAddrs)
	log.Printf("[MagicSock] Local addresses: %v", localAddrStrings)

	relayMappedAddrs := NewAddrMap()

	customPacketConn := NewCustomPacketConn(id)

	ms := &MagicSock{
		endpoint:         listener,
		remoteMap:        remoteMap,
		transports:       transports,
		relayMap:         relayMap,
		relayClients:     relayClients,
		id:               id,
		secretKey:        opts.SecretKey,
		discovery:        opts.Discovery,
		customPacketConn: customPacketConn,
		remoteStates:     make(map[string]*RemoteStateActor),
		localDirectAddrs: localDirectAddrs,
		relayMappedAddrs: relayMappedAddrs,
		ctx:              ctx,
		cancel:           cancel,
	}

	for _, transport := range transports.IPTransports() {
		if ipTransport, ok := transport.(*TransportIp); ok {
			if ipTransport.conn != nil {
				customPacketConn.SetIPv4Conn(ipTransport.conn)
			}
		}
	}

	if len(relayClients) > 0 {
		customPacketConn.SetRelayConn(relayClients[0])
	}

	customPacketConn.Start()

	ms.startBackgroundTasks()

	status := ms.Status()
	log.Printf("[MagicSock] MagicSock initialized successfully")
	log.Printf("[MagicSock] Status: Relay=%d, Active=%d, RemoteStates=%d, LocalAddrs=%v, EndpointId=%s",
		status.RelayConnectedCount, status.ActiveConnections, status.RemoteStatesCount,
		status.LocalAddresses, status.EndpointId)

	return ms, nil
}

func (ms *MagicSock) startBackgroundTasks() {
	ms.wg.Add(1)
	go func() {
		defer ms.wg.Done()
		ms.acceptLoop()
	}()

	ms.wg.Add(1)
	go func() {
		defer ms.wg.Done()
		ms.pathCheckLoop()
	}()

	ms.wg.Add(1)
	go func() {
		defer ms.wg.Done()
		ms.networkMonitorLoop()
	}()

	ms.wg.Add(1)
	go func() {
		defer ms.wg.Done()
		ms.udpReceiveLoop()
	}()
}

func (ms *MagicSock) acceptLoop() {
	for {
		select {
		case <-ms.ctx.Done():
			return
		default:
			conn, err := ms.endpoint.Accept(ms.ctx)
			if err != nil {
				return
			}

			ms.handleIncomingConnection(conn)
		}
	}
}

func (ms *MagicSock) handleIncomingConnection(conn quic.Connection) {
	remoteAddr := conn.RemoteAddr()

	remoteId := ms.extractEndpointId(conn)

	if remoteId != nil {
		ms.remoteStatesMu.Lock()
		actor, exists := ms.remoteStates[remoteId.String()]
		if !exists {
			actor = ms.createRemoteStateActor(remoteId)
			ms.remoteStates[remoteId.String()] = actor
			actor.Start()
		}
		ms.remoteStatesMu.Unlock()

		actor.AddConnection(conn, uint64(time.Now().UnixNano()))

		udpAddr, ok := remoteAddr.(*net.UDPAddr)
		if ok {
			addr := NewAddrFromIP(udpAddr)
			actor.AddPath(uint64(time.Now().UnixNano()), PathIdZero, *addr)
		}
	}
}

func (ms *MagicSock) extractEndpointId(conn quic.Connection) *crypto.EndpointId {
	return nil
}

func (ms *MagicSock) pathCheckLoop() {
	ticker := time.NewTicker(pathCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ms.ctx.Done():
			return
		case <-ticker.C:
			ms.checkAllPaths()
		}
	}
}

func (ms *MagicSock) checkAllPaths() {
	ms.remoteStatesMu.RLock()
	defer ms.remoteStatesMu.RUnlock()

	for _, actor := range ms.remoteStates {
		actor.checkConnections()
	}
}

func (ms *MagicSock) networkMonitorLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ms.ctx.Done():
			return
		case <-ticker.C:
			ms.monitorNetworkChanges()
		}
	}
}

func (ms *MagicSock) udpReceiveLoop() {
	buf := make([]byte, 65536)

	for {
		select {
		case <-ms.ctx.Done():
			return
		default:
			for _, transport := range ms.transports.IPTransports() {
				if ipTransport, ok := transport.(*TransportIp); ok {
					n, addr, err := ipTransport.ReceiveFrom(buf)
					if err != nil {
						continue
					}

					ms.handleUDPPacket(buf[:n], addr)
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (ms *MagicSock) handleUDPPacket(data []byte, addr *net.UDPAddr) {
	if IsHolepunchPacket(data) {
		ms.handleHolepunchPacket(data, addr)
	}
}

func (ms *MagicSock) handleHolepunchPacket(data []byte, addr *net.UDPAddr) {
	packet, err := ParseHolepunchPacket(data)
	if err != nil || packet == nil {
		return
	}

	senderId, err := crypto.ParseEndpointId(string(packet.SenderId[:]))
	if err != nil {
		return
	}

	log.Printf("[MagicSock] Received holepunch packet from %s (ID: %s)", addr, senderId.String())

	ms.remoteStatesMu.Lock()
	actor, exists := ms.remoteStates[senderId.String()]
	if !exists {
		actor = ms.createRemoteStateActor(senderId)
		ms.remoteStates[senderId.String()] = actor
		actor.Start()
	}
	ms.remoteStatesMu.Unlock()

	packetAddr := NewAddrFromIP(addr)
	actor.AddPath(uint64(time.Now().UnixNano()), PathIdZero, *packetAddr)
}

func (ms *MagicSock) monitorNetworkChanges() {
	currentAddrs := ms.transports.LocalAddrs()
	currentAddrsSet := make(map[string]bool)
	for _, addr := range currentAddrs {
		currentAddrsSet[addr] = true
	}

	localAddrs := ms.localDirectAddrs.Get()
	oldAddrsSet := make(map[string]bool)
	for _, addr := range localAddrs {
		oldAddrsSet[addr.String()] = true
	}

	hasChanges := false
	for addr := range currentAddrsSet {
		if !oldAddrsSet[addr] {
			hasChanges = true
			fmt.Printf("Network change detected: new address %s\n", addr)
		}
	}

	for addr := range oldAddrsSet {
		if !currentAddrsSet[addr] {
			hasChanges = true
			fmt.Printf("Network change detected: removed address %s\n", addr)
		}
	}

	if hasChanges {
		ms.handleNetworkChange()
	}
}

func (ms *MagicSock) handleNetworkChange() {
	newAddrs := make([]net.Addr, 0)
	for _, addrStr := range ms.transports.LocalAddrs() {
		if udpAddr, err := net.ResolveUDPAddr("udp", addrStr); err == nil {
			newAddrs = append(newAddrs, udpAddr)
		}
	}
	ms.localDirectAddrs.Set(newAddrs)

	ms.remoteStatesMu.RLock()
	for _, actor := range ms.remoteStates {
		actor.triggerHolepunching()
	}
	ms.remoteStatesMu.RUnlock()
}

func (ms *MagicSock) optimizePaths() {
	ms.remoteStatesMu.RLock()
	defer ms.remoteStatesMu.RUnlock()

	for _, actor := range ms.remoteStates {
		ms.optimizeRemoteStatePaths(actor)
	}
}

func (ms *MagicSock) optimizeRemoteStatePaths(actor *RemoteStateActor) {
	remoteInfo := actor.GetRemoteInfo()
	if remoteInfo == nil {
		return
	}

	actor.mu.Lock()
	defer actor.mu.Unlock()

	if ms.discovery != nil {
		discoveryCh, err := ms.discovery.Discover(remoteInfo.Id)
		if err == nil {
			for data := range discoveryCh {
				if data.Id.String() == remoteInfo.Id.String() {
					for _, transportAddr := range data.Addrs {
						if ipAddr, ok := transportAddr.(*common.TransportAddrIp); ok {
							udpAddr, err := net.ResolveUDPAddr("udp", ipAddr.Addr)
							if err == nil {
								addr := NewAddrFromIP(udpAddr)
								actor.openPath(addr)
							}
						}
					}
				}
			}
		}
	}
}

func (ms *MagicSock) createRemoteStateActor(remoteId *crypto.EndpointId) *RemoteStateActor {
	return NewRemoteStateActor(
		remoteId,
		ms.id,
		ms.localDirectAddrs,
		ms.relayMappedAddrs,
		ms,
	)
}

func (ms *MagicSock) Connect(addr EndpointAddr, alpn []byte) (*Connection, error) {
	log.Printf("[MagicSock] Attempting to connect to endpoint %s", addr.Id.String())

	ctx, cancel := context.WithTimeout(ms.ctx, defaultDialTimeout)
	defer cancel()

	if ms.discovery != nil {
		if err := ms.discoverAndConnect(ctx, addr, alpn); err != nil {
			log.Printf("[MagicSock] Discovery failed: %v, trying direct connection", err)
		} else {
			log.Printf("[MagicSock] Discovery completed successfully")
		}
	}

	log.Printf("[MagicSock] Attempting direct connection to endpoint %s", addr.Id.String())
	directConn, err := ms.tryDirectConnection(ctx, addr, alpn)
	if err == nil {
		log.Printf("[MagicSock] Direct connection successful to endpoint %s", addr.Id.String())
		return directConn, nil
	}
	log.Printf("[MagicSock] Direct connection failed: %v, trying relay connection", err)

	log.Printf("[MagicSock] Attempting relay connection to endpoint %s", addr.Id.String())
	relayConn, err := ms.tryRelayConnection(ctx, addr, alpn)
	if err == nil {
		log.Printf("[MagicSock] Relay connection successful to endpoint %s", addr.Id.String())
		return relayConn, nil
	}
	log.Printf("[MagicSock] Relay connection failed: %v", err)

	return nil, fmt.Errorf("failed to connect to peer: all connection attempts failed")
}

func (ms *MagicSock) discoverAndConnect(ctx context.Context, addr EndpointAddr, alpn []byte) error {
	log.Printf("[MagicSock] Starting discovery for endpoint %s", addr.Id.String())

	discoveryCh, err := ms.discovery.Discover(addr.Id)
	if err != nil {
		log.Printf("[MagicSock] Discovery error for endpoint %s: %v", addr.Id.String(), err)
		return err
	}

	for {
		select {
		case <-ctx.Done():
			log.Printf("[MagicSock] Discovery timeout for endpoint %s", addr.Id.String())
			return ctx.Err()
		case data, ok := <-discoveryCh:
			if !ok {
				log.Printf("[MagicSock] Discovery channel closed for endpoint %s", addr.Id.String())
				return nil
			}

			if data.Id.String() == addr.Id.String() {
				log.Printf("[MagicSock] Discovered endpoint %s with %d addresses", data.Id.String(), len(data.Addrs))

				if len(data.Addrs) > 0 {
					remoteInfo := &RemoteInfo{
						Id:        data.Id,
						Addresses: make([]string, 0, len(data.Addrs)),
						RelayUrl:  data.RelayURL,
					}
					for _, transportAddr := range data.Addrs {
						remoteInfo.Addresses = append(remoteInfo.Addresses, transportAddr.String())
					}
					ms.remoteMap.Set(data.Id, remoteInfo)

					addr.Addrs = data.Addrs
					if data.RelayURL != "" {
						addr.Addrs = append(addr.Addrs, &common.TransportAddrRelay{Url: data.RelayURL})
					}
					log.Printf("[MagicSock] Updated endpoint %s with %d addresses", data.Id.String(), len(addr.Addrs))
				}
			}
		}
	}
}

func (ms *MagicSock) tryDirectConnection(ctx context.Context, addr EndpointAddr, alpn []byte) (*Connection, error) {
	log.Printf("[MagicSock] Trying direct connection to endpoint %s", addr.Id.String())

	mappedAddr, err := ms.ResolveRemote(addr)
	if err == nil {
		log.Printf("[MagicSock] Attempting connection to mapped address %s", mappedAddr.Addr)
		conn, err := ms.dialQUIC(ctx, mappedAddr.Addr, addr.Id, alpn)
		if err == nil {
			log.Printf("[MagicSock] Successfully connected via mapped address %s", mappedAddr.Addr)
			return conn, nil
		}
		log.Printf("[MagicSock] Failed to connect to mapped address %s: %v", mappedAddr.Addr, err)
	} else {
		log.Printf("[MagicSock] No mapped address found: %v", err)
	}

	log.Printf("[MagicSock] Trying %d transport address(es)", len(addr.Addrs))
	for i, transportAddr := range addr.Addrs {
		log.Printf("[MagicSock] Attempting connection to transport address %d: %s", i+1, transportAddr.String())
		conn, err := ms.dialQUIC(ctx, transportAddr.String(), addr.Id, alpn)
		if err == nil {
			log.Printf("[MagicSock] Successfully connected via transport address %s", transportAddr.String())
			return conn, nil
		}
		log.Printf("[MagicSock] Failed to connect to address %s: %v", transportAddr.String(), err)
	}

	log.Printf("[MagicSock] All direct connection attempts failed for endpoint %s", addr.Id.String())
	return nil, fmt.Errorf("all direct connection attempts failed")
}

func (ms *MagicSock) tryRelayConnection(ctx context.Context, addr EndpointAddr, alpn []byte) (*Connection, error) {
	if len(ms.relayClients) == 0 {
		log.Printf("[MagicSock] No relay clients available for endpoint %s", addr.Id.String())
		return nil, fmt.Errorf("no relay clients available")
	}

	log.Printf("[MagicSock] Trying %d relay client(s) for endpoint %s", len(ms.relayClients), addr.Id.String())

	for i, relayClient := range ms.relayClients {
		log.Printf("[MagicSock] Attempting relay connection via client %d", i+1)

		relayConn := relay.NewRelayConnection(relayClient, addr.Id)
		relayConn.Start()

		log.Printf("[MagicSock] Relay connection established via %s", relayClient.URL())

		ms.remoteStatesMu.Lock()
		actor, exists := ms.remoteStates[addr.Id.String()]
		if !exists {
			actor = ms.createRemoteStateActor(addr.Id)
			ms.remoteStates[addr.Id.String()] = actor
			actor.Start()
			log.Printf("[MagicSock] Created remote state actor for %s", addr.Id.String())
		}
		ms.remoteStatesMu.Unlock()

		actor.SetRelayConnection(relayConn)

		return &Connection{
			quicConn:  nil,
			remoteId:  addr.Id,
			alpn:      alpn,
			relayConn: relayConn,
		}, nil
	}

	log.Printf("[MagicSock] All %d relay connection attempts failed for endpoint %s", len(ms.relayClients), addr.Id.String())
	return nil, fmt.Errorf("all relay connection attempts failed")
}

func (ms *MagicSock) dialQUIC(ctx context.Context, addr string, remoteId *crypto.EndpointId, alpn []byte) (*Connection, error) {
	log.Printf("[MagicSock] Dialing QUIC to %s (remote ID: %s, ALPN: %s)", addr, remoteId.String(), string(alpn))

	quicConfig := &quic.Config{
		MaxIdleTimeout:  defaultKeepAlive,
		KeepAlivePeriod: defaultKeepAlive,
	}

	tlsConfig := generateClientTLSConfig(ms.secretKey, [][]byte{alpn}, remoteId)

	conn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		log.Printf("[MagicSock] QUIC dial failed to %s: %v", addr, err)
		return nil, err
	}

	log.Printf("[MagicSock] QUIC connection established to %s", addr)

	if remoteId != nil {
		ms.remoteStatesMu.Lock()
		actor, exists := ms.remoteStates[remoteId.String()]
		if !exists {
			actor = ms.createRemoteStateActor(remoteId)
			ms.remoteStates[remoteId.String()] = actor
			actor.Start()
			log.Printf("[MagicSock] Created remote state actor for %s", remoteId.String())
		}
		ms.remoteStatesMu.Unlock()

		actor.AddConnection(conn, uint64(time.Now().UnixNano()))
	}

	return &Connection{
		quicConn: conn,
		remoteId: remoteId,
		alpn:     alpn,
	}, nil
}

func (ms *MagicSock) Accept() (<-chan *Incoming, error) {
	ch := make(chan *Incoming)

	go func() {
		for {
			conn, err := ms.endpoint.Accept(ms.ctx)
			if err != nil {
				break
			}

			incoming := &Incoming{
				conn:     conn,
				remoteId: ms.extractEndpointId(conn),
			}
			ch <- incoming
		}
		close(ch)
	}()

	go func() {
		for {
			for _, rc := range ms.relayClients {
				relayConn := relay.NewRelayConnection(rc, ms.id)
				stream, err := relayConn.AcceptStream(context.Background())
				if err != nil {
					break
				}
				incoming := &Incoming{
					conn:     stream,
					remoteId: ms.extractEndpointId(stream),
				}
				ch <- incoming
			}

		}
		close(ch)
	}()

	return ch, nil
}

func (ms *MagicSock) ResolveRemote(addr EndpointAddr) (*MappedAddr, error) {
	remoteInfo, ok := ms.remoteMap.Get(addr.Id)
	if ok && len(remoteInfo.Addresses) > 0 {
		return &MappedAddr{
			Addr: remoteInfo.Addresses[0],
		}, nil
	}

	if len(addr.Addrs) > 0 {
		return &MappedAddr{
			Addr: addr.Addrs[0].String(),
		}, nil
	}

	return nil, fmt.Errorf("no address available for remote endpoint")
}

func (ms *MagicSock) Id() *crypto.EndpointId {
	return ms.id
}

func (ms *MagicSock) Addr() EndpointAddr {
	addrs := []common.TransportAddr{}

	localAddr := ms.endpoint.Addr().String()
	addrs = append(addrs, &common.TransportAddrIp{
		Addr: localAddr,
	})

	return EndpointAddr{
		Id:    ms.id,
		Addrs: addrs,
	}
}

func (ms *MagicSock) Close() error {
	log.Printf("[MagicSock] Closing MagicSock")

	ms.cancel()

	ms.remoteStatesMu.Lock()
	for _, actor := range ms.remoteStates {
		actor.Stop()
	}
	ms.remoteStatesMu.Unlock()

	ms.wg.Wait()

	log.Printf("[MagicSock] MagicSock closed")
	return ms.endpoint.Close()
}

func (ms *MagicSock) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for _, transport := range ms.transports.IPTransports() {
		if ipTransport, ok := transport.(*TransportIp); ok {
			n, udpAddr, err := ipTransport.ReceiveFrom(p)
			if err == nil && n > 0 {
				return n, udpAddr, nil
			}
		}
	}
	return 0, nil, nil
}

func (ms *MagicSock) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("invalid address type")
	}

	packetAddr := NewAddrFromIP(udpAddr)
	for _, transport := range ms.transports.IPTransports() {
		if ipTransport, ok := transport.(*TransportIp); ok {
			err := ipTransport.Send(packetAddr, p)
			if err == nil {
				return len(p), nil
			}
		}
	}
	return 0, fmt.Errorf("failed to send packet")
}

func (ms *MagicSock) LocalAddr() net.Addr {
	return ms.endpoint.Addr()
}

func (ms *MagicSock) SetDeadline(t time.Time) error {
	return nil
}

func (ms *MagicSock) SetReadDeadline(t time.Time) error {
	return nil
}

func (ms *MagicSock) SetWriteDeadline(t time.Time) error {
	return nil
}

type ConnectionStatus struct {
	RelayConnectedCount int
	ActiveConnections   int
	RemoteStatesCount   int
	LocalAddresses      []string
	EndpointId          string
}

func (ms *MagicSock) Status() *ConnectionStatus {
	ms.remoteStatesMu.RLock()
	defer ms.remoteStatesMu.RUnlock()

	return &ConnectionStatus{
		RelayConnectedCount: len(ms.relayClients),
		ActiveConnections:   len(ms.remoteStates),
		RemoteStatesCount:   len(ms.remoteStates),
		LocalAddresses:      ms.transports.LocalAddrs(),
		EndpointId:          ms.id.String(),
	}
}

type MappedAddr struct {
	Addr string
}

func generateTLSConfig(secretKey *crypto.SecretKey, alpns [][]byte) *tls.Config {
	nextProtos := make([]string, len(alpns))
	for i, alpn := range alpns {
		nextProtos[i] = string(alpn)
	}

	return &tls.Config{
		NextProtos:         nextProtos,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
		Certificates:       []tls.Certificate{generateCertificate(secretKey)},
		ClientAuth:         tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no certificates provided")
			}
			return nil
		},
	}
}

func generateCertificate(secretKey *crypto.SecretKey) tls.Certificate {
	privKey := secretKey.PrivateKey()
	pubKey := secretKey.Public().Ed25519PublicKey()

	serialNumber := big.NewInt(1)

	certDER := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(nil, &certDER, &certDER, pubKey, privKey)
	if err != nil {
		panic(fmt.Sprintf("failed to create certificate: %v", err))
	}

	return tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privKey,
		Leaf:        &certDER,
	}
}

func generateClientTLSConfig(secretKey *crypto.SecretKey, alpns [][]byte, remoteId *crypto.EndpointId) *tls.Config {
	nextProtos := make([]string, len(alpns))
	for i, alpn := range alpns {
		nextProtos[i] = string(alpn)
	}

	config := &tls.Config{
		NextProtos:         nextProtos,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
		ServerName:         encodeEndpointIdAsServerName(remoteId),
		Certificates:       []tls.Certificate{generateCertificate(secretKey)},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no certificates provided")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %w", err)
			}
			certPubKey, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("certificate public key is not ed25519")
			}
			if !certPubKey.Equal(remoteId.Ed25519PublicKey()) {
				return errors.New("certificate public key does not match remote endpoint ID")
			}
			return nil
		},
	}
	return config
}

func encodeEndpointIdAsServerName(endpointId *crypto.EndpointId) string {
	encoded := base32.StdEncoding.EncodeToString(endpointId.Bytes())
	return fmt.Sprintf("%s.iroh.invalid", encoded)
}

func (ms *MagicSock) Resolve(ctx context.Context, id *crypto.EndpointId) (<-chan *DiscoveryItem, error) {
	if ms.discovery == nil {
		ch := make(chan *DiscoveryItem)
		close(ch)
		return ch, nil
	}

	dataCh, err := ms.discovery.Discover(id)
	if err != nil {
		return nil, err
	}

	resultCh := make(chan *DiscoveryItem)

	go func() {
		defer close(resultCh)

		for data := range dataCh {
			item := &DiscoveryItem{
				Addrs: make([]Addr, 0, len(data.Addrs)),
			}

			for _, transportAddr := range data.Addrs {
				if ipAddr, ok := transportAddr.(*common.TransportAddrIp); ok {
					udpAddr, err := net.ResolveUDPAddr("udp", ipAddr.Addr)
					if err == nil {
						item.Addrs = append(item.Addrs, *NewAddrFromIP(udpAddr))
					}
				}
			}

			if len(item.Addrs) > 0 {
				resultCh <- item
			}
		}
	}()

	return resultCh, nil
}
