package magicsock

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"

	"github/yixinin/iroh-go/crypto"
)

const (
	ADDR_PREFIXL = 0xfd
)

var (
	ADDR_GLOBAL_ID = [5]byte{21, 7, 10, 81, 11}
	RELAY_MAPPED_SUBNET = [2]byte{0, 1}
	ENDPOINT_ID_SUBNET = [2]byte{0, 0}
	MAPPED_PORT = 12345
)

var (
	relayAddrCounter     uint64
	endpointIdAddrCounter uint64
)

type MappedAddrInterface interface {
	Generate() MappedAddrInterface
	PrivateSocketAddr() net.Addr
}

type EndpointIdMappedAddr struct {
	addr net.IP
	id   *crypto.EndpointId
}

func NewEndpointIdMappedAddr(id *crypto.EndpointId) *EndpointIdMappedAddr {
	counter := atomic.AddUint64(&endpointIdAddrCounter, 1)
	addr := generateMappedAddr(ENDPOINT_ID_SUBNET, id.Bytes(), counter)
	return &EndpointIdMappedAddr{addr: addr, id: id}
}

func (e *EndpointIdMappedAddr) Generate() MappedAddrInterface {
	return NewEndpointIdMappedAddr(e.id)
}

func (e *EndpointIdMappedAddr) PrivateSocketAddr() net.Addr {
	return &net.UDPAddr{
		IP:   e.addr,
		Port: MAPPED_PORT,
	}
}

func (e *EndpointIdMappedAddr) ToIP() net.IP {
	return e.addr
}

func (e *EndpointIdMappedAddr) IsEndpointIdMappedAddr(ip net.IP) bool {
	if ip.To4() != nil {
		return false
	}
	if ip[0] != ADDR_PREFIXL {
		return false
	}
	if len(ip) < 8 {
		return false
	}
	for i := 0; i < 5; i++ {
		if ip[i+1] != ADDR_GLOBAL_ID[i] {
			return false
		}
	}
	if ip[6] != ENDPOINT_ID_SUBNET[0] || ip[7] != ENDPOINT_ID_SUBNET[1] {
		return false
	}
	return true
}

type RelayMappedAddr struct {
	addr net.IP
}

func NewRelayMappedAddr(relayUrl string, nodeId *crypto.EndpointId) *RelayMappedAddr {
	counter := atomic.AddUint64(&relayAddrCounter, 1)
	
	hash := sha256.Sum256([]byte(relayUrl + nodeId.String()))
	var combined [16]byte
	copy(combined[:8], hash[:8])
	binary.BigEndian.PutUint64(combined[8:], counter)
	
	addr := generateMappedAddr(RELAY_MAPPED_SUBNET, combined[:], 0)
	return &RelayMappedAddr{addr: addr}
}

func (r *RelayMappedAddr) Generate() MappedAddrInterface {
	return NewRelayMappedAddr("", nil)
}

func (r *RelayMappedAddr) PrivateSocketAddr() net.Addr {
	return &net.UDPAddr{
		IP:   r.addr,
		Port: MAPPED_PORT,
	}
}

func (r *RelayMappedAddr) ToIP() net.IP {
	return r.addr
}

func (r *RelayMappedAddr) IsRelayMappedAddr(ip net.IP) bool {
	if ip.To4() != nil {
		return false
	}
	if ip[0] != ADDR_PREFIXL {
		return false
	}
	if len(ip) < 8 {
		return false
	}
	for i := 0; i < 5; i++ {
		if ip[i+1] != ADDR_GLOBAL_ID[i] {
			return false
		}
	}
	if ip[6] != RELAY_MAPPED_SUBNET[0] || ip[7] != RELAY_MAPPED_SUBNET[1] {
		return false
	}
	return true
}

func generateMappedAddr(subnet [2]byte, data []byte, counter uint64) net.IP {
	addr := make(net.IP, 16)
	addr[0] = ADDR_PREFIXL
	copy(addr[1:6], ADDR_GLOBAL_ID[:])
	copy(addr[6:8], subnet[:])
	
	if len(data) >= 8 {
		copy(addr[8:16], data[:8])
	} else {
		binary.BigEndian.PutUint64(addr[8:16], counter)
	}
	
	return addr
}

type AddrMapKey interface {
	Equals(other AddrMapKey) bool
	Hash() uint64
}

type AddrMap struct {
	mu     sync.RWMutex
	addrs  map[string]MappedAddrInterface
	lookup map[string]string
}

func NewAddrMap() *AddrMap {
	return &AddrMap{
		addrs:  make(map[string]MappedAddrInterface),
		lookup: make(map[string]string),
	}
}

func (am *AddrMap) Get(key string, generator func() MappedAddrInterface) MappedAddrInterface {
	am.mu.RLock()
	if addr, ok := am.addrs[key]; ok {
		am.mu.RUnlock()
		return addr
	}
	am.mu.RUnlock()
	
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if addr, ok := am.addrs[key]; ok {
		return addr
	}
	
	newAddr := generator()
	am.addrs[key] = newAddr
	
	var ip net.IP
	switch v := newAddr.(type) {
	case *EndpointIdMappedAddr:
		ip = v.ToIP()
	case *RelayMappedAddr:
		ip = v.ToIP()
	}
	
	am.lookup[ip.String()] = key
	
	return newAddr
}

func (am *AddrMap) Lookup(ip net.IP) string {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	return am.lookup[ip.String()]
}

type EndpointIdKey struct {
	id *crypto.EndpointId
}

func NewEndpointIdKey(id *crypto.EndpointId) *EndpointIdKey {
	return &EndpointIdKey{id: id}
}

func (k *EndpointIdKey) String() string {
	return k.id.String()
}

type RelayKey struct {
	url    string
	nodeId *crypto.EndpointId
}

func NewRelayKey(url string, nodeId *crypto.EndpointId) *RelayKey {
	return &RelayKey{
		url:    url,
		nodeId: nodeId,
	}
}

func (k *RelayKey) String() string {
	return k.url + ":" + k.nodeId.String()
}

type MultipathMappedAddr struct {
	Type  MultipathMappedAddrType
	Ip    net.Addr
	Relay *RelayMappedAddr
	Mixed *EndpointIdMappedAddr
}

type MultipathMappedAddrType int

const (
	MultipathMappedAddrTypeIp MultipathMappedAddrType = iota
	MultipathMappedAddrTypeRelay
	MultipathMappedAddrTypeMixed
)

func NewMultipathMappedAddrFromIP(ip net.Addr) *MultipathMappedAddr {
	return &MultipathMappedAddr{
		Type: MultipathMappedAddrTypeIp,
		Ip:   ip,
	}
}

func NewMultipathMappedAddrFromRelay(relay *RelayMappedAddr) *MultipathMappedAddr {
	return &MultipathMappedAddr{
		Type:  MultipathMappedAddrTypeRelay,
		Relay: relay,
	}
}

func NewMultipathMappedAddrFromMixed(mixed *EndpointIdMappedAddr) *MultipathMappedAddr {
	return &MultipathMappedAddr{
		Type:  MultipathMappedAddrTypeMixed,
		Mixed: mixed,
	}
}

func (m *MultipathMappedAddr) ToSocketAddr() net.Addr {
	switch m.Type {
	case MultipathMappedAddrTypeIp:
		return m.Ip
	case MultipathMappedAddrTypeRelay:
		return m.Relay.PrivateSocketAddr()
	case MultipathMappedAddrTypeMixed:
		return m.Mixed.PrivateSocketAddr()
	default:
		return nil
	}
}

func (m *MultipathMappedAddr) IsRelay() bool {
	return m.Type == MultipathMappedAddrTypeRelay
}

func (m *MultipathMappedAddr) IsIP() bool {
	return m.Type == MultipathMappedAddrTypeIp
}

func (m *MultipathMappedAddr) IsMixed() bool {
	return m.Type == MultipathMappedAddrTypeMixed
}
