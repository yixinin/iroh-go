package magicsock

import (
	"fmt"
	"net"

	"github/yixinin/iroh-go/common"
	"github/yixinin/iroh-go/crypto"
)

// Addr 传输地址
type Addr struct {
	Type  TransportType
	Ip    *net.UDPAddr
	Relay *RelayAddr
}

// RelayAddr 中继地址
type RelayAddr struct {
	Url    string
	NodeId *crypto.EndpointId
}

// String 获取地址字符串
func (a *Addr) String() string {
	switch a.Type {
	case TransportTypeIp:
		if a.Ip != nil {
			return a.Ip.String()
		}
	case TransportTypeRelay:
		if a.Relay != nil {
			return fmt.Sprintf("relay:%s@%s", a.Relay.NodeId.String(), a.Relay.Url)
		}
	}
	return ""
}

// Equals 比较两个地址是否相等
func (a *Addr) Equals(other *Addr) bool {
	if a == nil || other == nil {
		return a == other
	}
	if a.Type != other.Type {
		return false
	}
	switch a.Type {
	case TransportTypeIp:
		if a.Ip == nil || other.Ip == nil {
			return a.Ip == other.Ip
		}
		return a.Ip.String() == other.Ip.String()
	case TransportTypeRelay:
		if a.Relay == nil || other.Relay == nil {
			return a.Relay == other.Relay
		}
		return a.Relay.Url == other.Relay.Url && a.Relay.NodeId.Equals(other.Relay.NodeId)
	}
	return false
}

// NewAddrFromIP 从IP地址创建Addr
func NewAddrFromIP(ip *net.UDPAddr) *Addr {
	return &Addr{
		Type: TransportTypeIp,
		Ip:   ip,
	}
}

// NewAddrFromRelay 从中继地址创建Addr
func NewAddrFromRelay(url string, nodeId *crypto.EndpointId) *Addr {
	return &Addr{
		Type:  TransportTypeRelay,
		Relay: &RelayAddr{Url: url, NodeId: nodeId},
	}
}

// Transport 传输接口
type Transport interface {
	Type() TransportType
	Addr() string
	Close() error
}

// TransportType 传输类型
type TransportType int

const (
	// TransportTypeIp IP传输
	TransportTypeIp TransportType = iota
	// TransportTypeRelay 中继传输
	TransportTypeRelay
)

// TransportIp IP传输实现
type TransportIp struct {
	addr string
}

// Type 获取传输类型
func (t *TransportIp) Type() TransportType {
	return TransportTypeIp
}

// Addr 获取传输地址
func (t *TransportIp) Addr() string {
	return t.addr
}

// Close 关闭传输
func (t *TransportIp) Close() error {
	return nil
}

// TransportRelay 中继传输实现
type TransportRelay struct {
	url string
}

// Type 获取传输类型
func (t *TransportRelay) Type() TransportType {
	return TransportTypeRelay
}

// Addr 获取传输地址
func (t *TransportRelay) Addr() string {
	return t.url
}

// Close 关闭传输
func (t *TransportRelay) Close() error {
	return nil
}

// RelayMap 中继映射
type RelayMap struct {
	relays []string
}

// NewRelayMap 创建新的中继映射
func NewRelayMap(mode common.RelayMode) *RelayMap {
	var relays []string

	switch mode {
	case common.RelayModeDefault:
		relays = []string{
			"https://relay.n0.computer",
		}
	case common.RelayModeStaging:
		relays = []string{
			"https://relay-staging.n0.computer",
		}
	case common.RelayModeCustom:
		// 自定义中继
		relays = []string{}
	}

	return &RelayMap{
		relays: relays,
	}
}

// Relays 获取所有中继
func (rm *RelayMap) Relays() []string {
	return rm.relays
}

// AddRelay 添加中继
func (rm *RelayMap) AddRelay(url string) {
	rm.relays = append(rm.relays, url)
}

// RemoveRelay 移除中继
func (rm *RelayMap) RemoveRelay(url string) {
	for i, relay := range rm.relays {
		if relay == url {
			rm.relays = append(rm.relays[:i], rm.relays[i+1:]...)
			break
		}
	}
}

// initTransports 初始化传输层
func initTransports(mode common.RelayMode, relayMap *RelayMap) ([]Transport, error) {
	var transports []Transport

	// 添加IP传输
	ipTransport := &TransportIp{
		addr: "0.0.0.0:0", // 自动分配端口
	}
	transports = append(transports, ipTransport)

	// 添加中继传输
	if mode != common.RelayModeDisabled {
		for _, relay := range relayMap.Relays() {
			relayTransport := &TransportRelay{
				url: relay,
			}
			transports = append(transports, relayTransport)
		}
	}

	return transports, nil
}
