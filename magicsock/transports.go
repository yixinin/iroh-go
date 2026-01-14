package magicsock

import (
	"fmt"
	"net"

	"github/yixinin/iroh-go/common"
	"github/yixinin/iroh-go/crypto"
)

// Addr 传输地址
type Addr struct {
	inner addrInner
}

// addrInner 地址内部实现
type addrInner interface {
	String() string
	Equals(other addrInner) bool
	IsIP() bool
	IsRelay() bool
	ToSocketAddr() *net.UDPAddr
}

// AddrIP IP地址实现
type AddrIP struct {
	Addr *net.UDPAddr
}

// AddrRelay 中继地址实现
type AddrRelay struct {
	Url    string
	NodeId *crypto.EndpointId
}

// String 获取地址字符串
func (a *AddrIP) String() string {
	if a.Addr != nil {
		return a.Addr.String()
	}
	return ""
}

// Equals 比较两个地址是否相等
func (a *AddrIP) Equals(other addrInner) bool {
	if otherIp, ok := other.(*AddrIP); ok {
		if a.Addr == nil || otherIp.Addr == nil {
			return a.Addr == otherIp.Addr
		}
		return a.Addr.String() == otherIp.Addr.String()
	}
	return false
}

// IsIP 检查是否为IP地址
func (a *AddrIP) IsIP() bool {
	return true
}

// IsRelay 检查是否为中继地址
func (a *AddrIP) IsRelay() bool {
	return false
}

// ToSocketAddr 转换为SocketAddr
func (a *AddrIP) ToSocketAddr() *net.UDPAddr {
	return a.Addr
}

// String 获取地址字符串
func (a *AddrRelay) String() string {
	if a.NodeId == nil {
		return fmt.Sprintf("relay:@%s", a.Url)
	}
	return fmt.Sprintf("relay:%s@%s", a.NodeId.String(), a.Url)
}

// Equals 比较两个地址是否相等
func (a *AddrRelay) Equals(other addrInner) bool {
	if otherRelay, ok := other.(*AddrRelay); ok {
		if a.NodeId == nil || otherRelay.NodeId == nil {
			return a.NodeId == otherRelay.NodeId && a.Url == otherRelay.Url
		}
		return a.Url == otherRelay.Url && a.NodeId.String() == otherRelay.NodeId.String()
	}
	return false
}

// IsIP 检查是否为IP地址
func (a *AddrRelay) IsIP() bool {
	return false
}

// IsRelay 检查是否为中继地址
func (a *AddrRelay) IsRelay() bool {
	return true
}

// ToSocketAddr 转换为SocketAddr
func (a *AddrRelay) ToSocketAddr() *net.UDPAddr {
	return nil
}

// String 获取地址字符串
func (a *Addr) String() string {
	if a.inner != nil {
		return a.inner.String()
	}
	return ""
}

// Equals 比较两个地址是否相等
func (a *Addr) Equals(other *Addr) bool {
	if a == nil || other == nil {
		return a == other
	}
	if a.inner == nil || other.inner == nil {
		return a.inner == other.inner
	}
	return a.inner.Equals(other.inner)
}

// IsIP 检查是否为IP地址
func (a *Addr) IsIP() bool {
	if a.inner != nil {
		return a.inner.IsIP()
	}
	return false
}

// IsRelay 检查是否为中继地址
func (a *Addr) IsRelay() bool {
	if a.inner != nil {
		return a.inner.IsRelay()
	}
	return false
}

// ToSocketAddr 转换为SocketAddr
func (a *Addr) ToSocketAddr() *net.UDPAddr {
	if a.inner != nil {
		return a.inner.ToSocketAddr()
	}
	return nil
}

// NewAddrFromIP 从IP地址创建Addr
func NewAddrFromIP(ip *net.UDPAddr) *Addr {
	return &Addr{
		inner: &AddrIP{Addr: ip},
	}
}

// NewAddrFromRelay 从中继地址创建Addr
func NewAddrFromRelay(url string, nodeId *crypto.EndpointId) *Addr {
	return &Addr{
		inner: &AddrRelay{Url: url, NodeId: nodeId},
	}
}

// Transport 传输接口
type Transport interface {
	Type() TransportType
	Addr() string
	Close() error
	LocalAddr() string
	BindAddr() string
}

// TransportSender 传输发送接口
type TransportSender interface {
	Send(dst *Addr, data []byte) error
}

// NetworkChangeSender 网络变化发送接口
type NetworkChangeSender interface {
	OnNetworkChange() error
	Rebind() error
}

// NetworkChangeManager 网络变化管理器
type NetworkChangeManager struct {
	ipSenders    []NetworkChangeSender
	relaySenders []NetworkChangeSender
}

// NewNetworkChangeManager 创建新的网络变化管理器
func NewNetworkChangeManager() *NetworkChangeManager {
	return &NetworkChangeManager{
		ipSenders:    make([]NetworkChangeSender, 0),
		relaySenders: make([]NetworkChangeSender, 0),
	}
}

// AddIPSender 添加 IP 网络变化发送器
func (n *NetworkChangeManager) AddIPSender(sender NetworkChangeSender) {
	n.ipSenders = append(n.ipSenders, sender)
}

// AddRelaySender 添加中继网络变化发送器
func (n *NetworkChangeManager) AddRelaySender(sender NetworkChangeSender) {
	n.relaySenders = append(n.relaySenders, sender)
}

// OnNetworkChange 处理网络变化
func (n *NetworkChangeManager) OnNetworkChange() error {
	for _, sender := range n.ipSenders {
		if err := sender.OnNetworkChange(); err != nil {
			return err
		}
	}

	for _, sender := range n.relaySenders {
		if err := sender.OnNetworkChange(); err != nil {
			return err
		}
	}

	return nil
}

// Rebind 重新绑定所有传输
func (n *NetworkChangeManager) Rebind() error {
	for _, sender := range n.ipSenders {
		if err := sender.Rebind(); err != nil {
			return err
		}
	}

	for _, sender := range n.relaySenders {
		if err := sender.Rebind(); err != nil {
			return err
		}
	}

	return nil
}

// TransportType 传输类型
type TransportType int

const (
	// TransportTypeIp IP传输
	TransportTypeIp TransportType = iota
	// TransportTypeRelay 中继传输
	TransportTypeRelay
)

// TransportConfig 传输配置
type TransportConfig struct {
	Type     TransportType
	BindAddr string
	RelayMap *RelayMap
}

// NewIPTransportConfig 创建 IP 传输配置
func NewIPTransportConfig(bindAddr string) *TransportConfig {
	return &TransportConfig{
		Type:     TransportTypeIp,
		BindAddr: bindAddr,
	}
}

// NewRelayTransportConfig 创建中继传输配置
func NewRelayTransportConfig(relayMap *RelayMap) *TransportConfig {
	return &TransportConfig{
		Type:     TransportTypeRelay,
		RelayMap: relayMap,
	}
}

// DefaultIPv4Config 创建默认的 IPv4 传输配置
func DefaultIPv4Config() *TransportConfig {
	return NewIPTransportConfig("0.0.0.0:0")
}

// DefaultIPv6Config 创建默认的 IPv6 传输配置
func DefaultIPv6Config() *TransportConfig {
	return NewIPTransportConfig("[::]:0")
}

// TransportIp IP传输实现
type TransportIp struct {
	addr      string
	localAddr string
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

// LocalAddr 获取本地地址
func (t *TransportIp) LocalAddr() string {
	if t.localAddr != "" {
		return t.localAddr
	}
	return t.addr
}

// BindAddr 获取绑定地址
func (t *TransportIp) BindAddr() string {
	return t.addr
}

// NewTransportIp 创建新的 IP 传输
func NewTransportIp(addr string) *TransportIp {
	return &TransportIp{
		addr: addr,
	}
}

// Send 发送数据
func (t *TransportIp) Send(dst *Addr, data []byte) error {
	if !dst.IsIP() {
		return fmt.Errorf("invalid destination address for IP transport")
	}
	// 这里只是示例实现，实际需要使用 UDP 套接字发送数据
	return nil
}

// OnNetworkChange 处理网络变化
func (t *TransportIp) OnNetworkChange() error {
	// 处理网络变化，例如重新绑定套接字
	return nil
}

// Rebind 重新绑定传输
func (t *TransportIp) Rebind() error {
	// 重新绑定套接字
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

// LocalAddr 获取本地地址
func (t *TransportRelay) LocalAddr() string {
	return t.url
}

// BindAddr 获取绑定地址
func (t *TransportRelay) BindAddr() string {
	return t.url
}

// Send 发送数据
func (t *TransportRelay) Send(dst *Addr, data []byte) error {
	if !dst.IsRelay() {
		return fmt.Errorf("invalid destination address for relay transport")
	}
	// 这里只是示例实现，实际需要使用中继服务发送数据
	return nil
}

// OnNetworkChange 处理网络变化
func (t *TransportRelay) OnNetworkChange() error {
	// 处理网络变化，例如重新连接中继
	return nil
}

// Rebind 重新绑定传输
func (t *TransportRelay) Rebind() error {
	// 重新连接中继
	return nil
}

// NewTransportRelay 创建新的中继传输
func NewTransportRelay(url string) *TransportRelay {
	return &TransportRelay{
		url: url,
	}
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
			"https://aps1-1.relay.n0.iroh-canary.iroh.link",
		}
	case common.RelayModeStaging:
		relays = []string{
			"https://staging-use1-1.relay.iroh.network",
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

// Transports 管理所有传输方式
type Transports struct {
	ip    []Transport
	relay []Transport
}

// NewTransports 创建新的 Transports 实例
func NewTransports() *Transports {
	return &Transports{
		ip:    make([]Transport, 0),
		relay: make([]Transport, 0),
	}
}

// NewTransportsFromConfigs 从配置创建 Transports 实例
func NewTransportsFromConfigs(configs []*TransportConfig) *Transports {
	transports := NewTransports()

	for _, config := range configs {
		switch config.Type {
		case TransportTypeIp:
			ipTransport := NewTransportIp(config.BindAddr)
			transports.AddIPTransport(ipTransport)
		case TransportTypeRelay:
			if config.RelayMap != nil {
				for _, relay := range config.RelayMap.Relays() {
					relayTransport := NewTransportRelay(relay)
					transports.AddRelayTransport(relayTransport)
				}
			}
		}
	}

	return transports
}

// AddIPTransport 添加 IP 传输
func (t *Transports) AddIPTransport(transport Transport) {
	if transport.Type() == TransportTypeIp {
		t.ip = append(t.ip, transport)
	}
}

// AddRelayTransport 添加中继传输
func (t *Transports) AddRelayTransport(transport Transport) {
	if transport.Type() == TransportTypeRelay {
		t.relay = append(t.relay, transport)
	}
}

// IPTransports 获取所有 IP 传输
func (t *Transports) IPTransports() []Transport {
	return t.ip
}

// RelayTransports 获取所有中继传输
func (t *Transports) RelayTransports() []Transport {
	return t.relay
}

// AllTransports 获取所有传输
func (t *Transports) AllTransports() []Transport {
	all := make([]Transport, 0, len(t.ip)+len(t.relay))
	all = append(all, t.ip...)
	all = append(all, t.relay...)
	return all
}

// LocalAddrs 获取所有本地地址
func (t *Transports) LocalAddrs() []string {
	addrs := make([]string, 0)
	for _, transport := range t.ip {
		addrs = append(addrs, transport.LocalAddr())
	}
	for _, transport := range t.relay {
		addrs = append(addrs, transport.LocalAddr())
	}
	return addrs
}

// CreateNetworkChangeManager 创建网络变化管理器
func (t *Transports) CreateNetworkChangeManager() *NetworkChangeManager {
	manager := NewNetworkChangeManager()

	// 添加 IP 网络变化发送器
	for _, transport := range t.ip {
		if sender, ok := transport.(NetworkChangeSender); ok {
			manager.AddIPSender(sender)
		}
	}

	// 添加中继网络变化发送器
	for _, transport := range t.relay {
		if sender, ok := transport.(NetworkChangeSender); ok {
			manager.AddRelaySender(sender)
		}
	}

	return manager
}

// CreateTransportSenders 创建传输发送器
func (t *Transports) CreateTransportSenders() []TransportSender {
	senders := make([]TransportSender, 0)

	// 添加 IP 传输发送器
	for _, transport := range t.ip {
		if sender, ok := transport.(TransportSender); ok {
			senders = append(senders, sender)
		}
	}

	// 添加中继传输发送器
	for _, transport := range t.relay {
		if sender, ok := transport.(TransportSender); ok {
			senders = append(senders, sender)
		}
	}

	return senders
}

// PollRecv 轮询接收数据
func (t *Transports) PollRecv() ([]byte, *Addr, error) {
	// 轮询所有传输，尝试接收数据
	// 这里只是示例实现，实际需要使用非阻塞 I/O 轮询所有传输
	return nil, nil, nil
}

// Send 发送数据
func (t *Transports) Send(dst *Addr, data []byte) error {
	// 根据目标地址类型选择合适的传输发送数据
	if dst.IsIP() {
		// 使用 IP 传输发送数据
		for _, transport := range t.ip {
			sender, ok := transport.(TransportSender)
			if ok {
				return sender.Send(dst, data)
			}
		}
	} else if dst.IsRelay() {
		// 使用中继传输发送数据
		for _, transport := range t.relay {
			sender, ok := transport.(TransportSender)
			if ok {
				return sender.Send(dst, data)
			}
		}
	}
	return fmt.Errorf("no suitable transport found for destination address")
}

// MagicTransport 魔法传输，用于与 QUIC 协议集成
type MagicTransport struct {
	transports *Transports
}

// NewMagicTransport 创建新的魔法传输
func NewMagicTransport(transports *Transports) *MagicTransport {
	return &MagicTransport{
		transports: transports,
	}
}

// LocalAddr 获取本地地址
func (m *MagicTransport) LocalAddr() net.Addr {
	// 返回一个合适的本地地址，用于 QUIC 协议
	// 这里只是示例实现，实际需要返回一个真实的本地地址
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	return udpAddr
}

// ReadFrom 从传输中读取数据
func (m *MagicTransport) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// 从所有传输中读取数据
	// 这里只是示例实现，实际需要使用非阻塞 I/O 读取数据
	return 0, nil, nil
}

// WriteTo 向传输中写入数据
func (m *MagicTransport) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// 向指定地址写入数据
	// 这里只是示例实现，实际需要根据地址类型选择合适的传输写入数据
	return 0, nil
}

// SetReadBuffer 设置读取缓冲区大小
func (m *MagicTransport) SetReadBuffer(bytes int) error {
	// 设置读取缓冲区大小
	return nil
}

// SetWriteBuffer 设置写入缓冲区大小
func (m *MagicTransport) SetWriteBuffer(bytes int) error {
	// 设置写入缓冲区大小
	return nil
}

// initTransports 初始化传输层
func initTransports(mode common.RelayMode, relayMap *RelayMap) (*Transports, error) {
	transports := NewTransports()

	// 添加IP传输
	ipTransport := NewTransportIp("0.0.0.0:0") // 自动分配端口
	transports.AddIPTransport(ipTransport)

	// 添加IPv6传输
	ipv6Transport := NewTransportIp("[::]:0") // 自动分配端口
	transports.AddIPTransport(ipv6Transport)

	// 添加中继传输
	if mode != common.RelayModeDisabled {
		for _, relay := range relayMap.Relays() {
			relayTransport := NewTransportRelay(relay)
			transports.AddRelayTransport(relayTransport)
		}
	}

	return transports, nil
}
