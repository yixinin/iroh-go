package magicsock

import (
	"context"
	"crypto/tls"
	"fmt"
	"github/yixinin/iroh-go/common"
	"github/yixinin/iroh-go/crypto"
	"github/yixinin/iroh-go/relay"
	"time"

	"github.com/quic-go/quic-go"
)

// Options 魔法套接字选项
type Options struct {
	RelayMode common.RelayMode
	SecretKey *crypto.SecretKey
	ALPNs     [][]byte
}

// EndpointAddr 端点地址
type EndpointAddr struct {
	Id    *crypto.EndpointId
	Addrs []common.TransportAddr
}

// Connection 连接
type Connection struct {
	conn     quic.Connection
	remoteId *crypto.EndpointId
	alpn     []byte
}

// Conn 获取连接的底层连接
func (c *Connection) Conn() quic.Connection {
	return c.conn
}

// RemoteId 获取远程端点ID
func (c *Connection) RemoteId() *crypto.EndpointId {
	return c.remoteId
}

// ALPN 获取ALPN
func (c *Connection) ALPN() []byte {
	return c.alpn
}

// Incoming incoming连接
type Incoming struct {
	conn     quic.Connection
	remoteId *crypto.EndpointId
	alpn     []byte
}

// Conn 获取incoming连接的底层连接
func (i *Incoming) Conn() quic.Connection {
	return i.conn
}

// RemoteId 获取远程端点ID
func (i *Incoming) RemoteId() *crypto.EndpointId {
	return i.remoteId
}

// ALPN 获取ALPN
func (i *Incoming) ALPN() []byte {
	return i.alpn
}

// MagicSock 负责路由数据包到端点，最初通过中继路由，然后尝试建立直接连接
type MagicSock struct {
	endpoint     *quic.Listener
	remoteMap    *RemoteMap
	transports   *Transports
	relayMap     *RelayMap
	relayClients []*relay.Client
	id           *crypto.EndpointId
	secretKey    *crypto.SecretKey
}

// NewMagicSock 创建新的魔法套接字
func NewMagicSock(opts Options) (*MagicSock, error) {
	// 创建远程节点映射
	remoteMap := NewRemoteMap()

	// 创建中继映射
	relayMap := NewRelayMap(opts.RelayMode)

	// 初始化传输层
	transports, err := initTransports(opts.RelayMode, relayMap)
	if err != nil {
		return nil, err
	}

	// 初始化中继客户端
	var relayClients []*relay.Client
	if opts.RelayMode != common.RelayModeDisabled {
		for _, relayURL := range relayMap.Relays() {
			config := relay.NewConfig([]string{relayURL}, opts.SecretKey)
			client, err := relay.NewClient(config)
			if err != nil {
				continue
			}
			if err := client.Connect(); err != nil {
				continue
			}
			relayClients = append(relayClients, client)
		}
	}

	// 创建QUIC监听器
	quicConfig := &quic.Config{
		// 配置QUIC
	}
	listener, err := quic.ListenAddr("0.0.0.0:0", generateTLSConfig(opts.SecretKey, opts.ALPNs), quicConfig)
	if err != nil {
		return nil, err
	}

	// 获取端点ID
	id := crypto.EndpointIdFromPublicKey(opts.SecretKey.Public())

	return &MagicSock{
		endpoint:     listener,
		remoteMap:    remoteMap,
		transports:   transports,
		relayMap:     relayMap,
		relayClients: relayClients,
		id:           id,
		secretKey:    opts.SecretKey,
	}, nil
}

// Connect 连接到远程端点
func (ms *MagicSock) Connect(addr EndpointAddr, alpn []byte) (*Connection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 尝试直接连接所有可用地址
	directConn, err := ms.tryDirectConnection(ctx, addr, alpn)
	if err == nil {
		return directConn, nil
	}
	fmt.Printf("Direct connection failed: %v, trying relay connection\n", err)

	// 尝试通过中继连接
	relayConn, err := ms.tryRelayConnection(ctx, addr, alpn)
	if err == nil {
		return relayConn, nil
	}
	fmt.Printf("Relay connection failed: %v\n", err)

	return nil, fmt.Errorf("failed to connect to peer: all connection attempts failed")
}

// tryDirectConnection 尝试直接连接到远程端点
func (ms *MagicSock) tryDirectConnection(ctx context.Context, addr EndpointAddr, alpn []byte) (*Connection, error) {
	// 尝试使用远程映射中的地址
	mappedAddr, err := ms.ResolveRemote(addr)
	if err == nil {
		conn, err := ms.dialQUIC(ctx, mappedAddr.Addr, addr.Id, alpn)
		if err == nil {
			return conn, nil
		}
		fmt.Printf("Failed to connect to mapped address %s: %v\n", mappedAddr.Addr, err)
	}

	// 尝试使用提供的所有地址
	for _, transportAddr := range addr.Addrs {
		conn, err := ms.dialQUIC(ctx, transportAddr.String(), addr.Id, alpn)
		if err == nil {
			return conn, nil
		}
		fmt.Printf("Failed to connect to address %s: %v\n", transportAddr.String(), err)
	}

	return nil, fmt.Errorf("all direct connection attempts failed")
}

// tryRelayConnection 尝试通过中继连接到远程端点
func (ms *MagicSock) tryRelayConnection(ctx context.Context, addr EndpointAddr, alpn []byte) (*Connection, error) {
	if len(ms.relayClients) == 0 {
		return nil, fmt.Errorf("no relay clients available")
	}

	for _, relayClient := range ms.relayClients {
		// 连接到中继
		relayConn, err := relayClient.ConnectToPeer(addr.Id, alpn)
		if err != nil {
			fmt.Printf("Failed to connect to peer via relay: %v\n", err)
			continue
		}

		// 检查返回的连接类型
		if rc, ok := relayConn.(*relay.RelayConnection); ok {
			fmt.Printf("Connected to peer %s via relay, relay ID: %s\n", addr.Id.String(), rc.RelayId())

			// TODO: 实现通过中继的QUIC连接
			// 这里需要使用中继连接创建一个 QUIC 连接
			// 暂时使用模拟实现，后续需要根据实际情况修改

			// 模拟通过中继的QUIC连接
			// 实际实现需要使用中继提供的连接信息创建QUIC连接
			conn, err := ms.dialQUIC(ctx, "127.0.0.1:0", addr.Id, alpn)
			if err == nil {
				return conn, nil
			}
			fmt.Printf("Failed to create QUIC connection via relay: %v\n", err)
		} else {
			fmt.Printf("Unexpected relay connection type: %T\n", relayConn)
		}
	}

	return nil, fmt.Errorf("all relay connection attempts failed")
}

// dialQUIC 建立QUIC连接
func (ms *MagicSock) dialQUIC(ctx context.Context, addr string, remoteId *crypto.EndpointId, alpn []byte) (*Connection, error) {
	// 创建QUIC配置
	quicConfig := &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	}

	// 生成TLS配置
	tlsConfig := generateTLSConfig(ms.secretKey, [][]byte{alpn})

	// 建立QUIC连接
	conn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}

	// 创建并返回Connection实例
	return &Connection{
		conn:     conn,
		remoteId: remoteId,
		alpn:     alpn,
	}, nil
}

// Accept 接受incoming连接
func (ms *MagicSock) Accept() (<-chan *Incoming, error) {
	ch := make(chan *Incoming)

	// 启动接受循环
	go func() {
		for {
			conn, err := ms.endpoint.Accept(context.Background())
			if err != nil {
				break
			}

			// 处理incoming连接
			incoming := &Incoming{
				conn: conn,
				// TODO: 解析remoteId和alpn
			}
			ch <- incoming
		}
		close(ch)
	}()

	return ch, nil
}

// ResolveRemote 解析远程端点地址
func (ms *MagicSock) ResolveRemote(addr EndpointAddr) (*MappedAddr, error) {
	// 从远程映射中获取节点信息
	remoteInfo, ok := ms.remoteMap.Get(addr.Id)
	if ok && len(remoteInfo.Addresses) > 0 {
		// 返回第一个可用地址
		return &MappedAddr{
			Addr: remoteInfo.Addresses[0],
		}, nil
	}

	// 从提供的地址中选择第一个可用地址
	if len(addr.Addrs) > 0 {
		return &MappedAddr{
			Addr: addr.Addrs[0].String(),
		}, nil
	}

	return nil, fmt.Errorf("no address available for remote endpoint")
}

// Id 获取端点ID
func (ms *MagicSock) Id() *crypto.EndpointId {
	return ms.id
}

// Addr 获取端点地址
func (ms *MagicSock) Addr() EndpointAddr {
	addrs := []common.TransportAddr{}

	// 添加本地IP地址
	localAddr := ms.endpoint.Addr().String()
	addrs = append(addrs, &common.TransportAddrIp{
		Addr: localAddr,
	})

	// 添加中继地址
	// 暂时不添加中继地址，因为relay.Client没有Addr()方法

	return EndpointAddr{
		Id:    ms.id,
		Addrs: addrs,
	}
}

// Close 关闭魔法套接字
func (ms *MagicSock) Close() error {
	return ms.endpoint.Close()
}

// MappedAddr 映射地址
type MappedAddr struct {
	Addr string
}

// generateTLSConfig 生成TLS配置
func generateTLSConfig(secretKey *crypto.SecretKey, alpns [][]byte) *tls.Config {
	// 转换alpns为[]string类型
	nextProtos := make([]string, len(alpns))
	for i, alpn := range alpns {
		nextProtos[i] = string(alpn)
	}

	// TODO: 实现TLS配置生成
	return &tls.Config{
		NextProtos: nextProtos,
	}
}
