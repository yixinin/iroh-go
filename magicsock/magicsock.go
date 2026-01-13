package magicsock

import (
	"context"
	"crypto/tls"
	"fmt"
	"github/yixinin/iroh-go/common"
	"github/yixinin/iroh-go/crypto"
	"github/yixinin/iroh-go/relay"

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
	transports   []Transport
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
	// 尝试直接连接
	mappedAddr, err := ms.ResolveRemote(addr)
	if err == nil {
		conn, err := quic.DialAddr(context.Background(), mappedAddr.Addr, generateTLSConfig(ms.secretKey, [][]byte{alpn}), &quic.Config{})
		if err == nil {
			return &Connection{
				conn:     conn,
				remoteId: addr.Id,
				alpn:     alpn,
			}, nil
		}
	}

	// 尝试通过中继连接
	for _, relayClient := range ms.relayClients {
		_, err := relayClient.ConnectToPeer(addr.Id, alpn)
		if err == nil {
			// TODO: 实现通过中继的QUIC连接
			// 暂时返回错误，后续实现
			continue
		}
	}

	return nil, fmt.Errorf("failed to connect to peer: all connection attempts failed")
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
	// TODO: 实现地址解析逻辑
	return &MappedAddr{
		Addr: "127.0.0.1:0", // 临时返回
	}, nil
}

// Id 获取端点ID
func (ms *MagicSock) Id() *crypto.EndpointId {
	return ms.id
}

// Addr 获取端点地址
func (ms *MagicSock) Addr() EndpointAddr {
	// TODO: 实现地址获取逻辑
	return EndpointAddr{
		Id:    ms.id,
		Addrs: []common.TransportAddr{},
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
