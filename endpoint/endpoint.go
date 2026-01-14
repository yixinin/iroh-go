package endpoint

import (
	"net"

	"github/yixinin/iroh-go/common"
	"github/yixinin/iroh-go/crypto"
	"github/yixinin/iroh-go/magicsock"

	"github.com/quic-go/quic-go"
)

const (
	// DefaultRelayMode 默认中继模式
	DefaultRelayMode = common.RelayModeDefault
	// DefaultALPN 默认 ALPN 协议
	DefaultALPN = "h3"
	// DefaultInsecureSkipCertVerify 默认是否跳过证书验证
	DefaultInsecureSkipCertVerify = false
)

// EndpointAddr 端点地址
type EndpointAddr struct {
	Id    *crypto.EndpointId
	Addrs []common.TransportAddr
}

// Options 端点选项
type Options struct {
	RelayMode              common.RelayMode
	SecretKey              *crypto.SecretKey
	ALPNs                  [][]byte
	RelayUrls              []string
	DnsResolver            *net.Resolver
	AddressFamilySelector  func() bool
	InsecureSkipCertVerify bool
}

// Endpoint 控制iroh端点，与其他端点建立连接
type Endpoint struct {
	msock     *magicsock.MagicSock
	id        *crypto.EndpointId
	secretKey *crypto.SecretKey
}

// NewEndpoint 创建新的端点
func NewEndpoint(opts Options) (*Endpoint, error) {
	// 应用默认值
	if opts.DnsResolver == nil {
		opts.DnsResolver = net.DefaultResolver
	}
	if opts.AddressFamilySelector == nil {
		opts.AddressFamilySelector = func() bool { return false }
	}

	// 创建魔法套接字（magicsock 会应用自己的默认值）
	msockOpts := magicsock.Options{
		RelayMode: common.RelayMode(opts.RelayMode),
		SecretKey: opts.SecretKey,
		ALPNs:     opts.ALPNs,
	}
	msock, err := magicsock.NewMagicSock(msockOpts)
	if err != nil {
		return nil, err
	}

	// 获取端点ID
	var id *crypto.EndpointId
	if opts.SecretKey != nil {
		id = crypto.EndpointIdFromPublicKey(opts.SecretKey.Public())
	} else {
		id = msock.Id()
	}

	return &Endpoint{
		msock:     msock,
		id:        id,
		secretKey: opts.SecretKey,
	}, nil
}

// Connect 连接到远程端点
func (e *Endpoint) Connect(addr EndpointAddr, alpn []byte) (*Connection, error) {
	// 转换为magicsock.EndpointAddr
	msAddr := magicsock.EndpointAddr{
		Id:    addr.Id,
		Addrs: addr.Addrs,
	}

	// 连接到远程端点
	msConn, err := e.msock.Connect(msAddr, alpn)
	if err != nil {
		return nil, err
	}

	// 转换为endpoint.Connection
	return &Connection{
		conn:     msConn.Conn(),
		remoteId: msConn.RemoteId(),
		alpn:     msConn.ALPN(),
	}, nil
}

// Accept 接受incoming连接
func (e *Endpoint) Accept() (<-chan *Incoming, error) {
	// 接受incoming连接
	msIncomingCh, err := e.msock.Accept()
	if err != nil {
		return nil, err
	}

	// 转换为endpoint.Incoming
	ch := make(chan *Incoming)
	go func() {
		for msIncoming := range msIncomingCh {
			incoming := &Incoming{
				conn:     msIncoming.Conn(),
				remoteId: msIncoming.RemoteId(),
				alpn:     msIncoming.ALPN(),
			}
			ch <- incoming
		}
		close(ch)
	}()

	return ch, nil
}

// ID 获取端点ID
func (e *Endpoint) ID() *crypto.EndpointId {
	return e.id
}

// Close 关闭端点
func (e *Endpoint) Close() error {
	return e.msock.Close()
}

// Addr 获取端点地址
func (e *Endpoint) Addr() EndpointAddr {
	// 获取magicsock.EndpointAddr
	msAddr := e.msock.Addr()

	// 转换为endpoint.EndpointAddr
	return EndpointAddr{
		Id:    msAddr.Id,
		Addrs: msAddr.Addrs,
	}
}

// Conn 获取连接的底层连接
func (c *Connection) Conn() interface{} {
	return c.conn
}

// RemoteId 获取远程端点ID
func (c *Connection) RemoteId() *crypto.EndpointId {
	return c.remoteId
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
