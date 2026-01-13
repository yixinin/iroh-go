package endpoint

import (
	"context"
	"fmt"
	"net"
	"time"

	"github/yixinin/iroh-go/common"
	"github/yixinin/iroh-go/crypto"
	"github/yixinin/iroh-go/magicsock"

	"github.com/quic-go/quic-go"
)

// EndpointAddr 端点地址
type EndpointAddr struct {
	Id    *crypto.EndpointId
	Addrs []common.TransportAddr
}

// Options 端点选项
type Options struct {
	RelayMode common.RelayMode
	SecretKey *crypto.SecretKey
	ALPNs     [][]byte
}

// RelayMode 中继模式

const (
	// RelayModeDisabled 禁用中继
	RelayModeDisabled common.RelayMode = common.RelayModeDisabled
	// RelayModeDefault 默认中继
	RelayModeDefault common.RelayMode = common.RelayModeDefault
	// RelayModeStaging 测试中继
	RelayModeStaging common.RelayMode = common.RelayModeStaging
	// RelayModeCustom 自定义中继
	RelayModeCustom common.RelayMode = common.RelayModeCustom
)

// Endpoint 控制iroh端点，与其他端点建立连接
type Endpoint struct {
	msock     *magicsock.MagicSock
	id        *crypto.EndpointId
	secretKey *crypto.SecretKey
}

// NewEndpoint 创建新的端点
func NewEndpoint(opts Options) (*Endpoint, error) {
	// 创建魔法套接字
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

// Listener 实现net.Listener接口的结构

type Listener struct {
	endpoint   *Endpoint
	incomingCh <-chan *Incoming
}

// NewListener 创建新的Listener
func NewListener(endpoint *Endpoint) (*Listener, error) {
	incomingCh, err := endpoint.Accept()
	if err != nil {
		return nil, err
	}
	return &Listener{
		endpoint:   endpoint,
		incomingCh: incomingCh,
	}, nil
}

// Accept 接受连接
func (l *Listener) Accept() (net.Conn, error) {
	incoming, ok := <-l.incomingCh
	if !ok {
		return nil, net.ErrClosed
	}

	// 输出连接信息
	if incoming.RemoteId() != nil {
		fmt.Printf("[Iroh] New connection established: Remote ID = %s, ALPN = %s\n",
			incoming.RemoteId().String(), string(incoming.ALPN()))
	} else {
		fmt.Printf("[Iroh] New connection established: Remote ID = unknown, ALPN = %s\n",
			string(incoming.ALPN()))
	}

	return &Conn{
		conn:     incoming.Conn(),
		remoteId: incoming.RemoteId(),
		alpn:     incoming.ALPN(),
	}, nil
}

// Close 关闭Listener
func (l *Listener) Close() error {
	return l.endpoint.Close()
}

// Addr 获取Listener地址
func (l *Listener) Addr() net.Addr {
	return &Addr{
		id: "iroh://" + l.endpoint.ID().String(),
	}
}

// Conn 实现net.Conn接口的结构

type Conn struct {
	conn     quic.Connection
	remoteId *crypto.EndpointId
	alpn     []byte
	stream   quic.Stream
}

// Read 读取数据
func (c *Conn) Read(b []byte) (n int, err error) {
	if c.stream == nil {
		stream, err := c.conn.AcceptStream(context.Background())
		if err != nil {
			return 0, err
		}
		c.stream = stream
	}
	return c.stream.Read(b)
}

// Write 写入数据
func (c *Conn) Write(b []byte) (n int, err error) {
	if c.stream == nil {
		stream, err := c.conn.OpenStream()
		if err != nil {
			return 0, err
		}
		c.stream = stream
	}
	return c.stream.Write(b)
}

// Close 关闭连接
func (c *Conn) Close() error {
	if c.stream != nil {
		c.stream.Close()
	}
	return c.conn.CloseWithError(0, "")
}

// LocalAddr 获取本地地址
func (c *Conn) LocalAddr() net.Addr {
	return &Addr{
		id: c.conn.LocalAddr().String(),
	}
}

// RemoteAddr 获取远程地址
func (c *Conn) RemoteAddr() net.Addr {
	if c.remoteId != nil {
		return &Addr{
			id: "iroh://" + c.remoteId.String(),
		}
	}
	return &Addr{
		id: "iroh://unknown",
	}
}

// SetDeadline 设置截止时间
func (c *Conn) SetDeadline(t time.Time) error {
	// QUIC连接不支持设置截止时间
	return nil
}

// SetReadDeadline 设置读取截止时间
func (c *Conn) SetReadDeadline(t time.Time) error {
	// QUIC流不支持设置截止时间
	return nil
}

// SetWriteDeadline 设置写入截止时间
func (c *Conn) SetWriteDeadline(t time.Time) error {
	// QUIC流不支持设置截止时间
	return nil
}

// Addr 实现net.Addr接口的结构

type Addr struct {
	id string
}

// Network 获取网络类型
func (a *Addr) Network() string {
	return "iroh"
}

// String 获取地址字符串
func (a *Addr) String() string {
	return a.id
}
