package endpoint

import (
	"context"
	"fmt"
	"github.com/yixinin/iroh-go/crypto"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

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
	sync.Mutex
	conn     quic.Connection
	remoteId *crypto.EndpointId
	alpn     []byte
	stream   quic.Stream
}

func (c *Conn) getStream() (quic.Stream, error) {
	c.Lock()
	defer c.Unlock()
	if c.stream == nil {
		stream, err := c.conn.AcceptStream(context.Background())
		if err != nil {
			return nil, err
		}
		c.stream = stream
	}
	return c.stream, nil
}

// Read 读取数据
func (c *Conn) Read(b []byte) (n int, err error) {
	stream, err := c.getStream()
	if err != nil {
		return 0, err
	}
	return stream.Read(b)
}

// Write 写入数据
func (c *Conn) Write(b []byte) (n int, err error) {
	stream, err := c.getStream()
	if err != nil {
		return 0, err
	}
	return stream.Write(b)
}

// Close 关闭连接
func (c *Conn) Close() error {
	c.Lock()
	defer c.Unlock()
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
