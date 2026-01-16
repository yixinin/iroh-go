package endpoint

import (
	"context"
	"net"

	"github.com/yixinin/iroh-go/crypto"

	"github.com/quic-go/quic-go"
)

// Connection 表示与远程端点的连接
type Connection struct {
	conn     quic.Connection
	remoteId *crypto.EndpointId
	alpn     []byte
}

// NewConnection 创建新的连接
func NewConnection(conn quic.Connection, remoteId *crypto.EndpointId, alpn []byte) *Connection {
	return &Connection{
		conn:     conn,
		remoteId: remoteId,
		alpn:     alpn,
	}
}

// Incoming 表示incoming连接
type Incoming struct {
	conn     quic.Connection
	remoteId *crypto.EndpointId
	alpn     []byte
}

// NewIncoming 创建新的incoming连接
func NewIncoming(conn quic.Connection, remoteId *crypto.EndpointId, alpn []byte) *Incoming {
	return &Incoming{
		conn:     conn,
		remoteId: remoteId,
		alpn:     alpn,
	}
}

// OpenBi 打开双向流
func (c *Connection) OpenBi() (quic.Stream, error) {
	return c.conn.OpenStream()
}

// OpenUni 打开单向流
func (c *Connection) OpenUni() (quic.SendStream, error) {
	return c.conn.OpenUniStream()
}

// AcceptBi 接受双向流
func (c *Connection) AcceptBi(ctx context.Context) (quic.Stream, error) {
	return c.conn.AcceptStream(ctx)
}

// AcceptUni 接受单向流
func (c *Connection) AcceptUni(ctx context.Context) (quic.ReceiveStream, error) {
	return c.conn.AcceptUniStream(ctx)
}

// RemoteId 获取远程端点ID
func (c *Connection) RemoteId() *crypto.EndpointId {
	return c.remoteId
}

// ALPN 获取ALPN
func (c *Connection) ALPN() []byte {
	return c.alpn
}

// Close 关闭连接
func (c *Connection) Close() error {
	return c.conn.CloseWithError(0, "")
}

// CloseWithError 带错误码关闭连接
func (c *Connection) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	return c.conn.CloseWithError(code, reason)
}

// Context 获取连接的上下文
func (c *Connection) Context() context.Context {
	return c.conn.Context()
}

// ConnectionState 获取连接状态
func (c *Connection) ConnectionState() quic.ConnectionState {
	return c.conn.ConnectionState()
}

// LocalAddr 获取本地地址
func (c *Connection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr 获取远程地址
func (c *Connection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// Conn 获取底层QUIC连接
func (c *Connection) Conn() quic.Connection {
	return c.conn
}

// RemoteId 获取远程端点ID
func (i *Incoming) RemoteId() *crypto.EndpointId {
	return i.remoteId
}

// ALPN 获取ALPN
func (i *Incoming) ALPN() []byte {
	return i.alpn
}

// Conn 获取底层QUIC连接
func (i *Incoming) Conn() quic.Connection {
	return i.conn
}

// Accept 接受连接并返回Connection
func (i *Incoming) Accept() (*Connection, error) {
	return NewConnection(i.conn, i.remoteId, i.alpn), nil
}

// OpenBi 打开双向流
func (i *Incoming) OpenBi() (quic.Stream, error) {
	return i.conn.OpenStream()
}

// OpenUni 打开单向流
func (i *Incoming) OpenUni() (quic.SendStream, error) {
	return i.conn.OpenUniStream()
}
