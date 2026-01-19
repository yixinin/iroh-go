package endpoint

import (
	"context"
	"errors"
	"net"

	"github.com/yixinin/iroh-go/crypto"
	"github.com/yixinin/iroh-go/relay"

	"github.com/quic-go/quic-go"
)

// Connection 表示与远程端点的连接
type Connection struct {
	conn     quic.Connection
	relay    *relay.RelayConnection
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

// NewRelayConnection 创建新的 relay 连接
func NewRelayConnection(relayConn *relay.RelayConnection, remoteId *crypto.EndpointId, alpn []byte) *Connection {
	return &Connection{
		relay:    relayConn,
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
	if c.conn == nil {
		return nil, errors.New("relay connections do not support direct stream operations")
	}
	return c.conn.OpenStream()
}

// OpenUni 打开单向流
func (c *Connection) OpenUni() (quic.SendStream, error) {
	if c.conn == nil {
		return nil, errors.New("relay connections do not support direct stream operations")
	}
	return c.conn.OpenUniStream()
}

// AcceptBi 接受双向流
func (c *Connection) AcceptBi(ctx context.Context) (quic.Stream, error) {
	if c.conn == nil {
		return nil, errors.New("relay connections do not support direct stream operations")
	}
	return c.conn.AcceptStream(ctx)
}

// AcceptUni 接受单向流
func (c *Connection) AcceptUni(ctx context.Context) (quic.ReceiveStream, error) {
	if c.conn == nil {
		return nil, errors.New("relay connections do not support direct stream operations")
	}
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
	if c.conn != nil {
		return c.conn.CloseWithError(0, "")
	}
	if c.relay != nil {
		return c.relay.Close()
	}
	return nil
}

// CloseWithError 带错误码关闭连接
func (c *Connection) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	if c.conn != nil {
		return c.conn.CloseWithError(code, reason)
	}
	if c.relay != nil {
		return c.relay.Close()
	}
	return nil
}

// Context 获取连接的上下文
func (c *Connection) Context() context.Context {
	if c.conn != nil {
		return c.conn.Context()
	}
	return context.Background()
}

// ConnectionState 获取连接状态
func (c *Connection) ConnectionState() quic.ConnectionState {
	if c.conn != nil {
		return c.conn.ConnectionState()
	}
	return quic.ConnectionState{}
}

// LocalAddr 获取本地地址
func (c *Connection) LocalAddr() net.Addr {
	if c.conn != nil {
		return c.conn.LocalAddr()
	}
	return nil
}

// RemoteAddr 获取远程地址
func (c *Connection) RemoteAddr() net.Addr {
	if c.conn != nil {
		return c.conn.RemoteAddr()
	}
	return nil
}

// Conn 获取底层QUIC连接
func (c *Connection) Conn() quic.Connection {
	return c.conn
}

// Relay 获取底层Relay连接
func (c *Connection) Relay() *relay.RelayConnection {
	return c.relay
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
