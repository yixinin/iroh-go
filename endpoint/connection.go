package endpoint

import (
	"context"
	"github/yixinin/iroh-go/crypto"

	"github.com/quic-go/quic-go"
)

// Connection 表示与远程端点的连接
type Connection struct {
	conn     quic.Connection
	remoteId *crypto.EndpointId
	alpn     []byte
}

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

// OpenBi 打开双向流
func (c *Connection) OpenBi() (quic.Stream, error) {
	return c.conn.OpenStream()
}

// AcceptBi 接受双向流
func (c *Connection) AcceptBi() (quic.Stream, error) {
	return c.conn.AcceptStream(context.Background())
}

// RemoteID 获取远程端点ID
func (c *Connection) RemoteID() *crypto.EndpointId {
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

// Context 获取连接的上下文
func (c *Connection) Context() interface{} {
	return c.conn.Context()
}
