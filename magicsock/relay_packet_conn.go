package magicsock

import (
	"net"
	"time"

	"github.com/yixinin/iroh-go/relay"
)

type RelayPacketConn struct {
	client *relay.Client
}

func NewRelayPacketConn(client *relay.Client) *RelayPacketConn {
	return &RelayPacketConn{
		client: client,
	}
}

func (r *RelayPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = r.client.Read(p)
	if err != nil {
		return 0, nil, err
	}

	localAddr, _ := net.ResolveUDPAddr("udp", r.client.LocalAddr())
	return n, localAddr, nil
}

func (r *RelayPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return r.client.Write(p)
}

func (r *RelayPacketConn) Close() error {
	return r.client.Close()
}

func (r *RelayPacketConn) LocalAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", r.client.LocalAddr())
	return addr
}

func (r *RelayPacketConn) SetDeadline(t time.Time) error {
	return r.client.SetWriteDeadline(t)
}

func (r *RelayPacketConn) SetReadDeadline(t time.Time) error {
	return r.client.SetReadDeadline(t)
}

func (r *RelayPacketConn) SetWriteDeadline(t time.Time) error {
	return r.client.SetWriteDeadline(t)
}
