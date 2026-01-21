package magicsock

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/quic-go/quic-go"
)

type QuicConnection struct {
	*MagicSock
}

func NewQuicConnection(magicSock net.PacketConn, addr net.Addr, tls *tls.Config, conf *quic.Config) (quic.Connection, error) {
	conn, err := quic.DialEarly(context.TODO(), magicSock, addr, tls, conf)
	return conn, err
}
