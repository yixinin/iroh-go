package iroh

import (
	"net"

	"github.com/yixinin/iroh-go/crypto"
)

type Addr struct {
	udpAddr    *net.UDPAddr
	endpointId *crypto.EndpointId
}

func NewAddr(endpointId *crypto.EndpointId, udpAddr *net.UDPAddr) *Addr {
	return &Addr{
		endpointId: endpointId,
		udpAddr:    udpAddr,
	}
}

func (a *Addr) PublicKey() *crypto.PublicKey {
	return a.endpointId
}

// Network 获取网络类型
func (a *Addr) Network() string {
	if a.udpAddr != nil {
		return a.udpAddr.Network()
	}
	return "iroh"
}

// String 获取地址字符串
func (a *Addr) String() string {
	if a.udpAddr != nil {
		return a.udpAddr.String()
	}
	return a.endpointId.String()
}
