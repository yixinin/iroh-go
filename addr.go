package iroh

import "github.com/yixinin/iroh-go/crypto"

type Addr struct {
	endpointId *crypto.EndpointId
}

func NewAddr(endpointId *crypto.EndpointId) *Addr {
	return &Addr{
		endpointId: endpointId,
	}
}

func (a *Addr) PublicKey() *crypto.PublicKey {
	return a.endpointId
}

// Network 获取网络类型
func (a *Addr) Network() string {
	return "iroh"
}

// String 获取地址字符串
func (a *Addr) String() string {
	return a.endpointId.String()
}
