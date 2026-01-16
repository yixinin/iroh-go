package common

import (
	"github.com/yixinin/iroh-go/crypto"
)

// EndpointAddr 端点地址
type EndpointAddr struct {
	Id    *crypto.EndpointId
	Addrs []TransportAddr
}

// TransportAddr 传输地址接口
type TransportAddr interface {
	String() string
}

// TransportAddrIp IP传输地址
type TransportAddrIp struct {
	Addr string
}

// String 获取IP传输地址的字符串表示
func (a *TransportAddrIp) String() string {
	return a.Addr
}

// TransportAddrRelay 中继传输地址
type TransportAddrRelay struct {
	Url string
}

// String 获取中继传输地址的字符串表示
func (a *TransportAddrRelay) String() string {
	return a.Url
}

// RelayMode 中继模式
type RelayMode int

const (
	// RelayModeDisabled 禁用中继
	RelayModeDisabled RelayMode = iota
	// RelayModeDefault 默认中继
	RelayModeDefault
	// RelayModeStaging 测试中继
	RelayModeStaging
	// RelayModeCustom 自定义中继
	RelayModeCustom
)

// RelayModeFromString 从字符串解析中继模式
func RelayModeFromString(s string) RelayMode {
	switch s {
	case "disabled":
		return RelayModeDisabled
	case "default":
		return RelayModeDefault
	case "staging":
		return RelayModeStaging
	case "custom":
		return RelayModeCustom
	default:
		return RelayModeDefault
	}
}

// String 获取中继模式的字符串表示
func (m RelayMode) String() string {
	switch m {
	case RelayModeDisabled:
		return "disabled"
	case RelayModeDefault:
		return "default"
	case RelayModeStaging:
		return "staging"
	case RelayModeCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// EndpointData 端点数据
type EndpointData struct {
	Id       *crypto.EndpointId
	Addrs    []TransportAddr
	RelayURL string
	UserData []byte
}

// NewEndpointData 创建新的端点数据
func NewEndpointData(id *crypto.EndpointId, addrs []TransportAddr) *EndpointData {
	return &EndpointData{
		Id:       id,
		Addrs:    addrs,
		RelayURL: "",
		UserData: nil,
	}
}

// WithRelayURL 设置中继URL
func (d *EndpointData) WithRelayURL(relayURL string) *EndpointData {
	d.RelayURL = relayURL
	return d
}

// WithUserData 设置用户数据
func (d *EndpointData) WithUserData(userData []byte) *EndpointData {
	d.UserData = userData
	return d
}
