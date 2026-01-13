package endpoint

import (
	"github/yixinin/iroh-go/common"
	"github/yixinin/iroh-go/crypto"
)

// Builder 端点构建器
type Builder struct {
	options Options
}

// NewBuilder 创建新的构建器
func NewBuilder() *Builder {
	return &Builder{
		options: Options{
			RelayMode: common.RelayModeDefault,
			SecretKey: crypto.NewSecretKey(),
			ALPNs:     [][]byte{},
		},
	}
}

// RelayMode 设置中继模式
func (b *Builder) RelayMode(mode common.RelayMode) *Builder {
	b.options.RelayMode = mode
	return b
}

// SecretKey 设置密钥
func (b *Builder) SecretKey(key *crypto.SecretKey) *Builder {
	b.options.SecretKey = key
	return b
}

// ALPNs 设置ALPNs
func (b *Builder) ALPNs(alpns [][]byte) *Builder {
	b.options.ALPNs = alpns
	return b
}

// Build 构建端点
func (b *Builder) Build() (*Endpoint, error) {
	return NewEndpoint(b.options)
}
