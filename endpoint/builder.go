package endpoint

import (
	"net"

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
			RelayMode:            common.RelayModeDefault,
			SecretKey:            crypto.NewSecretKey(),
			ALPNs:                [][]byte{},
			RelayUrls:            []string{},
			DnsResolver:          net.DefaultResolver,
			AddressFamilySelector: func() bool { return false },
			InsecureSkipCertVerify: false,
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

// RelayUrls 设置中继URLs
func (b *Builder) RelayUrls(urls []string) *Builder {
	b.options.RelayUrls = urls
	return b
}

// DnsResolver 设置DNS解析器
func (b *Builder) DnsResolver(resolver *net.Resolver) *Builder {
	b.options.DnsResolver = resolver
	return b
}

// AddressFamilySelector 设置地址族选择器
func (b *Builder) AddressFamilySelector(selector func() bool) *Builder {
	b.options.AddressFamilySelector = selector
	return b
}

// InsecureSkipCertVerify 设置是否跳过证书验证
func (b *Builder) InsecureSkipCertVerify(skip bool) *Builder {
	b.options.InsecureSkipCertVerify = skip
	return b
}

// Build 构建端点
func (b *Builder) Build() (*Endpoint, error) {
	return NewEndpoint(b.options)
}
