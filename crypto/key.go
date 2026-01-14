package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
)

// SecretKey 用于身份验证的密钥
type SecretKey struct {
	key ed25519.PrivateKey
}

// PublicKey 公钥
type PublicKey struct {
	key ed25519.PublicKey
}

// EndpointId 端点ID，基于公钥
type EndpointId struct {
	key PublicKey
}

// NewSecretKey 生成新的密钥
func NewSecretKey() *SecretKey {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return &SecretKey{key: priv}
}

// SecretKeyFromBytes 从字节数组创建密钥
func SecretKeyFromBytes(b []byte) (*SecretKey, error) {
	if len(b) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid secret key length")
	}
	return &SecretKey{key: ed25519.PrivateKey(b)}, nil
}

// Public 获取公钥
func (k *SecretKey) Public() *PublicKey {
	return &PublicKey{key: k.key.Public().(ed25519.PublicKey)}
}

// Bytes 获取密钥的字节表示
func (k *SecretKey) Bytes() []byte {
	return k.key
}

// Sign 签名数据
func (k *SecretKey) Sign(data []byte) []byte {
	return ed25519.Sign(k.key, data)
}

// PublicKeyFromBytes 从字节数组创建公钥
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key length")
	}
	return &PublicKey{key: ed25519.PublicKey(b)}, nil
}

// Bytes 获取公钥的字节表示
func (k *PublicKey) Bytes() []byte {
	return k.key
}

// String 获取公钥的字符串表示
func (k *PublicKey) String() string {
	return hex.EncodeToString(k.key)
}

// EndpointIdFromPublicKey 从公钥创建端点ID
func EndpointIdFromPublicKey(pk *PublicKey) *EndpointId {
	return &EndpointId{key: *pk}
}

// PublicKey 获取端点ID的公钥
func (id *EndpointId) PublicKey() *PublicKey {
	return &id.key
}

// String 获取端点ID的字符串表示
func (id *EndpointId) String() string {
	return id.key.String()
}

// Bytes 获取端点ID的字节表示
func (id *EndpointId) Bytes() []byte {
	return id.key.Bytes()
}

// ParseEndpointId 从字符串解析端点ID
func ParseEndpointId(s string) (*EndpointId, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty endpoint ID")
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if len(b) != ed25519.PublicKeySize {
		return nil, errors.New("invalid endpoint ID length")
	}

	pk, err := PublicKeyFromBytes(b)
	if err != nil {
		return nil, err
	}

	return &EndpointId{key: *pk}, nil
}
