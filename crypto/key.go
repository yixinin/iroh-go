package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
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

// Signature 签名
type Signature struct {
	sig [64]byte
}

// EndpointId 端点ID，基于公钥（与 Rust 版本保持一致，EndpointId 就是 PublicKey）
type EndpointId = PublicKey

func (id *EndpointId) PublicKey() ed25519.PublicKey {
	return id.key
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

// PrivateKey 获取 ed25519 私钥
func (k *SecretKey) PrivateKey() ed25519.PrivateKey {
	return k.key
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

// Ed25519PublicKey 获取底层的 ed25519 公钥
func (k *PublicKey) Ed25519PublicKey() ed25519.PublicKey {
	return k.key
}

// String 获取公钥的字符串表示
func (k *PublicKey) String() string {
	return hex.EncodeToString(k.key)
}

// Verify 验证签名
func (k *PublicKey) Verify(message []byte, sig *Signature) bool {
	return ed25519.Verify(k.key, message, sig.sig[:])
}

// FmtShort 获取公钥的短字符串表示（前5字节）
func (k *PublicKey) FmtShort() string {
	return hex.EncodeToString(k.key[:5])
}

// NewSignature 从字节数组创建签名
func NewSignature(b []byte) (*Signature, error) {
	if len(b) != 64 {
		return nil, fmt.Errorf("invalid signature length: expected 64, got %d", len(b))
	}
	sig := &Signature{}
	copy(sig.sig[:], b)
	return sig, nil
}

// Bytes 获取签名的字节表示
func (s *Signature) Bytes() [64]byte {
	return s.sig
}

// EndpointIdFromPublicKey 从公钥创建端点ID
func EndpointIdFromPublicKey(pk *PublicKey) *EndpointId {
	return pk
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

	return pk, nil
}
