package relay

import (
	"encoding/base64"
	"fmt"

	"github/yixinin/iroh-go/crypto"

	"github.com/zeebo/blake3"
)

const (
	DomainSepChallenge      = "iroh-relay handshake v1 challenge signature"
	DomainSepTLSExportLabel = "iroh-relay handshake v1"
)

type ServerChallenge struct {
	Challenge [16]byte
}

type ClientAuth struct {
	PublicKey [32]byte
	Signature [64]byte
}

type ServerConfirmsAuth struct{}

type ServerDeniesAuth struct {
	Reason string
}

type KeyMaterialClientAuth struct {
	PublicKey         [32]byte
	Signature         [64]byte
	KeyMaterialSuffix [16]byte
}

func (sc *ServerChallenge) MessageToSign() [32]byte {
	var result [32]byte
	blake3.DeriveKey(DomainSepChallenge, sc.Challenge[:], result[:])
	return result
}

func NewClientAuth(secretKey *crypto.SecretKey, challenge *ServerChallenge) *ClientAuth {
	message := challenge.MessageToSign()
	signature := secretKey.Sign(message[:])

	var pk [32]byte
	copy(pk[:], secretKey.Public().Bytes())

	var sig [64]byte
	copy(sig[:], signature)

	return &ClientAuth{
		PublicKey: pk,
		Signature: sig,
	}
}

func NewKeyMaterialClientAuth(secretKey *crypto.SecretKey, keyMaterial []byte) (*KeyMaterialClientAuth, error) {
	if len(keyMaterial) != 32 {
		return nil, fmt.Errorf("invalid key material length: expected 32, got %d", len(keyMaterial))
	}

	publicKey := secretKey.Public().Bytes()
	message := keyMaterial[:16]
	suffix := [16]byte{}
	copy(suffix[:], keyMaterial[16:])

	signature := secretKey.Sign(message)

	var pk [32]byte
	copy(pk[:], publicKey)

	var sig [64]byte
	copy(sig[:], signature)

	return &KeyMaterialClientAuth{
		PublicKey:         pk,
		Signature:         sig,
		KeyMaterialSuffix: suffix,
	}, nil
}

func (kmca *KeyMaterialClientAuth) ToHeaderValue() string {
	data := make([]byte, 32+64+16)
	copy(data[0:32], kmca.PublicKey[:])
	copy(data[32:96], kmca.Signature[:])
	copy(data[96:112], kmca.KeyMaterialSuffix[:])

	return base64.URLEncoding.EncodeToString(data)
}

func ParseKeyMaterialClientAuth(headerValue string) (*KeyMaterialClientAuth, error) {
	data, err := base64.URLEncoding.DecodeString(headerValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	if len(data) != 32+64+16 {
		return nil, fmt.Errorf("invalid key material client auth length: expected %d, got %d", 32+64+16, len(data))
	}

	kmca := &KeyMaterialClientAuth{}
	copy(kmca.PublicKey[:], data[0:32])
	copy(kmca.Signature[:], data[32:96])
	copy(kmca.KeyMaterialSuffix[:], data[96:112])

	return kmca, nil
}

func (ca *ClientAuth) Verify(challenge *ServerChallenge, publicKey *crypto.PublicKey) error {
	message := challenge.MessageToSign()

	signature, err := crypto.NewSignature(ca.Signature[:])
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	if !publicKey.Verify(message[:], signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func (kmca *KeyMaterialClientAuth) Verify(keyMaterial []byte, publicKey *crypto.PublicKey) error {
	if len(keyMaterial) != 32 {
		return fmt.Errorf("invalid key material length: expected 32, got %d", len(keyMaterial))
	}

	suffix := [16]byte{}
	copy(suffix[:], keyMaterial[16:])

	if suffix != kmca.KeyMaterialSuffix {
		return fmt.Errorf("key material suffix mismatch: expected %x, got %x", kmca.KeyMaterialSuffix, suffix)
	}

	message := keyMaterial[:16]

	signature, err := crypto.NewSignature(kmca.Signature[:])
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	if !publicKey.Verify(message, signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

type VerificationError struct {
	Reason string
}

func (e *VerificationError) Error() string {
	return e.Reason
}

func NewVerificationError(reason string) *VerificationError {
	return &VerificationError{Reason: reason}
}

func NewVerificationErrorMismatchedSuffix(expected, actual [16]byte) *VerificationError {
	return &VerificationError{
		Reason: fmt.Sprintf("key material suffix mismatch: expected %x, got %x", expected, actual),
	}
}

func NewVerificationErrorSignatureInvalid(message []byte, signature [64]byte, publicKey *crypto.PublicKey) *VerificationError {
	return &VerificationError{
		Reason: fmt.Sprintf("signature %x for message %x invalid for public key %x", signature, message, publicKey.Bytes()),
	}
}
