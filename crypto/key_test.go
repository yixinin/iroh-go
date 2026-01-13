package crypto

import (
	"testing"
)

func TestNewSecretKey(t *testing.T) {
	key := NewSecretKey()
	if key == nil {
		t.Fatal("Failed to generate secret key")
	}
}

func TestSecretKeyPublic(t *testing.T) {
	key := NewSecretKey()
	pk := key.Public()
	if pk == nil {
		t.Fatal("Failed to get public key")
	}
}

func TestEndpointIdFromPublicKey(t *testing.T) {
	key := NewSecretKey()
	pk := key.Public()
	id := EndpointIdFromPublicKey(pk)
	if id == nil {
		t.Fatal("Failed to create endpoint ID")
	}
}
