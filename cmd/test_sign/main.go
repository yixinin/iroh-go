package main

import (
	"fmt"
	"log"

	"github.com/yixinin/iroh-go/crypto"
	"github.com/yixinin/iroh-go/relay"
)

func main() {
	secretKey := crypto.NewSecretKey()
	log.Printf("[Test] Secret key: %x", secretKey.Bytes())
	log.Printf("[Test] Public key: %x", secretKey.Public().Bytes())

	challenge := &relay.ServerChallenge{
		Challenge: [16]byte{0xd1, 0x63, 0x4a, 0x8d, 0x41, 0x14, 0xb9, 0xc8, 0x83, 0xee, 0xdd, 0xe2, 0x22, 0x14, 0x60, 0xf8},
	}

	log.Printf("[Test] Challenge: %x", challenge.Challenge)

	auth := relay.NewClientAuth(secretKey, challenge)
	log.Printf("[Test] Auth PublicKey: %x", auth.PublicKey)
	log.Printf("[Test] Auth Signature: %x", auth.Signature)

	authData, err := relay.EncodeClientAuth(auth)
	if err != nil {
		log.Fatalf("[Test] Failed to encode client auth: %v", err)
	}

	log.Printf("[Test] Encoded auth (%d bytes): %x", len(authData), authData)

	decoded, err := relay.DecodeClientAuth(authData)
	if err != nil {
		log.Fatalf("[Test] Failed to decode client auth: %v", err)
	}

	log.Printf("[Test] Decoded PublicKey: %x", decoded.PublicKey)
	log.Printf("[Test] Decoded Signature: %x", decoded.Signature)

	publicKey, err := crypto.PublicKeyFromBytes(auth.PublicKey[:])
	if err != nil {
		log.Fatalf("[Test] Failed to create public key: %v", err)
	}

	if err := decoded.Verify(challenge, publicKey); err != nil {
		log.Fatalf("[Test] Signature verification failed: %v", err)
	}

	log.Printf("[Test] Signature verification succeeded")

	fmt.Println("Test passed!")
}
