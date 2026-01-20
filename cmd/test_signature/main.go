package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/yixinin/iroh-go/crypto"
	"github.com/yixinin/iroh-go/relay"
	"github.com/zeebo/blake3"
)

func main() {
	secretKey := crypto.NewSecretKey()
	publicKey := secretKey.Public()

	log.Printf("Public key: %x", publicKey.Bytes())

	challenge := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	log.Printf("Challenge: %x", challenge[:])

	sc := &relay.ServerChallenge{Challenge: challenge}
	messageToSign := sc.MessageToSign()
	log.Printf("Message to sign: %x", messageToSign[:])

	signature := secretKey.Sign(messageToSign[:])
	log.Printf("Signature: %x", signature)

	auth := relay.NewClientAuth(secretKey, sc)
	log.Printf("Auth public key: %x", auth.PublicKey[:])
	log.Printf("Auth signature: %x", auth.Signature[:])

	authData, err := relay.EncodeClientAuth(auth)
	if err != nil {
		log.Fatalf("Failed to encode client auth: %v", err)
	}
	log.Printf("Encoded client auth (%d bytes): %x", len(authData), authData)

	decodedAuth, err := relay.DecodeClientAuth(authData)
	if err != nil {
		log.Fatalf("Failed to decode client auth: %v", err)
	}
	log.Printf("Decoded public key: %x", decodedAuth.PublicKey[:])
	log.Printf("Decoded signature: %x", decodedAuth.Signature[:])

	sig, err := crypto.NewSignature(decodedAuth.Signature[:])
	if err != nil {
		log.Fatalf("Failed to create signature: %v", err)
	}
	if !publicKey.Verify(messageToSign[:], sig) {
		log.Fatalf("Signature verification failed!")
	}
	log.Printf("Signature verification succeeded!")

	encodedChallenge, err := relay.EncodeServerChallenge(sc)
	if err != nil {
		log.Fatalf("Failed to encode server challenge: %v", err)
	}
	log.Printf("Encoded server challenge (%d bytes): %x", len(encodedChallenge), encodedChallenge)

	decodedChallenge, err := relay.DecodeServerChallenge(encodedChallenge)
	if err != nil {
		log.Fatalf("Failed to decode server challenge: %v", err)
	}
	log.Printf("Decoded challenge: %x", decodedChallenge.Challenge[:])

	encodedConfirm, err := relay.EncodeServerConfirmsAuth(&relay.ServerConfirmsAuth{})
	if err != nil {
		log.Fatalf("Failed to encode server confirms auth: %v", err)
	}
	log.Printf("Encoded server confirms auth (%d bytes): %x", len(encodedConfirm), encodedConfirm)

	decodedConfirm, err := relay.ParseRelayMessage(encodedConfirm)
	if err != nil {
		log.Fatalf("Failed to parse server confirms auth: %v", err)
	}
	log.Printf("Decoded server confirms auth: %T", decodedConfirm)

	testBlake3DeriveKey()
}

func testBlake3DeriveKey() {
	log.Println("\n=== Testing Blake3 DeriveKey ===")
	
	context := "iroh-relay handshake v1 challenge signature"
	challenge := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	
	result := [32]byte{}
	blake3.DeriveKey(context, challenge[:], result[:])
	
	log.Printf("Context: %s", context)
	log.Printf("Challenge: %x", challenge[:])
	log.Printf("Derived key: %x", result[:])
	
	expectedHex := "3ccbe27a63847df7f1b881e202bf9e7e6d8db0c414783f731348d77de277b9cf"
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		log.Fatalf("Failed to decode expected hex: %v", err)
	}
	
	if fmt.Sprintf("%x", result[:]) != fmt.Sprintf("%x", expected) {
		log.Fatalf("Derived key mismatch! Expected: %x, Got: %x", expected, result[:])
	}
	log.Printf("Derived key matches expected value!")
}
