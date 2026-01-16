package relay

import (
	"log"
	"testing"
	"time"

	"github.com/yixinin/iroh-go/crypto"
)

func TestRelayConnection(t *testing.T) {
	secretKey := crypto.NewSecretKey()
	log.Printf("[Test] Secret key: %x", secretKey.Bytes())
	log.Printf("[Test] Public key: %x", secretKey.Public().Bytes())

	relayURL := "https://aps1-1.relay.n0.iroh-canary.iroh.link"
	log.Printf("[Test] Connecting to relay: %s", relayURL)

	config := NewConfig([]string{relayURL}, secretKey)
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create relay client: %v", err)
	}

	log.Printf("[Test] Relay client created successfully")

	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect to relay: %v", err)
	}

	log.Printf("[Test] Successfully connected to relay")

	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("[Test] Error closing client: %v", err)
		}
	}()

	time.Sleep(1 * time.Second)
	log.Printf("[Test] Test completed successfully")
}

func TestRelayConnectionWithStaging(t *testing.T) {
	secretKey := crypto.NewSecretKey()
	log.Printf("[Test] Secret key: %x", secretKey.Bytes())
	log.Printf("[Test] Public key: %x", secretKey.Public().Bytes())

	relayURL := "https://aps1-1.relay.n0.iroh-canary.iroh.link"
	log.Printf("[Test] Connecting to staging relay: %s", relayURL)

	config := NewConfig([]string{relayURL}, secretKey)
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create relay client: %v", err)
	}

	log.Printf("[Test] Relay client created successfully")

	err = client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect to relay: %v", err)
	}

	log.Printf("[Test] Successfully connected to relay")

	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("[Test] Error closing client: %v", err)
		}
	}()

	time.Sleep(1 * time.Second)
	log.Printf("[Test] Test completed successfully")
}
