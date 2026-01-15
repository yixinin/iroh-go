package relay

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github/yixinin/iroh-go/crypto"
)

func TestMessageTypes(t *testing.T) {
	tests := []struct {
		name     string
		msgType  byte
		expected byte
	}{
		{"ServerChallenge", MsgTypeServerChallenge, 0x00},
		{"ClientAuth", MsgTypeClientAuth, 0x01},
		{"ServerAuthResult", MsgTypeServerAuthResult, 0x02},
		{"ServerDeniesAuth", MsgTypeServerDeniesAuth, 0x03},
		{"Connect", MsgTypeConnect, 0x10},
		{"ConnectResponse", MsgTypeConnectResponse, 0x11},
		{"Data", MsgTypeData, 0x20},
		{"Close", MsgTypeClose, 0x30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.msgType != tt.expected {
				t.Errorf("Expected message type 0x%02x, got 0x%02x", tt.expected, tt.msgType)
			}
		})
	}
}

func TestServerChallengeSerialization(t *testing.T) {
	challenge := ServerChallenge{
		Challenge: [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
	}

	data := make([]byte, 1+16)
	data[0] = MsgTypeServerChallenge
	copy(data[1:17], challenge.Challenge[:])

	if len(data) != 17 {
		t.Errorf("Expected 17 bytes, got %d", len(data))
	}

	if data[0] != MsgTypeServerChallenge {
		t.Errorf("Expected message type 0x%02x, got 0x%02x", MsgTypeServerChallenge, data[0])
	}

	var decoded ServerChallenge
	copy(decoded.Challenge[:], data[1:17])

	if decoded.Challenge != challenge.Challenge {
		t.Errorf("Challenge mismatch: expected %x, got %x", challenge.Challenge, decoded.Challenge)
	}
}

func TestClientAuthSerialization(t *testing.T) {
	secretKey := crypto.NewSecretKey()
	publicKey := secretKey.Public()
	signature := secretKey.Sign([]byte("test challenge"))

	auth := ClientAuth{
		PublicKey: [32]byte{},
		Signature: [64]byte{},
	}
	copy(auth.PublicKey[:], publicKey.Bytes())
	copy(auth.Signature[:], signature)

	data := make([]byte, 1+32+64)
	data[0] = MsgTypeClientAuth
	copy(data[1:33], auth.PublicKey[:])
	copy(data[33:97], auth.Signature[:])

	if len(data) != 97 {
		t.Errorf("Expected 97 bytes, got %d", len(data))
	}

	if data[0] != MsgTypeClientAuth {
		t.Errorf("Expected message type 0x%02x, got 0x%02x", MsgTypeClientAuth, data[0])
	}

	var decoded ClientAuth
	copy(decoded.PublicKey[:], data[1:33])
	copy(decoded.Signature[:], data[33:97])

	if decoded.PublicKey != auth.PublicKey {
		t.Errorf("PublicKey mismatch")
	}

	if decoded.Signature != auth.Signature {
		t.Errorf("Signature mismatch")
	}
}

func TestConnectRequestSerialization(t *testing.T) {
	secretKey := crypto.NewSecretKey()
	peerId := crypto.EndpointIdFromPublicKey(secretKey.Public())
	alpn := []byte("test-alpn")
	clientId := crypto.EndpointIdFromPublicKey(secretKey.Public())

	request := ConnectRequest{
		PeerId:   [32]byte{},
		ALPN:     alpn,
		ClientId: [32]byte{},
	}
	copy(request.PeerId[:], peerId.Bytes())
	copy(request.ClientId[:], clientId.Bytes())

	alpnLen := len(request.ALPN)
	data := make([]byte, 1+32+2+alpnLen+32)
	data[0] = MsgTypeConnect
	copy(data[1:33], request.PeerId[:])
	binary.BigEndian.PutUint16(data[33:35], uint16(alpnLen))
	copy(data[35:35+alpnLen], request.ALPN)
	copy(data[35+alpnLen:67+alpnLen], request.ClientId[:])

	expectedLen := 1 + 32 + 2 + alpnLen + 32
	if len(data) != expectedLen {
		t.Errorf("Expected %d bytes, got %d", expectedLen, len(data))
	}

	if data[0] != MsgTypeConnect {
		t.Errorf("Expected message type 0x%02x, got 0x%02x", MsgTypeConnect, data[0])
	}

	decodedAlpnLen := binary.BigEndian.Uint16(data[33:35])
	if int(decodedAlpnLen) != alpnLen {
		t.Errorf("Expected ALPN length %d, got %d", alpnLen, decodedAlpnLen)
	}

	var decoded ConnectRequest
	copy(decoded.PeerId[:], data[1:33])
	decoded.ALPN = data[35 : 35+alpnLen]
	copy(decoded.ClientId[:], data[35+alpnLen:67+alpnLen])

	if decoded.PeerId != request.PeerId {
		t.Errorf("PeerId mismatch")
	}

	if !bytes.Equal(decoded.ALPN, request.ALPN) {
		t.Errorf("ALPN mismatch: expected %s, got %s", request.ALPN, decoded.ALPN)
	}

	if decoded.ClientId != request.ClientId {
		t.Errorf("ClientId mismatch")
	}
}

func TestConnectResponseSerialization(t *testing.T) {
	response := ConnectResponse{
		Status:  0,
		RelayId: [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
	}

	data := make([]byte, 1+1+16)
	data[0] = MsgTypeConnectResponse
	data[1] = response.Status
	copy(data[2:18], response.RelayId[:])

	if len(data) != 18 {
		t.Errorf("Expected 18 bytes, got %d", len(data))
	}

	if data[0] != MsgTypeConnectResponse {
		t.Errorf("Expected message type 0x%02x, got 0x%02x", MsgTypeConnectResponse, data[0])
	}

	if data[1] != 0 {
		t.Errorf("Expected status 0, got %d", data[1])
	}

	var decoded ConnectResponse
	decoded.Status = data[1]
	copy(decoded.RelayId[:], data[2:18])

	if decoded.Status != response.Status {
		t.Errorf("Status mismatch: expected %d, got %d", response.Status, decoded.Status)
	}

	if decoded.RelayId != response.RelayId {
		t.Errorf("RelayId mismatch: expected %x, got %x", response.RelayId, decoded.RelayId)
	}
}

func TestDataMessageSerialization(t *testing.T) {
	relayId := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	data := []byte("test data payload")

	dataLen := len(data)
	msgData := make([]byte, 1+16+4+dataLen)
	msgData[0] = MsgTypeData
	copy(msgData[1:17], relayId[:])
	binary.BigEndian.PutUint32(msgData[17:21], uint32(dataLen))
	copy(msgData[21:], data)

	expectedLen := 1 + 16 + 4 + dataLen
	if len(msgData) != expectedLen {
		t.Errorf("Expected %d bytes, got %d", expectedLen, len(msgData))
	}

	if msgData[0] != MsgTypeData {
		t.Errorf("Expected message type 0x%02x, got 0x%02x", MsgTypeData, msgData[0])
	}

	decodedDataLen := binary.BigEndian.Uint32(msgData[17:21])
	if int(decodedDataLen) != dataLen {
		t.Errorf("Expected data length %d, got %d", dataLen, decodedDataLen)
	}

	decodedData := msgData[21 : 21+dataLen]
	if !bytes.Equal(decodedData, data) {
		t.Errorf("Data mismatch: expected %s, got %s", data, decodedData)
	}
}

func TestCloseMessageSerialization(t *testing.T) {
	relayId := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	closeMsg := make([]byte, 1+16)
	closeMsg[0] = MsgTypeClose
	copy(closeMsg[1:17], relayId[:])

	if len(closeMsg) != 17 {
		t.Errorf("Expected 17 bytes, got %d", len(closeMsg))
	}

	if closeMsg[0] != MsgTypeClose {
		t.Errorf("Expected message type 0x%02x, got 0x%02x", MsgTypeClose, closeMsg[0])
	}

	var decodedRelayId [16]byte
	copy(decodedRelayId[:], closeMsg[1:17])

	if decodedRelayId != relayId {
		t.Errorf("RelayId mismatch: expected %x, got %x", relayId, decodedRelayId)
	}
}

func TestConfigCreation(t *testing.T) {
	secretKey := crypto.NewSecretKey()
	urls := []string{"ws://localhost:8080/relay"}

	config := NewConfig(urls, secretKey)

	if config == nil {
		t.Fatal("Config should not be nil")
	}

	if len(config.Urls) != 1 {
		t.Errorf("Expected 1 URL, got %d", len(config.Urls))
	}

	if config.Urls[0] != urls[0] {
		t.Errorf("Expected URL %s, got %s", urls[0], config.Urls[0])
	}

	if config.SecretKey != secretKey {
		t.Error("SecretKey mismatch")
	}
}

func TestConfigWithProxyURL(t *testing.T) {
	secretKey := crypto.NewSecretKey()
	urls := []string{"ws://localhost:8080/relay"}

	config := NewConfig(urls, secretKey).WithProxyURL("http://proxy.example.com:8080")

	if config.ProxyURL != "http://proxy.example.com:8080" {
		t.Errorf("Expected proxy URL http://proxy.example.com:8080, got %s", config.ProxyURL)
	}
}

func TestNewClient(t *testing.T) {
	secretKey := crypto.NewSecretKey()
	urls := []string{"ws://localhost:8080/relay"}

	config := NewConfig(urls, secretKey)
	client, err := NewClient(config)

	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client == nil {
		t.Fatal("Client should not be nil")
	}

	if client.config != config {
		t.Error("Config mismatch")
	}

	if client.url != urls[0] {
		t.Errorf("Expected URL %s, got %s", urls[0], client.url)
	}
}

func TestNewClientWithEmptyURLs(t *testing.T) {
	secretKey := crypto.NewSecretKey()
	urls := []string{}

	config := NewConfig(urls, secretKey)
	_, err := NewClient(config)

	if err == nil {
		t.Error("Expected error when creating client with empty URLs")
	}
}

func TestKeyCache(t *testing.T) {
	cache := NewKeyCache(2)

	secretKey := crypto.NewSecretKey()
	publicKey := secretKey.Public()

	cache.Set("key1", publicKey)
	retrieved, ok := cache.Get("key1")

	if !ok {
		t.Error("Failed to retrieve key from cache")
	}

	if retrieved != publicKey {
		t.Error("Retrieved key mismatch")
	}

	_, ok = cache.Get("nonexistent")
	if ok {
		t.Error("Should not retrieve nonexistent key")
	}

	secretKey2 := crypto.NewSecretKey()
	publicKey2 := secretKey2.Public()

	cache.Set("key2", publicKey2)

	secretKey3 := crypto.NewSecretKey()
	publicKey3 := secretKey3.Public()

	cache.Set("key3", publicKey3)

	count := 0
	cache.mutex.RLock()
	for range cache.cache {
		count++
	}
	cache.mutex.RUnlock()

	if count != 2 {
		t.Errorf("Expected cache size 2, got %d", count)
	}
}
