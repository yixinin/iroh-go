package relay

import (
	"testing"

	"github.com/yixinin/iroh-go/crypto"
)

func TestVarIntEncoding(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected []byte
	}{
		{"zero", 0, []byte{0x00}},
		{"small", 127, []byte{0x40, 0x7f}},
		{"two bytes", 128, []byte{0x40, 0x80}},
		{"four bytes", 16384, []byte{0x80, 0x00, 0x40, 0x00}},
		{"max safe", 268435455, []byte{0x8f, 0xff, 0xff, 0xff}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 5)
			n := VarInt(tt.value).Encode(buf)

			if n != len(tt.expected) {
				t.Errorf("Expected %d bytes, got %d", len(tt.expected), n)
			}

			for i, b := range tt.expected {
				if buf[i] != b {
					t.Errorf("Byte %d: expected 0x%02x, got 0x%02x", i, b, buf[i])
				}
			}

			decoded, err := Decode(buf)
			if err != nil {
				t.Fatalf("Failed to decode varint: %v", err)
			}

			if decoded != VarInt(tt.value) {
				t.Errorf("Expected %d, got %d", tt.value, decoded)
			}

			if decoded.Size() != len(tt.expected) {
				t.Errorf("Expected to read %d bytes, read %d", len(tt.expected), decoded.Size())
			}
		})
	}
}

func TestFrameTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected string
	}{
		{"ServerChallenge", FrameTypeServerChallenge, "ServerChallenge"},
		{"ClientAuth", FrameTypeClientAuth, "ClientAuth"},
		{"ServerConfirmsAuth", FrameTypeServerConfirmsAuth, "ServerConfirmsAuth"},
		{"ServerDeniesAuth", FrameTypeServerDeniesAuth, "ServerDeniesAuth"},
		{"ClientToRelayDatagram", FrameTypeClientToRelayDatagram, "ClientToRelayDatagram"},
		{"ClientToRelayDatagramBatch", FrameTypeClientToRelayDatagramBatch, "ClientToRelayDatagramBatch"},
		{"RelayToClientDatagram", FrameTypeRelayToClientDatagram, "RelayToClientDatagram"},
		{"RelayToClientDatagramBatch", FrameTypeRelayToClientDatagramBatch, "RelayToClientDatagramBatch"},
		{"EndpointGone", FrameTypeEndpointGone, "EndpointGone"},
		{"Ping", FrameTypePing, "Ping"},
		{"Pong", FrameTypePong, "Pong"},
		{"Health", FrameTypeHealth, "Health"},
		{"Restarting", FrameTypeRestarting, "Restarting"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := FrameTypeToString(tt.value)
			if str != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, str)
			}

			if !IsValidFrameType(tt.value) {
				t.Errorf("Frame type %d should be valid", tt.value)
			}
		})
	}

	if IsValidFrameType(999) {
		t.Error("Frame type 999 should be invalid")
	}
}

func TestServerChallengeEncoding(t *testing.T) {
	challenge := &ServerChallenge{
		Challenge: [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
	}

	encoded, err := EncodeServerChallenge(challenge)
	if err != nil {
		t.Fatalf("Failed to encode ServerChallenge: %v", err)
	}

	decoded, err := DecodeServerChallenge(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ServerChallenge: %v", err)
	}

	if decoded.Challenge != challenge.Challenge {
		t.Errorf("Challenge mismatch: expected %x, got %x", challenge.Challenge, decoded.Challenge)
	}
}

func TestClientAuthEncoding(t *testing.T) {
	secretKey := crypto.NewSecretKey()
	challenge := &ServerChallenge{
		Challenge: [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
	}

	auth := NewClientAuth(secretKey, challenge)

	encoded, err := EncodeClientAuth(auth)
	if err != nil {
		t.Fatalf("Failed to encode ClientAuth: %v", err)
	}

	decoded, err := DecodeClientAuth(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ClientAuth: %v", err)
	}

	if decoded.PublicKey != auth.PublicKey {
		t.Error("PublicKey mismatch")
	}

	if decoded.Signature != auth.Signature {
		t.Error("Signature mismatch")
	}

	publicKey, err := crypto.PublicKeyFromBytes(auth.PublicKey[:])
	if err != nil {
		t.Fatalf("Failed to create public key: %v", err)
	}
	if err := decoded.Verify(challenge, publicKey); err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

func TestServerConfirmsAuthEncoding(t *testing.T) {
	confirm := &ServerConfirmsAuth{}

	encoded, err := EncodeServerConfirmsAuth(confirm)
	if err != nil {
		t.Fatalf("Failed to encode ServerConfirmsAuth: %v", err)
	}

	decoded, err := DecodeServerConfirmsAuth(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ServerConfirmsAuth: %v", err)
	}

	if decoded == nil {
		t.Error("Decoded ServerConfirmsAuth should not be nil")
	}
}

func TestServerDeniesAuthEncoding(t *testing.T) {
	denies := &ServerDeniesAuth{
		Reason: "test reason",
	}

	encoded, err := EncodeServerDeniesAuth(denies)
	if err != nil {
		t.Fatalf("Failed to encode ServerDeniesAuth: %v", err)
	}

	decoded, err := DecodeServerDeniesAuth(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ServerDeniesAuth: %v", err)
	}

	if decoded.Reason != denies.Reason {
		t.Errorf("Reason mismatch: expected %s, got %s", denies.Reason, decoded.Reason)
	}
}

func TestClientToRelayDatagramEncoding(t *testing.T) {
	secretKey := crypto.NewSecretKey()
	destPublicKey := secretKey.Public()

	destPkBytes := [32]byte{}
	copy(destPkBytes[:], destPublicKey.Bytes())

	dgram := &ClientToRelayDatagram{
		DestPublicKey: destPkBytes,
		ECN:           0x01,
		Data:          []byte("test data"),
	}

	encoded, err := EncodeClientToRelayDatagram(dgram)
	if err != nil {
		t.Fatalf("Failed to encode ClientToRelayDatagram: %v", err)
	}

	decoded, err := DecodeClientToRelayDatagram(encoded)
	if err != nil {
		t.Fatalf("Failed to decode ClientToRelayDatagram: %v", err)
	}

	if decoded.DestPublicKey != dgram.DestPublicKey {
		t.Error("DestPublicKey mismatch")
	}

	if decoded.ECN != dgram.ECN {
		t.Errorf("ECN mismatch: expected %d, got %d", dgram.ECN, decoded.ECN)
	}

	if string(decoded.Data) != string(dgram.Data) {
		t.Errorf("Data mismatch: expected %s, got %s", dgram.Data, decoded.Data)
	}
}

func TestPingPongEncoding(t *testing.T) {
	ping := &Ping{
		Payload: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	encoded, err := EncodePing(ping)
	if err != nil {
		t.Fatalf("Failed to encode Ping: %v", err)
	}

	decoded, err := DecodePing(encoded)
	if err != nil {
		t.Fatalf("Failed to decode Ping: %v", err)
	}

	if decoded.Payload != ping.Payload {
		t.Errorf("Payload mismatch: expected %x, got %x", ping.Payload, decoded.Payload)
	}

	pong := &Pong{
		Payload: ping.Payload,
	}

	encoded, err = EncodePong(pong)
	if err != nil {
		t.Fatalf("Failed to encode Pong: %v", err)
	}

	decodedPong, err := DecodePong(encoded)
	if err != nil {
		t.Fatalf("Failed to decode Pong: %v", err)
	}

	if decodedPong.Payload != pong.Payload {
		t.Errorf("Payload mismatch: expected %x, got %x", pong.Payload, decodedPong.Payload)
	}
}

func TestHealthEncoding(t *testing.T) {
	health := &Health{
		Message: "test health message",
	}

	encoded, err := EncodeHealth(health)
	if err != nil {
		t.Fatalf("Failed to encode Health: %v", err)
	}

	decoded, err := DecodeHealth(encoded)
	if err != nil {
		t.Fatalf("Failed to decode Health: %v", err)
	}

	if decoded.Message != health.Message {
		t.Errorf("Message mismatch: expected %s, got %s", health.Message, decoded.Message)
	}
}

func TestRestartingEncoding(t *testing.T) {
	restarting := &Restarting{
		ReconnectDelayMs: 1000,
		TotalTryTimeMs:   5000,
	}

	encoded, err := EncodeRestarting(restarting)
	if err != nil {
		t.Fatalf("Failed to encode Restarting: %v", err)
	}

	decoded, err := DecodeRestarting(encoded)
	if err != nil {
		t.Fatalf("Failed to decode Restarting: %v", err)
	}

	if decoded.ReconnectDelayMs != restarting.ReconnectDelayMs {
		t.Errorf("ReconnectDelayMs mismatch: expected %d, got %d", restarting.ReconnectDelayMs, decoded.ReconnectDelayMs)
	}

	if decoded.TotalTryTimeMs != restarting.TotalTryTimeMs {
		t.Errorf("TotalTryTimeMs mismatch: expected %d, got %d", restarting.TotalTryTimeMs, decoded.TotalTryTimeMs)
	}
}

func TestBatchUnbatchDatagrams(t *testing.T) {
	datagrams := [][]byte{
		[]byte("data1"),
		[]byte("data2"),
		[]byte("data3"),
	}

	segmentSize := uint16(16)

	batched := BatchDatagrams(datagrams, segmentSize)

	unbatched := UnbatchDatagrams(batched, segmentSize)

	if len(unbatched) != len(datagrams) {
		t.Errorf("Expected %d datagrams, got %d", len(datagrams), len(unbatched))
	}

	for i, dgram := range datagrams {
		if string(unbatched[i]) != string(dgram) {
			t.Errorf("Datagram %d mismatch: expected %s, got %s", i, dgram, unbatched[i])
		}
	}
}

func TestKeyMaterialClientAuth(t *testing.T) {
	secretKey := crypto.NewSecretKey()
	keyMaterial := make([]byte, 32)
	for i := range keyMaterial {
		keyMaterial[i] = byte(i)
	}

	kmca, err := NewKeyMaterialClientAuth(secretKey, keyMaterial)
	if err != nil {
		t.Fatalf("NewKeyMaterialClientAuth failed: %v", err)
	}

	headerValue := kmca.ToHeaderValue()
	if headerValue == "" {
		t.Error("ToHeaderValue returned empty string")
	}

	parsed, err := ParseKeyMaterialClientAuth(headerValue)
	if err != nil {
		t.Fatalf("Failed to parse key material client auth: %v", err)
	}

	if parsed.PublicKey != kmca.PublicKey {
		t.Error("PublicKey mismatch")
	}

	if parsed.Signature != kmca.Signature {
		t.Error("Signature mismatch")
	}

	if parsed.KeyMaterialSuffix != kmca.KeyMaterialSuffix {
		t.Error("KeyMaterialSuffix mismatch")
	}

	publicKey, err := crypto.PublicKeyFromBytes(kmca.PublicKey[:])
	if err != nil {
		t.Fatalf("Failed to create public key: %v", err)
	}
	if err := parsed.Verify(keyMaterial, publicKey); err != nil {
		t.Errorf("Verification failed: %v", err)
	}
}

func TestParseRelayMessage(t *testing.T) {
	tests := []struct {
		name      string
		encode    func() ([]byte, error)
		checkType func(interface{}) bool
	}{
		{
			name: "ServerChallenge",
			encode: func() ([]byte, error) {
				challenge := &ServerChallenge{Challenge: [16]byte{}}
				return EncodeServerChallenge(challenge)
			},
			checkType: func(msg interface{}) bool {
				_, ok := msg.(*ServerChallenge)
				return ok
			},
		},
		{
			name: "ClientAuth",
			encode: func() ([]byte, error) {
				secretKey := crypto.NewSecretKey()
				challenge := &ServerChallenge{Challenge: [16]byte{}}
				auth := NewClientAuth(secretKey, challenge)
				return EncodeClientAuth(auth)
			},
			checkType: func(msg interface{}) bool {
				_, ok := msg.(*ClientAuth)
				return ok
			},
		},
		{
			name: "Ping",
			encode: func() ([]byte, error) {
				ping := &Ping{Payload: [8]byte{}}
				return EncodePing(ping)
			},
			checkType: func(msg interface{}) bool {
				_, ok := msg.(*Ping)
				return ok
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := tt.encode()
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}

			msg, err := ParseRelayMessage(encoded)
			if err != nil {
				t.Fatalf("Failed to parse: %v", err)
			}

			if !tt.checkType(msg) {
				t.Errorf("Unexpected message type: %T", msg)
			}
		})
	}
}
