package relay

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github/yixinin/iroh-go/crypto"

	"github.com/gorilla/websocket"
)

// KeyCache 公钥缓存
type KeyCache struct {
	cache    map[string]*crypto.PublicKey
	mutex    sync.RWMutex
	capacity int
}

// NewKeyCache 创建新的公钥缓存
func NewKeyCache(capacity int) *KeyCache {
	return &KeyCache{
		cache:    make(map[string]*crypto.PublicKey),
		capacity: capacity,
	}
}

// Get 从缓存中获取公钥
func (k *KeyCache) Get(key string) (*crypto.PublicKey, bool) {
	k.mutex.RLock()
	defer k.mutex.RUnlock()

	pubKey, ok := k.cache[key]
	return pubKey, ok
}

// Set 将公钥添加到缓存中
func (k *KeyCache) Set(key string, pubKey *crypto.PublicKey) {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if len(k.cache) >= k.capacity {
		for oldestKey := range k.cache {
			delete(k.cache, oldestKey)
			break
		}
	}

	k.cache[key] = pubKey
}

const (
	RelayPath            = "/relay"
	RelayProtocolVersion = "iroh-relay-v1"
	ClientAuthHeader     = "x-iroh-relay-client-auth-v1"
	RelayProbePath       = "/ping"
	MaxFrameSize         = 16384
)

type Client struct {
	conn      *websocket.Conn
	config    *Config
	url       string
	localAddr string
	keyCache  *KeyCache
}

type Config struct {
	Urls      []string
	SecretKey *crypto.SecretKey
	ProxyURL  string
}

func NewConfig(urls []string, secretKey *crypto.SecretKey) *Config {
	return &Config{
		Urls:      urls,
		SecretKey: secretKey,
	}
}

func (c *Config) WithProxyURL(proxyURL string) *Config {
	c.ProxyURL = proxyURL
	return c
}

func NewClient(config *Config) (*Client, error) {
	if len(config.Urls) == 0 {
		return nil, fmt.Errorf("no relay URLs provided")
	}

	return &Client{
		config:   config,
		url:      config.Urls[0],
		keyCache: NewKeyCache(128),
	}, nil
}

func (c *Client) Connect() error {
	dialURL, err := c.buildWebSocketURL()
	if err != nil {
		return err
	}

	log.Printf("[RelayClient] Connecting to relay: %s", dialURL)

	if _, err := url.Parse(dialURL); err != nil {
		return fmt.Errorf("invalid relay URL: %w", err)
	}

	dialer := &websocket.Dialer{
		HandshakeTimeout:  30 * time.Second,
		ReadBufferSize:    MaxFrameSize,
		WriteBufferSize:   MaxFrameSize,
		Subprotocols:      []string{RelayProtocolVersion},
		NetDial:           nil,
		Proxy:             http.ProxyFromEnvironment,
		TLSClientConfig:   nil,
		EnableCompression: false,
	}

	headers := http.Header{}
	headers.Set("User-Agent", "iroh-go/1.0")

	conn, resp, err := dialer.Dial(dialURL, headers)
	if err != nil {
		if resp != nil {
			log.Printf("[RelayClient] Connection failed with status: %s", resp.Status)
			return fmt.Errorf("failed to connect to relay: %w, status: %s", err, resp.Status)
		}
		return fmt.Errorf("failed to connect to relay: %w", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("unexpected upgrade status: %s", resp.Status)
	}

	log.Printf("[RelayClient] WebSocket connection established successfully")

	if localAddr := conn.LocalAddr(); localAddr != nil {
		c.localAddr = localAddr.String()
	}
	c.conn = conn

	log.Printf("[RelayClient] Starting handshake")
	if err := c.handshake(); err != nil {
		conn.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}

	log.Printf("[RelayClient] Handshake completed successfully")

	return nil
}

func (c *Client) handshake() error {
	log.Printf("[RelayClient] Waiting for server challenge")

	challengeData, err := c.Receive()
	if err != nil {
		return fmt.Errorf("failed to receive challenge: %w", err)
	}

	log.Printf("[RelayClient] Received %d bytes from server", len(challengeData))
	log.Printf("[RelayClient] Raw data: %x", challengeData)

	msg, err := ParseRelayMessage(challengeData)
	if err != nil {
		return fmt.Errorf("failed to parse challenge message: %w", err)
	}

	switch m := msg.(type) {
	case *ServerChallenge:
		log.Printf("[RelayClient] Received ServerChallenge")
		return c.handleChallenge(m)
	case *ServerConfirmsAuth:
		log.Printf("[RelayClient] Server already confirmed auth (TLS key material)")
		return nil
	default:
		return fmt.Errorf("expected ServerChallenge or ServerConfirmsAuth, got %T", msg)
	}
}

func (c *Client) handleChallenge(challenge *ServerChallenge) error {
	log.Printf("[RelayClient] Challenge: %x", challenge.Challenge)

	auth := NewClientAuth(c.config.SecretKey, challenge)
	authData, err := EncodeClientAuth(auth)
	if err != nil {
		return fmt.Errorf("failed to encode client auth: %w", err)
	}

	log.Printf("[RelayClient] Sending ClientAuth message")
	log.Printf("[RelayClient] Full message (%d bytes): %x", len(authData), authData)

	if err := c.Send(authData); err != nil {
		return fmt.Errorf("failed to send auth: %w", err)
	}

	log.Printf("[RelayClient] ClientAuth message sent successfully")

	return c.waitForAuthResult()
}

func (c *Client) waitForAuthResult() error {
	log.Printf("[RelayClient] Waiting for auth result...")

	confirmData, err := c.Receive()
	if err != nil {
		return fmt.Errorf("failed to receive auth result: %w", err)
	}

	resultMsg, err := ParseRelayMessage(confirmData)
	if err != nil {
		return fmt.Errorf("failed to parse auth result message: %w", err)
	}

	switch result := resultMsg.(type) {
	case *ServerConfirmsAuth:
		log.Printf("[RelayClient] Authentication confirmed by server")
		return nil
	case *ServerDeniesAuth:
		log.Printf("[RelayClient] Server denied authentication: %s", result.Reason)
		return fmt.Errorf("server denied authentication: %s", result.Reason)
	default:
		return fmt.Errorf("expected ServerConfirmsAuth or ServerDeniesAuth, got %T", resultMsg)
	}
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) Send(msg []byte) error {
	if c.conn == nil {
		return fmt.Errorf("not connected to relay")
	}
	return c.conn.WriteMessage(websocket.BinaryMessage, msg)
}

func (c *Client) Receive() ([]byte, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected to relay")
	}
	_, msg, err := c.conn.ReadMessage()
	return msg, err
}

func (c *Client) SendDatagram(dest *crypto.PublicKey, ecn uint8, data []byte) error {
	if c.conn == nil {
		return fmt.Errorf("not connected to relay server")
	}

	var destPk [32]byte
	copy(destPk[:], dest.Bytes())

	dgram := &ClientToRelayDatagram{
		DestPublicKey: destPk,
		ECN:           ecn,
		Data:          data,
	}

	msg, err := EncodeClientToRelayDatagram(dgram)
	if err != nil {
		return fmt.Errorf("failed to encode datagram: %w", err)
	}

	return c.Send(msg)
}

func (c *Client) SendDatagramBatch(dest *crypto.PublicKey, ecn uint8, segmentSize uint16, datagrams [][]byte) error {
	if c.conn == nil {
		return fmt.Errorf("not connected to relay server")
	}

	batched := BatchDatagrams(datagrams, segmentSize)

	var destPk [32]byte
	copy(destPk[:], dest.Bytes())

	dgramBatch := &ClientToRelayDatagramBatch{
		DestPublicKey: destPk,
		ECN:           ecn,
		SegmentSize:   segmentSize,
		Datagrams:     batched,
	}

	msg, err := EncodeClientToRelayDatagramBatch(dgramBatch)
	if err != nil {
		return fmt.Errorf("failed to encode datagram batch: %w", err)
	}

	return c.Send(msg)
}

func (c *Client) ReceiveMessage() (interface{}, error) {
	data, err := c.Receive()
	if err != nil {
		return nil, err
	}

	msg, err := ParseRelayMessage(data)
	if err != nil {
		return nil, err
	}

	switch m := msg.(type) {
	case *Ping:
		log.Printf("[RelayClient] Received Ping, sending Pong")
		pong := &Pong{Payload: m.Payload}
		pongData, err := EncodePong(pong)
		if err != nil {
			return nil, fmt.Errorf("failed to encode pong: %w", err)
		}
		if err := c.Send(pongData); err != nil {
			return nil, fmt.Errorf("failed to send pong: %w", err)
		}
		return m, nil
	case *Pong:
		log.Printf("[RelayClient] Received Pong")
		return m, nil
	default:
		return msg, nil
	}
}

func (c *Client) SendPing(payload [8]byte) error {
	ping := &Ping{Payload: payload}
	pingData, err := EncodePing(ping)
	if err != nil {
		return fmt.Errorf("failed to encode ping: %w", err)
	}
	return c.Send(pingData)
}

func (c *Client) SendPong(payload [8]byte) error {
	pong := &Pong{Payload: payload}
	pongData, err := EncodePong(pong)
	if err != nil {
		return fmt.Errorf("failed to encode pong: %w", err)
	}
	return c.Send(pongData)
}

func (c *Client) buildWebSocketURL() (string, error) {
	parsedURL, err := url.Parse(c.url)
	if err != nil {
		return "", fmt.Errorf("invalid relay URL: %w", err)
	}

	scheme := parsedURL.Scheme
	switch scheme {
	case "http":
		parsedURL.Scheme = "ws"
	case "https":
		parsedURL.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("unsupported scheme: %s", scheme)
	}

	parsedURL.Path = RelayPath

	return parsedURL.String(), nil
}

func (c *Client) LocalAddr() string {
	return c.localAddr
}

func (c *Client) URL() string {
	return c.url
}
