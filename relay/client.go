package relay

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yixinin/iroh-go/crypto"

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

type Packet struct {
	RemoteID *crypto.EndpointId
	Data     []byte
}

type Client struct {
	conn       *websocket.Conn
	config     *Config
	url        string
	localAddr  *crypto.EndpointId
	keyCache   *KeyCache
	latestPing atomic.Int64

	packets chan *Packet
	mu      sync.Mutex

	writeBuffer chan []byte

	readDeadline  time.Time
	writeDeadline time.Time

	ctx    context.Context
	cancel context.CancelFunc
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

func NewClient(config *Config, localAddr *crypto.EndpointId) (*Client, error) {
	if len(config.Urls) == 0 {
		return nil, fmt.Errorf("no relay URLs provided")
	}

	return &Client{
		config:    config,
		localAddr: localAddr,
		url:       config.Urls[0],
		keyCache:  NewKeyCache(128),
		packets:   make(chan *Packet, 1024),
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

	// Try to use TLS key material authentication if available
	// For now, disable this as it causes connection issues
	// if c.config.SecretKey != nil {
	// 	kmca, err := c.tryKeyMaterialAuth()
	// 	if err == nil {
	// 		headers.Set("x-iroh-relay-client-auth-v1", kmca.ToHeaderValue())
	// 		log.Printf("[RelayClient] Using TLS key material authentication")
	// 	} else {
	// 		log.Printf("[RelayClient] Failed to create TLS key material auth: %v", err)
	// 	}
	// }

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

	conn.SetPingHandler(c.handlePing)

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	conn.SetPongHandler(func(appData string) error {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		log.Printf("[Relay WebSocket] Received WebSocket pong")
		return nil
	})

	c.conn = conn

	c.ctx, c.cancel = context.WithCancel(context.Background())

	log.Printf("[RelayClient] Starting handshake")
	if err := c.handshake(); err != nil {
		conn.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}

	log.Printf("[RelayClient] Handshake completed successfully")
	go c.loopRead()
	go c.loopWrite()
	return nil
}

func (c *Client) tryKeyMaterialAuth() (*KeyMaterialClientAuth, error) {
	// This is a simplified implementation
	// In a real implementation, we would need to extract TLS key material
	// For now, we'll return an error to force challenge-response auth
	return nil, fmt.Errorf("TLS key material extraction not implemented")
}

func (c *Client) handlePing(appData string) error {
	log.Printf("[Relay WebSocket] Received WebSocket ping, sending pong")
	return c.conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(5*time.Second))
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
		log.Printf("[RelayClient] Failed to receive auth result: %v", err)
		return fmt.Errorf("failed to receive auth result: %w", err)
	}

	log.Printf("[RelayClient] Received %d bytes from server", len(confirmData))
	log.Printf("[RelayClient] Raw data: %x", confirmData)

	// Debug: log first byte to see message type
	if len(confirmData) > 0 {
		log.Printf("[RelayClient] First byte (message type): %02x", confirmData[0])
	}

	resultMsg, err := ParseRelayMessage(confirmData)
	if err != nil {
		log.Printf("[RelayClient] Failed to parse auth result message: %v", err)
		return fmt.Errorf("failed to parse auth result message: %w", err)
	}

	log.Printf("[RelayClient] Parsed message type: %T", resultMsg)

	switch result := resultMsg.(type) {
	case *ServerConfirmsAuth:
		log.Printf("[RelayClient] Authentication confirmed by server")
		return nil
	case *ServerDeniesAuth:
		log.Printf("[RelayClient] Server denied authentication: %s", result.Reason)
		return fmt.Errorf("server denied authentication: %s", result.Reason)
	default:
		log.Printf("[RelayClient] Unexpected message type: %T", resultMsg)
		return fmt.Errorf("expected ServerConfirmsAuth or ServerDeniesAuth, got %T", resultMsg)
	}
}
func (c *Client) loopRead() {
	for {
		select {
		case <-c.ctx.Done():
			log.Printf("[RelayClient] Context canceled, closing connection")
			return
		default:
			msg, err := c.ReceiveMessage()
			if err != nil {
				log.Printf("[RelayClient] Error reading message: %v", err)
				return
			}

			switch m := msg.(type) {
			case *RelayToClientDatagram:
				publicKey, err := crypto.PublicKeyFromBytes(m.SrcPublicKey[:])
				if err != nil {
					log.Printf("[RelayClient] Error parsing public key: %v", err)
					continue
				}
				c.mu.Lock()
				c.packets <- &Packet{
					RemoteID: publicKey,
					Data:     m.Datagrams.Contents,
				}
				c.mu.Unlock()
			case *RelayToClientDatagramBatch:
				publicKey, err := crypto.PublicKeyFromBytes(m.SrcPublicKey[:])
				if err != nil {
					log.Printf("[RelayClient] Error parsing public key: %v", err)
					continue
				}
				c.mu.Lock()
				c.packets <- &Packet{
					RemoteID: publicKey,
					Data:     m.Datagrams.Contents,
				}
				c.mu.Unlock()
			case *Ping, *Pong:
				c.latestPing.Store(time.Now().Unix())
			default:
				log.Printf("[RelayClient] Unexpected message type: %T", m)
			}
		}
	}
}

func (c *Client) loopWrite() {
	for {
		select {
		case <-c.ctx.Done():
			log.Printf("[RelayClient] Context canceled, closing connection")
			return
		case data := <-c.writeBuffer:
			if err := c.Send(data); err != nil {
				log.Printf("[RelayClient] Error sending message: %v", err)
				return
			}
		}
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
	msgType, msg, err := c.conn.ReadMessage()
	log.Printf("[RelayClient.Receive] ReadMessage returned: msgType=%d, len(msg)=%d, err=%v", msgType, len(msg), err)
	if err != nil {
		log.Printf("[RelayClient.Receive] ReadMessage error details: %v", err)
		return nil, err
	}
	switch msgType {
	case websocket.BinaryMessage, websocket.TextMessage:
		return msg, err
	case websocket.CloseMessage:
		log.Printf("[RelayClient.Receive] Received close message")
		return nil, fmt.Errorf("server closed connection")
	case websocket.PingMessage:
		log.Printf("[RelayClient.Receive] Received ping message")
		return nil, fmt.Errorf("server sent ping message, not supported")
	case websocket.PongMessage:
		log.Printf("[RelayClient.Receive] Received pong message")
		return nil, fmt.Errorf("server sent pong message, not supported")
	default:
		log.Printf("[RelayClient.Receive] Unexpected message type: %d", msgType)
		return nil, fmt.Errorf("unexpected message type: %d", msgType)
	}
}

func (c *Client) SendDatagram(dest *crypto.PublicKey, ecn ECN, data []byte) error {
	if c.conn == nil {
		return fmt.Errorf("not connected to relay server")
	}

	var destPk [32]byte
	copy(destPk[:], dest.Bytes())

	dgram := &ClientToRelayDatagram{
		DestPublicKey: destPk,
		Datagrams:     NewDatagrams(data),
	}

	msg, err := EncodeClientToRelayDatagram(dgram)
	if err != nil {
		return fmt.Errorf("failed to encode datagram: %w", err)
	}

	return c.Send(msg)
}

func (c *Client) SendDatagramBatch(dest *crypto.PublicKey, ecn ECN, segmentSize uint16, datagrams [][]byte) error {
	if c.conn == nil {
		return fmt.Errorf("not connected to relay server")
	}

	batched := make([]byte, 0, len(datagrams)*int(segmentSize))
	for _, d := range datagrams {
		batched = append(batched, d...)
	}

	var destPk [32]byte
	copy(destPk[:], dest.Bytes())

	dgramBatch := &ClientToRelayDatagramBatch{
		DestPublicKey: destPk,
		Datagrams:     NewDatagramsBatch(ecn, segmentSize, batched),
	}
	log.Printf("[Relay WebSocket] Sending DatagramBatch: %+v", *dgramBatch)
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
		log.Printf("[Relay WebSocket] Received Ping: %x, sending Pong...", m.Payload)
		c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		pong := &Pong{Payload: m.Payload}
		pongData, err := EncodePong(pong)
		if err != nil {
			return nil, fmt.Errorf("failed to encode pong: %w", err)
		}
		if err := c.Send(pongData); err != nil {
			return nil, fmt.Errorf("failed to send pong: %w", err)
		}

		return msg, nil
	case *Pong:
		return msg, nil
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

func (c *Client) URL() string {
	return c.url
}
