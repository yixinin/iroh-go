package relay

import (
	"encoding/binary"
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

	// 如果缓存已满，删除最早的条目
	if len(k.cache) >= k.capacity {
		for oldestKey := range k.cache {
			delete(k.cache, oldestKey)
			break
		}
	}

	k.cache[key] = pubKey
}

// 常量定义
const (
	// RelayPath 中继服务路径
	RelayPath = "/relay"
	// RelayProtocolVersion 中继协议版本
	RelayProtocolVersion = "iroh-relay-v1"
	// ClientAuthHeader 客户端认证头部
	ClientAuthHeader = "x-iroh-relay-client-auth-v1"
	// RelayProbePath 中继探测路径
	RelayProbePath = "/ping"
	// MaxFrameSize 最大帧大小
	MaxFrameSize = 16384
)

// 消息类型 (iroh-relay binary protocol)
const (
	// MsgTypeServerChallenge 服务器挑战消息
	MsgTypeServerChallenge = 0x00
	// MsgTypeClientAuth 客户端认证消息
	MsgTypeClientAuth = 0x01
	// MsgTypeServerAuthResult 服务器认证结果
	MsgTypeServerAuthResult = 0x02
	// MsgTypeServerDeniesAuth 服务器拒绝认证
	MsgTypeServerDeniesAuth = 0x03
	// MsgTypeConnect 连接请求
	MsgTypeConnect = 0x10
	// MsgTypeConnectResponse 连接响应
	MsgTypeConnectResponse = 0x11
	// MsgTypeData 数据传输
	MsgTypeData = 0x20
	// MsgTypeClose 关闭连接
	MsgTypeClose = 0x30
)

// ServerChallenge 服务器挑战消息 (MsgTypeServerChallenge)
type ServerChallenge struct {
	Challenge [16]byte
}

// ClientAuth 客户端认证消息 (MsgTypeClientAuth)
type ClientAuth struct {
	PublicKey [32]byte
	Signature [64]byte
}

// ServerAuthResult 服务器认证结果 (MsgTypeServerAuthResult)
type ServerAuthResult struct {
	Status uint8
}

// ConnectRequest 连接请求消息 (MsgTypeConnect)
type ConnectRequest struct {
	PeerId   [32]byte
	ALPN     []byte
	ClientId [32]byte
}

// ConnectResponse 连接响应消息 (MsgTypeConnectResponse)
type ConnectResponse struct {
	Status  uint8
	RelayId [16]byte
}

// DataMessage 数据消息 (MsgTypeData)
type DataMessage struct {
	RelayId [16]byte
	Data    []byte
}

// CloseMessage 关闭消息 (MsgTypeClose)
type CloseMessage struct {
	RelayId [16]byte
}

// Client 中继客户端
type Client struct {
	conn      *websocket.Conn
	config    *Config
	url       string
	localAddr string
	keyCache  *KeyCache
}

// NewClient 创建新的中继客户端
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

// Connect 连接到中继服务器
func (c *Client) Connect() error {
	// 构建 WebSocket URL
	dialURL, err := c.buildWebSocketURL()
	if err != nil {
		return err
	}

	log.Printf("[RelayClient] Connecting to relay: %s", dialURL)

	// 验证 URL 格式
	if _, err := url.Parse(dialURL); err != nil {
		return fmt.Errorf("invalid relay URL: %w", err)
	}

	// 构建 WebSocket 拨号器
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

	// 构建请求头
	headers := http.Header{}
	headers.Set("User-Agent", "iroh-go/1.0")
	log.Printf("[RelayClient] Headers: %v", headers)
	log.Printf("[RelayClient] Subprotocols: %v", dialer.Subprotocols)

	// 建立 WebSocket 连接
	conn, resp, err := dialer.Dial(dialURL, headers)
	if err != nil {
		if resp != nil {
			log.Printf("[RelayClient] Connection failed with status: %s", resp.Status)
			log.Printf("[RelayClient] Response headers: %v", resp.Header)
			return fmt.Errorf("failed to connect to relay: %w, status: %s", err, resp.Status)
		}
		log.Printf("[RelayClient] Connection failed: %v", err)
		return fmt.Errorf("failed to connect to relay: %w", err)
	}

	// 检查响应状态
	if resp.StatusCode != http.StatusSwitchingProtocols {
		log.Printf("[RelayClient] Unexpected status code: %d (expected %d)", resp.StatusCode, http.StatusSwitchingProtocols)
		return fmt.Errorf("unexpected upgrade status: %s", resp.Status)
	}

	log.Printf("[RelayClient] WebSocket connection established successfully")

	// 获取本地地址
	if localAddr := conn.LocalAddr(); localAddr != nil {
		c.localAddr = localAddr.String()
		log.Printf("[RelayClient] Local address: %s", c.localAddr)
	}
	c.conn = conn

	// 执行握手过程
	log.Printf("[RelayClient] Starting handshake")
	if err := c.handshake(); err != nil {
		conn.Close()
		log.Printf("[RelayClient] Handshake failed: %v", err)
		return fmt.Errorf("handshake failed: %w", err)
	}

	log.Printf("[RelayClient] Handshake completed successfully")

	return nil
}

// handshake 执行与中继服务器的握手过程
func (c *Client) handshake() error {
	log.Printf("[RelayClient] Waiting for server challenge")

	challengeData, err := c.Receive()
	if err != nil {
		return fmt.Errorf("failed to receive challenge: %w", err)
	}

	log.Printf("[RelayClient] Received %d bytes from server", len(challengeData))
	log.Printf("[RelayClient] Raw data: %x", challengeData)

	if len(challengeData) < 16 {
		return fmt.Errorf("invalid challenge message: expected at least 16 bytes, got %d", len(challengeData))
	}

	var challenge ServerChallenge
	var challengeBytes []byte

	if len(challengeData) == 16 {
		log.Printf("[RelayClient] Server sent 16 bytes directly (no message type)")
		copy(challenge.Challenge[:], challengeData[0:16])
		challengeBytes = challengeData[0:16]
	} else if len(challengeData) == 17 {
		msgType := challengeData[0]
		log.Printf("[RelayClient] Server sent message type: 0x%02x", msgType)
		if msgType != MsgTypeServerChallenge {
			log.Printf("[RelayClient] WARNING: Expected ServerChallenge (0x%02x), got 0x%02x", MsgTypeServerChallenge, msgType)
			return fmt.Errorf("expected ServerChallenge (0x%02x), got 0x%02x", MsgTypeServerChallenge, msgType)
		}
		copy(challenge.Challenge[:], challengeData[1:17])
		challengeBytes = challengeData[1:17]
	} else {
		return fmt.Errorf("invalid challenge message: expected 16 or 17 bytes, got %d", len(challengeData))
	}

	log.Printf("[RelayClient] Challenge: %x", challenge.Challenge)

	publicKey := c.config.SecretKey.Public()

	signature := c.config.SecretKey.Sign(challengeBytes)

	log.Printf("[RelayClient] Generated signature (direct challenge signing): %x", signature)

	var auth ClientAuth
	copy(auth.PublicKey[:], publicKey.Bytes())
	copy(auth.Signature[:], signature)

	authData := make([]byte, 1+32+64)
	authData[0] = MsgTypeClientAuth
	copy(authData[1:33], auth.PublicKey[:])
	copy(authData[33:97], auth.Signature[:])

	log.Printf("[RelayClient] Sending ClientAuth message")
	log.Printf("[RelayClient] Message type: 0x%02x", authData[0])
	log.Printf("[RelayClient] Public key: %x", authData[1:33])
	log.Printf("[RelayClient] Signature: %x", authData[33:97])
	log.Printf("[RelayClient] Full message (%d bytes): %x", len(authData), authData)

	if err := c.Send(authData); err != nil {
		return fmt.Errorf("failed to send auth: %w", err)
	}

	log.Printf("[RelayClient] ClientAuth message sent successfully")

	log.Printf("[RelayClient] Waiting for auth result...")

	confirmData, err := c.Receive()
	if err != nil {
		return fmt.Errorf("failed to receive auth result: %w", err)
	}

	if len(confirmData) < 1 {
		return fmt.Errorf("invalid auth result message: too short")
	}

	resultType := confirmData[0]
	log.Printf("[RelayClient] Received auth result message type: 0x%02x", resultType)

	switch resultType {
	case MsgTypeServerAuthResult:
		if len(confirmData) < 2 {
			return fmt.Errorf("invalid auth result message: too short")
		}
		status := confirmData[1]
		log.Printf("[RelayClient] Auth result status: %d", status)
		if status != 0 {
			return fmt.Errorf("authentication failed with status: %d", status)
		}
	case MsgTypeServerDeniesAuth:
		reason := string(confirmData[1:])
		log.Printf("[RelayClient] Server denied authentication: %s", reason)
		return fmt.Errorf("server denied authentication: %s", reason)
	default:
		return fmt.Errorf("expected ServerAuthResult (0x%02x) or ServerDeniesAuth (0x%02x), got 0x%02x", MsgTypeServerAuthResult, MsgTypeServerDeniesAuth, resultType)
	}

	log.Printf("[RelayClient] Handshake completed successfully")

	return nil
}

// Close 关闭中继客户端
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Send 发送消息到中继服务器
func (c *Client) Send(msg []byte) error {
	if c.conn == nil {
		return fmt.Errorf("not connected to relay")
	}
	return c.conn.WriteMessage(websocket.BinaryMessage, msg)
}

// Receive 从中继服务器接收消息
func (c *Client) Receive() ([]byte, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected to relay")
	}
	_, msg, err := c.conn.ReadMessage()
	return msg, err
}

// ConnectToPeer 通过中继连接到对等点
func (c *Client) ConnectToPeer(peerId *crypto.EndpointId, alpn []byte) (interface{}, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected to relay server")
	}

	var request ConnectRequest
	copy(request.PeerId[:], peerId.Bytes())
	request.ALPN = alpn
	copy(request.ClientId[:], c.config.SecretKey.Public().Bytes())

	alpnLen := len(request.ALPN)
	requestData := make([]byte, 1+32+2+32+alpnLen)
	requestData[0] = MsgTypeConnect
	copy(requestData[1:33], request.PeerId[:])
	binary.BigEndian.PutUint16(requestData[33:35], uint16(alpnLen))
	copy(requestData[35:35+alpnLen], request.ALPN)
	copy(requestData[35+alpnLen:67+alpnLen], request.ClientId[:])

	if err := c.Send(requestData); err != nil {
		return nil, fmt.Errorf("failed to send connect request: %w", err)
	}

	responseData, err := c.Receive()
	if err != nil {
		return nil, fmt.Errorf("failed to receive connect response: %w", err)
	}

	if len(responseData) < 18 {
		return nil, fmt.Errorf("invalid connect response: expected at least 18 bytes, got %d", len(responseData))
	}

	responseType := responseData[0]
	if responseType != MsgTypeConnectResponse {
		return nil, fmt.Errorf("expected ConnectResponse (0x%02x), got 0x%02x", MsgTypeConnectResponse, responseType)
	}

	var response ConnectResponse
	response.Status = responseData[1]
	copy(response.RelayId[:], responseData[2:18])

	if response.Status != 0 {
		return nil, fmt.Errorf("relay connection failed with status: %d", response.Status)
	}

	connection := &RelayConnection{
		client:  c,
		peerId:  peerId,
		relayId: response.RelayId,
	}

	return connection, nil
}

// RelayConnection 中继连接
type RelayConnection struct {
	client  *Client
	peerId  *crypto.EndpointId
	relayId [16]byte
	closed  bool
}

// RelayId 获取中继连接ID
func (rc *RelayConnection) RelayId() [16]byte {
	return rc.relayId
}

// Send 通过中继发送数据
func (rc *RelayConnection) Send(data []byte) error {
	if rc.closed {
		return fmt.Errorf("relay connection is closed")
	}

	dataLen := len(data)
	msgData := make([]byte, 1+16+4+dataLen)
	msgData[0] = MsgTypeData
	copy(msgData[1:17], rc.relayId[:])
	binary.BigEndian.PutUint32(msgData[17:21], uint32(dataLen))
	copy(msgData[21:], data)

	return rc.client.Send(msgData)
}

// Receive 通过中继接收数据
func (rc *RelayConnection) Receive() ([]byte, error) {
	if rc.closed {
		return nil, fmt.Errorf("relay connection is closed")
	}

	data, err := rc.client.Receive()
	if err != nil {
		return nil, err
	}

	if len(data) < 1 {
		return nil, fmt.Errorf("invalid message: too short")
	}

	msgType := data[0]
	if msgType != MsgTypeData {
		return nil, fmt.Errorf("unexpected message type: 0x%02x", msgType)
	}

	if len(data) < 21 {
		return nil, fmt.Errorf("invalid data message: too short")
	}

	dataLen := binary.BigEndian.Uint32(data[17:21])
	if len(data) < 21+int(dataLen) {
		return nil, fmt.Errorf("invalid data message: data length mismatch")
	}

	return data[21 : 21+dataLen], nil
}

// Close 关闭中继连接
func (rc *RelayConnection) Close() error {
	if rc.closed {
		return nil
	}

	closeMsg := make([]byte, 1+16)
	closeMsg[0] = MsgTypeClose
	copy(closeMsg[1:17], rc.relayId[:])

	if err := rc.client.Send(closeMsg); err != nil {
		rc.closed = true
		return err
	}

	rc.closed = true
	return nil
}

// IsClosed 检查连接是否已关闭
func (rc *RelayConnection) IsClosed() bool {
	return rc.closed
}

// buildWebSocketURL 构建 WebSocket URL
func (c *Client) buildWebSocketURL() (string, error) {
	// 解析原始 URL
	parsedURL, err := url.Parse(c.url)
	if err != nil {
		return "", fmt.Errorf("invalid relay URL: %w", err)
	}

	// 修改 scheme
	scheme := parsedURL.Scheme
	switch scheme {
	case "http":
		parsedURL.Scheme = "ws"
	case "https":
		parsedURL.Scheme = "wss"
	case "ws", "wss":
		// 保持不变
	default:
		return "", fmt.Errorf("unsupported scheme: %s", scheme)
	}

	// 设置路径
	parsedURL.Path = RelayPath

	return parsedURL.String(), nil
}

// Config 中继配置
type Config struct {
	Urls      []string
	SecretKey *crypto.SecretKey
	ProxyURL  string
}

// NewConfig 创建新的中继配置
func NewConfig(urls []string, secretKey *crypto.SecretKey) *Config {
	return &Config{
		Urls:      urls,
		SecretKey: secretKey,
	}
}

// WithProxyURL 设置代理 URL
func (c *Config) WithProxyURL(proxyURL string) *Config {
	c.ProxyURL = proxyURL
	return c
}
