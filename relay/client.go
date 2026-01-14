package relay

import (
	"encoding/json"
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

// 消息类型
const (
	// MsgTypeConnect 连接请求
	MsgTypeConnect = 0x01
	// MsgTypeConnectResponse 连接响应
	MsgTypeConnectResponse = 0x02
	// MsgTypeData 数据传输
	MsgTypeData = 0x03
)

// ConnectRequest 连接请求消息
type ConnectRequest struct {
	MsgType  byte   `json:"msg_type"`
	PeerId   string `json:"peer_id"`
	ALPN     []byte `json:"alpn"`
	ClientId string `json:"client_id"`
}

// ConnectResponse 连接响应消息
type ConnectResponse struct {
	MsgType byte   `json:"msg_type"`
	Status  uint8  `json:"status"`
	RelayId string `json:"relay_id,omitempty"`
	Error   string `json:"error,omitempty"`
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
		HandshakeTimeout: 10 * time.Second,
		ReadBufferSize:   MaxFrameSize,
		WriteBufferSize:  MaxFrameSize,
		Subprotocols:     []string{RelayProtocolVersion},
	}

	// 构建请求头
	headers := http.Header{}
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

	// 接收服务器挑战
	challengeData, err := c.Receive()
	if err != nil {
		return fmt.Errorf("failed to receive challenge: %w", err)
	}

	log.Printf("[RelayClient] Received challenge: %x", challengeData)

	// 解析挑战
	var challenge map[string]interface{}
	if err := json.Unmarshal(challengeData, &challenge); err != nil {
		return fmt.Errorf("failed to unmarshal challenge: %w", err)
	}

	// 检查挑战类型
	challengeType, ok := challenge["type"].(string)
	if !ok || challengeType != "challenge" {
		return fmt.Errorf("invalid challenge type: %v", challengeType)
	}

	// 获取挑战数据
	challengeBytes, ok := challenge["challenge"].(string)
	if !ok {
		return fmt.Errorf("missing challenge data")
	}

	log.Printf("[RelayClient] Challenge data: %s", challengeBytes)

	// 使用私钥签名挑战
	signature := c.config.SecretKey.Sign([]byte(challengeBytes))
	log.Printf("[RelayClient] Generated signature: %x", signature)

	// 构建响应
	response := map[string]interface{}{
		"type":      "response",
		"client_id": c.config.SecretKey.Public().String(),
		"signature": fmt.Sprintf("%x", signature),
	}

	// 序列化响应
	responseData, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	log.Printf("[RelayClient] Sending response")

	// 发送响应
	if err := c.Send(responseData); err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	// 接收握手完成确认
	confirmData, err := c.Receive()
	if err != nil {
		return fmt.Errorf("failed to receive handshake confirmation: %w", err)
	}

	log.Printf("[RelayClient] Received confirmation: %x", confirmData)

	// 解析确认
	var confirm map[string]interface{}
	if err := json.Unmarshal(confirmData, &confirm); err != nil {
		return fmt.Errorf("failed to unmarshal confirmation: %w", err)
	}

	// 检查确认状态
	status, ok := confirm["status"].(string)
	if !ok || status != "ok" {
		errorMsg := "handshake failed"
		if msg, ok := confirm["error"].(string); ok {
			errorMsg = msg
		}
		return fmt.Errorf(errorMsg)
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
	// 检查是否已连接到中继服务器
	if c.conn == nil {
		return nil, fmt.Errorf("not connected to relay server")
	}

	// 构建连接请求消息
	request := ConnectRequest{
		MsgType:  MsgTypeConnect,
		PeerId:   peerId.String(),
		ALPN:     alpn,
		ClientId: c.config.SecretKey.Public().String(),
	}

	// 序列化请求消息
	requestData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal connect request: %w", err)
	}

	// 发送请求到中继服务器
	if err := c.Send(requestData); err != nil {
		return nil, fmt.Errorf("failed to send connect request: %w", err)
	}

	// 接收并解析响应
	responseData, err := c.Receive()
	if err != nil {
		return nil, fmt.Errorf("failed to receive connect response: %w", err)
	}

	// 解析响应消息
	var response ConnectResponse
	if err := json.Unmarshal(responseData, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal connect response: %w", err)
	}

	// 检查响应状态
	if response.Status != 0 {
		return nil, fmt.Errorf("relay connection failed: %s", response.Error)
	}

	// 构建并返回连接对象
	// 注意：这里返回一个简单的连接对象，实际项目中应该返回QUIC连接
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
	relayId string
	closed  bool
}

// RelayId 获取中继连接ID
func (rc *RelayConnection) RelayId() string {
	return rc.relayId
}

// Send 通过中继发送数据
func (rc *RelayConnection) Send(data []byte) error {
	// 检查连接是否已关闭
	if rc.closed {
		return fmt.Errorf("relay connection is closed")
	}

	// 构建数据传输消息
	dataMsg := map[string]interface{}{
		"msg_type": MsgTypeData,
		"relay_id": rc.relayId,
		"data":     data,
	}

	// 序列化消息
	dataMsgBytes, err := json.Marshal(dataMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal data message: %w", err)
	}

	// 发送数据
	return rc.client.Send(dataMsgBytes)
}

// Receive 通过中继接收数据
func (rc *RelayConnection) Receive() ([]byte, error) {
	// 检查连接是否已关闭
	if rc.closed {
		return nil, fmt.Errorf("relay connection is closed")
	}

	// 接收数据
	data, err := rc.client.Receive()
	if err != nil {
		return nil, err
	}

	// 解析消息
	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	// 检查消息类型
	msgType, ok := msg["msg_type"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid message type")
	}

	// 根据消息类型处理
	switch int(msgType) {
	case MsgTypeData:
		// 提取数据
		if dataBytes, ok := msg["data"].([]byte); ok {
			return dataBytes, nil
		}
		return nil, fmt.Errorf("invalid data message format")
	default:
		return nil, fmt.Errorf("unexpected message type: %d", int(msgType))
	}
}

// Close 关闭中继连接
func (rc *RelayConnection) Close() error {
	// 检查连接是否已关闭
	if rc.closed {
		return nil
	}

	// 构建关闭连接消息
	closeMsg := map[string]interface{}{
		"msg_type": 0x04, // 关闭连接消息类型
		"relay_id": rc.relayId,
	}

	// 序列化消息
	closeMsgBytes, err := json.Marshal(closeMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal close message: %w", err)
	}

	// 发送关闭请求
	if err := rc.client.Send(closeMsgBytes); err != nil {
		// 即使发送失败，也标记为关闭
		rc.closed = true
		return err
	}

	// 标记连接为关闭
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
