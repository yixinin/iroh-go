package relay

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github/yixinin/iroh-go/crypto"

	"github.com/gorilla/websocket"
)

// 常量定义
const (
	// RelayPath 中继服务路径
	RelayPath = "/relay"
	// RelayProtocolVersion 中继协议版本
	RelayProtocolVersion = "iroh/relay/0"
	// ClientAuthHeader 客户端认证头部
	ClientAuthHeader = "X-Iroh-Client-Auth"
	// MaxFrameSize 最大帧大小
	MaxFrameSize = 16384
)

// Client 中继客户端
type Client struct {
	conn   *websocket.Conn
	config *Config
	url    string
}

// NewClient 创建新的中继客户端
func NewClient(config *Config) (*Client, error) {
	if len(config.Urls) == 0 {
		return nil, fmt.Errorf("no relay URLs provided")
	}

	return &Client{
		config: config,
		url:    config.Urls[0],
	}, nil
}

// Connect 连接到中继服务器
func (c *Client) Connect() error {
	// 构建 WebSocket URL
	dialURL, err := c.buildWebSocketURL()
	if err != nil {
		return err
	}

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
	if c.config.SecretKey != nil {
		// TODO: 实现 TLS 密钥导出用于客户端认证
		// 目前暂不实现，后续可以添加
	}

	// 建立 WebSocket 连接
	conn, resp, err := dialer.Dial(dialURL, headers)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("failed to connect to relay: %w, status: %s", err, resp.Status)
		}
		return fmt.Errorf("failed to connect to relay: %w", err)
	}

	// 检查响应状态
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("unexpected upgrade status: %s", resp.Status)
	}

	c.conn = conn
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
	// TODO: 实现通过中继连接到对等点的逻辑
	// 1. 向中继服务器发送连接请求
	// 2. 处理中继服务器的响应
	// 3. 建立并返回QUIC连接
	return nil, fmt.Errorf("ConnectToPeer not implemented")
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
