package discovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/yixinin/iroh-go/common"
	"github.com/yixinin/iroh-go/crypto"
)

// 常量定义
const (
	// N0_DNS_PKARR_RELAY_PROD 生产环境的 PKARR 中继服务器
	N0_DNS_PKARR_RELAY_PROD = "https://pkarr.n0.computer"
	// N0_DNS_PKARR_RELAY_STAGING 测试环境的 PKARR 中继服务器
	N0_DNS_PKARR_RELAY_STAGING = "https://pkarr-staging.n0.computer"
	// DEFAULT_PKARR_TTL 默认的 PKARR TTL
	DEFAULT_PKARR_TTL = 3600
)

// PkarrDiscovery PKARR发现服务
type PkarrDiscovery struct {
	ctx        context.Context
	cancel     context.CancelFunc
	httpClient *http.Client
	relayURL   string
	secretKey  *crypto.SecretKey
}

// NewPkarrDiscovery 创建新的PKARR发现服务
func NewPkarrDiscovery() (*PkarrDiscovery, error) {
	return NewPkarrDiscoveryWithRelay(N0_DNS_PKARR_RELAY_PROD)
}

// NewPkarrDiscoveryWithRelay 使用指定的中继服务器创建PKARR发现服务
func NewPkarrDiscoveryWithRelay(relayURL string) (*PkarrDiscovery, error) {
	ctx, cancel := context.WithCancel(context.Background())

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	return &PkarrDiscovery{
		ctx:        ctx,
		cancel:     cancel,
		httpClient: httpClient,
		relayURL:   relayURL,
	}, nil
}

// SetSecretKey 设置密钥
func (d *PkarrDiscovery) SetSecretKey(key *crypto.SecretKey) {
	d.secretKey = key
}

// Publish 发布端点信息
func (d *PkarrDiscovery) Publish(data *common.EndpointData) error {
	if d.secretKey == nil {
		return fmt.Errorf("secret key is not set")
	}

	// 准备PKARR数据
	addrs := make([]string, 0)
	for _, addr := range data.Addrs {
		addrs = append(addrs, addr.String())
	}

	// 构建签名数据
	signData := data.Id.String() + data.RelayURL
	for _, addr := range addrs {
		signData += addr
	}
	signData += fmt.Sprintf("%d", DEFAULT_PKARR_TTL)

	// 签名数据
	signature := d.secretKey.Sign([]byte(signData))

	pkarrData := map[string]interface{}{
		"id":        data.Id.String(),
		"relay_url": data.RelayURL,
		"addrs":     addrs,
		"ttl":       DEFAULT_PKARR_TTL,
		"signature": hex.EncodeToString(signature),
	}

	// 序列化数据
	dataJSON, err := json.Marshal(pkarrData)
	if err != nil {
		return fmt.Errorf("[pkarr] Failed to marshal data: %w", err)
	}

	// 创建请求
	url := fmt.Sprintf("%s/pkarr", d.relayURL)
	req, err := http.NewRequestWithContext(d.ctx, http.MethodPut, url, bytes.NewBuffer(dataJSON))
	if err != nil {
		return fmt.Errorf("[pkarr] Failed to create request: %w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("[pkarr] Failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("[pkarr] Failed to read response: %w", err)
	}

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("[pkarr] Failed to publish: %s, status code: %d", string(respBody), resp.StatusCode)
	}

	log.Printf("[pkarr] Published PKARR record for endpoint %s to %s", data.Id.String(), d.relayURL)
	return nil
}

// Discover 发现端点
func (d *PkarrDiscovery) Discover(id *crypto.EndpointId) (<-chan *common.EndpointData, error) {
	ch := make(chan *common.EndpointData)

	go func() {
		defer close(ch)

		if id == nil {
			log.Println("Cannot discover endpoint without ID")
			return
		}

		// 构建请求URL
		url := fmt.Sprintf("%s/pkarr/%s", d.relayURL, id.String())

		// 创建请求
		req, err := http.NewRequestWithContext(d.ctx, http.MethodGet, url, nil)
		if err != nil {
			log.Printf("[pkarr] Failed to create request: %v", err)
			return
		}

		// 发送请求
		resp, err := d.httpClient.Do(req)
		if err != nil {
			log.Printf("[pkarr] Failed to send request: %v", err)
			return
		}
		defer resp.Body.Close()

		// 读取响应
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[pkarr] Failed to read response: %v", err)
			return
		}

		// 检查响应状态
		if resp.StatusCode != http.StatusOK {
			log.Printf("[pkarr] Failed to discover endpoint: %s, status code: %d", string(respBody), resp.StatusCode)
			return
		}

		// 解析响应
		var pkarrData map[string]interface{}
		if err := json.Unmarshal(respBody, &pkarrData); err != nil {
			log.Printf("[pkarr] Failed to unmarshal response: %v", err)
			return
		}

		// 构建端点数据
		data := &common.EndpointData{
			Id:       id,
			Addrs:    []common.TransportAddr{},
			RelayURL: "",
		}

		// 解析relay_url
		if relayURL, ok := pkarrData["relay_url"].(string); ok {
			data.RelayURL = relayURL
		}

		// 解析addrs
		if addrs, ok := pkarrData["addrs"].([]interface{}); ok {
			for _, addr := range addrs {
				if addrStr, ok := addr.(string); ok {
					transportAddr := &common.TransportAddrIp{
						Addr: addrStr,
					}
					data.Addrs = append(data.Addrs, transportAddr)
				}
			}
		}

		// 验证签名
		if signatureHex, ok := pkarrData["signature"].(string); ok {
			// 构建签名数据
			signData := data.Id.String() + data.RelayURL
			for _, addr := range data.Addrs {
				signData += addr.String()
			}
			signData += fmt.Sprintf("%d", DEFAULT_PKARR_TTL)

			// 解码签名
			signature, err := hex.DecodeString(signatureHex)
			if err != nil {
				log.Printf("Failed to decode signature: %v", err)
				return
			}

			// 验证签名
			publicKey := data.Id.PublicKey()
			if !ed25519.Verify(publicKey, []byte(signData), signature) {
				log.Printf("Invalid signature for endpoint: %s", data.Id.String())
				return
			}

			log.Printf("Signature verified for endpoint: %s", data.Id.String())
		}

		// 发送发现结果
		ch <- data
		log.Printf("Discovered endpoint via PKARR: %s", data.Id.String())
	}()

	return ch, nil
}

// Close 关闭发现服务
func (d *PkarrDiscovery) Close() error {
	// 取消上下文
	d.cancel()

	log.Println("Closed PKARR discovery service")
	return nil
}
