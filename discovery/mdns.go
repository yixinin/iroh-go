package discovery

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/grandcat/zeroconf"

	"github/yixinin/iroh-go/common"
	"github/yixinin/iroh-go/crypto"
)

// MdnsDiscovery mDNS发现服务
type MdnsDiscovery struct {
	ctx        context.Context
	cancel     context.CancelFunc
	publisher  *zeroconf.Server
	resolver   *zeroconf.Resolver
	discovered map[string]*common.EndpointData
}

// NewMdnsDiscovery 创建新的mDNS发现服务
func NewMdnsDiscovery() (*MdnsDiscovery, error) {
	ctx, cancel := context.WithCancel(context.Background())

	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create resolver: %w", err)
	}

	return &MdnsDiscovery{
		ctx:        ctx,
		cancel:     cancel,
		resolver:   resolver,
		discovered: make(map[string]*common.EndpointData),
	}, nil
}

// Publish 发布端点信息
func (d *MdnsDiscovery) Publish(data *common.EndpointData) error {
	// 停止之前的发布
	if d.publisher != nil {
		d.publisher.Shutdown()
		d.publisher = nil
	}

	// 准备TXT记录
	txtRecords := make([]string, 0)

	// 添加relay信息
	if data.RelayURL != "" {
		txtRecords = append(txtRecords, fmt.Sprintf("relay=%s", data.RelayURL))
	}

	// 添加addr信息
	if len(data.Addrs) > 0 {
		addrs := make([]string, 0)
		for _, addr := range data.Addrs {
			addrs = append(addrs, addr.String())
		}
		txtRecords = append(txtRecords, fmt.Sprintf("addr=%s", strings.Join(addrs, " ")))
	}

	// 添加endpoint id
	txtRecords = append(txtRecords, fmt.Sprintf("id=%s", data.Id.String()))

	// 创建服务
	server, err := zeroconf.Register(
		"iroh-endpoint", // 服务名
		"_iroh._tcp",    // 服务类型
		"local.",        // 域
		443,             // 端口
		txtRecords,      // TXT记录
		nil,             // 接口
	)
	if err != nil {
		return fmt.Errorf("failed to register service: %w", err)
	}

	d.publisher = server
	log.Printf("Published mDNS service for endpoint %s", data.Id.String())
	return nil
}

// Discover 发现端点
func (d *MdnsDiscovery) Discover(id *crypto.EndpointId) (<-chan *common.EndpointData, error) {
	ch := make(chan *common.EndpointData)

	go func() {
		defer close(ch)

		// 搜索服务
		entries := make(chan *zeroconf.ServiceEntry)
		err := d.resolver.Browse(d.ctx, "_iroh._tcp", "local.", entries)
		if err != nil {
			log.Printf("Failed to browse services: %v", err)
			return
		}

		for entry := range entries {
			// 解析TXT记录
			data := &common.EndpointData{
				Id:       &crypto.EndpointId{},
				Addrs:    []common.TransportAddr{},
				RelayURL: "",
			}

			// 解析TXT记录
			for _, txt := range entry.Text {
				parts := strings.SplitN(txt, "=", 2)
				if len(parts) != 2 {
					continue
				}

				key, value := parts[0], parts[1]
				switch key {
				case "id":
					// 解析endpoint id
					// 从十六进制字符串解析公钥
					publicKeyBytes, err := hex.DecodeString(value)
					if err != nil {
						log.Printf("Failed to decode endpoint id: %v", err)
						continue
					}
					publicKey, err := crypto.PublicKeyFromBytes(publicKeyBytes)
					if err != nil {
						log.Printf("Failed to create public key: %v", err)
						continue
					}
					data.Id = crypto.EndpointIdFromPublicKey(publicKey)
				case "relay":
					data.RelayURL = value
				case "addr":
					// 解析地址
					addrStrs := strings.Split(value, " ")
					for _, addrStr := range addrStrs {
						if addrStr == "" {
							continue
						}
						addr := &common.TransportAddrIp{
							Addr: addrStr,
						}
						data.Addrs = append(data.Addrs, addr)
					}
				}
			}

			// 检查是否是目标端点
			if id != nil && data.Id.String() != id.String() {
				continue
			}

			// 检查是否已经发现过
			if _, exists := d.discovered[data.Id.String()]; exists {
				continue
			}

			// 添加到已发现列表
			d.discovered[data.Id.String()] = data

			// 发送发现结果
			ch <- data
			log.Printf("Discovered endpoint via mDNS: %s", data.Id.String())
		}
	}()

	return ch, nil
}

// Close 关闭发现服务
func (d *MdnsDiscovery) Close() error {
	// 停止发布
	if d.publisher != nil {
		d.publisher.Shutdown()
		d.publisher = nil
	}

	// 取消上下文
	d.cancel()

	log.Println("Closed mDNS discovery service")
	return nil
}
