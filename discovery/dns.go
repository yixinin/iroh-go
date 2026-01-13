package discovery

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github/yixinin/iroh-go/common"
	"github/yixinin/iroh-go/crypto"
)

// 常量定义
const (
	// N0_DNS_ENDPOINT_ORIGIN_PROD 生产环境的DNS端点源域名
	N0_DNS_ENDPOINT_ORIGIN_PROD = "iroh.link"
	// N0_DNS_ENDPOINT_ORIGIN_STAGING 测试环境的DNS端点源域名
	N0_DNS_ENDPOINT_ORIGIN_STAGING = "iroh-staging.link"
	// DNS_STAGGERING_MS DNS查询的时间间隔
	DNS_STAGGERING_MS = 200
)

// DnsDiscovery DNS发现服务
type DnsDiscovery struct {
	ctx          context.Context
	cancel       context.CancelFunc
	originDomain string
	dnsResolver  *net.Resolver
}

// NewDnsDiscovery 创建新的DNS发现服务
func NewDnsDiscovery() *DnsDiscovery {
	return NewDnsDiscoveryWithOrigin(N0_DNS_ENDPOINT_ORIGIN_PROD)
}

// NewDnsDiscoveryWithOrigin 使用指定的源域名创建DNS发现服务
func NewDnsDiscoveryWithOrigin(originDomain string) *DnsDiscovery {
	ctx, cancel := context.WithCancel(context.Background())

	return &DnsDiscovery{
		ctx:          ctx,
		cancel:       cancel,
		originDomain: originDomain,
		dnsResolver:  net.DefaultResolver,
	}
}

// Publish 发布端点信息
func (d *DnsDiscovery) Publish(data *common.EndpointData) error {
	// DNS发现服务不支持发布功能
	// 发布功能通常通过PKARR或其他服务实现
	return fmt.Errorf("DNS discovery does not support publish")
}

// Discover 发现端点
func (d *DnsDiscovery) Discover(id *crypto.EndpointId) (<-chan *common.EndpointData, error) {
	ch := make(chan *common.EndpointData)

	go func() {
		defer close(ch)

		if id == nil {
			log.Println("Cannot discover endpoint without ID")
			return
		}

		// 构建DNS查询域名
		// 格式: _iroh.<z32-endpoint-id>.<origin-domain>
		endpointIdStr := id.String()
		// 注意：这里需要将endpoint ID转换为z-base-32格式
		// 暂时使用原始字符串，后续需要实现z-base-32编码
		domain := fmt.Sprintf("_iroh.%s.%s", endpointIdStr, d.originDomain)

		// 执行DNS TXT记录查询
		ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
		defer cancel()

		// 添加时间间隔，避免DNS服务器限流
		time.Sleep(time.Duration(DNS_STAGGERING_MS) * time.Millisecond)

		txtRecords, err := d.dnsResolver.LookupTXT(ctx, domain)
		if err != nil {
			log.Printf("Failed to lookup TXT records: %v", err)
			return
		}

		// 解析TXT记录
		data := &common.EndpointData{
			Id:       id,
			Addrs:    []common.TransportAddr{},
			RelayURL: "",
		}

		for _, txt := range txtRecords {
			// 解析TXT记录内容
			parts := strings.SplitN(txt, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key, value := parts[0], parts[1]
			switch key {
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

		// 发送发现结果
		ch <- data
		log.Printf("Discovered endpoint via DNS: %s", data.Id.String())
	}()

	return ch, nil
}

// Close 关闭发现服务
func (d *DnsDiscovery) Close() error {
	// 取消上下文
	d.cancel()

	log.Println("Closed DNS discovery service")
	return nil
}
