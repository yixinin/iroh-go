package discovery

import (
	"fmt"
	"log"

	"github/yixinin/iroh-go/common"
	"github/yixinin/iroh-go/crypto"
)

// Discovery 发现服务接口
type Discovery interface {
	// Publish 发布端点信息
	Publish(data *common.EndpointData) error

	// Discover 发现端点
	Discover(id *crypto.EndpointId) (<-chan *common.EndpointData, error)

	// Close 关闭发现服务
	Close() error
}

// DefaultDiscovery 创建默认的发现服务
// 默认启用 mDNS 发现服务
func DefaultDiscovery() Discovery {
	mdnsDisc, err := NewMdnsDiscovery()
	if err != nil {
		log.Printf("Warning: Failed to create mDNS discovery: %v", err)
		return NewConcurrentDiscovery()
	}

	cd := NewConcurrentDiscovery()
	cd.Add(mdnsDisc)
	return cd
}

// ConcurrentDiscovery 并发发现服务
type ConcurrentDiscovery struct {
	discoveries []Discovery
}

// NewConcurrentDiscovery 创建新的并发发现服务
func NewConcurrentDiscovery() *ConcurrentDiscovery {
	return &ConcurrentDiscovery{
		discoveries: []Discovery{},
	}
}

// Add 添加发现服务
func (cd *ConcurrentDiscovery) Add(discovery Discovery) {
	cd.discoveries = append(cd.discoveries, discovery)
}

// Publish 发布端点信息
func (cd *ConcurrentDiscovery) Publish(data *common.EndpointData) error {
	for _, discovery := range cd.discoveries {
		if err := discovery.Publish(data); err != nil {
			// 记录错误但继续
		}
	}
	return nil
}

// Discover 发现端点
func (cd *ConcurrentDiscovery) Discover(id *crypto.EndpointId) (<-chan *common.EndpointData, error) {
	ch := make(chan *common.EndpointData)

	if len(cd.discoveries) == 0 {
		close(ch)
		return ch, nil
	}

	// 启动所有发现服务
	for _, discovery := range cd.discoveries {
		go func(d Discovery) {
			dataCh, err := d.Discover(id)
			if err != nil {
				return
			}
			for data := range dataCh {
				ch <- data
			}
		}(discovery)
	}

	return ch, nil
}

// Close 关闭所有发现服务
func (cd *ConcurrentDiscovery) Close() error {
	var errs []error
	for _, discovery := range cd.discoveries {
		if err := discovery.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to close some discoveries: %v", errs)
	}
	return nil
}
