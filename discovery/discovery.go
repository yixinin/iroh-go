package discovery

import (
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
	for _, discovery := range cd.discoveries {
		if err := discovery.Close(); err != nil {
			// 记录错误但继续
		}
	}
	return nil
}
