package magicsock

import (
	"github.com/yixinin/iroh-go/crypto"
	"sync"
)

// RemoteMap 远程节点映射
type RemoteMap struct {
	remotes sync.Map
}

// RemoteInfo 远程节点信息
type RemoteInfo struct {
	Id        *crypto.EndpointId
	Addresses []string
	RelayUrl  string
}

// NewRemoteMap 创建新的远程节点映射
func NewRemoteMap() *RemoteMap {
	return &RemoteMap{
		remotes: sync.Map{},
	}
}

// Get 获取远程节点信息
func (rm *RemoteMap) Get(id *crypto.EndpointId) (*RemoteInfo, bool) {
	info, ok := rm.remotes.Load(id.String())
	if !ok {
		return nil, false
	}
	return info.(*RemoteInfo), true
}

// Set 设置远程节点信息
func (rm *RemoteMap) Set(id *crypto.EndpointId, info *RemoteInfo) {
	rm.remotes.Store(id.String(), info)
}

// Delete 删除远程节点信息
func (rm *RemoteMap) Delete(id *crypto.EndpointId) {
	rm.remotes.Delete(id.String())
}

// Iterate 遍历所有远程节点
func (rm *RemoteMap) Iterate(f func(*crypto.EndpointId, *RemoteInfo) bool) {
	rm.remotes.Range(func(key, value interface{}) bool {
		id := &crypto.EndpointId{}
		// TODO: 从key解析id
		info := value.(*RemoteInfo)
		return f(id, info)
	})
}
