# iroh-go P2P 连接实现

## 概述

本项目基于 Rust iroh 实现，完善了 iroh-go 的 UDP 打洞和 relay 中继功能，实现了完整的 P2P 连接能力。

## 主要改进

### 1. UDP Socket 传输层实现

- **文件**: `magicsock/transports.go`
- **改进**: 实现了完整的 `TransportIp` 结构，包括：
  - UDP socket 的创建和绑定
  - 数据发送和接收功能
  - 网络变化时的重新绑定
  - 读写缓冲区设置

### 2. UDP 打洞逻辑

- **文件**: `magicsock/remote_state.go`, `magicsock/holepunch.go`
- **改进**: 实现了 UDP 打洞的核心逻辑：
  - 打洞数据包的创建和发送
  - 多次重试机制（3次，间隔50ms）
  - 打洞状态跟踪

### 3. Relay 连接与 QUIC 集成

- **文件**: `relay/connection.go`, `relay/stream.go`
- **改进**: 创建了完整的 QUIC 连接适配器：
  - `RelayConnection` 实现 `quic.Connection` 接口
  - `RelayStream` 实现 `quic.Stream` 接口
  - 支持双向和单向流
  - 完整的生命周期管理

### 4. 打洞数据包处理

- **文件**: `magicsock/holepunch.go`, `magicsock/magicsock.go`
- **改进**: 实现了打洞数据包的接收和处理：
  - 打洞数据包的序列化和反序列化
  - UDP 接收循环
  - 自动创建 RemoteStateActor 处理新连接

## 架构说明

### 连接建立流程

```
1. 创建 MagicSock
   ↓
2. 初始化传输层（UDP + Relay）
   ↓
3. 启动后台任务
   - 接受连接循环
   - 路径检查循环
   - 网络监控循环
   - UDP 接收循环
   ↓
4. 连接到远程端点
   a. 尝试直接连接（UDP）
   b. 如果失败，尝试 Relay 连接
   ↓
5. 建立 P2P 连接
   - 通过 UDP 打洞建立直连
   - 或通过 Relay 中继传输数据
```

### UDP 打洞流程

```
1. 发现远程端点地址
   ↓
2. 创建 RemoteStateActor
   ↓
3. 触发打洞
   - 发送打洞数据包到候选地址
   - 多次重试提高成功率
   ↓
4. 接收打洞数据包
   - 创建对应的 RemoteStateActor
   - 添加路径到连接
   ↓
5. 建立 QUIC 连接
   - 使用打洞成功的地址
   - 或回退到 Relay 连接
```

## 使用方法

### 基本使用

```go
package main

import (
    "github.com/yixinin/iroh-go/common"
    "github.com/yixinin/iroh-go/crypto"
    "github.com/yixinin/iroh-go/discovery"
    "github.com/yixinin/iroh-go/magicsock"
)

func main() {
    // 创建 MagicSock
    opts := magicsock.Options{
        RelayMode: common.RelayModeDefault,
        SecretKey: crypto.NewSecretKey(),
        ALPNs:     [][]byte{[]byte("my-app")},
        Discovery: discovery.DefaultDiscovery(),
    }

    ms, err := magicsock.NewMagicSock(opts)
    if err != nil {
        panic(err)
    }
    defer ms.Close()

    // 获取端点信息
    fmt.Printf("Endpoint ID: %s\n", ms.Id().String())
    fmt.Printf("Addresses: %v\n", ms.Addr().Addrs)

    // 连接到远程端点
    remoteId, _ := crypto.ParseEndpointId("remote-endpoint-id")
    addr := magicsock.EndpointAddr{
        Id:    remoteId,
        Addrs: []common.TransportAddr{},
    }

    conn, err := ms.Connect(addr, []byte("my-app"))
    if err != nil {
        panic(err)
    }
    defer conn.Conn().Close()

    // 使用连接
    stream, err := conn.Conn().OpenStream()
    if err != nil {
        panic(err)
    }
    defer stream.Close()

    // 发送数据
    stream.Write([]byte("Hello, P2P!"))
}
```

### 测试 P2P 连接

项目包含一个测试程序来验证 P2P 连接功能：

```bash
# 终端 1: 启动节点 1
go run cmd/test_p2p/main.go node1

# 终端 2: 启动节点 2 并连接到节点 1
# 使用节点 1 的 Endpoint ID
go run cmd/test_p2p/main.go node2 <node1-endpoint-id>
```

## 配置选项

### Relay 模式

```go
const (
    RelayModeDisabled  // 禁用中继
    RelayModeDefault  // 使用默认中继
    RelayModeStaging // 使用测试中继
    RelayModeCustom  // 使用自定义中继
)
```

### Discovery 服务

支持多种发现机制：
- DNS-based discovery
- mDNS (local network)
- PKARR (DHT-based)

## 技术细节

### UDP 打洞原理

UDP 打洞利用 NAT 的特性：
1. 两个端点都向对方发送 UDP 数据包
2. NAT 会为这些数据包创建临时映射
3. 一旦映射建立，双方就可以直接通信
4. 打洞数据包包含端点 ID，用于识别连接

### Relay 中继

当 UDP 打洞失败时，系统会自动回退到 Relay 中继：
- 通过 WebSocket 连接到中继服务器
- 使用 Ed25519 签名进行身份验证
- 中继服务器转发数据包到目标端点

### QUIC 协议

- 使用 QUIC 作为传输层协议
- 支持多路复用和流控
- 内置 TLS 1.3 加密
- 支持连接迁移

## 性能优化

1. **路径选择**: 自动选择延迟最低的路径
2. **连接复用**: 多个连接共享同一个 MagicSock 实例
3. **批量发送**: 支持批量发送数据包以提高效率
4. **心跳机制**: 定期发送心跳保持连接活跃

## 故障处理

1. **网络变化**: 自动检测网络变化并重新绑定
2. **连接失败**: 自动尝试备用路径（Relay）
3. **超时处理**: 合理的超时设置和重试机制
4. **资源清理**: 正确关闭连接和释放资源

## 限制和注意事项

1. **NAT 类型**: 某些严格的 NAT 类型可能无法打洞
2. **防火墙**: 需要允许 UDP 流量
3. **IPv6**: 当前主要支持 IPv4，IPv6 支持有限
4. **中继依赖**: Relay 模式依赖中继服务器可用性

## 未来改进

1. 完整的 STUN/TURN 支持
2. ICE 协议实现
3. 更智能的路径选择算法
4. IPv6 完整支持
5. 连接质量监控和报告

## 参考资料

- [Rust iroh 项目](https://github.com/n0-computer/iroh)
- [QUIC 协议](https://quicwg.org/)
- [WebRTC NAT 穿透](https://webrtc.org/getting-started/nat-traversal)
- [UDP 打洞技术](https://en.wikipedia.org/wiki/UDP_hole_punching)
