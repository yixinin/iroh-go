# iroh-go P2P 连接实现

基于 Rust iroh 项目实现的 Go 版本 P2P 连接库，支持 UDP 打洞和 Relay 中继。

## 功能特性

✅ **UDP 打洞** - 自动 NAT 穿透，建立直连
✅ **Relay 中继** - 当打洞失败时自动回退到中继
✅ **QUIC 协议** - 基于 QUIC 的可靠传输
✅ **多路径支持** - 同时管理多个网络路径
✅ **自动发现** - 支持多种发现机制（DNS、mDNS、PKARR）
✅ **连接迁移** - 支持在不中断连接的情况下切换路径

## 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                    MagicSock                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │         RemoteStateActor (per peer)          │   │
│  │  ┌────────────────────────────────────────┐   │   │
│  │  │        ConnectionState                │   │   │
│  │  │  - QUIC Connection                 │   │   │
│  │  │  - Relay Connection               │   │   │
│  │  │  - Multiple Paths                 │   │   │
│  │  └────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────┐   │
│  │         Transports                         │   │
│  │  - TransportIp (IPv4/IPv6)              │   │
│  │  - TransportRelay                        │   │
│  └──────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────┐   │
│  │         Discovery                          │   │
│  │  - DNS Discovery                        │   │
│  │  - mDNS Discovery                       │   │
│  │  - PKARR Discovery                       │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## 快速开始

### 安装

```bash
go get github.com/yixinin/iroh-go
```

### 基本使用

```go
package main

import (
    "fmt"
    "log"

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
        log.Fatalf("Failed to create MagicSock: %v", err)
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
        log.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Conn().CloseWithError(0, "")

    // 使用连接
    stream, err := conn.Conn().OpenStream()
    if err != nil {
        log.Fatalf("Failed to open stream: %v", err)
    }
    defer stream.Close()

    // 发送数据
    _, err = stream.Write([]byte("Hello, P2P!"))
    if err != nil {
        log.Fatalf("Failed to write: %v", err)
    }

    log.Println("Message sent successfully!")
}
```

## 连接流程

### 1. 初始化

```go
opts := magicsock.Options{
    RelayMode: common.RelayModeDefault,  // 使用默认中继
    SecretKey: crypto.NewSecretKey(),    // 生成密钥对
    ALPNs:     [][]byte{[]byte("app")}, // ALPN 协议
    Discovery: discovery.DefaultDiscovery(), // 发现服务
}

ms, err := magicsock.NewMagicSock(opts)
```

### 2. 连接建立

```
尝试直接连接 (UDP)
    ↓
失败？
    ↓
尝试 UDP 打洞
    ↓
失败？
    ↓
使用 Relay 中继
```

### 3. 路径管理

- **直连路径**: 通过 UDP 打洞建立的直接连接
- **中继路径**: 通过 Relay 服务器的连接
- **自动切换**: 根据网络条件自动选择最佳路径

## UDP 打洞

### 原理

UDP 打洞利用 NAT 的特性：

1. **发送打洞包**: 两个端点同时向对方发送 UDP 数据包
2. **NAT 映射**: NAT 为这些数据包创建临时端口映射
3. **建立连接**: 一旦映射建立，双方就可以直接通信
4. **保持活跃**: 定期发送心跳保持 NAT 映射

### 实现

```go
// 创建打洞数据包
packet := NewHolepunchPacket(localEndpointId)
data := packet.Serialize()

// 发送到候选地址
for _, addr := range candidateAddrs {
    udpConn.WriteTo(data, addr)
    time.Sleep(50 * time.Millisecond)
}
```

### 打洞数据包格式

```
+--------+----------------------------------+------------------+
| Type   | Sender ID (32 bytes)          | Timestamp (8 bytes) |
| 1 byte |                                |                    |
+--------+----------------------------------+------------------+
  0x01        Ed25519 Public Key              UnixNano()
```

## Relay 中继

### 连接流程

```
1. WebSocket 连接到中继服务器
    ↓
2. 接收服务器挑战
    ↓
3. 使用私钥签名挑战
    ↓
4. 发送认证响应
    ↓
5. 等待服务器确认
    ↓
6. 开始传输数据
```

### 认证

```go
// 1. 接收挑战
challenge := &ServerChallenge{Challenge: [16]byte}

// 2. 创建签名
auth := NewClientAuth(secretKey, challenge)

// 3. 发送认证
client.Send(EncodeClientAuth(auth))

// 4. 等待确认
confirm := client.Receive()
```

### 数据传输

```go
// 发送数据
client.SendDatagram(remotePublicKey, ECN, data)

// 接收数据
data, err := client.Read(buf)
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

```go
// DNS Discovery
dnsDiscovery := discovery.NewDNSDiscovery([]string{"example.com"})

// mDNS Discovery
mdnsDiscovery := discovery.NewMDNSDiscovery()

// PKARR Discovery
pkarrDiscovery := discovery.NewPKARRDiscovery()

// 组合多个发现服务
multiDiscovery := discovery.NewMultiDiscovery(
    dnsDiscovery,
    mdnsDiscovery,
    pkarrDiscovery,
)
```

## 测试

### 运行测试程序

```bash
# 终端 1: 启动节点 1
go run cmd/test_p2p/main.go node1

# 终端 2: 启动节点 2 并连接到节点 1
go run cmd/test_p2p/main.go node2 <node1-endpoint-id>
```

### 测试输出

```
2026/01/20 14:08:41 Starting Node 1...
2026/01/20 14:08:41 [MagicSock] Initializing relay connections (mode: default)
2026/01/20 14:08:41 [MagicSock] Attempting to connect to relay: https://aps1-1.relay.n0.iroh-canary.iroh.link
2026/01/20 14:08:44 [RelayClient] Authentication confirmed by server
2026/01/20 14:08:45 [MagicSock] Successfully connected to relay
2026/01/20 14:08:45 [MagicSock] QUIC listener started successfully
2026/01/20 14:08:45 Node 1 started with ID: 5bab4094fa8004b827cad17746fc8aaacce0e91d444f302b0aa8cf0b2c0042bd
```

## 性能优化

### 路径选择

- **延迟优先**: 选择延迟最低的路径
- **IPv6 优先**: 在相同延迟下优先选择 IPv6
- **稳定性考虑**: 考虑路径的稳定性和丢包率

### 连接复用

- **共享 MagicSock**: 多个连接共享同一个 MagicSock 实例
- **路径共享**: 同一远程端点的多个连接共享路径信息
- **资源优化**: 减少重复的连接和资源消耗

### 批量发送

- **数据包批处理**: 支持批量发送多个数据包
- **GRO 支持**: 支持 Generic Receive Offload
- **零拷贝**: 尽可能减少数据拷贝

## 故障处理

### 网络变化

```go
// 自动检测网络变化
ms.networkMonitorLoop()

// 重新绑定传输
ms.handleNetworkChange()

// 触发打洞
actor.triggerHolepunching()
```

### 连接失败

```go
// 尝试备用路径
if directConn == nil {
    relayConn := ms.tryRelayConnection(addr, alpn)
    return relayConn
}
```

### 超时处理

```go
// 连接超时
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

conn, err := ms.Connect(addr, alpn)
```

## 安全性

### 加密

- **TLS 1.3**: 所有连接使用 TLS 1.3 加密
- **Ed25519**: 使用 Ed25519 进行身份验证
- **前向保密**: 支持前向保密

### 认证

- **端点 ID**: 基于公钥的端点 ID
- **签名验证**: 所有消息都经过签名验证
- **中继认证**: 中继服务器需要客户端认证

## 限制和注意事项

### NAT 类型

- **Full Cone NAT**: 完全支持
- **Restricted Cone NAT**: 完全支持
- **Port Restricted Cone NAT**: 完全支持
- **Symmetric NAT**: 部分支持（需要中继）

### 防火墙

- **UDP 流量**: 需要允许 UDP 流量
- **端口范围**: 可能需要开放特定端口范围
- **出站连接**: 需要允许出站连接

### IPv6

- **当前支持**: 主要支持 IPv4
- **IPv6 支持**: IPv6 支持有限
- **未来改进**: 计划完整支持 IPv6

## 未来改进

### 短期

- [ ] 完整的 STUN/TURN 支持
- [ ] ICE 协议实现
- [ ] 更智能的路径选择算法
- [ ] 连接质量监控和报告

### 长期

- [ ] IPv6 完整支持
- [ ] 多中继服务器支持
- [ ] 负载均衡
- [ ] 更完善的错误处理和重试机制

## 文件结构

```
iroh-go/
├── cmd/
│   └── test_p2p/          # P2P 连接测试程序
├── common/
│   └── types.go            # 通用类型定义
├── crypto/
│   └── key.go              # 密钥和签名
├── discovery/
│   ├── discovery.go         # 发现服务接口
│   ├── dns.go              # DNS 发现
│   ├── mdns.go             # mDNS 发现
│   └── pkarr.go            # PKARR 发现
├── endpoint/
│   ├── endpoint.go         # 端点实现
│   ├── builder.go          # 端点构建器
│   ├── connection.go       # 连接实现
│   └── net.go              # 网络工具
├── magicsock/
│   ├── magicsock.go        # MagicSock 核心实现
│   ├── transports.go       # 传输层实现
│   ├── remote_state.go     # 远程状态管理
│   ├── remote_map.go       # 远程节点映射
│   ├── mapped_addrs.go     # 地址映射
│   └── holepunch.go        # UDP 打洞实现
├── relay/
│   ├── client.go           # 中继客户端
│   ├── connection.go       # 中继连接
│   ├── stream.go           # 中继流
│   ├── handshake.go        # 握手协议
│   ├── message.go          # 消息编解码
│   └── frame.go            # 帧类型定义
└── README.md
```

## 参考资料

- [Rust iroh 项目](https://github.com/n0-computer/iroh)
- [QUIC 协议](https://quicwg.org/)
- [WebRTC NAT 穿透](https://webrtc.org/getting-started/nat-traversal)
- [UDP 打洞技术](https://en.wikipedia.org/wiki/UDP_hole_punching)
- [RFC 9000 - QUIC](https://datatracker.ietf.org/doc/html/rfc9000)
- [RFC 8445 - Connection-Oriented NAT](https://datatracker.ietf.org/doc/html/rfc8445)

## 许可证

本项目基于 Rust iroh 项目，遵循相同的许可证。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 联系方式

如有问题或建议，请通过以下方式联系：

- GitHub Issues
- Email: your-email@example.com

---

**注意**: 这是一个实验性项目，请谨慎在生产环境中使用。
