# 基于 quic-go 的 NAT 穿透实现方案

## 核心思路

通过自定义 `net.PacketConn` 实现来管理多个 UDP 连接，在底层实现 NAT 穿透和路径管理，同时保持与 `quic-go` 的兼容性。

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                     MagicSock                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              CustomPacketConn                         │  │
│  │  ┌─────────┐  ┌─────────┐  ┌───────────────────┐  │  │
│  │  │ IPv4    │  │ IPv6    │  │ Relay Connection   │  │  │
│  │  │ UDP     │  │ UDP     │  │ (WebSocket)        │  │  │
│  │  └─────────┘  └─────────┘  └───────────────────┘  │  │
│  │                                                       │  │
│  │  ┌─────────────────────────────────────────────┐    │  │
│  │  │         Path Manager                        │    │  │
│  │  │  - Path selection                          │    │  │
│  │  │  - Load balancing                          │    │  │
│  │  │  - Failover                                │    │  │
│  │  └─────────────────────────────────────────────┘    │  │
│  │                                                       │  │
│  │  ┌─────────────────────────────────────────────┐    │  │
│  │  │         NAT Traversal                        │    │  │
│  │  │  - Hole punching                            │    │  │
│  │  │  - Candidate discovery                      │    │  │
│  │  │  - Path validation                          │    │  │
│  │  └─────────────────────────────────────────────┘    │  │
│  └───────────────────────────────────────────────────────┘  │
│                           │                                  │
│                           ▼                                  │
│                   quic.Connection                           │
└─────────────────────────────────────────────────────────────┘
```

## 实现方案

### 1. CustomPacketConn

```go
type CustomPacketConn struct {
    mu sync.RWMutex

    // 底层传输层
    ipv4Conn *net.UDPConn
    ipv6Conn *net.UDPConn
    relayConn *relay.Client

    // 路径管理
    paths map[string]*Path
    selectedPath *Path

    // NAT 穿透
    holepuncher *Holepuncher
    candidates []*Candidate

    // QUIC 连接
    quicConn quic.Connection

    // 通道
    readChan chan []byte
    writeChan chan *Packet

    // 上下文
    ctx context.Context
    cancel context.CancelFunc
}

type Path struct {
    addr net.Addr
    conn net.PacketConn
    rtt time.Duration
    active bool
    lastSeen time.Time
}

type Packet struct {
    data []byte
    addr net.Addr
    path *Path
}

type Candidate struct {
    addr net.Addr
    source string // "local", "remote", "discovery"
    priority int
}
```

### 2. 实现 net.PacketConn 接口

```go
func (c *CustomPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
    select {
    case data := <-c.readChan:
        copy(p, data)
        return len(data), c.selectedPath.addr, nil
    case <-c.ctx.Done():
        return 0, nil, c.ctx.Err()
    }
}

func (c *CustomPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
    packet := &Packet{
        data: p,
        addr: addr,
    }

    // 选择最佳路径
    path := c.selectPath(addr)
    if path == nil {
        return 0, fmt.Errorf("no available path")
    }

    packet.path = path
    c.writeChan <- packet

    return len(p), nil
}

func (c *CustomPacketConn) Close() error {
    c.cancel()
    if c.ipv4Conn != nil {
        c.ipv4Conn.Close()
    }
    if c.ipv6Conn != nil {
        c.ipv6Conn.Close()
    }
    if c.relayConn != nil {
        c.relayConn.Close()
    }
    return nil
}

func (c *CustomPacketConn) LocalAddr() net.Addr {
    if c.selectedPath != nil {
        return c.selectedPath.conn.LocalAddr()
    }
    return nil
}

func (c *CustomPacketConn) SetDeadline(t time.Time) error {
    return nil
}

func (c *CustomPacketConn) SetReadDeadline(t time.Time) error {
    return nil
}

func (c *CustomPacketConn) SetWriteDeadline(t time.Time) error {
    return nil
}
```

### 3. 路径管理

```go
func (c *CustomPacketConn) selectPath(addr net.Addr) *Path {
    c.mu.RLock()
    defer c.mu.RUnlock()

    // 如果有选定的路径且活跃，使用它
    if c.selectedPath != nil && c.selectedPath.active {
        return c.selectedPath
    }

    // 选择最佳路径
    var bestPath *Path
    var bestRTT time.Duration

    for _, path := range c.paths {
        if !path.active {
            continue
        }

        if bestPath == nil || path.rtt < bestRTT {
            bestPath = path
            bestRTT = path.rtt
        }
    }

    return bestPath
}

func (c *CustomPacketConn) updatePathRTT(path *Path, rtt time.Duration) {
    c.mu.Lock()
    defer c.mu.Unlock()

    path.rtt = rtt
    path.lastSeen = time.Now()

    // 如果这个路径更好，切换到它
    if c.selectedPath == nil || rtt < c.selectedPath.rtt {
        c.selectedPath = path
    }
}

func (c *CustomPacketConn) addPath(addr net.Addr, conn net.PacketConn) *Path {
    c.mu.Lock()
    defer c.mu.Unlock()

    key := addr.String()
    if path, exists := c.paths[key]; exists {
        return path
    }

    path := &Path{
        addr: addr,
        conn: conn,
        active: false,
        lastSeen: time.Now(),
    }

    c.paths[key] = path
    return path
}
```

### 4. NAT 穿透

```go
type Holepuncher struct {
    conn *CustomPacketConn
    candidates []*Candidate
    attempts int
    lastAttempt time.Time
}

func (h *Holepuncher) Start() {
    go h.run()
}

func (h *Holepuncher) run() {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            h.attemptHolepunch()
        case <-h.conn.ctx.Done():
            return
        }
    }
}

func (h *Holepuncher) attemptHolepunch() {
    h.attempts++

    for _, candidate := range h.candidates {
        // 发送打洞数据包
        h.sendHolepunchPacket(candidate.addr)
    }
}

func (h *Holepuncher) sendHolepunchPacket(addr net.Addr) {
    packet := h.createHolepunchPacket()
    h.conn.WriteTo(packet, addr)
}

func (h *Holepuncher) createHolepunchPacket() []byte {
    // 创建打洞数据包
    // 格式: [Type:1][EndpointID:32][Timestamp:8]
    buf := make([]byte, 41)
    buf[0] = 0x01 // Holepunch packet type
    copy(buf[1:33], h.conn.endpointId[:])
    binary.BigEndian.PutUint64(buf[33:41], uint64(time.Now().UnixNano()))
    return buf
}

func (h *Holepuncher) handleHolepunchPacket(data []byte, addr net.Addr) {
    if len(data) < 41 || data[0] != 0x01 {
        return
    }

    var endpointId [32]byte
    copy(endpointId[:], data[1:33])
    timestamp := time.Unix(0, int64(binary.BigEndian.Uint64(data[33:41])))

    // 验证时间戳
    if time.Since(timestamp) > 30*time.Second {
        return
    }

    // 添加为候选路径
    h.addCandidate(addr, "holepunch", 10)
}

func (h *Holepuncher) addCandidate(addr net.Addr, source string, priority int) {
    candidate := &Candidate{
        addr: addr,
        source: source,
        priority: priority,
    }

    h.candidates = append(h.candidates, candidate)

    // 尝试建立连接
    h.conn.tryConnect(addr)
}
```

### 5. 数据包处理

```go
func (c *CustomPacketConn) startPacketLoop() {
    go c.readFromIPv4()
    go c.readFromIPv6()
    go c.readFromRelay()
    go c.processPackets()
}

func (c *CustomPacketConn) readFromIPv4() {
    if c.ipv4Conn == nil {
        return
    }

    buf := make([]byte, 65535)
    for {
        n, addr, err := c.ipv4Conn.ReadFrom(buf)
        if err != nil {
            if !errors.Is(err, net.ErrClosed) {
                log.Printf("IPv4 read error: %v", err)
            }
            return
        }

        c.handlePacket(buf[:n], addr, c.ipv4Conn)
    }
}

func (c *CustomPacketConn) readFromIPv6() {
    if c.ipv6Conn == nil {
        return
    }

    buf := make([]byte, 65535)
    for {
        n, addr, err := c.ipv6Conn.ReadFrom(buf)
        if err != nil {
            if !errors.Is(err, net.ErrClosed) {
                log.Printf("IPv6 read error: %v", err)
            }
            return
        }

        c.handlePacket(buf[:n], addr, c.ipv6Conn)
    }
}

func (c *CustomPacketConn) readFromRelay() {
    if c.relayConn == nil {
        return
    }

    buf := make([]byte, 65535)
    for {
        n, err := c.relayConn.Read(buf)
        if err != nil {
            if !errors.Is(err, io.EOF) {
                log.Printf("Relay read error: %v", err)
            }
            return
        }

        // 从 relay 获取地址
        addr := c.relayConn.RemoteAddr()
        c.handlePacket(buf[:n], addr, c.relayConn)
    }
}

func (c *CustomPacketConn) handlePacket(data []byte, addr net.Addr, conn net.PacketConn) {
    // 检查是否是打洞数据包
    if c.holepuncher != nil && c.holepuncher.isHolepunchPacket(data) {
        c.holepuncher.handleHolepunchPacket(data, addr)
        return
    }

    // 添加或更新路径
    path := c.addPath(addr, conn)
    path.active = true
    path.lastSeen = time.Now()

    // 将数据包发送到 QUIC 层
    select {
    case c.readChan <- data:
    default:
        log.Printf("Read channel full, dropping packet")
    }
}

func (c *CustomPacketConn) processPackets() {
    for {
        select {
        case packet := <-c.writeChan:
            _, err := packet.path.conn.WriteTo(packet.data, packet.addr)
            if err != nil {
                log.Printf("Write error: %v", err)
                packet.path.active = false
            }
        case <-c.ctx.Done():
            return
        }
    }
}
```

### 6. 与 quic-go 集成

```go
func (m *MagicSock) Dial(ctx context.Context, remoteId *crypto.EndpointId) (*Connection, error) {
    // 创建自定义 PacketConn
    customConn := NewCustomPacketConn(m.transports, m.relayClients)
    defer customConn.Close()

    // 使用自定义 PacketConn 建立 QUIC 连接
    tlsConf := &tls.Config{
        InsecureSkipVerify: true,
        NextProtos: []string{"h3"},
    }

    quicConn, err := quic.Dial(
        ctx,
        customConn,
        remoteId.ToAddr(),
        tlsConf,
        &quic.Config{
            MaxIdleTimeout: time.Minute * 5,
            KeepAlive: true,
        },
    )
    if err != nil {
        return nil, err
    }

    conn := &Connection{
        quicConn: quicConn,
        remoteId: remoteId,
        alpn: []byte("h3"),
    }

    return conn, nil
}

func (m *MagicSock) Listen() (*quic.Listener, error) {
    // 创建自定义 PacketConn
    customConn := NewCustomPacketConn(m.transports, m.relayClients)

    // 使用自定义 PacketConn 监听
    tlsConf := &tls.Config{
        Certificates: []tls.Certificate{m.generateCert()},
        NextProtos: []string{"h3"},
    }

    listener, err := quic.Listen(
        customConn,
        tlsConf,
        &quic.Config{
            MaxIdleTimeout: time.Minute * 5,
            KeepAlive: true,
        },
    )
    if err != nil {
        return nil, err
    }

    return listener, nil
}
```

## 优势

1. **不需要 fork quic-go**：使用标准 quic-go 库
2. **完全控制底层连接**：可以管理多个 UDP 连接
3. **实现 NAT 穿透**：可以在底层实现打洞逻辑
4. **路径管理**：可以实现路径选择和负载均衡
5. **与 Rust 版本兼容**：可以实现类似的功能

## 挑战

1. **复杂度**：需要仔细管理多个连接和数据包路由
2. **性能**：需要优化数据包处理路径
3. **错误处理**：需要处理各种网络错误情况
4. **测试**：需要充分测试各种网络场景

## 实现步骤

1. 实现 CustomPacketConn
2. 实现路径管理
3. 实现 NAT 穿透
4. 与 quic-go 集成
5. 测试和优化

## 参考资料

- [quic-go Documentation](https://github.com/quic-go/quic-go)
- [QUIC Protocol RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000)
- [NAT Traversal Draft](https://datatracker.ietf.org/doc/html/draft-ietf-quic-nat-traversal-00)
