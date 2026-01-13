package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github/yixinin/iroh-go/common"
	"github/yixinin/iroh-go/crypto"
	"github/yixinin/iroh-go/magicsock"
)

// IrohTransport 实现了 http.RoundTripper 接口，使用 iroh 协议进行通信
type IrohTransport struct {
	magicSock *magicsock.MagicSock
	alpn      []byte
	timeout   time.Duration
}

// NewIrohTransport 创建一个新的 IrohTransport 实例
func NewIrohTransport(ms *magicsock.MagicSock, alpn []byte, timeout time.Duration) *IrohTransport {
	return &IrohTransport{
		magicSock: ms,
		alpn:      alpn,
		timeout:   timeout,
	}
}

// RoundTrip 实现 http.RoundTripper 接口，处理 HTTP 请求
func (t *IrohTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 设置请求超时
	ctx, cancel := context.WithTimeout(req.Context(), t.timeout)
	defer cancel()
	req = req.WithContext(ctx)

	// 解析请求 URL，获取远程端点 ID
	// 注意：这里简化处理，实际实现需要从 URL 中提取端点 ID
	remoteId := t.magicSock.Id()

	// 构建远程端点地址
	remoteAddr := magicsock.EndpointAddr{
		Id: remoteId,
		Addrs: []common.TransportAddr{
			&common.TransportAddrIp{
				Addr: req.Host,
			},
		},
	}

	// 连接到远程端点
	fmt.Printf("Connecting to remote endpoint %s at %s...\n", remoteId.String(), req.Host)
	conn, err := t.magicSock.Connect(remoteAddr, t.alpn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to remote endpoint: %v", err)
	}
	fmt.Println("Connected to remote endpoint successfully")

	// 获取底层的 QUIC 连接
	quicConn := conn.Conn()
	if quicConn == nil {
		return nil, fmt.Errorf("failed to get QUIC connection")
	}

	// 打开一个 QUIC 流
	stream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open QUIC stream: %v", err)
	}
	defer stream.Close()

	// 构建 HTTP 请求
	fmt.Printf("Sending %s request to %s\n", req.Method, req.URL.Path)
	reqBuf := &bytes.Buffer{}
	// 写入请求行
	reqBuf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", req.Method, req.URL.Path))
	// 写入请求头
	reqBuf.WriteString(fmt.Sprintf("Host: %s\r\n", req.Host))
	for key, values := range req.Header {
		for _, value := range values {
			reqBuf.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}
	// 写入请求体
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %v", err)
		}
		reqBuf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		reqBuf.WriteString("\r\n")
		reqBuf.Write(body)
	} else {
		reqBuf.WriteString("\r\n")
	}

	// 发送 HTTP 请求
	_, err = stream.Write(reqBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %v", err)
	}
	fmt.Println("HTTP request sent successfully")

	// 读取 HTTP 响应
	responseBuf := &bytes.Buffer{}
	_, err = io.Copy(responseBuf, stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response: %v", err)
	}
	fmt.Println("HTTP response received successfully")

	// 解析 HTTP 响应
	response := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(responseBuf.Bytes())),
		Header:     make(http.Header),
		Request:    req,
	}

	// 解析响应状态行和头部
	// 注意：这里简化处理，实际实现需要更复杂的解析
	response.Header.Set("Content-Type", "text/plain")

	return response, nil
}

func main() {
	// 解析命令行参数
	urlFlag := flag.String("url", "http://example.com/health", "目标 URL")
	methodFlag := flag.String("method", "GET", "HTTP 方法")
	dataFlag := flag.String("data", "", "请求体数据")
	alpnFlag := flag.String("alpn", "h3", "ALPN 协议")
	relayModeFlag := flag.Int("relay-mode", 0, "中继模式 (0: 默认, 1: 禁用, 2: 测试, 3: 自定义)")
	timeoutFlag := flag.Duration("timeout", 30*time.Second, "请求超时时间")
	retryFlag := flag.Int("retry", 3, "重试次数")
	flag.Parse()

	// 生成密钥对
	secretKey := crypto.NewSecretKey()
	fmt.Println("Generated secret key successfully")

	// 初始化魔法套接字选项
	opts := magicsock.Options{
		RelayMode: common.RelayMode(*relayModeFlag),
		SecretKey: secretKey,
		ALPNs:     [][]byte{[]byte(*alpnFlag)},
	}

	// 创建魔法套接字
	fmt.Println("Creating magic sock...")
	ms, err := magicsock.NewMagicSock(opts)
	if err != nil {
		log.Fatalf("Failed to create magic sock: %v", err)
	}
	defer ms.Close()

	// 打印本地端点信息
	localAddr := ms.Addr()
	fmt.Printf("Local endpoint ID: %s\n", localAddr.Id.String())
	fmt.Printf("Local addresses: %v\n", localAddr.Addrs)

	// 创建使用 iroh 协议的 HTTP 客户端
	client := &http.Client{
		Transport: NewIrohTransport(ms, []byte(*alpnFlag), *timeoutFlag),
	}

	// 构建请求体
	var body io.Reader
	if *dataFlag != "" {
		body = bytes.NewBufferString(*dataFlag)
	}

	// 发送 HTTP 请求
	fmt.Printf("Sending %s request to %s...\n", *methodFlag, *urlFlag)
	req, err := http.NewRequest(*methodFlag, *urlFlag, body)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Iroh-Go Client/1.0")

	// 执行请求（带重试机制）
	var resp *http.Response
	for i := 0; i < *retryFlag; i++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		fmt.Printf("Request failed (attempt %d/%d): %v\n", i+1, *retryFlag, err)
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		log.Fatalf("Failed to send request after %d attempts: %v", *retryFlag, err)
	}
	defer resp.Body.Close()

	// 读取响应
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	// 打印响应
	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Body: %s\n", respBody)

	// 打印响应头
	fmt.Println("Response Headers:")
	for key, values := range resp.Header {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", key, value)
		}
	}

	fmt.Println("HTTP client test completed successfully")
}
