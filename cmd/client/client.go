package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/yixinin/iroh-go/crypto"
	"github.com/yixinin/iroh-go/endpoint"
	"github.com/yixinin/iroh-go/irohttp"
)

func main() {
	// 解析命令行参数
	urlFlag := flag.String("url", "iroh://7b6b951dcc796191d79b203f533f72992c7d16e2f85f12f38722e8b27e141864/health", "目标 URL")
	methodFlag := flag.String("method", "GET", "HTTP 方法")
	dataFlag := flag.String("data", "", "请求体数据")
	timeoutFlag := flag.Duration("timeout", 30*time.Second, "请求超时时间")
	retryFlag := flag.Int("retry", 3, "重试次数")
	flag.Parse()

	// 生成密钥对
	secretKey := crypto.NewSecretKey()
	// 创建 endpoint（使用默认值）
	ep, err := endpoint.NewEndpoint(endpoint.Options{
		SecretKey: secretKey,
	})
	if err != nil {
		log.Fatalf("Failed to create endpoint: %v", err)
	}
	defer ep.Close()

	// 创建使用 iroh 协议的 HTTP 客户端（使用默认 ALPN）
	client := &http.Client{
		Timeout:   *timeoutFlag,
		Transport: irohttp.NewTransport(ep),
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
