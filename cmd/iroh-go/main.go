package main

import (
	"fmt"
	"log"
	"net/http"

	"github/yixinin/iroh-go/common"
	"github/yixinin/iroh-go/crypto"
	"github/yixinin/iroh-go/discovery"
	"github/yixinin/iroh-go/endpoint"
	"github/yixinin/iroh-go/protocol"

	"github.com/gin-gonic/gin"
)

func main() {
	// 创建端点
	builder := endpoint.NewBuilder()
	builder.RelayMode(endpoint.RelayModeDefault)
	builder.ALPNs([][]byte{[]byte("/iroh/echo/1")})

	endp, err := builder.Build()
	if err != nil {
		log.Fatal(err)
	}
	defer endp.Close()

	// 打印端点信息
	fmt.Printf("Endpoint ID: %s\n", endp.ID().String())
	fmt.Printf("Endpoint Addr: %v\n", endp.Addr())

	// 初始化并发发现服务
	discoveryService := discovery.NewConcurrentDiscovery()

	// 添加mDNS发现服务
	mdnsDiscovery, err := discovery.NewMdnsDiscovery()
	if err != nil {
		log.Printf("Failed to create mDNS discovery: %v", err)
	} else {
		discoveryService.Add(mdnsDiscovery)
		log.Println("Added mDNS discovery service")
	}

	// 添加PKARR发现服务
	pkarrDiscovery, err := discovery.NewPkarrDiscovery()
	if err != nil {
		log.Printf("Failed to create PKARR discovery: %v", err)
	} else {
		// 设置密钥
		// 注意：这里应该使用实际的密钥，暂时使用一个新生成的密钥
		secretKey := crypto.NewSecretKey()
		pkarrDiscovery.SetSecretKey(secretKey)
		discoveryService.Add(pkarrDiscovery)
		log.Println("Added PKARR discovery service")
	}

	// 创建协议路由器
	router := protocol.NewRouter(endp)

	// 注册Echo协议处理器
	echoHandler := protocol.NewEchoHandler()
	router.Accept("http/3", echoHandler)

	// 启动路由器
	if err := router.Spawn(); err != nil {
		log.Fatal(err)
	}

	// 发布当前端点信息
	endpointData := common.NewEndpointData(
		endp.ID(),
		[]common.TransportAddr{},
	).WithRelayURL("")

	if err := discoveryService.Publish(endpointData); err != nil {
		log.Printf("Failed to publish endpoint: %v", err)
	} else {
		log.Println("Published endpoint information")
	}

	// 发现其他端点
	// 暂时注释掉，先测试发布功能
	/*
		go func() {
			// 这里可以传入特定的endpoint ID来发现特定端点
			// 现在我们传入nil来发现所有端点
			discoveryCh, err := discoveryService.Discover(nil)
			if err != nil {
				log.Printf("Failed to start discovery: %v", err)
				return
			}

			for discoveredEndpoint := range discoveryCh {
				log.Printf("Discovered endpoint: %s", discoveredEndpoint.Id.String())
				log.Printf("  Relay URL: %s", discoveredEndpoint.RelayURL)
				log.Printf("  Addresses: %v", discoveredEndpoint.Addrs)
			}
		}()
	*/

	// 创建Gin路由器
	ginRouter := gin.Default()

	// 添加健康检查路由
	ginRouter.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":      "ok",
			"endpoint_id": endp.ID().String(),
		})
	})

	// 创建iroh Listener
	listener, err := endpoint.NewListener(endp)
	if err != nil {
		log.Fatal(err)
	}

	// 创建HTTP服务器
	server := &http.Server{
		Handler: ginRouter,
	}

	// 启动服务器
	fmt.Println("Starting HTTP server with iroh connection...")
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
