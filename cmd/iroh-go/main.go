package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/yixinin/iroh-go/crypto"
	"github.com/yixinin/iroh-go/endpoint"

	"github.com/gin-gonic/gin"
)

func main() {
	// 创建端点（使用默认值）
	endp, err := endpoint.NewEndpoint(endpoint.Options{
		ALPNs:     [][]byte{[]byte("iroh3")},
		SecretKey: crypto.NewSecretKey(),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer endp.Close()

	// 打印端点信息
	fmt.Printf("Endpoint ID: %s\n", endp.ID().String())
	fmt.Printf("Endpoint Addr: %v\n", endp.Addr())

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
