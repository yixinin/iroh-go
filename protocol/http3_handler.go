package protocol

import (
	"fmt"
	"net/http"

	"github/yixinin/iroh-go/endpoint"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Http3Handler HTTP/3协议处理器
type Http3Handler struct {
	mux *http.ServeMux
}

// NewHttp3Handler 创建新的HTTP/3协议处理器
func NewHttp3Handler() *Http3Handler {
	mux := http.NewServeMux()
	
	// 注册默认的健康检查路由
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	
	return &Http3Handler{
		mux: mux,
	}
}

// Handle 注册HTTP路由
func (h *Http3Handler) Handle(pattern string, handler http.Handler) {
	h.mux.Handle(pattern, handler)
}

// HandleFunc 注册HTTP路由处理函数
func (h *Http3Handler) HandleFunc(pattern string, handler http.HandlerFunc) {
	h.mux.HandleFunc(pattern, handler)
}

// Accept 处理incoming连接
func (h *Http3Handler) Accept(conn *endpoint.Connection) error {
	// 创建HTTP/3服务器
	server := &http3.Server{
		Handler: h.mux,
	}
	
	// 处理连接
	go func() {
		if err := server.ServeQUICConn(conn.Conn().(quic.Connection)); err != nil {
			fmt.Printf("HTTP/3 server error: %v\n", err)
		}
	}()
	
	return nil
}

// Shutdown 关闭处理器
func (h *Http3Handler) Shutdown() error {
	// HTTP/3服务器会在连接关闭时自动关闭
	return nil
}
