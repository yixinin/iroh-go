package protocol

import (
	"github/yixinin/iroh-go/endpoint"
	"sync"
)

// Router 协议路由器
type Router struct {
	endpoint   *endpoint.Endpoint
	handlers   map[string]ProtocolHandler
	handlersMu sync.RWMutex
}

// NewRouter 创建新的路由器
func NewRouter(endpoint *endpoint.Endpoint) *Router {
	return &Router{
		endpoint: endpoint,
		handlers: make(map[string]ProtocolHandler),
	}
}

// Accept 注册协议处理器
func (r *Router) Accept(alpn string, handler ProtocolHandler) *Router {
	r.handlersMu.Lock()
	defer r.handlersMu.Unlock()
	r.handlers[alpn] = handler
	return r
}

// Spawn 启动接受循环
func (r *Router) Spawn() error {
	// 接受incoming连接
	incomingCh, err := r.endpoint.Accept()
	if err != nil {
		return err
	}

	// 处理incoming连接
	go func() {
		for incoming := range incomingCh {
			go r.handleIncoming(incoming)
		}
	}()

	return nil
}

// handleIncoming 处理incoming连接
func (r *Router) handleIncoming(incoming *endpoint.Incoming) {
	// 获取ALPN
	alpn := string(incoming.ALPN())

	// 查找处理器
	r.handlersMu.RLock()
	handler, ok := r.handlers[alpn]
	r.handlersMu.RUnlock()

	if !ok {
		// 没有找到处理器，关闭连接
		incoming.Conn().CloseWithError(0, "unsupported protocol")
		return
	}

	// 转换为连接
	conn := endpoint.NewConnection(incoming.Conn(), incoming.RemoteId(), incoming.ALPN())

	// 处理连接
	if err := handler.Accept(conn); err != nil {
		// 处理错误
		conn.Close()
	}
}

// Shutdown 关闭路由器
func (r *Router) Shutdown() error {
	// 关闭所有处理器
	r.handlersMu.RLock()
	handlers := make([]ProtocolHandler, 0, len(r.handlers))
	for _, handler := range r.handlers {
		handlers = append(handlers, handler)
	}
	r.handlersMu.RUnlock()

	// 调用所有处理器的Shutdown方法
	for _, handler := range handlers {
		if err := handler.Shutdown(); err != nil {
			// 记录错误但继续
		}
	}

	return nil
}
