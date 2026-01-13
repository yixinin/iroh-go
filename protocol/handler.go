package protocol

import (
	"github/yixinin/iroh-go/endpoint"
)

// ProtocolHandler 处理incoming连接的接口
type ProtocolHandler interface {
	// Accept 处理incoming连接
	Accept(conn *endpoint.Connection) error

	// Shutdown 关闭处理器
	Shutdown() error
}

// EchoHandler 回显处理器实现
type EchoHandler struct{}

// NewEchoHandler 创建新的回显处理器
func NewEchoHandler() *EchoHandler {
	return &EchoHandler{}
}

// Accept 处理incoming连接
func (h *EchoHandler) Accept(conn *endpoint.Connection) error {
	// 接受双向流
	stream, err := conn.OpenBi()
	if err != nil {
		return err
	}
	defer stream.Close()

	// 回显数据
	buffer := make([]byte, 1024)
	for {
		n, err := stream.Read(buffer)
		if err != nil {
			break
		}
		if n == 0 {
			break
		}
		_, err = stream.Write(buffer[:n])
		if err != nil {
			break
		}
	}

	return nil
}

// Shutdown 关闭处理器
func (h *EchoHandler) Shutdown() error {
	return nil
}
