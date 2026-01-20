package relay

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/yixinin/iroh-go/crypto"
)

type RelayConnection struct {
	client    *Client
	remoteId  *crypto.EndpointId
	streams   sync.Map
	streamId  uint64
	mu        sync.RWMutex
	closed    bool
	closeChan chan struct{}

	accepts sync.Map
}

func NewRelayConnection(client *Client, remoteId *crypto.EndpointId) *RelayConnection {
	return &RelayConnection{
		client:    client,
		remoteId:  remoteId,
		streams:   sync.Map{},
		streamId:  0,
		closeChan: make(chan struct{}),
	}
}

func (rc *RelayConnection) Start() {
	go rc.readLoop()
}

func (rc *RelayConnection) readLoop() {
	buf := make([]byte, 65536)

	for {
		select {
		case <-rc.closeChan:
			return
		default:
			n, err := rc.client.Read(buf)
			if err != nil {
				return
			}

			rc.handleDatagram(buf[:n])
		}
	}
}

func (rc *RelayConnection) handleDatagram(data []byte) {
	msg, err := ParseRelayMessage(data)
	if err != nil {
		return
	}

	switch m := msg.(type) {
	case *RelayToClientDatagram:
		rc.routeToStream(m.Datagrams.Contents)
	case *RelayToClientDatagramBatch:
		rc.routeToStream(m.Datagrams.Contents)
	}
}

func (rc *RelayConnection) routeToStream(data []byte) {
	if len(data) < 8 {
		return
	}

	streamId := binary.BigEndian.Uint64(data[:8])
	payload := data[8:]

	if stream, ok := rc.streams.Load(streamId); ok {
		if relayStream, ok := stream.(*RelayStream); ok {
			select {
			case relayStream.readChan <- payload:
			case <-relayStream.closeChan:
			}
		}
	}
	if stream, ok := rc.accepts.Load(streamId); ok {
		if relayStream, ok := stream.(*RelayStream); ok {
			select {
			case relayStream.readChan <- payload:
			case <-relayStream.closeChan:
			}
		}
	}
}

func (rc *RelayConnection) AcceptStream(ctx context.Context) (quic.Stream, error) {
	tk := time.NewTicker(10 * time.Millisecond)
	for range tk.C {
		var stream *RelayStream
		rc.accepts.Range(func(key, value any) bool {
			if relayStream, ok := value.(*RelayStream); ok {
				stream = relayStream
				return false
			}
			return true
		})
		if stream != nil {
			rc.accepts.Delete(stream.streamId)
			rc.streams.Store(stream.streamId, stream)
			return stream, nil
		}
	}
	panic("dead code")
}

func (rc *RelayConnection) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	return nil, io.EOF
}

func (rc *RelayConnection) OpenStream() (quic.Stream, error) {
	return rc.OpenStreamSync(context.Background())
}

func (rc *RelayConnection) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.closed {
		return nil, io.ErrClosedPipe
	}

	rc.streamId++
	streamId := rc.streamId

	stream := NewRelayStream(rc, streamId, true)
	rc.streams.Store(streamId, stream)

	return stream, nil
}

func (rc *RelayConnection) OpenUniStream() (quic.SendStream, error) {
	return rc.OpenUniStreamSync(context.Background())
}

func (rc *RelayConnection) OpenUniStreamSync(ctx context.Context) (quic.SendStream, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.closed {
		return nil, io.ErrClosedPipe
	}

	rc.streamId++
	streamId := rc.streamId

	stream := NewRelayStream(rc, streamId, false)
	rc.streams.Store(streamId, stream)

	return stream, nil
}

func (rc *RelayConnection) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	}
}

func (rc *RelayConnection) RemoteAddr() net.Addr {
	return &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0,
	}
}

func (rc *RelayConnection) CloseWithError(errorCode quic.ApplicationErrorCode, reason string) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.closed {
		return nil
	}

	rc.closed = true
	close(rc.closeChan)

	rc.streams.Range(func(key, value interface{}) bool {
		if stream, ok := value.(*RelayStream); ok {
			stream.Close()
		}
		return true
	})

	return nil
}

func (rc *RelayConnection) Close() error {
	return rc.CloseWithError(0, "")
}

func (rc *RelayConnection) Context() context.Context {
	return context.Background()
}

func (rc *RelayConnection) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}

func (rc *RelayConnection) GetTLSConnectionState() any {
	return nil
}

func (rc *RelayConnection) SendMessage(message []byte) error {
	return nil
}

func (rc *RelayConnection) SendDatagram(data []byte) error {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	if rc.closed {
		return io.ErrClosedPipe
	}

	return rc.client.SendDatagram((*crypto.PublicKey)(rc.remoteId), Ce, data)
}

func (rc *RelayConnection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-rc.closeChan:
		return nil, io.EOF
	}
}

func (rc *RelayConnection) MaxDatagramSize() int {
	return 1350
}

func (rc *RelayConnection) SetReadDeadline(t time.Time) error {
	return nil
}

func (rc *RelayConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

func (rc *RelayConnection) ConnectionID() quic.ConnectionID {
	return quic.ConnectionID{}
}

func (rc *RelayConnection) ReceiveMessage(ctx context.Context) ([]byte, error) {
	buf := make([]byte, 65536)
	n, err := rc.client.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
