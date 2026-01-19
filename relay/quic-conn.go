package relay

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/yixinin/iroh-go/crypto"
)

type QUICConnection struct {
	relayConn    *RelayConnection
	remoteId     *crypto.EndpointId
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.RWMutex
	streams      map[quic.StreamID]*QUICStream
	nextStreamID quic.StreamID
	streamMu     sync.Mutex
}

func NewQUICConnection(relayConn *RelayConnection, remoteId *crypto.EndpointId) *QUICConnection {
	ctx, cancel := context.WithCancel(context.Background())
	return &QUICConnection{
		relayConn:    relayConn,
		remoteId:     remoteId,
		ctx:          ctx,
		cancel:       cancel,
		streams:      make(map[quic.StreamID]*QUICStream),
		nextStreamID: 1,
	}
}

func (qc *QUICConnection) AcceptStream(ctx context.Context) (quic.Stream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-qc.ctx.Done():
		return nil, io.EOF
	default:
		qc.streamMu.Lock()
		streamID := qc.nextStreamID
		qc.nextStreamID += 4
		qc.streamMu.Unlock()

		stream := NewQUICStream(qc, streamID, true, true)
		qc.mu.Lock()
		qc.streams[streamID] = stream
		qc.mu.Unlock()

		return stream, nil
	}
}

func (qc *QUICConnection) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-qc.ctx.Done():
		return nil, io.EOF
	default:
		qc.streamMu.Lock()
		streamID := qc.nextStreamID
		qc.nextStreamID += 4
		qc.streamMu.Unlock()

		stream := NewQUICStream(qc, streamID, true, false)
		qc.mu.Lock()
		qc.streams[streamID] = stream
		qc.mu.Unlock()

		return stream, nil
	}
}

func (qc *QUICConnection) OpenStream() (quic.Stream, error) {
	qc.streamMu.Lock()
	streamID := qc.nextStreamID
	qc.nextStreamID += 4
	qc.streamMu.Unlock()

	stream := NewQUICStream(qc, streamID, false, true)
	qc.mu.Lock()
	qc.streams[streamID] = stream
	qc.mu.Unlock()

	return stream, nil
}

func (qc *QUICConnection) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	return qc.OpenStream()
}

func (qc *QUICConnection) OpenUniStream() (quic.SendStream, error) {
	qc.streamMu.Lock()
	streamID := qc.nextStreamID
	qc.nextStreamID += 4
	qc.streamMu.Unlock()

	stream := NewQUICStream(qc, streamID, false, false)
	qc.mu.Lock()
	qc.streams[streamID] = stream
	qc.mu.Unlock()

	return stream, nil
}

func (qc *QUICConnection) OpenUniStreamSync(ctx context.Context) (quic.SendStream, error) {
	return qc.OpenUniStream()
}

func (qc *QUICConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (qc *QUICConnection) RemoteAddr() net.Addr {
	if qc.remoteId != nil {
		return &Addr{id: "iroh://" + qc.remoteId.String()}
	}
	return &Addr{id: "iroh://unknown"}
}

func (qc *QUICConnection) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	qc.cancel()
	qc.mu.Lock()
	defer qc.mu.Unlock()
	for _, stream := range qc.streams {
		stream.Close()
	}
	qc.streams = make(map[quic.StreamID]*QUICStream)
	return qc.relayConn.Close()
}

func (qc *QUICConnection) Context() context.Context {
	return qc.ctx
}

func (qc *QUICConnection) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{
		TLS: tls.ConnectionState{
			Version:           tls.VersionTLS13,
			HandshakeComplete: true,
		},
		SupportsDatagrams: true,
		Used0RTT:          false,
		Version:           quic.Version1,
	}
}

func (qc *QUICConnection) SendMessage(msg []byte) error {
	return qc.relayConn.SendDatagram(msg)
}

func (qc *QUICConnection) ReceiveMessage(ctx context.Context) ([]byte, error) {
	timeout := 30 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
		if timeout < 0 {
			return nil, context.DeadlineExceeded
		}
	}
	return qc.relayConn.ReceiveDatagram(timeout)
}

func (qc *QUICConnection) removeStream(streamID quic.StreamID) {
	qc.mu.Lock()
	delete(qc.streams, streamID)
	qc.mu.Unlock()
}

type Addr struct {
	id string
}

func (a *Addr) Network() string {
	return "iroh"
}

func (a *Addr) String() string {
	return a.id
}
