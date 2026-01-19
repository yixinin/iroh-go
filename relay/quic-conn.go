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

type QUICStream struct {
	conn        *QUICConnection
	streamID    quic.StreamID
	canRead     bool
	canWrite    bool
	readBuffer  []byte
	writeBuffer []byte
	mu          sync.RWMutex
	readCond    *sync.Cond
	writeCond   *sync.Cond
	closed      bool
	ctx         context.Context
	cancel      context.CancelFunc
}

func NewQUICStream(conn *QUICConnection, streamID quic.StreamID, canRead, canWrite bool) *QUICStream {
	ctx, cancel := context.WithCancel(conn.ctx)
	s := &QUICStream{
		conn:        conn,
		streamID:    streamID,
		canRead:     canRead,
		canWrite:    canWrite,
		readBuffer:  make([]byte, 0),
		writeBuffer: make([]byte, 0),
		ctx:         ctx,
		cancel:      cancel,
	}
	s.readCond = sync.NewCond(&s.mu)
	s.writeCond = sync.NewCond(&s.mu)
	return s
}

func (qs *QUICStream) StreamID() quic.StreamID {
	return qs.streamID
}

func (qs *QUICStream) Read(p []byte) (n int, err error) {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	if !qs.canRead {
		return 0, io.ErrClosedPipe
	}

	for len(qs.readBuffer) == 0 && !qs.closed {
		qs.readCond.Wait()
	}

	if qs.closed && len(qs.readBuffer) == 0 {
		return 0, io.EOF
	}

	n = copy(p, qs.readBuffer)
	qs.readBuffer = qs.readBuffer[n:]
	return n, nil
}

func (qs *QUICStream) Write(p []byte) (n int, err error) {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	if !qs.canWrite {
		return 0, io.ErrClosedPipe
	}

	if qs.closed {
		return 0, io.ErrClosedPipe
	}

	qs.writeBuffer = append(qs.writeBuffer, p...)
	n = len(p)
	return n, nil
}

func (qs *QUICStream) Close() error {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	if qs.closed {
		return nil
	}

	qs.closed = true
	qs.cancel()
	qs.readCond.Broadcast()
	qs.writeCond.Broadcast()
	qs.conn.removeStream(qs.streamID)
	return nil
}

func (qs *QUICStream) CancelRead(code quic.StreamErrorCode) {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	qs.canRead = false
	qs.readBuffer = nil
	qs.readCond.Broadcast()
}

func (qs *QUICStream) CancelWrite(code quic.StreamErrorCode) {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	qs.canWrite = false
	qs.writeBuffer = nil
	qs.writeCond.Broadcast()
}

func (qs *QUICStream) SetReadDeadline(t time.Time) error {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	if !t.IsZero() {
		go func() {
			time.Sleep(time.Until(t))
			qs.mu.Lock()
			qs.readCond.Broadcast()
			qs.mu.Unlock()
		}()
	}
	return nil
}

func (qs *QUICStream) SetWriteDeadline(t time.Time) error {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	if !t.IsZero() {
		go func() {
			time.Sleep(time.Until(t))
			qs.mu.Lock()
			qs.writeCond.Broadcast()
			qs.mu.Unlock()
		}()
	}
	return nil
}

func (qs *QUICStream) SetDeadline(t time.Time) error {
	if err := qs.SetReadDeadline(t); err != nil {
		return err
	}
	return qs.SetWriteDeadline(t)
}

func (qs *QUICStream) Context() context.Context {
	return qs.ctx
}

func (qs *QUICStream) WriteData(data []byte) {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	if qs.canRead && !qs.closed {
		qs.readBuffer = append(qs.readBuffer, data...)
		qs.readCond.Broadcast()
	}
}

func (qs *QUICStream) FlushWrite() error {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	if !qs.canWrite || qs.closed {
		return io.ErrClosedPipe
	}

	if len(qs.writeBuffer) == 0 {
		return nil
	}

	err := qs.conn.relayConn.SendDatagram(qs.writeBuffer)
	if err != nil {
		return err
	}

	qs.writeBuffer = qs.writeBuffer[:0]
	return nil
}
