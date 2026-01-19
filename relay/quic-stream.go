package relay

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

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
