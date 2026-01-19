package relay

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type QUICStream struct {
	conn          *QUICConnection
	streamID      quic.StreamID
	canRead       bool
	canWrite      bool
	readBuffer    []byte
	mu            sync.RWMutex
	readCond      *sync.Cond
	writeCond     *sync.Cond
	readDeadline  time.Time
	writeDeadline time.Time
	closed        bool
	ctx           context.Context
	cancel        context.CancelFunc
}

func NewQUICStream(conn *QUICConnection, streamID quic.StreamID, canRead, canWrite bool) *QUICStream {
	ctx, cancel := context.WithCancel(conn.ctx)
	s := &QUICStream{
		conn:       conn,
		streamID:   streamID,
		canRead:    canRead,
		canWrite:   canWrite,
		readBuffer: make([]byte, 0),
		ctx:        ctx,
		cancel:     cancel,
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

	if qs.closed {
		return 0, io.EOF
	}

	for len(qs.readBuffer) < len(p) {
		if qs.closed {
			return 0, io.EOF
		}

		if !qs.readDeadline.IsZero() {
			if time.Now().After(qs.readDeadline) {
				return 0, io.ErrNoProgress
			}
			remaining := time.Until(qs.readDeadline)
			if remaining <= 0 {
				return 0, io.ErrNoProgress
			}
			go func() {
				time.Sleep(remaining)
				qs.readCond.Broadcast()
			}()
		}

		var timeout time.Duration
		if !qs.readDeadline.IsZero() {
			timeout = time.Until(qs.readDeadline)
			if timeout < 0 {
				return 0, io.ErrNoProgress
			}
		}

		qs.mu.Unlock()
		buf, err := qs.conn.relayConn.ReceiveDatagram(timeout)
		qs.mu.Lock()

		if err != nil {
			if err == io.EOF || err == context.DeadlineExceeded {
				if len(qs.readBuffer) > 0 {
					n = copy(p, qs.readBuffer)
					qs.readBuffer = qs.readBuffer[n:]
					return n, nil
				}
				return 0, io.EOF
			}
			if len(qs.readBuffer) > 0 {
				n = copy(p, qs.readBuffer)
				qs.readBuffer = qs.readBuffer[n:]
				return n, nil
			}
			return 0, err
		}

		qs.readBuffer = append(qs.readBuffer, buf...)
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

	if !qs.writeDeadline.IsZero() {
		if time.Now().After(qs.writeDeadline) {
			return 0, io.ErrNoProgress
		}
		remaining := time.Until(qs.writeDeadline)
		if remaining <= 0 {
			return 0, io.ErrNoProgress
		}
	}

	err = qs.conn.relayConn.SendDatagram(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (qs *QUICStream) Close() error {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	if qs.closed {
		return nil
	}

	qs.closed = true
	qs.cancel()
	qs.conn.removeStream(qs.streamID)
	return nil
}

func (qs *QUICStream) CancelRead(code quic.StreamErrorCode) {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	qs.canRead = false
	qs.readBuffer = nil
}

func (qs *QUICStream) CancelWrite(code quic.StreamErrorCode) {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	qs.canWrite = false
	qs.writeCond.Broadcast()
}

func (qs *QUICStream) SetReadDeadline(t time.Time) error {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	qs.readDeadline = t
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

	qs.writeDeadline = t
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
