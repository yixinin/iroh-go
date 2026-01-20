package relay

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/yixinin/iroh-go/crypto"
)

type RelayStream struct {
	conn      *RelayConnection
	streamId  uint64
	bidirect  bool
	readChan  chan []byte
	writeChan chan []byte
	closeChan chan struct{}
	mu        sync.RWMutex
	closed    bool
}

func NewRelayStream(conn *RelayConnection, streamId uint64, bidirect bool) *RelayStream {
	stream := &RelayStream{
		conn:      conn,
		streamId:  streamId,
		bidirect:  bidirect,
		readChan:  make(chan []byte, 1024),
		writeChan: make(chan []byte, 1024),
		closeChan: make(chan struct{}),
	}

	go stream.writeLoop()

	return stream
}

func (rs *RelayStream) Read(p []byte) (n int, err error) {
	select {
	case <-rs.closeChan:
		return 0, io.EOF
	case data := <-rs.readChan:
		n = copy(p, data)
		return n, nil
	}
}

func (rs *RelayStream) Write(p []byte) (n int, err error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if rs.closed {
		return 0, io.ErrClosedPipe
	}

	select {
	case <-rs.closeChan:
		return 0, io.ErrClosedPipe
	case rs.writeChan <- p:
		return len(p), nil
	}
}

func (rs *RelayStream) writeLoop() {
	for {
		select {
		case <-rs.closeChan:
			return
		case data := <-rs.writeChan:
			if err := rs.sendToRelay(data); err != nil {
				rs.Close()
				return
			}
		}
	}
}

func (rs *RelayStream) sendToRelay(data []byte) error {
	if rs.conn == nil || rs.conn.client == nil {
		return io.ErrClosedPipe
	}

	streamIdBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(streamIdBytes, rs.streamId)

	payload := make([]byte, 8+len(data))
	copy(payload[:8], streamIdBytes)
	copy(payload[8:], data)

	return rs.conn.client.SendDatagram((*crypto.PublicKey)(rs.conn.remoteId), Ce, payload)
}

func (rs *RelayStream) Close() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.closed {
		return nil
	}

	rs.closed = true
	close(rs.closeChan)
	return nil
}

func (rs *RelayStream) CancelRead(errorCode quic.StreamErrorCode) {
	rs.Close()
}

func (rs *RelayStream) CancelWrite(errorCode quic.StreamErrorCode) {
	rs.Close()
}

func (rs *RelayStream) SetDeadline(t time.Time) error {
	rs.SetReadDeadline(t)
	rs.SetWriteDeadline(t)
	return nil
}

func (rs *RelayStream) SetReadDeadline(t time.Time) error {
	return nil
}

func (rs *RelayStream) SetWriteDeadline(t time.Time) error {
	return nil
}

func (rs *RelayStream) StreamID() quic.StreamID {
	return quic.StreamID(rs.streamId)
}

func (rs *RelayStream) Context() context.Context {
	return context.Background()
}
