package relay

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/yixinin/iroh-go/crypto"
)

const (
	relayPingInterval = 15 * time.Second
	relayReadTimeout  = 30 * time.Second
)

type RelayConnection struct {
	client     *Client
	remoteId   *crypto.EndpointId
	sendQueue  chan []byte
	recvQueue  chan *RelayToClientDatagram
	closeChan  chan struct{}
	closeOnce  sync.Once
	closed     bool
	closeMutex sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	lastPong   time.Time
	lastPongMu sync.RWMutex
}

func NewRelayConnection(client *Client, remoteId *crypto.EndpointId) *RelayConnection {
	ctx, cancel := context.WithCancel(context.Background())

	return &RelayConnection{
		client:    client,
		remoteId:  remoteId,
		sendQueue: make(chan []byte, 128),
		recvQueue: make(chan *RelayToClientDatagram, 128),
		closeChan: make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (rc *RelayConnection) Start() {
	rc.wg.Add(2)
	go rc.sendLoop()
	go rc.receiveLoop()
	go rc.pingLoop()
}

func (rc *RelayConnection) sendLoop() {
	defer rc.wg.Done()

	for {
		select {
		case <-rc.ctx.Done():
			return
		case <-rc.closeChan:
			return
		case data, ok := <-rc.sendQueue:
			if !ok {
				return
			}

			if err := rc.client.Send(data); err != nil {
				log.Printf("[RelayConnection] Failed to send data: %v", err)
				rc.Close()
				return
			}
		}
	}
}

func (rc *RelayConnection) receiveLoop() {
	defer rc.wg.Done()

	for {
		select {
		case <-rc.ctx.Done():
			return
		case <-rc.closeChan:
			return
		default:
		}

		msg, err := rc.client.ReceiveMessage()
		if err != nil {
			if err == io.EOF {
				log.Printf("[RelayConnection] Connection closed by server")
			} else {
				log.Printf("[RelayConnection] Failed to receive message: %v", err)
			}
			rc.Close()
			return
		}

		switch m := msg.(type) {
		case *RelayToClientDatagram:
			if rc.remoteId == nil {
				rc.recvQueue <- m
			} else {
				if pk, err := crypto.PublicKeyFromBytes(m.SrcPublicKey[:]); err == nil && pk.String() == rc.remoteId.String() {
					rc.recvQueue <- m
				}
			}
		case *RelayToClientDatagramBatch:
			datagrams := UnbatchDatagrams(m.Datagrams, m.SegmentSize)
			for _, data := range datagrams {
				dgram := &RelayToClientDatagram{
					SrcPublicKey: m.SrcPublicKey,
					ECN:          m.ECN,
					Data:         data,
				}
				if rc.remoteId == nil {
					rc.recvQueue <- dgram
				} else {
					if pk, err := crypto.PublicKeyFromBytes(m.SrcPublicKey[:]); err == nil && pk.String() == rc.remoteId.String() {
						rc.recvQueue <- dgram
					}
				}
			}
		case *EndpointGone:
			log.Printf("[RelayConnection] Endpoint gone: %x", m.PublicKey)
			rc.Close()
			return
		case *Health:
			if m.Message != "" {
				log.Printf("[RelayConnection] Health issue: %s", m.Message)
			} else {
				log.Printf("[RelayConnection] Health restored")
			}
		case *Restarting:
			log.Printf("[RelayConnection] Relay restarting: reconnect in %dms, try for %dms", m.ReconnectDelayMs, m.TotalTryTimeMs)
			time.Sleep(time.Duration(m.ReconnectDelayMs) * time.Millisecond)
			rc.Close()
			return
		case *Pong, *Ping:
			rc.lastPongMu.Lock()
			rc.lastPong = time.Now()
			rc.lastPongMu.Unlock()
			log.Printf("[RelayConnection] Received Ping/Pong")
		}
	}
}

func (rc *RelayConnection) pingLoop() {
	ticker := time.NewTicker(relayPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rc.ctx.Done():
			return
		case <-rc.closeChan:
			return
		case <-ticker.C:
			var payload [8]byte
			copy(payload[:], fmt.Sprintf("%d", time.Now().UnixNano()))

			ping := &Ping{Payload: payload}
			pingData, err := EncodePing(ping)
			if err != nil {
				log.Printf("[RelayConnection] Failed to encode ping: %v", err)
				continue
			}

			if err := rc.client.Send(pingData); err != nil {
				log.Printf("[RelayConnection] Failed to send ping: %v", err)
				rc.Close()
				return
			}
		}
	}
}

func (rc *RelayConnection) SendDatagram(data []byte) error {
	rc.closeMutex.RLock()
	if rc.closed {
		rc.closeMutex.RUnlock()
		return fmt.Errorf("connection closed")
	}
	rc.closeMutex.RUnlock()

	destPk := rc.remoteId.PublicKey()
	var destPkArray [32]byte
	copy(destPkArray[:], destPk)

	dgram := &ClientToRelayDatagram{
		DestPublicKey: destPkArray,
		ECN:           0,
		Data:          data,
	}

	msg, err := EncodeClientToRelayDatagram(dgram)
	if err != nil {
		return fmt.Errorf("failed to encode datagram: %w", err)
	}

	select {
	case rc.sendQueue <- msg:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("send queue full")
	}
}

func (rc *RelayConnection) ReceiveDatagram(timeout time.Duration) ([]byte, error) {
	select {
	case dgram := <-rc.recvQueue:
		return dgram.Data, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("receive timeout")
	case <-rc.closeChan:
		return nil, fmt.Errorf("connection closed")
	}
}

func (rc *RelayConnection) RemoteId() *crypto.EndpointId {
	return rc.remoteId
}

func (rc *RelayConnection) RelayId() string {
	if rc.client != nil {
		return rc.client.URL()
	}
	return ""
}

func (rc *RelayConnection) Close() error {
	rc.closeOnce.Do(func() {
		rc.closeMutex.Lock()
		rc.closed = true
		rc.closeMutex.Unlock()

		close(rc.closeChan)
		rc.cancel()

		rc.wg.Wait()

		close(rc.sendQueue)
		close(rc.recvQueue)

		if rc.client != nil {
			rc.client.Close()
		}
	})

	return nil
}

func (rc *RelayConnection) IsClosed() bool {
	rc.closeMutex.RLock()
	defer rc.closeMutex.RUnlock()
	return rc.closed
}

func (rc *RelayConnection) LastPongTime() time.Time {
	rc.lastPongMu.RLock()
	defer rc.lastPongMu.RUnlock()
	return rc.lastPong
}

func (rc *RelayConnection) IsHealthy(timeout time.Duration) bool {
	if rc.IsClosed() {
		return false
	}

	lastPong := rc.LastPongTime()
	if lastPong.IsZero() {
		return true
	}

	return time.Since(lastPong) < timeout
}
