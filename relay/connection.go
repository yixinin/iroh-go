package relay

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/yixinin/iroh-go"
	"github.com/yixinin/iroh-go/crypto"
	"github.com/yixinin/postcard-go/postcard"
)

type RelayConnection struct {
	remoteID *crypto.EndpointId
	recvChan chan []byte
	sendChan chan []byte

	readBuffer []byte
	mu         sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
}

func NewRelayConnection(client *Client, remoteID *crypto.EndpointId) *RelayConnection {
	rc := &RelayConnection{
		remoteID: remoteID,
		recvChan: make(chan []byte, 1024),
		sendChan: client.writeBuffer,
	}

	go rc.loopRead()
	return rc
}

func (rc *RelayConnection) RemoteID() *crypto.EndpointId {
	if rc.remoteID != nil {
		return rc.remoteID
	}
	return rc.remoteID
}

func (rc *RelayConnection) loopRead() error {
	for data := range rc.recvChan {
		rc.mu.Lock()
		rc.readBuffer = append(rc.readBuffer, data...)
		rc.mu.Unlock()
	}
	return nil
}

func (rc *RelayConnection) Read(b []byte) (int, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	n := copy(b, rc.readBuffer)
	rc.readBuffer = rc.readBuffer[n:]
	return n, nil
}

func (rc *RelayConnection) Write(b []byte) (int, error) {
	n := len(b)
	var segmentSize uint16
	if n > 0 {
		segmentSize = uint16(n)
	}
	var publicKey [32]byte
	copy(publicKey[:], rc.remoteID.PublicKey())
	var frameType postcard.Varint
	if err := postcard.Deserialize(b, &frameType); err != nil {
		return 0, err
	}
	var data []byte
	var err error
	switch FrameType(frameType) {
	case FrameTypeClientToRelayDatagramBatch:
		msg := &ClientToRelayDatagramBatch{
			DestPublicKey: publicKey,
			Datagrams:     &Datagrams{Contents: b, SegmentSize: &segmentSize},
		}
		data, err = EncodeClientToRelayDatagramBatch(msg)

	case FrameTypeClientToRelayDatagram:
		msg := &ClientToRelayDatagram{
			DestPublicKey: publicKey,
			Datagrams:     &Datagrams{Contents: b, SegmentSize: &segmentSize},
		}
		data, err = EncodeClientToRelayDatagram(msg)
	}

	if err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	select {
	case <-rc.ctx.Done():
		return 0, rc.ctx.Err()
	case rc.sendChan <- data:
	}
	return n, nil
}

func (c *Client) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet := <-c.packets
	n = copy(p, packet.Data)
	return n, iroh.NewAddr(packet.RemoteID), nil
}

func (rc *Client) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if addr, ok := addr.(*iroh.Addr); ok {
		err := rc.SendDatagram(addr.PublicKey(), Ce, p)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return 0, fmt.Errorf("invalid address type")
}

func (rc *Client) LocalAddr() net.Addr {
	return iroh.NewAddr(rc.localAddr)
}

func (rc *Client) SetDeadline(t time.Time) error {
	rc.readDeadline = t
	rc.writeDeadline = t
	return nil
}

func (rc *Client) SetReadDeadline(t time.Time) error {
	rc.readDeadline = t
	return nil
}

func (rc *Client) SetWriteDeadline(t time.Time) error {
	rc.writeDeadline = t
	return nil
}
