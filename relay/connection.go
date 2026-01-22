package relay

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/yixinin/iroh-go"
	"github.com/yixinin/iroh-go/crypto"
)

func (c *Client) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	ctx := context.Background()
	var timeout = 0 * time.Second
	if !c.readDeadline.IsZero() {
		timeout = time.Until(c.readDeadline)
		if timeout <= 0 {
			return 0, nil, context.DeadlineExceeded
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case packet := <-c.packets:
		n = copy(p, packet.Data)
		return n, iroh.NewAddr(packet.RemoteID, nil), nil
	}
}

func (rc *Client) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if addr, ok := addr.(*iroh.Addr); ok {
		ctx := context.Background()
		var timeout = 0 * time.Second
		if !rc.writeDeadline.IsZero() {
			timeout = time.Until(rc.writeDeadline)
			if timeout <= 0 {
				return 0, context.DeadlineExceeded
			}
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		var errChan = make(chan error)
		var dataSize = len(p)
		go func() {
			defer close(errChan)
			err := rc.SendDatagram(addr.PublicKey(), Ce, p)
			errChan <- err
		}()

		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case err := <-errChan:
			if err != nil {
				return 0, err
			}
		}
		return dataSize, nil
	}
	return 0, fmt.Errorf("invalid address type")
}

func (rc *Client) RemoteID() *crypto.EndpointId {
	return rc.endpointID
}

func (rc *Client) LocalAddr() net.Addr {
	return iroh.NewAddr(rc.endpointID, nil)
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
