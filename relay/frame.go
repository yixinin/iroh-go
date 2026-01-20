package relay

import (
	"errors"
	"fmt"
)

var (
	ErrVarIntTooLarge   = errors.New("varint too large")
	ErrUnexpectedEnd    = errors.New("unexpected end of buffer")
	ErrUnknownFrameType = errors.New("unknown frame type")
	ErrFrameTooLarge    = errors.New("frame too large")
	ErrInvalidFrame     = errors.New("invalid frame")
	ErrInvalidPublicKey = errors.New("invalid public key")
	ErrNotConnected     = errors.New("not connected to relay")
)

type FrameTypeError struct {
	FrameType uint32
	Reason    string
}

func (e *FrameTypeError) Error() string {
	return fmt.Sprintf("frame type error: %s (type: %d)", e.Reason, e.FrameType)
}

func NewFrameTypeError(frameType uint32, reason string) *FrameTypeError {
	return &FrameTypeError{
		FrameType: frameType,
		Reason:    reason,
	}
}

type ConnectError struct {
	Reason string
	Cause  error
}

func (e *ConnectError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("connect error: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("connect error: %s", e.Reason)
}

func (e *ConnectError) Unwrap() error {
	return e.Cause
}

func NewConnectError(reason string, cause error) *ConnectError {
	return &ConnectError{
		Reason: reason,
		Cause:  cause,
	}
}

type HandshakeError struct {
	Reason string
	Cause  error
}

func (e *HandshakeError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("handshake error: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("handshake error: %s", e.Reason)
}

func (e *HandshakeError) Unwrap() error {
	return e.Cause
}

func NewHandshakeError(reason string, cause error) *HandshakeError {
	return &HandshakeError{
		Reason: reason,
		Cause:  cause,
	}
}

type SendError struct {
	Reason string
	Cause  error
}

func (e *SendError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("send error: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("send error: %s", e.Reason)
}

func (e *SendError) Unwrap() error {
	return e.Cause
}

func NewSendError(reason string, cause error) *SendError {
	return &SendError{
		Reason: reason,
		Cause:  cause,
	}
}

type RecvError struct {
	Reason string
	Cause  error
}

func (e *RecvError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("receive error: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("receive error: %s", e.Reason)
}

func (e *RecvError) Unwrap() error {
	return e.Cause
}

func NewRecvError(reason string, cause error) *RecvError {
	return &RecvError{
		Reason: reason,
		Cause:  cause,
	}
}

type FrameType uint32

const (
	FrameTypeServerChallenge            FrameType = 0
	FrameTypeClientAuth                 FrameType = 1
	FrameTypeServerConfirmsAuth         FrameType = 2
	FrameTypeServerDeniesAuth           FrameType = 3
	FrameTypeClientToRelayDatagram      FrameType = 4
	FrameTypeClientToRelayDatagramBatch FrameType = 5
	FrameTypeRelayToClientDatagram      FrameType = 6
	FrameTypeRelayToClientDatagramBatch FrameType = 7
	FrameTypeEndpointGone               FrameType = 8
	FrameTypePing                       FrameType = 9
	FrameTypePong                       FrameType = 10
	FrameTypeHealth                     FrameType = 11
	FrameTypeRestarting                 FrameType = 12
)

func FrameTypeToString(frameType FrameType) string {
	switch frameType {
	case FrameTypeServerChallenge:
		return "ServerChallenge"
	case FrameTypeClientAuth:
		return "ClientAuth"
	case FrameTypeServerConfirmsAuth:
		return "ServerConfirmsAuth"
	case FrameTypeServerDeniesAuth:
		return "ServerDeniesAuth"
	case FrameTypeClientToRelayDatagram:
		return "ClientToRelayDatagram"
	case FrameTypeClientToRelayDatagramBatch:
		return "ClientToRelayDatagramBatch"
	case FrameTypeRelayToClientDatagram:
		return "RelayToClientDatagram"
	case FrameTypeRelayToClientDatagramBatch:
		return "RelayToClientDatagramBatch"
	case FrameTypeEndpointGone:
		return "EndpointGone"
	case FrameTypePing:
		return "Ping"
	case FrameTypePong:
		return "Pong"
	case FrameTypeHealth:
		return "Health"
	case FrameTypeRestarting:
		return "Restarting"
	default:
		return fmt.Sprintf("Unknown(%d)", frameType)
	}
}

func IsValidFrameType(frameType FrameType) bool {
	return frameType <= FrameTypeRestarting
}
