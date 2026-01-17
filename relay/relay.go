package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/yixinin/iroh-go/crypto"
	"github.com/yixinin/postcard-go/postcard"
)

const (
	MAX_PACKET_SIZE = 64 * 1024
)

type Datagrams struct {
	ECN         uint8
	SegmentSize *uint16
	Contents    []byte
}

func NewDatagrams(data []byte) *Datagrams {
	return &Datagrams{
		ECN:         0,
		SegmentSize: nil,
		Contents:    data,
	}
}

func NewDatagramsBatch(ecn uint8, segmentSize uint16, data []byte) *Datagrams {
	return &Datagrams{
		ECN:         ecn,
		SegmentSize: &segmentSize,
		Contents:    data,
	}
}

func (d *Datagrams) IsBatch() bool {
	return d.SegmentSize != nil
}

func (d *Datagrams) EncodedLen() int {
	result := 1
	if d.SegmentSize != nil {
		result += 2
	}
	return result + len(d.Contents)
}

func (d *Datagrams) WriteTo(buf []byte) int {
	offset := 0
	buf[offset] = d.ECN
	offset += 1
	if d.SegmentSize != nil {
		binary.BigEndian.PutUint16(buf[offset:offset+2], *d.SegmentSize)
		offset += 2
	}
	copy(buf[offset:], d.Contents)
	return offset + len(d.Contents)
}

func (d *Datagrams) FromBytes(data []byte, isBatch bool) error {
	if isBatch {
		if len(data) < 3 {
			return fmt.Errorf("data too short for batch datagrams")
		}
	} else {
		if len(data) < 1 {
			return fmt.Errorf("data too short for datagrams")
		}
	}

	d.ECN = data[0]
	offset := 1

	if isBatch {
		segmentSize := binary.BigEndian.Uint16(data[offset : offset+2])
		d.SegmentSize = &segmentSize
		offset += 2
	} else {
		d.SegmentSize = nil
	}

	d.Contents = data[offset:]
	return nil
}

func (d *Datagrams) TakeSegments(numSegments int) *Datagrams {
	if d.SegmentSize == nil {
		contents := make([]byte, len(d.Contents))
		copy(contents, d.Contents)
		d.Contents = nil
		return &Datagrams{
			ECN:         d.ECN,
			SegmentSize: nil,
			Contents:    contents,
		}
	}

	segmentSize := int(*d.SegmentSize)
	maxContentLen := numSegments * segmentSize
	if maxContentLen > len(d.Contents) {
		maxContentLen = len(d.Contents)
	}

	contents := d.Contents[:maxContentLen]
	d.Contents = d.Contents[maxContentLen:]

	isDatagramBatch := numSegments > 1 && segmentSize < len(contents)

	if len(d.Contents) <= segmentSize {
		d.SegmentSize = nil
	}

	var segmentSizePtr *uint16
	if isDatagramBatch {
		segmentSizePtr = d.SegmentSize
	}

	return &Datagrams{
		ECN:         d.ECN,
		SegmentSize: segmentSizePtr,
		Contents:    contents,
	}
}

type ClientToRelayDatagram struct {
	DestPublicKey [32]byte
	ECN           uint8
	Data          []byte
}

type ClientToRelayDatagramBatch struct {
	DestPublicKey [32]byte
	ECN           uint8
	SegmentSize   uint16
	Datagrams     []byte
}

type RelayToClientDatagram struct {
	SrcPublicKey [32]byte
	ECN          uint8
	Data         []byte
}

type RelayToClientDatagramBatch struct {
	SrcPublicKey [32]byte
	ECN          uint8
	SegmentSize  uint16
	Datagrams    []byte
}

type EndpointGone struct {
	PublicKey [32]byte
}

type Ping struct {
	Payload [8]byte
}

type Pong struct {
	Payload [8]byte
}

type Health struct {
	Message string
}

type Restarting struct {
	ReconnectDelayMs uint32
	TotalTryTimeMs   uint32
}

func EncodeClientToRelayDatagram(dgram *ClientToRelayDatagram) ([]byte, error) {
	frameTypeBytes, _ := postcard.Serialize(uint32(FrameTypeClientToRelayDatagram))
	buf := make([]byte, len(frameTypeBytes)+32+1+len(dgram.Data))

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	copy(buf[offset:offset+32], dgram.DestPublicKey[:])
	offset += 32
	buf[offset] = dgram.ECN
	offset += 1
	copy(buf[offset:], dgram.Data)
	offset += len(dgram.Data)

	return buf[:offset], nil
}

func DecodeClientToRelayDatagram(data []byte) (*ClientToRelayDatagram, error) {
	if len(data) < 1+32+1 {
		return nil, fmt.Errorf("data too short for ClientToRelayDatagram")
	}

	var frameType uint32
	err := postcard.Deserialize(data, &frameType)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != uint32(FrameTypeClientToRelayDatagram) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	frameTypeBytes, _ := postcard.Serialize(frameType)
	offset := len(frameTypeBytes)
	if len(data) < offset+32+1 {
		return nil, fmt.Errorf("data too short for public key and ECN")
	}

	dgram := &ClientToRelayDatagram{}
	copy(dgram.DestPublicKey[:], data[offset:offset+32])
	offset += 32
	dgram.ECN = data[offset]
	offset += 1
	dgram.Data = data[offset:]

	return dgram, nil
}

func EncodeClientToRelayDatagramBatch(batch *ClientToRelayDatagramBatch) ([]byte, error) {
	buf := make([]byte, 1+postcard.Varint(FrameTypeClientToRelayDatagramBatch).Size()+32+1+2+len(batch.Datagrams))

	offset := 0
	encoded := postcard.Varint(FrameTypeClientToRelayDatagramBatch).Encode()
	copy(buf[offset:], encoded)
	offset += len(encoded)
	copy(buf[offset:offset+32], batch.DestPublicKey[:])
	offset += 32
	buf[offset] = batch.ECN
	offset += 1
	binary.BigEndian.PutUint16(buf[offset:offset+2], batch.SegmentSize)
	offset += 2
	copy(buf[offset:], batch.Datagrams)
	offset += len(batch.Datagrams)

	return buf[:offset], nil
}

func DecodeClientToRelayDatagramBatch(data []byte) (*ClientToRelayDatagramBatch, error) {
	if len(data) < 1+32+1+2 {
		return nil, fmt.Errorf("data too short for ClientToRelayDatagramBatch")
	}

	var frameType postcard.Varint
	err := postcard.Deserialize(data, &frameType)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != postcard.Varint(FrameTypeClientToRelayDatagramBatch) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	offset := frameType.Size()
	if len(data) < offset+32+1+2 {
		return nil, fmt.Errorf("data too short for public key, ECN and segment size")
	}

	batch := &ClientToRelayDatagramBatch{}
	copy(batch.DestPublicKey[:], data[offset:offset+32])
	offset += 32
	batch.ECN = data[offset]
	offset += 1
	batch.SegmentSize = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	batch.Datagrams = data[offset:]

	return batch, nil
}

func EncodeRelayToClientDatagram(dgram *RelayToClientDatagram) ([]byte, error) {
	buf := make([]byte, 1+postcard.Varint(FrameTypeRelayToClientDatagram).Size()+32+1+len(dgram.Data))

	offset := 0
	encoded := postcard.Varint(FrameTypeRelayToClientDatagram).Encode()
	copy(buf[offset:], encoded)
	offset += len(encoded)
	copy(buf[offset:offset+32], dgram.SrcPublicKey[:])
	offset += 32
	buf[offset] = dgram.ECN
	offset += 1
	copy(buf[offset:], dgram.Data)
	offset += len(dgram.Data)

	return buf[:offset], nil
}

func DecodeRelayToClientDatagram(data []byte) (*RelayToClientDatagram, error) {
	if len(data) < 1+32+1 {
		return nil, fmt.Errorf("data too short for RelayToClientDatagram")
	}

	var frameType postcard.Varint
	err := postcard.Deserialize(data, &frameType)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != postcard.Varint(FrameTypeRelayToClientDatagram) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	offset := frameType.Size()
	if len(data) < offset+32+1 {
		return nil, fmt.Errorf("data too short for public key and ECN")
	}

	dgram := &RelayToClientDatagram{}
	copy(dgram.SrcPublicKey[:], data[offset:offset+32])
	offset += 32
	dgram.ECN = data[offset]
	offset += 1
	dgram.Data = data[offset:]

	return dgram, nil
}

func EncodeRelayToClientDatagramBatch(batch *RelayToClientDatagramBatch) ([]byte, error) {
	buf := make([]byte, 1+postcard.Varint(FrameTypeRelayToClientDatagramBatch).Size()+32+1+2+len(batch.Datagrams))

	offset := 0
	encoded := postcard.Varint(FrameTypeRelayToClientDatagramBatch).Encode()
	copy(buf[offset:], encoded)
	offset += len(encoded)
	copy(buf[offset:offset+32], batch.SrcPublicKey[:])
	offset += 32
	buf[offset] = batch.ECN
	offset += 1
	binary.BigEndian.PutUint16(buf[offset:offset+2], batch.SegmentSize)
	offset += 2
	copy(buf[offset:], batch.Datagrams)
	offset += len(batch.Datagrams)

	return buf[:offset], nil
}

func DecodeRelayToClientDatagramBatch(data []byte) (*RelayToClientDatagramBatch, error) {
	if len(data) < 1+32+1+2 {
		return nil, fmt.Errorf("data too short for RelayToClientDatagramBatch")
	}

	var frameType postcard.Varint
	err := postcard.Deserialize(data, &frameType)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != postcard.Varint(FrameTypeRelayToClientDatagramBatch) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	offset := frameType.Size()
	if len(data) < offset+32+1+2 {
		return nil, fmt.Errorf("data too short for public key, ECN and segment size")
	}

	batch := &RelayToClientDatagramBatch{}
	copy(batch.SrcPublicKey[:], data[offset:offset+32])
	offset += 32
	batch.ECN = data[offset]
	offset += 1
	batch.SegmentSize = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	batch.Datagrams = data[offset:]

	return batch, nil
}

func EncodeEndpointGone(eg *EndpointGone) ([]byte, error) {
	buf := make([]byte, 1+postcard.Varint(FrameTypeEndpointGone).Size()+32)

	offset := 0
	encoded := postcard.Varint(FrameTypeEndpointGone).Encode()
	copy(buf[offset:], encoded)
	offset += len(encoded)
	copy(buf[offset:offset+32], eg.PublicKey[:])
	offset += 32

	return buf[:offset], nil
}

func DecodeEndpointGone(data []byte) (*EndpointGone, error) {
	if len(data) < 1+32 {
		return nil, fmt.Errorf("data too short for EndpointGone")
	}

	var frameType postcard.Varint
	err := postcard.Deserialize(data, &frameType)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != postcard.Varint(FrameTypeEndpointGone) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	offset := frameType.Size()
	if len(data) < offset+32 {
		return nil, fmt.Errorf("data too short for public key")
	}

	eg := &EndpointGone{}
	copy(eg.PublicKey[:], data[offset:offset+32])

	return eg, nil
}

func EncodePing(ping *Ping) ([]byte, error) {
	buf := make([]byte, 1+postcard.Varint(FrameTypePing).Size()+8)

	offset := 0
	encoded := postcard.Varint(FrameTypePing).Encode()
	copy(buf[offset:], encoded)
	offset += len(encoded)
	copy(buf[offset:offset+8], ping.Payload[:])
	offset += 8

	return buf[:offset], nil
}

func DecodePing(data []byte) (*Ping, error) {
	if len(data) < 1+8 {
		return nil, fmt.Errorf("data too short for Ping")
	}

	var frameType postcard.Varint
	err := postcard.Deserialize(data, &frameType)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != postcard.Varint(FrameTypePing) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	offset := frameType.Size()
	if len(data) < offset+8 {
		return nil, fmt.Errorf("data too short for payload")
	}

	ping := &Ping{}
	copy(ping.Payload[:], data[offset:offset+8])

	return ping, nil
}

func EncodePong(pong *Pong) ([]byte, error) {
	buf := make([]byte, 1+postcard.Varint(FrameTypePong).Size()+8)

	offset := 0
	encoded := postcard.Varint(FrameTypePong).Encode()
	copy(buf[offset:], encoded)
	offset += len(encoded)
	copy(buf[offset:offset+8], pong.Payload[:])
	offset += 8

	return buf[:offset], nil
}

func DecodePong(data []byte) (*Pong, error) {
	if len(data) < 1+8 {
		return nil, fmt.Errorf("data too short for Pong")
	}

	var frameType postcard.Varint
	err := postcard.Deserialize(data, &frameType)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != postcard.Varint(FrameTypePong) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	offset := frameType.Size()
	if len(data) < offset+8 {
		return nil, fmt.Errorf("data too short for payload")
	}

	pong := &Pong{}
	copy(pong.Payload[:], data[offset:offset+8])

	return pong, nil
}

func EncodeHealth(health *Health) ([]byte, error) {
	msgBytes := []byte(health.Message)
	buf := make([]byte, 1+postcard.Varint(FrameTypeHealth).Size()+len(msgBytes))

	offset := 0
	encoded := postcard.Varint(FrameTypeHealth).Encode()
	copy(buf[offset:], encoded)
	offset += len(encoded)
	copy(buf[offset:], msgBytes)
	offset += len(msgBytes)

	return buf[:offset], nil
}

func DecodeHealth(data []byte) (*Health, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for Health")
	}

	var frameType postcard.Varint
	err := postcard.Deserialize(data, &frameType)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != postcard.Varint(FrameTypeHealth) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	offset := frameType.Size()
	health := &Health{
		Message: string(data[offset:]),
	}

	return health, nil
}

func EncodeRestarting(restarting *Restarting) ([]byte, error) {
	frameTypeBytes := encodeQuicVarint(FrameTypeRestarting)
	buf := make([]byte, len(frameTypeBytes)+4+4)

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	binary.BigEndian.PutUint32(buf[offset:offset+4], restarting.ReconnectDelayMs)
	offset += 4
	binary.BigEndian.PutUint32(buf[offset:offset+4], restarting.TotalTryTimeMs)
	offset += 4

	return buf[:offset], nil
}

func DecodeRestarting(data []byte) (*Restarting, error) {
	if len(data) < 1+4+4 {
		return nil, fmt.Errorf("data too short for Restarting")
	}

	var frameType postcard.Varint
	err := postcard.Deserialize(data, &frameType)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != postcard.Varint(FrameTypeRestarting) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	offset := frameType.Size()
	if len(data) < offset+4+4 {
		return nil, fmt.Errorf("data too short for durations")
	}

	restarting := &Restarting{}
	restarting.ReconnectDelayMs = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	restarting.TotalTryTimeMs = binary.BigEndian.Uint32(data[offset : offset+4])

	return restarting, nil
}

func EncodeServerChallenge(sc *ServerChallenge) ([]byte, error) {
	frameTypeBytes := encodeQuicVarint(FrameTypeServerChallenge)
	buf := make([]byte, len(frameTypeBytes)+16)

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	copy(buf[offset:offset+16], sc.Challenge[:])
	offset += 16

	return buf[:offset], nil
}

func DecodeServerChallenge(data []byte) (*ServerChallenge, error) {
	if len(data) < 1+16 {
		return nil, fmt.Errorf("data too short for ServerChallenge")
	}

	frameType, offset, err := decodeQuicVarint(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != FrameTypeServerChallenge {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	if len(data) < offset+16 {
		return nil, fmt.Errorf("data too short for challenge")
	}

	sc := &ServerChallenge{}
	copy(sc.Challenge[:], data[offset:offset+16])

	return sc, nil
}

func encodeQuicVarint(value uint32) []byte {
	if value < 64 {
		return []byte{byte(value)}
	} else if value < 16384 {
		return []byte{
			0x40 | byte(value>>8),
			byte(value),
		}
	} else if value < 1073741824 {
		return []byte{
			0x80 | byte(value>>24),
			byte(value >> 16),
			byte(value >> 8),
			byte(value),
		}
	} else {
		return []byte{
			0xc0,
			0x00,
			0x00,
			0x00,
			byte(value >> 24),
			byte(value >> 16),
			byte(value >> 8),
			byte(value),
		}
	}
}

func decodeQuicVarint(data []byte) (uint32, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("insufficient data for varint")
	}

	firstByte := data[0]
	switch {
	case firstByte < 0x40:
		// 1-byte varint
		return uint32(firstByte), 1, nil
	case firstByte < 0x80:
		// 2-byte varint
		if len(data) < 2 {
			return 0, 0, fmt.Errorf("insufficient data for 2-byte varint")
		}
		value := uint32(firstByte&0x3f)<<8 | uint32(data[1])
		return value, 2, nil
	case firstByte < 0xc0:
		// 4-byte varint
		if len(data) < 4 {
			return 0, 0, fmt.Errorf("insufficient data for 4-byte varint")
		}
		value := uint32(firstByte&0x1f)<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		return value, 4, nil
	default:
		// 8-byte varint
		if len(data) < 8 {
			return 0, 0, fmt.Errorf("insufficient data for 8-byte varint")
		}
		value := uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
		return value, 8, nil
	}
}

func EncodeClientAuth(ca *ClientAuth) ([]byte, error) {
	frameTypeBytes := encodeQuicVarint(FrameTypeClientAuth)
	// Manually serialize ClientAuth to match server's expected format
	// Server uses postcard with #[serde(with = "serde_bytes")] for signature
	// This means signature is serialized as a varint length followed by the bytes
	// But since signature is always 64 bytes, we can optimize
	buf := make([]byte, len(frameTypeBytes)+32+postcard.Varint(64).Size()+64)

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	// Serialize public key (32 bytes)
	copy(buf[offset:offset+32], ca.PublicKey[:])
	offset += 32
	// Serialize signature with varint length prefix (postcard format)
	sigLength := postcard.Varint(64)
	sigLengthBytes := sigLength.Encode()
	copy(buf[offset:], sigLengthBytes)
	offset += len(sigLengthBytes)
	copy(buf[offset:offset+64], ca.Signature[:])
	offset += 64

	return buf[:offset], nil
}

func DecodeClientAuth(data []byte) (*ClientAuth, error) {
	if len(data) < 1+32+64 {
		return nil, fmt.Errorf("data too short for ClientAuth")
	}

	var frameType postcard.Varint
	err := postcard.Deserialize(data, &frameType)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != postcard.Varint(FrameTypeClientAuth) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	offset := frameType.Size()
	if len(data) < offset+32+64 {
		return nil, fmt.Errorf("data too short for public key and signature")
	}

	ca := &ClientAuth{}
	copy(ca.PublicKey[:], data[offset:offset+32])
	offset += 32
	copy(ca.Signature[:], data[offset:offset+64])

	return ca, nil
}

func EncodeServerConfirmsAuth(_ *ServerConfirmsAuth) ([]byte, error) {
	buf := make([]byte, 1+postcard.Varint(FrameTypeServerConfirmsAuth).Size())

	offset := 0
	encoded := postcard.Varint(FrameTypeServerConfirmsAuth).Encode()
	copy(buf[offset:], encoded)
	offset += len(encoded)

	return buf[:offset], nil
}

func DecodeServerConfirmsAuth(data []byte) (*ServerConfirmsAuth, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for ServerConfirmsAuth")
	}

	var frameType postcard.Varint
	err := postcard.Deserialize(data, &frameType)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != postcard.Varint(FrameTypeServerConfirmsAuth) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	return &ServerConfirmsAuth{}, nil
}

func EncodeServerDeniesAuth(sda *ServerDeniesAuth) ([]byte, error) {
	reasonBytes := []byte(sda.Reason)
	buf := make([]byte, 1+postcard.Varint(FrameTypeServerDeniesAuth).Size()+len(reasonBytes))

	offset := 0
	encoded := postcard.Varint(FrameTypeServerDeniesAuth).Encode()
	copy(buf[offset:], encoded)
	offset += len(encoded)
	copy(buf[offset:], reasonBytes)
	offset += len(reasonBytes)

	return buf[:offset], nil
}

func DecodeServerDeniesAuth(data []byte) (*ServerDeniesAuth, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for ServerDeniesAuth")
	}

	var frameType postcard.Varint
	err := postcard.Deserialize(data, &frameType)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != postcard.Varint(FrameTypeServerDeniesAuth) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	sda := &ServerDeniesAuth{
		Reason: string(data[frameType.Size():]),
	}

	return sda, nil
}

func ParseRelayMessage(data []byte) (interface{}, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short")
	}

	var frameType postcard.Varint
	err := postcard.Deserialize(data, &frameType)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	switch frameType {
	case postcard.Varint(FrameTypeServerChallenge):
		return DecodeServerChallenge(data)
	case postcard.Varint(FrameTypeClientAuth):
		return DecodeClientAuth(data)
	case postcard.Varint(FrameTypeServerConfirmsAuth):
		return DecodeServerConfirmsAuth(data)
	case postcard.Varint(FrameTypeServerDeniesAuth):
		return DecodeServerDeniesAuth(data)
	case postcard.Varint(FrameTypeClientToRelayDatagram):
		return DecodeClientToRelayDatagram(data)
	case postcard.Varint(FrameTypeClientToRelayDatagramBatch):
		return DecodeClientToRelayDatagramBatch(data)
	case postcard.Varint(FrameTypeRelayToClientDatagram):
		return DecodeRelayToClientDatagram(data)
	case postcard.Varint(FrameTypeRelayToClientDatagramBatch):
		return DecodeRelayToClientDatagramBatch(data)
	case postcard.Varint(FrameTypeEndpointGone):
		return DecodeEndpointGone(data)
	case postcard.Varint(FrameTypePing):
		return DecodePing(data)
	case postcard.Varint(FrameTypePong):
		return DecodePong(data)
	case postcard.Varint(FrameTypeHealth):
		return DecodeHealth(data)
	case postcard.Varint(FrameTypeRestarting):
		return DecodeRestarting(data)
	default:
		return nil, fmt.Errorf("unknown frame type: %d", frameType)
	}
}

func EncodeRelayMessage(msg interface{}) ([]byte, error) {
	switch m := msg.(type) {
	case *ServerChallenge:
		return EncodeServerChallenge(m)
	case *ClientAuth:
		return EncodeClientAuth(m)
	case *ServerConfirmsAuth:
		return EncodeServerConfirmsAuth(m)
	case *ServerDeniesAuth:
		return EncodeServerDeniesAuth(m)
	case *ClientToRelayDatagram:
		return EncodeClientToRelayDatagram(m)
	case *ClientToRelayDatagramBatch:
		return EncodeClientToRelayDatagramBatch(m)
	case *RelayToClientDatagram:
		return EncodeRelayToClientDatagram(m)
	case *RelayToClientDatagramBatch:
		return EncodeRelayToClientDatagramBatch(m)
	case *EndpointGone:
		return EncodeEndpointGone(m)
	case *Ping:
		return EncodePing(m)
	case *Pong:
		return EncodePong(m)
	case *Health:
		return EncodeHealth(m)
	case *Restarting:
		return EncodeRestarting(m)
	default:
		return nil, fmt.Errorf("unknown message type: %T", msg)
	}
}

func ParsePublicKey(data []byte) (*crypto.PublicKey, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid public key length: expected 32, got %d", len(data))
	}

	return crypto.PublicKeyFromBytes(data)
}

func EncodePublicKey(pk *crypto.PublicKey) [32]byte {
	bytes := pk.Bytes()
	var result [32]byte
	copy(result[:], bytes)
	return result
}

func PublicKeyToArray(pk *crypto.PublicKey) [32]byte {
	return EncodePublicKey(pk)
}

func BatchDatagrams(datagrams [][]byte, segmentSize uint16) []byte {
	var buf bytes.Buffer

	for _, dgram := range datagrams {
		if len(dgram) > int(segmentSize) {
			panic("datagram too large for segment size")
		}

		buf.Write(dgram)
	}

	return buf.Bytes()
}

func UnbatchDatagrams(data []byte, segmentSize uint16) [][]byte {
	var datagrams [][]byte

	for len(data) > 0 {
		if len(data) < int(segmentSize) {
			datagrams = append(datagrams, data)
			break
		}

		datagrams = append(datagrams, data[:segmentSize])
		data = data[segmentSize:]
	}

	return datagrams
}
