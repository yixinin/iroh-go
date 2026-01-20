package relay

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/yixinin/postcard-go/postcard"
)

const (
	MAX_PACKET_SIZE = 64 * 1024
)

type ECN uint8

const (
	Ect0 ECN = 0b10
	Ect1 ECN = 0b01
	Ce   ECN = 0b11
)

type Datagrams struct {
	ECN         ECN
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

func NewDatagramsBatch(ecn ECN, segmentSize uint16, data []byte) *Datagrams {
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
	buf[offset] = byte(d.ECN)
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

	d.ECN = ECN(data[0])
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
	Datagrams     *Datagrams
}

type ClientToRelayDatagramBatch struct {
	DestPublicKey [32]byte
	Datagrams     *Datagrams
}

type RelayToClientDatagram struct {
	SrcPublicKey [32]byte
	Datagrams    *Datagrams
}

type RelayToClientDatagramBatch struct {
	SrcPublicKey [32]byte
	Datagrams    *Datagrams
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
	Problem string
}

type Restarting struct {
	ReconnectInMs uint32
	TryForMs      uint32
}

func encodeQuicVarint(value FrameType) []byte {
	return postcard.Varint(value).Encode()
}

func decodeQuicVarint(data []byte) (FrameType, int, error) {
	frameType, err := postcard.DeserializeUint8(data)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read frame type: %w", err)
	}
	return FrameType(frameType), 1, nil
}

func EncodeClientToRelayDatagram(dgram *ClientToRelayDatagram) ([]byte, error) {
	frameTypeBytes := encodeQuicVarint(FrameTypeClientToRelayDatagram)
	buf := make([]byte, len(frameTypeBytes)+32+dgram.Datagrams.EncodedLen())

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	copy(buf[offset:offset+32], dgram.DestPublicKey[:])
	offset += 32
	offset += dgram.Datagrams.WriteTo(buf[offset:])

	return buf[:offset], nil
}

func DecodeClientToRelayDatagram(data []byte) (*ClientToRelayDatagram, error) {
	if len(data) < 1+32+1 {
		return nil, fmt.Errorf("data too short for ClientToRelayDatagram")
	}

	frameType, offset, err := decodeQuicVarint(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != FrameTypeClientToRelayDatagram {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	if len(data) < offset+32+1 {
		return nil, fmt.Errorf("data too short for public key and ECN")
	}

	dgram := &ClientToRelayDatagram{
		Datagrams: &Datagrams{},
	}
	copy(dgram.DestPublicKey[:], data[offset:offset+32])
	offset += 32

	if err := dgram.Datagrams.FromBytes(data[offset:], false); err != nil {
		return nil, fmt.Errorf("failed to parse datagrams: %w", err)
	}

	return dgram, nil
}

func EncodeClientToRelayDatagramBatch(batch *ClientToRelayDatagramBatch) ([]byte, error) {
	frameTypeBytes := encodeQuicVarint(FrameTypeClientToRelayDatagramBatch)
	buf := make([]byte, len(frameTypeBytes)+32+batch.Datagrams.EncodedLen())

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	copy(buf[offset:offset+32], batch.DestPublicKey[:])
	offset += 32
	offset += batch.Datagrams.WriteTo(buf[offset:])

	return buf[:offset], nil
}

func DecodeClientToRelayDatagramBatch(data []byte) (*ClientToRelayDatagramBatch, error) {
	if len(data) < 1+32+3 {
		return nil, fmt.Errorf("data too short for ClientToRelayDatagramBatch")
	}

	frameType, offset, err := decodeQuicVarint(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != FrameTypeClientToRelayDatagramBatch {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	if len(data) < offset+32+3 {
		return nil, fmt.Errorf("data too short for public key, ECN and segment size")
	}

	batch := &ClientToRelayDatagramBatch{
		Datagrams: &Datagrams{},
	}
	copy(batch.DestPublicKey[:], data[offset:offset+32])
	offset += 32

	if err := batch.Datagrams.FromBytes(data[offset:], true); err != nil {
		return nil, fmt.Errorf("failed to parse datagrams: %w", err)
	}

	return batch, nil
}

func EncodeRelayToClientDatagram(dgram *RelayToClientDatagram) ([]byte, error) {
	frameTypeBytes := encodeQuicVarint(FrameTypeRelayToClientDatagram)
	buf := make([]byte, len(frameTypeBytes)+32+dgram.Datagrams.EncodedLen())

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	copy(buf[offset:offset+32], dgram.SrcPublicKey[:])
	offset += 32
	offset += dgram.Datagrams.WriteTo(buf[offset:])

	return buf[:offset], nil
}

func DecodeRelayToClientDatagram(data []byte) (*RelayToClientDatagram, error) {
	if len(data) < 1+32+1 {
		return nil, fmt.Errorf("data too short for RelayToClientDatagram")
	}

	frameType, offset, err := decodeQuicVarint(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != FrameTypeRelayToClientDatagram {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	if len(data) < offset+32+1 {
		return nil, fmt.Errorf("data too short for public key and ECN")
	}

	dgram := &RelayToClientDatagram{
		Datagrams: &Datagrams{},
	}
	copy(dgram.SrcPublicKey[:], data[offset:offset+32])
	offset += 32

	if err := dgram.Datagrams.FromBytes(data[offset:], false); err != nil {
		return nil, fmt.Errorf("failed to parse datagrams: %w", err)
	}

	return dgram, nil
}

func EncodeRelayToClientDatagramBatch(batch *RelayToClientDatagramBatch) ([]byte, error) {
	frameTypeBytes := encodeQuicVarint(FrameTypeRelayToClientDatagramBatch)
	buf := make([]byte, len(frameTypeBytes)+32+batch.Datagrams.EncodedLen())

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	copy(buf[offset:offset+32], batch.SrcPublicKey[:])
	offset += 32
	offset += batch.Datagrams.WriteTo(buf[offset:])

	return buf[:offset], nil
}

func DecodeRelayToClientDatagramBatch(data []byte) (*RelayToClientDatagramBatch, error) {
	if len(data) < 1+32+3 {
		return nil, fmt.Errorf("data too short for RelayToClientDatagramBatch")
	}

	frameType, offset, err := decodeQuicVarint(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != FrameTypeRelayToClientDatagramBatch {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	if len(data) < offset+32+3 {
		return nil, fmt.Errorf("data too short for public key, ECN and segment size")
	}

	batch := &RelayToClientDatagramBatch{
		Datagrams: &Datagrams{},
	}
	copy(batch.SrcPublicKey[:], data[offset:offset+32])
	offset += 32

	if err := batch.Datagrams.FromBytes(data[offset:], true); err != nil {
		return nil, fmt.Errorf("failed to parse datagrams: %w", err)
	}

	return batch, nil
}

func EncodeEndpointGone(eg *EndpointGone) ([]byte, error) {
	frameTypeBytes := encodeQuicVarint(FrameTypeEndpointGone)
	buf := make([]byte, len(frameTypeBytes)+32)

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	copy(buf[offset:offset+32], eg.PublicKey[:])
	offset += 32

	return buf[:offset], nil
}

func DecodeEndpointGone(data []byte) (*EndpointGone, error) {
	if len(data) < 1+32 {
		return nil, fmt.Errorf("data too short for EndpointGone")
	}

	frameType, offset, err := decodeQuicVarint(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != FrameTypeEndpointGone {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	if len(data) < offset+32 {
		return nil, fmt.Errorf("data too short for public key")
	}

	eg := &EndpointGone{}
	copy(eg.PublicKey[:], data[offset:offset+32])

	return eg, nil
}

func EncodePing(ping *Ping) ([]byte, error) {
	frameTypeBytes := encodeQuicVarint(FrameTypePing)
	buf := make([]byte, len(frameTypeBytes)+8)

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	copy(buf[offset:offset+8], ping.Payload[:])
	offset += 8

	return buf[:offset], nil
}

func DecodePing(data []byte) (*Ping, error) {
	if len(data) < 1+8 {
		return nil, fmt.Errorf("data too short for Ping")
	}

	frameType, offset, err := decodeQuicVarint(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != FrameTypePing {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	if len(data) < offset+8 {
		return nil, fmt.Errorf("data too short for payload")
	}

	ping := &Ping{}
	copy(ping.Payload[:], data[offset:offset+8])

	return ping, nil
}

func EncodePong(pong *Pong) ([]byte, error) {
	frameTypeBytes := encodeQuicVarint(FrameTypePong)
	buf := make([]byte, len(frameTypeBytes)+8)

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	copy(buf[offset:offset+8], pong.Payload[:])
	offset += 8

	return buf[:offset], nil
}

func DecodePong(data []byte) (*Pong, error) {
	if len(data) < 1+8 {
		return nil, fmt.Errorf("data too short for Pong")
	}

	frameType, offset, err := decodeQuicVarint(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != FrameTypePong {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	if len(data) < offset+8 {
		return nil, fmt.Errorf("data too short for payload")
	}

	pong := &Pong{}
	copy(pong.Payload[:], data[offset:offset+8])

	return pong, nil
}

func EncodeHealth(health *Health) ([]byte, error) {
	frameTypeBytes := encodeQuicVarint(FrameTypeHealth)
	msgBytes := []byte(health.Problem)
	buf := make([]byte, len(frameTypeBytes)+len(msgBytes))

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	copy(buf[offset:], msgBytes)
	offset += len(msgBytes)

	return buf[:offset], nil
}

func DecodeHealth(data []byte) (*Health, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for Health")
	}

	frameType, offset, err := decodeQuicVarint(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != FrameTypeHealth {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	health := &Health{
		Problem: string(data[offset:]),
	}

	return health, nil
}

func EncodeRestarting(restarting *Restarting) ([]byte, error) {
	frameTypeBytes := encodeQuicVarint(FrameTypeRestarting)
	buf := make([]byte, len(frameTypeBytes)+4+4)

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	binary.BigEndian.PutUint32(buf[offset:offset+4], restarting.ReconnectInMs)
	offset += 4
	binary.BigEndian.PutUint32(buf[offset:offset+4], restarting.TryForMs)
	offset += 4

	return buf[:offset], nil
}

func DecodeRestarting(data []byte) (*Restarting, error) {
	if len(data) < 1+4+4 {
		return nil, fmt.Errorf("data too short for Restarting")
	}

	frameType, offset, err := decodeQuicVarint(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != FrameTypeRestarting {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	if len(data) < offset+4+4 {
		return nil, fmt.Errorf("data too short for durations")
	}

	restarting := &Restarting{}
	restarting.ReconnectInMs = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	restarting.TryForMs = binary.BigEndian.Uint32(data[offset : offset+4])

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
	frameTypeBytes := encodeQuicVarint(FrameTypeServerConfirmsAuth)
	buf := make([]byte, len(frameTypeBytes))

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)

	return buf[:offset], nil
}

func DecodeServerConfirmsAuth(data []byte) (*ServerConfirmsAuth, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for ServerConfirmsAuth")
	}

	frameType, _, err := decodeQuicVarint(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != FrameTypeServerConfirmsAuth {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	return &ServerConfirmsAuth{}, nil
}

func EncodeServerDeniesAuth(sda *ServerDeniesAuth) ([]byte, error) {
	frameTypeBytes := encodeQuicVarint(FrameTypeServerDeniesAuth)
	reasonBytes := []byte(sda.Reason)
	buf := make([]byte, len(frameTypeBytes)+len(reasonBytes))

	offset := 0
	copy(buf[offset:], frameTypeBytes)
	offset += len(frameTypeBytes)
	copy(buf[offset:], reasonBytes)
	offset += len(reasonBytes)

	return buf[:offset], nil
}

func DecodeServerDeniesAuth(data []byte) (*ServerDeniesAuth, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for ServerDeniesAuth")
	}

	frameType, offset, err := decodeQuicVarint(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != FrameTypeServerDeniesAuth {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	sda := &ServerDeniesAuth{
		Reason: string(data[offset:]),
	}

	return sda, nil
}

func ParseRelayMessage(data []byte) (interface{}, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short")
	}

	frameType, _, err := decodeQuicVarint(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	log.Printf("[ParseRelayMessage] Decoded frame type: %d (0x%x)", frameType, frameType)

	if int(frameType) < 0 {
		return nil, fmt.Errorf("invalid frame type (negative): %d", frameType)
	}

	switch frameType {
	case FrameTypeServerChallenge:
		return DecodeServerChallenge(data)
	case FrameTypeClientAuth:
		return DecodeClientAuth(data)
	case FrameTypeServerConfirmsAuth:
		return DecodeServerConfirmsAuth(data)
	case FrameTypeServerDeniesAuth:
		return DecodeServerDeniesAuth(data)
	case FrameTypeClientToRelayDatagram:
		return DecodeClientToRelayDatagram(data)
	case FrameTypeClientToRelayDatagramBatch:
		return DecodeClientToRelayDatagramBatch(data)
	case FrameTypeRelayToClientDatagram:
		return DecodeRelayToClientDatagram(data)
	case FrameTypeRelayToClientDatagramBatch:
		return DecodeRelayToClientDatagramBatch(data)
	case FrameTypeEndpointGone:
		return DecodeEndpointGone(data)
	case FrameTypePing:
		return DecodePing(data)
	case FrameTypePong:
		return DecodePong(data)
	case FrameTypeHealth:
		return DecodeHealth(data)
	case FrameTypeRestarting:
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
