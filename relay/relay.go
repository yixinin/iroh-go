package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github/yixinin/iroh-go/crypto"
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
	buf := make([]byte, 1+VarInt(FrameTypeClientToRelayDatagram).Size()+32+1+len(dgram.Data))

	offset := 0
	offset += VarInt(FrameTypeClientToRelayDatagram).Encode(buf[offset:])
	copy(buf[offset:offset+32], dgram.DestPublicKey[:])
	offset += 32
	buf[offset] = dgram.ECN
	offset += 1
	copy(buf[offset:], dgram.Data)

	return buf, nil
}

func DecodeClientToRelayDatagram(data []byte) (*ClientToRelayDatagram, error) {
	if len(data) < 1+32+1 {
		return nil, fmt.Errorf("data too short for ClientToRelayDatagram")
	}

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != VarInt(FrameTypeClientToRelayDatagram) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	offset := frameType.Size()
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
	buf := make([]byte, 1+VarInt(FrameTypeClientToRelayDatagramBatch).Size()+32+1+2+len(batch.Datagrams))

	offset := 0
	offset += VarInt(FrameTypeClientToRelayDatagramBatch).Encode(buf[offset:])
	copy(buf[offset:offset+32], batch.DestPublicKey[:])
	offset += 32
	buf[offset] = batch.ECN
	offset += 1
	binary.BigEndian.PutUint16(buf[offset:offset+2], batch.SegmentSize)
	offset += 2
	copy(buf[offset:], batch.Datagrams)

	return buf, nil
}

func DecodeClientToRelayDatagramBatch(data []byte) (*ClientToRelayDatagramBatch, error) {
	if len(data) < 1+32+1+2 {
		return nil, fmt.Errorf("data too short for ClientToRelayDatagramBatch")
	}

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != VarInt(FrameTypeClientToRelayDatagramBatch) {
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
	buf := make([]byte, 1+VarInt(FrameTypeRelayToClientDatagram).Size()+32+1+len(dgram.Data))

	offset := 0
	offset += VarInt(FrameTypeRelayToClientDatagram).Encode(buf[offset:])
	copy(buf[offset:offset+32], dgram.SrcPublicKey[:])
	offset += 32
	buf[offset] = dgram.ECN
	offset += 1
	copy(buf[offset:], dgram.Data)

	return buf, nil
}

func DecodeRelayToClientDatagram(data []byte) (*RelayToClientDatagram, error) {
	if len(data) < 1+32+1 {
		return nil, fmt.Errorf("data too short for RelayToClientDatagram")
	}

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != VarInt(FrameTypeRelayToClientDatagram) {
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
	buf := make([]byte, 1+VarInt(FrameTypeRelayToClientDatagramBatch).Size()+32+1+2+len(batch.Datagrams))

	offset := 0
	offset += VarInt(FrameTypeRelayToClientDatagramBatch).Encode(buf[offset:])
	copy(buf[offset:offset+32], batch.SrcPublicKey[:])
	offset += 32
	buf[offset] = batch.ECN
	offset += 1
	binary.BigEndian.PutUint16(buf[offset:offset+2], batch.SegmentSize)
	offset += 2
	copy(buf[offset:], batch.Datagrams)

	return buf, nil
}

func DecodeRelayToClientDatagramBatch(data []byte) (*RelayToClientDatagramBatch, error) {
	if len(data) < 1+32+1+2 {
		return nil, fmt.Errorf("data too short for RelayToClientDatagramBatch")
	}

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != VarInt(FrameTypeRelayToClientDatagramBatch) {
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
	buf := make([]byte, 1+VarInt(FrameTypeEndpointGone).Size()+32)

	offset := 0
	offset += VarInt(FrameTypeEndpointGone).Encode(buf[offset:])
	copy(buf[offset:offset+32], eg.PublicKey[:])

	return buf, nil
}

func DecodeEndpointGone(data []byte) (*EndpointGone, error) {
	if len(data) < 1+32 {
		return nil, fmt.Errorf("data too short for EndpointGone")
	}

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != VarInt(FrameTypeEndpointGone) {
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
	buf := make([]byte, 1+VarInt(FrameTypePing).Size()+8)

	offset := 0
	offset += VarInt(FrameTypePing).Encode(buf[offset:])
	copy(buf[offset:offset+8], ping.Payload[:])

	return buf, nil
}

func DecodePing(data []byte) (*Ping, error) {
	if len(data) < 1+8 {
		return nil, fmt.Errorf("data too short for Ping")
	}

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != VarInt(FrameTypePing) {
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
	buf := make([]byte, 1+VarInt(FrameTypePong).Size()+8)

	offset := 0
	offset += VarInt(FrameTypePong).Encode(buf[offset:])
	copy(buf[offset:offset+8], pong.Payload[:])

	return buf, nil
}

func DecodePong(data []byte) (*Pong, error) {
	if len(data) < 1+8 {
		return nil, fmt.Errorf("data too short for Pong")
	}

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != VarInt(FrameTypePong) {
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
	buf := make([]byte, 1+VarInt(FrameTypeHealth).Size()+len(msgBytes))

	offset := 0
	offset += VarInt(FrameTypeHealth).Encode(buf[offset:])
	copy(buf[offset:], msgBytes)

	return buf, nil
}

func DecodeHealth(data []byte) (*Health, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for Health")
	}

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != VarInt(FrameTypeHealth) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	offset := frameType.Size()
	health := &Health{
		Message: string(data[offset:]),
	}

	return health, nil
}

func EncodeRestarting(restarting *Restarting) ([]byte, error) {
	buf := make([]byte, 1+VarInt(FrameTypeRestarting).Size()+4+4)

	offset := 0
	offset += VarInt(FrameTypeRestarting).Encode(buf[offset:])
	binary.BigEndian.PutUint32(buf[offset:offset+4], restarting.ReconnectDelayMs)
	offset += 4
	binary.BigEndian.PutUint32(buf[offset:offset+4], restarting.TotalTryTimeMs)

	return buf, nil
}

func DecodeRestarting(data []byte) (*Restarting, error) {
	if len(data) < 1+4+4 {
		return nil, fmt.Errorf("data too short for Restarting")
	}

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != VarInt(FrameTypeRestarting) {
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
	buf := make([]byte, 1+VarInt(FrameTypeServerChallenge).Size()+16)

	offset := 0
	offset += VarInt(FrameTypeServerChallenge).Encode(buf[offset:])
	copy(buf[offset:offset+16], sc.Challenge[:])

	return buf, nil
}

func DecodeServerChallenge(data []byte) (*ServerChallenge, error) {
	if len(data) < 1+16 {
		return nil, fmt.Errorf("data too short for ServerChallenge")
	}

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != VarInt(FrameTypeServerChallenge) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	offset := frameType.Size()
	if len(data) < offset+16 {
		return nil, fmt.Errorf("data too short for challenge")
	}

	sc := &ServerChallenge{}
	copy(sc.Challenge[:], data[offset:offset+16])

	return sc, nil
}

func EncodeClientAuth(ca *ClientAuth) ([]byte, error) {
	buf := make([]byte, 1+VarInt(FrameTypeClientAuth).Size()+32+64)

	offset := 0
	offset += VarInt(FrameTypeClientAuth).Encode(buf[offset:])
	copy(buf[offset:offset+32], ca.PublicKey[:])
	offset += 32
	copy(buf[offset:offset+64], ca.Signature[:])

	return buf, nil
}

func DecodeClientAuth(data []byte) (*ClientAuth, error) {
	if len(data) < 1+32+64 {
		return nil, fmt.Errorf("data too short for ClientAuth")
	}

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != VarInt(FrameTypeClientAuth) {
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
	buf := make([]byte, 1+VarInt(FrameTypeServerConfirmsAuth).Size())

	offset := 0
	offset += VarInt(FrameTypeServerConfirmsAuth).Encode(buf[offset:])

	return buf, nil
}

func DecodeServerConfirmsAuth(data []byte) (*ServerConfirmsAuth, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for ServerConfirmsAuth")
	}

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != VarInt(FrameTypeServerConfirmsAuth) {
		return nil, fmt.Errorf("unexpected frame type: %d", frameType)
	}

	return &ServerConfirmsAuth{}, nil
}

func EncodeServerDeniesAuth(sda *ServerDeniesAuth) ([]byte, error) {
	reasonBytes := []byte(sda.Reason)
	buf := make([]byte, 1+VarInt(FrameTypeServerDeniesAuth).Size()+len(reasonBytes))

	offset := 0
	offset += VarInt(FrameTypeServerDeniesAuth).Encode(buf[offset:])
	copy(buf[offset:], reasonBytes)

	return buf, nil
}

func DecodeServerDeniesAuth(data []byte) (*ServerDeniesAuth, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for ServerDeniesAuth")
	}

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	if frameType != VarInt(FrameTypeServerDeniesAuth) {
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

	frameType, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read frame type: %w", err)
	}

	switch frameType {
	case VarInt(FrameTypeServerChallenge):
		return DecodeServerChallenge(data)
	case VarInt(FrameTypeClientAuth):
		return DecodeClientAuth(data)
	case VarInt(FrameTypeServerConfirmsAuth):
		return DecodeServerConfirmsAuth(data)
	case VarInt(FrameTypeServerDeniesAuth):
		return DecodeServerDeniesAuth(data)
	case VarInt(FrameTypeClientToRelayDatagram):
		return DecodeClientToRelayDatagram(data)
	case VarInt(FrameTypeClientToRelayDatagramBatch):
		return DecodeClientToRelayDatagramBatch(data)
	case VarInt(FrameTypeRelayToClientDatagram):
		return DecodeRelayToClientDatagram(data)
	case VarInt(FrameTypeRelayToClientDatagramBatch):
		return DecodeRelayToClientDatagramBatch(data)
	case VarInt(FrameTypeEndpointGone):
		return DecodeEndpointGone(data)
	case VarInt(FrameTypePing):
		return DecodePing(data)
	case VarInt(FrameTypePong):
		return DecodePong(data)
	case VarInt(FrameTypeHealth):
		return DecodeHealth(data)
	case VarInt(FrameTypeRestarting):
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
