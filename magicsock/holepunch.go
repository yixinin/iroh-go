package magicsock

import (
	"encoding/binary"
	"time"

	"github.com/yixinin/iroh-go/crypto"
)

const (
	HolepunchPacketType = 0x01
	HolepunchPacketLen  = 1 + 32 + 8
)

type HolepunchPacket struct {
	Type      byte
	SenderId  [32]byte
	Timestamp uint64
}

func NewHolepunchPacket(senderId *crypto.EndpointId) *HolepunchPacket {
	return &HolepunchPacket{
		Type:      HolepunchPacketType,
		SenderId:  [32]byte(senderId.Bytes()),
		Timestamp: uint64(time.Now().UnixNano()),
	}
}

func (hp *HolepunchPacket) Serialize() []byte {
	buf := make([]byte, HolepunchPacketLen)
	buf[0] = hp.Type
	copy(buf[1:33], hp.SenderId[:])
	binary.BigEndian.PutUint64(buf[33:41], hp.Timestamp)
	return buf
}

func ParseHolepunchPacket(data []byte) (*HolepunchPacket, error) {
	if len(data) < HolepunchPacketLen {
		return nil, nil
	}

	if data[0] != HolepunchPacketType {
		return nil, nil
	}

	return &HolepunchPacket{
		Type:      data[0],
		SenderId:  *(*[32]byte)(data[1:33]),
		Timestamp: binary.BigEndian.Uint64(data[33:41]),
	}, nil
}

func IsHolepunchPacket(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	return data[0] == HolepunchPacketType
}

func ValidateHolepunchPacket(packet *HolepunchPacket, maxAge time.Duration) bool {
	if packet == nil {
		return false
	}

	if packet.Type != HolepunchPacketType {
		return false
	}

	if maxAge > 0 {
		packetTime := time.Unix(0, int64(packet.Timestamp))
		age := time.Since(packetTime)
		if age > maxAge {
			return false
		}
	}

	return true
}

func CreateHolepunchResponse(senderId *crypto.EndpointId) []byte {
	packet := NewHolepunchPacket(senderId)
	return packet.Serialize()
}
