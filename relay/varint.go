package relay

import (
	"encoding/binary"
	"io"
	"math"
)

type VarInt uint64

const (
	MAX_VARINT_SIZE  = 8
	MAX_VARINT_VALUE = 1<<62 - 1
)

func Decode(data []byte) (VarInt, error) {
	if len(data) == 0 {
		return 0, io.EOF
	}
	buf := make([]byte, 8)
	buf[0] = data[0]
	buf[0] &= 0b0011_1111

	switch data[0] >> 6 {
	case 0b00:
		return VarInt(buf[0]), nil
	case 0b01:
		if len(buf) < 2 {
			return 0, io.ErrUnexpectedEOF
		}
		copy(buf[1:2], data[1:2])
		i := binary.BigEndian.Uint16(buf[:2])
		return VarInt(i), nil
	case 0b10:
		if len(buf) < 4 {
			return 0, io.ErrUnexpectedEOF
		}
		copy(buf[1:4], data[1:4])
		i := binary.BigEndian.Uint32(buf[:4])
		return VarInt(i), nil
	case 0b11:
		if len(buf) < 8 {
			return 0, io.ErrUnexpectedEOF
		}
		copy(buf[1:8], data[1:8])
		i := binary.BigEndian.Uint64(buf[:8])
		return VarInt(i), nil
	default:
		panic("malformed VarInt")
	}
}
func (v *VarInt) Decode(data []byte) (int, error) {
	vi, err := Decode(data)
	if err != nil {
		return 0, err
	}
	*v = vi
	return vi.Size(), nil
}
func (v VarInt) Encode(buf []byte) int {
	if v < VarInt(math.Pow(2, 6)) {
		buf[0] = byte(v)
		return 1
	}
	if v < VarInt(math.Pow(2, 14)) {
		buf[0] = byte((v >> 8) | 0x40)
		buf[1] = byte(v)
		return 2
	}
	if v < VarInt(math.Pow(2, 30)) {
		buf[0] = byte((v >> 24) | 0x80)
		buf[1] = byte((v >> 16) & 0xff)
		buf[2] = byte((v >> 8) & 0xff)
		buf[3] = byte(v & 0xff)
		return 4
	}
	buf[0] = byte((v >> 56) | 0xc0)
	buf[1] = byte((v >> 48) & 0xff)
	buf[2] = byte((v >> 40) & 0xff)
	buf[3] = byte((v >> 32) & 0xff)
	buf[4] = byte((v >> 24) & 0xff)
	buf[5] = byte((v >> 16) & 0xff)
	buf[6] = byte((v >> 8) & 0xff)
	buf[7] = byte(v & 0xff)
	return 8
}
func (v VarInt) Size() int {
	if v < VarInt(1<<6) {
		return 1
	}
	if v < VarInt(1<<14) {
		return 2
	}
	if v < VarInt(1<<30) {
		return 4
	}
	if v < VarInt(1<<62) {
		return 8
	}
	panic("malformed VarInt")
}
