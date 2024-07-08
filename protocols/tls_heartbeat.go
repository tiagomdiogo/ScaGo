package protocols

import (
	"encoding/binary"
	"github.com/google/gopacket"
)

type TLSHeartbeatType byte

const (
	Heartbeat_Request  TLSHeartbeatType = 1
	Heartbeat_Response TLSHeartbeatType = 2
)

var TLSHeartbeatTypesMap = map[byte]TLSHeartbeatType{
	1: Heartbeat_Request,
	2: Heartbeat_Response,
}

func (t TLSHeartbeatType) String() string {
	switch t {
	case Heartbeat_Request:
		return "Heartbeat Request"
	case Heartbeat_Response:
		return "Heartbeat Response"
	default:
		return "Unknown"
	}
}

type TLSHeartbeatRecord struct {
	TLSRecordHeader
	TLSHeartbeatType
	Length uint16
	Data   []byte
	EncryptedHeartBeatMessage
}

type EncryptedHeartBeatMessage struct {
	CipherHeartBeat []byte
}

func (t *TLSHeartbeatRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	t.TLSRecordHeader.ContentType = h.ContentType
	t.TLSRecordHeader.Length = h.Length
	t.TLSRecordHeader.Version = h.Version
	heartBeatType := TLSHeartbeatType(data[0])
	switch heartBeatType {
	case Heartbeat_Request:
		t.TLSHeartbeatType = TLSHeartbeatType(data[0])
		t.Length = binary.BigEndian.Uint16(data[1:3])
		t.Data = make([]byte, t.Length)
		copy(t.Data, data[3:3+t.Length])
		return nil
	case Heartbeat_Response:
		t.TLSHeartbeatType = TLSHeartbeatType(data[0])
		t.Length = binary.BigEndian.Uint16(data[1:3])
		t.Data = make([]byte, t.Length)
		copy(t.Data, data[3:3+t.Length])
		return nil
	default:
		t.EncryptedHeartBeatMessage.CipherHeartBeat = make([]byte, len(data))
		copy(t.EncryptedHeartBeatMessage.CipherHeartBeat, data)
		return nil
	}
	return nil
}

func (t *TLSHeartbeatRecord) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions, data []byte, off int) error {
	if t.TLSHeartbeatType == Heartbeat_Request || t.TLSHeartbeatType == Heartbeat_Response {
		data[off] = byte(t.TLSHeartbeatType)
		binary.BigEndian.PutUint16(data[off+1:], t.Length)
		copy(data[3:], t.Data)
		return nil
	}
	copy(data[off:off+len(t.EncryptedHeartBeatMessage.CipherHeartBeat)], t.EncryptedHeartBeatMessage.CipherHeartBeat)
	return nil
}
