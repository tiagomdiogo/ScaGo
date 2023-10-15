package protocols

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LayerTypeRip = gopacket.RegisterLayerType(7777, gopacket.LayerTypeMetadata{Name: "RIPPacket", Decoder: gopacket.DecodeFunc(decodeRIPPacket)})

type RIPEntry struct {
	layers.BaseLayer
	AddressFamilyIdentifier uint16
	RouteTag                uint16
	IPAddress               [4]byte
	SubnetMask              [4]byte
	NextHop                 [4]byte
	Metric                  uint32
}

type RIPPacket struct {
	Command uint8
	Version uint8
	Zero    uint16 // Unused, should be zero
	Entries []RIPEntry
}

func (r *RIPPacket) LayerType() gopacket.LayerType { return LayerTypeRip }

func decodeRIPPacket(data []byte, p gopacket.PacketBuilder) error {
	rip := &RIPPacket{}
	return rip.DecodeFromBytes(data, p)
}

func (r *RIPPacket) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 {
		return fmt.Errorf("RIP packet too short")
	}

	r.Command = data[0]
	r.Version = data[1]
	r.Zero = binary.BigEndian.Uint16(data[2:4])

	entryLength := 20 // Each RIP entry is typically 20 bytes long
	for i := 4; i < len(data) && i+entryLength <= len(data); i += entryLength {
		entry := RIPEntry{
			AddressFamilyIdentifier: binary.BigEndian.Uint16(data[i : i+2]),
			RouteTag:                binary.BigEndian.Uint16(data[i+2 : i+4]),
			Metric:                  binary.BigEndian.Uint32(data[i+16 : i+20]),
		}
		copy(entry.IPAddress[:], data[i+4:i+8])
		copy(entry.SubnetMask[:], data[i+8:i+12])
		copy(entry.NextHop[:], data[i+12:i+16])
		r.Entries = append(r.Entries, entry)
	}

	return nil
}
func (rip *RIPPacket) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(4 + 20*len(rip.Entries))
	if err != nil {
		return err
	}

	bytes[0] = rip.Command
	bytes[1] = uint8(rip.Version)
	binary.BigEndian.PutUint16(bytes[2:4], rip.Zero)

	for i, entry := range rip.Entries {
		offset := 4 + i*20
		binary.BigEndian.PutUint16(bytes[offset:offset+2], entry.AddressFamilyIdentifier)
		binary.BigEndian.PutUint16(bytes[offset+2:offset+4], entry.RouteTag)
		copy(bytes[offset+4:offset+8], entry.IPAddress[:])
		copy(bytes[offset+8:offset+12], entry.SubnetMask[:])
		copy(bytes[offset+12:offset+16], entry.NextHop[:])
		binary.BigEndian.PutUint32(bytes[offset+16:offset+20], entry.Metric)
	}

	return nil
}
