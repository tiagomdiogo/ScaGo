package packet

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type RIPVersion uint8

const (
	RIPv1 RIPVersion = 1
	RIPv2 RIPVersion = 2
)

type RIPEntry struct {
	AFI      uint16 // Address Family Identifier
	RouteTag uint16 // Only for RIPv2
	IP       [4]byte
	Mask     [4]byte // Only for RIPv2
	NextHop  [4]byte // Only for RIPv2
	Metric   uint32
}

type RIP struct {
	layers.BaseLayer
	Command   uint8
	Version   RIPVersion
	ZeroField uint16
	Entries   []RIPEntry
}

func (rip *RIP) LayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (rip *RIP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 {
		df.SetTruncated()
		return nil
	}

	rip.Command = data[0]
	rip.Version = RIPVersion(data[1])
	rip.ZeroField = binary.BigEndian.Uint16(data[2:4])
	rip.BaseLayer.Contents = data[:4]
	rip.BaseLayer.Payload = data[4:]

	entryData := data[4:]
	for len(entryData) >= 20 {
		var entry RIPEntry
		entry.AFI = binary.BigEndian.Uint16(entryData[0:2])
		entry.RouteTag = binary.BigEndian.Uint16(entryData[2:4])
		copy(entry.IP[:], entryData[4:8])
		copy(entry.Mask[:], entryData[8:12])
		copy(entry.NextHop[:], entryData[12:16])
		entry.Metric = binary.BigEndian.Uint32(entryData[16:20])
		rip.Entries = append(rip.Entries, entry)
		entryData = entryData[20:]
	}
	return nil
}

func (rip *RIP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(4 + 20*len(rip.Entries))
	if err != nil {
		return err
	}

	bytes[0] = rip.Command
	bytes[1] = uint8(rip.Version)
	binary.BigEndian.PutUint16(bytes[2:4], rip.ZeroField)

	for i, entry := range rip.Entries {
		offset := 4 + i*20
		binary.BigEndian.PutUint16(bytes[offset:offset+2], entry.AFI)
		binary.BigEndian.PutUint16(bytes[offset+2:offset+4], entry.RouteTag)
		copy(bytes[offset+4:offset+8], entry.IP[:])
		copy(bytes[offset+8:offset+12], entry.Mask[:])
		copy(bytes[offset+12:offset+16], entry.NextHop[:])
		binary.BigEndian.PutUint32(bytes[offset+16:offset+20], entry.Metric)
	}

	return nil
}
