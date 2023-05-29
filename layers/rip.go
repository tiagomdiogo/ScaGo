package layers

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	RIPCommandRequest  uint8 = 1
	RIPCommandResponse uint8 = 2
)

type RIPEntry struct {
	AddressFamily uint16
	RouteTag      uint16
	IP            net.IP
	Metric        uint32
}

type RIPLayer struct {
	layers.BaseLayer
	Command uint8
	Version uint8
	Entries []RIPEntry
}

// Define the custom layer type for RIP.
var LayerTypeRIP = gopacket.RegisterLayerType(40000, gopacket.LayerTypeMetadata{Name: "RIP", Decoder: gopacket.DecodeFunc(decodeRIPLayer)})

func (r *RIPLayer) LayerType() gopacket.LayerType {
	return LayerTypeRIP
}

func (r *RIPLayer) CanDecode() gopacket.LayerClass {
	return r.LayerType()
}

func (r *RIPLayer) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (r *RIPLayer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 {
		return errors.New("RIP layer incomplete: insufficient data")
	}

	r.Command = data[0]
	r.Version = data[1]

	data = data[4:]
	for len(data) >= 20 {
		entry := RIPEntry{
			AddressFamily: binary.BigEndian.Uint16(data[0:2]),
			RouteTag:      binary.BigEndian.Uint16(data[2:4]),
			IP:            net.IP(data[4:8]),
			Metric:        binary.BigEndian.Uint32(data[16:20]),
		}
		r.Entries = append(r.Entries, entry)
		data = data[20:]
	}

	return nil
}

// Custom decoder function for the RIP layer.
func decodeRIPLayer(data []byte, p gopacket.PacketBuilder) error {
	rip := &RIPLayer{}
	return rip.DecodeFromBytes(data, p)
}
