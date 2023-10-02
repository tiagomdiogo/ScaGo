package protocols

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

var LayerTypeDot3 = gopacket.RegisterLayerType(2001, gopacket.LayerTypeMetadata{Name: "Ethernet8023", Decoder: gopacket.DecodeFunc(decodeDot3)})

type Dot3 struct {
	layers.BaseLayer
	DstMAC, SrcMAC net.HardwareAddr
	Length         uint16
}

func (d *Dot3) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Calculate the length for the fixed header part: DstMAC (6 bytes) + SrcMAC (6 bytes) + Length (2 bytes)
	length := 6 + 6 + 2

	// Prepend bytes for the header at the beginning of the packet
	buf, err := b.PrependBytes(length)
	if err != nil {
		return err
	}

	// Copy DstMAC and SrcMAC to the buffer
	copy(buf[0:6], d.DstMAC)
	copy(buf[6:12], d.SrcMAC)

	// Handle options
	if opts.FixLengths {
		d.Length = uint16(len(b.Bytes())) - uint16(length)
	}

	binary.BigEndian.PutUint16(buf[12:14], d.Length)

	return nil
}

func (d *Dot3) LayerType() gopacket.LayerType { return LayerTypeDot3 }

func (d *Dot3) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	d.DstMAC = net.HardwareAddr(data[0:6])
	d.SrcMAC = net.HardwareAddr(data[6:12])
	d.Length = binary.BigEndian.Uint16(data[12:14])

	return nil
}

func (d *Dot3) NextLayerType() gopacket.LayerType {
	return layers.LayerTypeLLC
}

func (d *Dot3) CanDecode() gopacket.LayerClass {
	return LayerTypeDot3
}

func decodeDot3(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot3{}
	d.DecodeFromBytes(data, p)
	p.AddLayer(d)

	return p.NextDecoder(d.NextLayerType())
}
