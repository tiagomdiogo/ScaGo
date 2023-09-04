package protocols

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"net"
)

var LayerTypeDot3 = gopacket.RegisterLayerType(2001, gopacket.LayerTypeMetadata{Name: "Ethernet8023", Decoder: gopacket.DecodeFunc(decodeDot3)})

type Dot3 struct {
	layers.BaseLayer
	DstMAC, SrcMAC net.HardwareAddr
	Length         uint16
	Padding        []byte
	Payload        []byte
}

func (d *Dot3) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Calculate the length
	length := 6 + 6 + 2 // DstMAC (6 bytes) + SrcMAC (6 bytes) + Length (2 bytes)

	// Create the buffer
	buf, err := b.PrependBytes(length)
	if err != nil {
		return err
	}

	// Populate the buffer
	copy(buf[0:6], d.DstMAC)
	copy(buf[6:12], d.SrcMAC)
	binary.BigEndian.PutUint16(buf[12:14], d.Length)

	// Handle payload serialization, if opts.FixLengths is set, update the Length field accordingly
	if opts.FixLengths {
		d.Length = uint16(len(d.Payload))
	}

	// If there is a payload, append it to the buffer
	if len(d.Payload) > 0 {
		payload, err := b.AppendBytes(len(d.Payload))
		if err != nil {
			log.Fatal(err)
		}
		copy(payload, d.Payload)
	}

	// If padding is present, append it to the buffer
	if len(d.Padding) > 0 {
		padding, err := b.AppendBytes(len(d.Padding))
		if err != nil {
			log.Fatal(err)
		}
		copy(padding, d.Padding)
	}

	return nil
}

func (d *Dot3) LayerPayload() []byte {
	return d.Payload
}

func (d *Dot3) LayerType() gopacket.LayerType { return LayerTypeDot3 }
func (d *Dot3) LayerContents() []byte         { return d.Payload[:14] }
func (d *Dot3) LayerPadding() []byte          { return d.Padding[14:] }

func (d *Dot3) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	d.DstMAC = net.HardwareAddr(data[0:6])
	d.SrcMAC = net.HardwareAddr(data[6:12])
	d.Length = binary.BigEndian.Uint16(data[12:14])
	minLength := 64 - 14
	payloadLength := int(d.Length) - minLength

	if payloadLength < 0 {
		d.Padding = data[14:]
		d.Payload = nil
	} else {
		d.Padding = nil
		d.Payload = data[14 : 14+payloadLength]
	}

	return nil
}

func (d *Dot3) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (d *Dot3) CanDecode() gopacket.LayerClass {
	return LayerTypeDot3
}

func decodeDot3(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot3{}
	d.DecodeFromBytes(data, p)
	p.AddLayer(d)

	return p.NextDecoder(gopacket.LayerTypePayload)
}
