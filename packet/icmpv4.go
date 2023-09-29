package packet

import (
	golayers "github.com/google/gopacket/layers"
)

type ICMPv4 struct {
	layer *golayers.ICMPv4
}

func ICMPv4Layer() *ICMPv4 {
	return &ICMPv4{
		layer: &golayers.ICMPv4{
			TypeCode: golayers.ICMPv4TypeEchoRequest,
		},
	}
}

func (icmp *ICMPv4) SetTypeCode(TypeCode golayers.ICMPv4TypeCode) {
	icmp.layer.TypeCode = TypeCode

}

func (icmp *ICMPv4) SetChecksum(CheckSum uint16) {
	icmp.layer.Checksum = CheckSum
}

func (icmp *ICMPv4) SetID(ID uint16) {
	icmp.layer.Id = ID
}

func (icmp *ICMPv4) Layer() *golayers.ICMPv4 {
	return icmp.layer
}
