package packet

import (
	"errors"
	"net"

	golayers "github.com/google/gopacket/layers"
)

type Ethernet struct {
	layer *golayers.Ethernet
}

func EthernetLayer() *Ethernet {
	return &Ethernet{
		layer: &golayers.Ethernet{
			EthernetType: golayers.EthernetTypeLLC,
		},
	}
}

func (e *Ethernet) SetSrcMAC(macStr string) error {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return errors.New("invalid source MAC address")
	}
	e.layer.SrcMAC = mac
	return nil
}

func (e *Ethernet) SetDstMAC(macStr string) error {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return errors.New("invalid destination MAC address")
	}
	e.layer.DstMAC = mac
	return nil
}

func (e *Ethernet) SetEthernetType(ethType golayers.EthernetType) {
	e.layer.EthernetType = ethType
}

func (e *Ethernet) Layer() *golayers.Ethernet {
	return e.layer
}
