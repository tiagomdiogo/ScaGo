package packet

//todo add support for IP Layer and parseIP

import (
	"errors"
	"strconv"

	golayers "github.com/google/gopacket/layers"
)

type UDP struct {
	layer *golayers.UDP
}

func UDPLayer() *UDP {
	return &UDP{
		layer: &golayers.UDP{},
	}
}

func (udp *UDP) SetSrcPort(portStr string) error {
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return errors.New("invalid source port")
	}
	udp.layer.SrcPort = golayers.UDPPort(port)
	return nil
}

func (udp *UDP) SetDstPort(portStr string) error {
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return errors.New("invalid destination port")
	}
	udp.layer.DstPort = golayers.UDPPort(port)
	return nil
}

func (udp *UDP) Layer() *golayers.UDP {
	return udp.layer
}
