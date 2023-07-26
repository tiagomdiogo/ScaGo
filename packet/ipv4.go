package packet

import (
	"errors"
	"net"

	golayers "github.com/google/gopacket/layers"
)

type IPv4 struct {
	layer *golayers.IPv4
}

func IPv4Layer() *IPv4 {
	return &IPv4{
		layer: &golayers.IPv4{
			Version: 4,
			TTL:     64,
		},
	}
}

func (ip *IPv4) SetSrcIP(ipStr string) error {
	ipAddress := net.ParseIP(ipStr)
	if ipAddress == nil {
		return errors.New("invalid source IP")
	}
	ip.layer.SrcIP = ipAddress
	return nil
}

func (ip *IPv4) SetDstIP(ipStr string) error {
	ipAddress := net.ParseIP(ipStr)
	if ipAddress == nil {
		return errors.New("invalid destination IP")
	}
	ip.layer.DstIP = ipAddress
	return nil
}

func (ip *IPv4) SetProtocol(protocol golayers.IPProtocol) {
	ip.layer.Protocol = protocol
}

func (ip *IPv4) Layer() *golayers.IPv4 {
	return ip.layer
}
