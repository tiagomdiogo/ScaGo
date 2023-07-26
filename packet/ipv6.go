package packet

import (
	"errors"
	"net"

	golayers "github.com/google/gopacket/layers"
)

type IPv6 struct {
	layer *golayers.IPv6
}

func IPv6Layer() *IPv6 {
	return &IPv6{
		layer: &golayers.IPv6{},
	}
}

func (ipv6 *IPv6) SetSrcIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return errors.New("invalid IP address")
	}
	ipv6.layer.SrcIP = ip
	return nil
}

func (ipv6 *IPv6) SetDstIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return errors.New("invalid IP address")
	}
	ipv6.layer.DstIP = ip
	return nil
}

func (ipv6 *IPv6) Layer() *golayers.IPv6 {
	return ipv6.layer
}
