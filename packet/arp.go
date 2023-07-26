package packet

import (
	"errors"
	"net"

	golayers "github.com/google/gopacket/layers"
)

type ARP struct {
	layer *golayers.ARP
}

func ARPLayer() *ARP {
	return &ARP{
		layer: &golayers.ARP{
			AddrType:        golayers.LinkTypeEthernet,
			Protocol:        golayers.EthernetTypeIPv4,
			HwAddressSize:   6,
			ProtAddressSize: 4,
		},
	}
}

func (a *ARP) SetSrcMac(address string) error {
	hwAddr, err := net.ParseMAC(address)
	if err != nil {
		return errors.New("invalid source hardware address")
	}
	copy(a.layer.SourceHwAddress, hwAddr)
	return nil
}

func (a *ARP) SetDstMac(address string) error {
	hwAddr, err := net.ParseMAC(address)
	if err != nil {
		return errors.New("invalid destination hardware address")
	}
	copy(a.layer.DstHwAddress, hwAddr)
	return nil
}

func (a *ARP) SetSrcIP(ip string) error {
	protAddr := net.ParseIP(ip)
	if protAddr == nil {
		return errors.New("invalid source protocol address")
	}
	copy(a.layer.SourceProtAddress, protAddr.To4())
	return nil
}

func (a *ARP) SetDstIP(ip string) error {
	protAddr := net.ParseIP(ip)
	if protAddr == nil {
		return errors.New("invalid destination protocol address")
	}
	copy(a.layer.DstProtAddress, protAddr.To4())
	return nil
}

func (a *ARP) SetReply() {
	a.layer.Operation = golayers.ARPReply
}

func (a *ARP) SetRequest() {
	a.layer.Operation = golayers.ARPRequest
}

func (a *ARP) Layer() *golayers.ARP {
	return a.layer
}
