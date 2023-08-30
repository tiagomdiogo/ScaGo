package packet

import (
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

func (a *ARP) SetSrcMac(address string) {
	hwAddr, err := net.ParseMAC(address)
	if err != nil {
		return
	}
	copy(a.layer.SourceHwAddress, hwAddr)
	return
}

func (a *ARP) SetDstMac(address string) {
	hwAddr, err := net.ParseMAC(address)
	if err != nil {
		return
	}
	copy(a.layer.DstHwAddress, hwAddr)
	return
}

func (a *ARP) SetSrcIP(ip string) {
	protAddr := net.ParseIP(ip)
	if protAddr == nil {
		return
	}
	copy(a.layer.SourceProtAddress, protAddr.To4())
	return
}

func (a *ARP) SetDstIP(ip string) {
	protAddr := net.ParseIP(ip)
	if protAddr == nil {
		return
	}
	copy(a.layer.DstProtAddress, protAddr.To4())
	return
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
