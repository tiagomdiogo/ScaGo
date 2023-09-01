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
	srcHwAddress := make([]byte, 6)
	copy(srcHwAddress, hwAddr)
	a.layer.SourceHwAddress = srcHwAddress
	return
}

func (a *ARP) SetDstMac(address string) {
	hwAddr, err := net.ParseMAC(address)
	if err != nil {
		return
	}
	dstHwAddress := make([]byte, 6)
	copy(dstHwAddress, hwAddr)
	a.layer.DstHwAddress = dstHwAddress
	return
}

func (a *ARP) SetSrcIP(ip string) {
	protAddr := net.ParseIP(ip)
	if protAddr == nil {
		return
	}

	srcIP := make([]byte, 4)
	copy(srcIP, protAddr.To4())
	a.layer.SourceProtAddress = srcIP
	return
}

func (a *ARP) SetDstIP(ip string) {
	protAddr := net.ParseIP(ip)
	if protAddr == nil {
		return
	}
	dstIP := make([]byte, 4)
	copy(dstIP, protAddr.To4())
	a.layer.DstProtAddress = dstIP
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
