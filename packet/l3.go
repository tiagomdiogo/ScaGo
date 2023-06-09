package packet

import (
	"fmt"
	"net"

	"github.com/google/gopacket/layers"
	utils "github.com/tiagomdiogo/GoPpy/utils"
)

func CraftIPPacket(srcIPStr, dstIPStr, protocol string) (*layers.IPv4, error) {

	srcIP, err := utils.ParseIPGen(srcIPStr)
	if err != nil {
		return nil, err
	}
	dstIP, err := utils.ParseIPGen(dstIPStr)
	if err != nil {
		return nil, err
	}

	srcIPaux := net.ParseIP(srcIP)
	dstIPaux := net.ParseIP(dstIP)

	var ipProtocol layers.IPProtocol
	switch protocol {
	case "TCP":
		ipProtocol = layers.IPProtocolTCP
	case "UDP":
		ipProtocol = layers.IPProtocolUDP
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	ipLayer := &layers.IPv4{
		SrcIP:    srcIPaux,
		DstIP:    dstIPaux,
		Version:  4,
		TTL:      64,
		Protocol: ipProtocol,
	}

	return ipLayer, nil
}
