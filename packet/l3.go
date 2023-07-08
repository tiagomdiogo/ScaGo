package packet

import (
	"net"

	"github.com/google/gopacket/layers"
	utils "github.com/tiagomdiogo/GoPpy/utils"
)

func CraftIPPacket(srcIPStr, dstIPStr string) (*layers.IPv4, error) {

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

	ipLayer := &layers.IPv4{
		SrcIP:   srcIPaux,
		DstIP:   dstIPaux,
		Version: 4,
		TTL:     64,
	}

	return ipLayer, nil
}
