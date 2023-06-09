package packet

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	utils "github.com/tiagomdiogo/GoPpy/utils"
)

func CraftARPPacket(srcIPStr, dstIPStr, srcMACStr, dstMACStr string, isReply bool) ([]byte, error) {
	srcIP, err := utils.ParseIPGen(srcIPStr)
	if err != nil {
		return nil, err
	}
	dstIP, err := utils.ParseIPGen(dstIPStr)
	if err != nil {
		return nil, err
	}
	srcMAC, err := utils.ParseMACGen(srcMACStr)
	if err != nil {
		return nil, err
	}
	dstMAC, err := utils.ParseMACGen(dstMACStr)
	if err != nil {
		return nil, err
	}

	srcMACaux, err := net.ParseMAC(srcMAC)
	if err != nil {
		return nil, fmt.Errorf("invalid source MAC address: %v", err)
	}

	dstMACaux, err := net.ParseMAC(dstMAC)
	if err != nil {
		return nil, fmt.Errorf("invalid destination MAC address: %v", err)
	}

	srcIPaux := net.ParseIP(srcIP).To4()
	dstIPaux := net.ParseIP(dstIP).To4()

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		SourceHwAddress:   srcMACaux,
		SourceProtAddress: srcIPaux.To4(),
		DstHwAddress:      dstMACaux,
		DstProtAddress:    dstIPaux.To4(),
	}

	// Set the operation type of the ARP packet based on the isReply argument
	if isReply {
		arpLayer.Operation = layers.ARPReply
	} else {
		arpLayer.Operation = layers.ARPRequest
	}

	buffer := gopacket.NewSerializeBuffer()
	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buffer, serializeOptions, arpLayer)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
