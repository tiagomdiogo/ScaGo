package packet

import (
	"fmt"
	"math/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/GoPpy/utils"
)

func CraftARPPacket(srcIPStr, dstIPStr, srcMACStr, dstMACStr string, isReply bool) (*layers.ARP, error) {
	srcIP := utils.ParseIPGen(srcIPStr)

	dstIP := utils.ParseIPGen(dstIPStr)

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

	return arpLayer, nil
}

func CraftEthernetPacket(srcMACStr, dstMACStr string) (*layers.Ethernet, error) {
	srcMAC, err := utils.ParseMACGen(srcMACStr)
	if err != nil {
		return nil, fmt.Errorf("invalid source MAC address: %v", err)
	}

	dstMAC, err := utils.ParseMACGen(dstMACStr)
	if err != nil {
		return nil, fmt.Errorf("invalid destination MAC address: %v", err)
	}

	srcMACaux, err := net.ParseMAC(srcMAC)
	if err != nil {
		return nil, fmt.Errorf("invalid source MAC address: %v", err)
	}

	dstMACaux, err := net.ParseMAC(dstMAC)
	if err != nil {
		return nil, fmt.Errorf("invalid destination MAC address: %v", err)
	}
	// Prepare an Ethernet layer
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       srcMACaux,
		DstMAC:       dstMACaux,
		EthernetType: layers.EthernetTypeLLC,
	}

	return ethernetLayer, nil
}

func CraftDHCPPacket(srcMACStr, dhcpType string) (*layers.Ethernet, *layers.IPv4, *layers.UDP, gopacket.Payload, *layers.DHCPv4, error) {

	//Layer 2
	eth, err := CraftEthernetPacket(srcMACStr, "00:00:00:00:00:00")

	ipLayer, udpLayer, payload, err := CraftUDPPacket("0.0.0.0", "255.255.255.255", "67", "67", "")
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	srcMAC, err := utils.ParseMACGen(srcMACStr)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("invalid source MAC address: %v", err)
	}

	srcMACaux, err := net.ParseMAC(srcMAC)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("invalid source MAC address: %v", err)
	}
	// DHCP layer
	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		HardwareOpts: 0,
		Xid:          rand.Uint32(), // Transaction ID should be random
		Flags:        0x8000,        // Broadcast
		ClientHWAddr: srcMACaux,
	}

	// Define DHCP message type based on the input
	var msgType layers.DHCPMsgType
	switch dhcpType {
	case "discover":
		msgType = layers.DHCPMsgTypeDiscover
	case "offer":
		msgType = layers.DHCPMsgTypeOffer
	case "request":
		msgType = layers.DHCPMsgTypeRequest
	case "ack":
		msgType = layers.DHCPMsgTypeAck
	default:
		return nil, nil, nil, nil, nil, fmt.Errorf("unknown DHCP message type: %s", dhcpType)
	}

	// DHCP Options
	dhcp.Options = append(dhcp.Options,
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(msgType)}),
		layers.NewDHCPOption(layers.DHCPOptClientID, append([]byte{0x01}, srcMAC...)),
		layers.NewDHCPOption(layers.DHCPOptEnd, nil),
	)

	return eth, ipLayer, udpLayer, payload, dhcp, nil
}
