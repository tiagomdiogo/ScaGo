package packet

import (
	"fmt"
	"math/rand"
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

func CraftEthernetPacket(srcMACStr, dstMACStr string, payloadStr string) ([]byte, error) {
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
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Add payload to the Ethernet layer
	payload := gopacket.Payload([]byte(payloadStr))

	// Serialize the packet
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, opts, ethernetLayer, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Ethernet packet: %v", err)
	}

	return buffer.Bytes(), nil
}

func CraftDHCPPacket(srcMACStr, dhcpType string) ([]byte, error) {

	srcMAC, err := utils.ParseMACGen(srcMACStr)
	if err != nil {
		return nil, fmt.Errorf("invalid source MAC address: %v", err)
	}

	srcMACaux, err := net.ParseMAC(srcMAC)
	if err != nil {
		return nil, fmt.Errorf("invalid source MAC address: %v", err)
	}
	// Ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       srcMACaux,
		DstMAC:       layers.EthernetBroadcast,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// IP layer
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IPv4zero,
		DstIP:    net.IPv4bcast,
		Protocol: layers.IPProtocolUDP,
	}

	// UDP layer
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(68),
		DstPort: layers.UDPPort(67),
	}
	udp.SetNetworkLayerForChecksum(ip)

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
		return nil, fmt.Errorf("Unknown DHCP message type: %s", dhcpType)
	}

	// DHCP Options
	dhcp.Options = append(dhcp.Options,
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(msgType)}),
		layers.NewDHCPOption(layers.DHCPOptClientID, append([]byte{0x01}, srcMAC...)),
		layers.NewDHCPOption(layers.DHCPOptEnd, nil),
	)

	// Serialize
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buffer, opts, eth, ip, udp, dhcp)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DHCP packet: %v", err)
	}

	return buffer.Bytes(), nil
}
