package packet

import (
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func CraftTCPPacket(srcIPStr, dstIPStr, srcPortStr, dstPortStr, payloadStr, packetType string) (*layers.IPv4, *layers.TCP, gopacket.Payload, error) {
	srcPortUint, err := strconv.ParseUint(srcPortStr, 10, 16)
	if err != nil {
		return nil, nil, nil, err
	}
	srcPort := uint16(srcPortUint)

	dstPortUint, err := strconv.ParseUint(dstPortStr, 10, 16)
	if err != nil {
		return nil, nil, nil, err
	}
	dstPort := uint16(dstPortUint)

	ipLayer, err := CraftIPPacket(srcIPStr, dstIPStr)
	if err != nil {
		return nil, nil, nil, err
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     0,
		Window:  1505,
	}

	var ipProtocol layers.IPProtocol
	ipProtocol = layers.IPProtocolTCP
	ipLayer.Protocol = ipProtocol

	switch packetType {
	case "SYN":
		tcpLayer.SYN = true
	case "ACK":
		tcpLayer.ACK = true
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Add payload to the TCP layer
	payload := gopacket.Payload([]byte(payloadStr))

	return ipLayer, tcpLayer, payload, nil
}

func CraftUDPPacket(srcIPStr, dstIPStr, srcPortStr, dstPortStr, payloadStr string) (*layers.IPv4, *layers.UDP, gopacket.Payload, error) {

	srcPortUint, err := strconv.ParseUint(srcPortStr, 10, 16)
	if err != nil {
		return nil, nil, nil, err
	}
	srcPort := uint16(srcPortUint)

	dstPortUint, err := strconv.ParseUint(dstPortStr, 10, 16)
	if err != nil {
		return nil, nil, nil, err
	}
	dstPort := uint16(dstPortUint)

	ipLayer, err := CraftIPPacket(srcIPStr, dstIPStr)
	if err != nil {
		return nil, nil, nil, err
	}

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	var ipProtocol layers.IPProtocol
	ipProtocol = layers.IPProtocolUDP
	ipLayer.Protocol = ipProtocol

	// Add payload to the UDP layer
	payload := gopacket.Payload([]byte(payloadStr))
	udpLayer.Length = uint16(len(payloadStr) + 8)

	return ipLayer, udpLayer, payload, nil
}
