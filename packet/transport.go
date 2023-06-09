package packet

import (
	"fmt"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func CraftTCPPacket(srcIPStr, dstIPStr, srcPortStr, dstPortStr, payloadStr, packetType string) ([]byte, error) {
	srcPortUint, err := strconv.ParseUint(srcPortStr, 10, 16)
	if err != nil {
		return nil, err
	}
	srcPort := uint16(srcPortUint)

	dstPortUint, err := strconv.ParseUint(dstPortStr, 10, 16)
	if err != nil {
		return nil, err
	}
	dstPort := uint16(dstPortUint)

	ipLayer, err := CraftIPPacket(srcIPStr, dstIPStr, "TCP")
	if err != nil {
		return nil, err
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     0,
		Window:  1505,
	}

	switch packetType {
	case "SYN":
		tcpLayer.SYN = true
	case "ACK":
		tcpLayer.ACK = true
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Add payload to the TCP layer
	payload := gopacket.Payload([]byte(payloadStr))

	// Serialize the packet
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize TCP packet: %v", err)
	}

	return buffer.Bytes(), nil
}

func CraftUDPPacket(srcIPStr, dstIPStr, srcPortStr, dstPortStr, payloadStr string) ([]byte, error) {

	srcPortUint, err := strconv.ParseUint(srcPortStr, 10, 16)
	if err != nil {
		return nil, err
	}
	srcPort := uint16(srcPortUint)

	dstPortUint, err := strconv.ParseUint(dstPortStr, 10, 16)
	if err != nil {
		return nil, err
	}
	dstPort := uint16(dstPortUint)

	ipLayer, err := CraftIPPacket(srcIPStr, dstIPStr, "UDP")
	if err != nil {
		return nil, err
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Add payload to the UDP layer
	payload := gopacket.Payload([]byte(payloadStr))
	udpLayer.Length = uint16(len(payloadStr) + 8)

	// Serialize the packet
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, opts, ipLayer, udpLayer, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize UDP packet: %v", err)
	}

	return buffer.Bytes(), nil
}
