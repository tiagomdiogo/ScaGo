package packet

import (
	"fmt"
	"net"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"main.go/utils"
)

func CraftARPPacket(srcIPStr, dstIPStr, srcMACStr, dstMACStr string) ([]byte, error) {
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

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIP.To4(),
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

func CraftIPPacket(srcIPStr, dstIPStr, protocol string) (*layers.IPv4, error) {
	srcIP := net.ParseIP(srcIPStr)
	dstIP := net.ParseIP(dstIPStr)

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
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: ipProtocol,
	}

	return ipLayer, nil
}

func CraftTCPPacket(srcIPStr, dstIPStr, srcPortStr, dstPortStr, payloadStr string) ([]byte, error) {
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
	}
	// Add SetNetworkLayerForChecksum for TCP layer
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Add payload to the TCP layer
	payload := gopacket.Payload([]byte(payloadStr))
	tcpLayer.Ack = 0
	tcpLayer.Seq = 0
	tcpLayer.Window = 1505

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
	srcIP := net.ParseIP(srcIPStr)
	dstIP := net.ParseIP(dstIPStr)

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

	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
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

func CraftDNSPacket(srcIPStr, dstIPStr, srcPortStr, dstPortStr, queryDomain string) ([]byte, error) {
	srcIP := net.ParseIP(srcIPStr)
	dstIP := net.ParseIP(dstIPStr)

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

	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	dnsLayer := &layers.DNS{
		ID:      0xAAAA,
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		QDCount: 1,
	}

	dnsLayer.Questions = append(dnsLayer.Questions, layers.DNSQuestion{
		Name:  []byte(queryDomain),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	})

	buffer := gopacket.NewSerializeBuffer()
	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Serialize all layers together: IP, UDP, and DNS
	err = gopacket.SerializeLayers(buffer, serializeOptions, ipLayer, udpLayer, dnsLayer)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
