package packet

import (
	"net"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func CraftDNSQueryPacket(srcIPStr, dstIPStr, srcPortStr, dstPortStr, queryDomain string) ([]byte, error) {
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

func CraftDNSResponsePacket(srcIPStr, dstIPStr, srcPortStr, dstPortStr, queryDomain, answerIP string, transactionID uint16) ([]byte, error) {
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
		ID:      transactionID, // Match transaction ID
		QR:      true,          // This is a response
		OpCode:  layers.DNSOpCodeQuery,
		QDCount: 1,
		ANCount: 1, // We have one answer
	}

	// The question section is the same as in the request
	dnsLayer.Questions = append(dnsLayer.Questions, layers.DNSQuestion{
		Name:  []byte(queryDomain),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	})

	// The answer section
	dnsLayer.Answers = append(dnsLayer.Answers, layers.DNSResourceRecord{
		Name:  []byte(queryDomain),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
		TTL:   3600, // Time To Live - you might want to adjust
		IP:    net.ParseIP(answerIP),
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
