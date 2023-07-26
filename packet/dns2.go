package packet

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

func CraftDNSQueryPacket(srcIPStr, dstIPStr, srcPortStr, dstPortStr, queryDomain string) (*layers.IPv4, *layers.UDP, gopacket.Payload, *layers.DNS, error) {

	ipLayer, udpLayer, payload, err := CraftUDPPacket(srcIPStr, dstIPStr, srcPortStr, dstPortStr, "")
	if err != nil {
		return nil, nil, nil, nil, err
	}

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

	return ipLayer, udpLayer, payload, dnsLayer, nil
}

func CraftDNSResponsePacket(srcIPStr, dstIPStr, srcPortStr, dstPortStr, queryDomain, answerIP string, transactionID uint16) (*layers.IPv4, *layers.UDP, gopacket.Payload, *layers.DNS, error) {

	ipLayer, udpLayer, payload, err := CraftUDPPacket(srcIPStr, dstIPStr, srcPortStr, dstPortStr, "")
	if err != nil {
		return nil, nil, nil, nil, err
	}

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

	return ipLayer, udpLayer, payload, dnsLayer, nil
}
