package packet

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestCraftDNSPacket(t *testing.T) {
	srcIP := "192.168.1.1"
	dstIP := "8.8.8.8"
	srcPort := "12345"
	dstPort := "53"
	queryDomain := "example.com"

	packetBytes, err := CraftDNSPacket(srcIP, dstIP, srcPort, dstPort, queryDomain)
	if err != nil {
		t.Fatalf("Failed to craft DNS packet: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.Default)

	//test
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		t.Fatal("IP layer not found in the crafted packet")
	}

	ipv4Layer, _ := ipLayer.(*layers.IPv4)
	if ipv4Layer.SrcIP.String() != srcIP || ipv4Layer.DstIP.String() != dstIP {
		t.Fatal("IP addresses in the crafted packet do not match the expected values")
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatal("UDP layer not found in the crafted packet")
	}

	udpLayerData, _ := udpLayer.(*layers.UDP)
	if int(udpLayerData.SrcPort) != 12345 || int(udpLayerData.DstPort) != 53 {
		t.Fatal("UDP ports in the crafted packet do not match the expected values")
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		t.Fatal("DNS layer not found in the crafted packet")
	}

	dnsLayerData, _ := dnsLayer.(*layers.DNS)
	if string(dnsLayerData.Questions[0].Name) != queryDomain {
		t.Fatalf("Domain name in the crafted packet does not match the expected value: %s", queryDomain)
	}
}

func TestCraftARPPacket(t *testing.T) {
	srcMAC := "00:11:22:33:44:55"
	dstMAC := "66:77:88:99:aa:bb"
	srcIP := "192.168.1.1"
	dstIP := "192.168.1.2"

	packetBytes, err := CraftARPPacket(srcIP, dstIP, srcMAC, dstMAC)
	if err != nil {
		t.Fatalf("Failed to craft ARP packet: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeARP, gopacket.Default)
	arpLayer := packet.Layer(layers.LayerTypeARP)

	if arpLayer == nil {
		t.Fatal("ARP layer not found in the crafted packet")
	}

	arpLayerData, _ := arpLayer.(*layers.ARP)
	if net.HardwareAddr(arpLayerData.SourceHwAddress).String() != srcMAC || net.HardwareAddr(arpLayerData.DstHwAddress).String() != dstMAC {
		t.Fatal("Hardware addresses in the crafted ARP packet do not match the expected values")
	}
}

func TestCraftIPPacket(t *testing.T) {
	srcIP := "192.168.1.1"
	dstIP := "8.8.8.8"

	ipLayer, err := CraftIPPacket(srcIP, dstIP, "TCP")
	if err != nil {
		t.Fatalf("Failed to craft IP packet: %v", err)
	}

	if ipLayer.SrcIP.String() != srcIP || ipLayer.DstIP.String() != dstIP {
		t.Fatal("IP addresses in the crafted IP packet do not match the expected values")
	}
}

func TestCraftUDPPacket(t *testing.T) {
	srcIP := "192.168.1.1"
	dstIP := "8.8.8.8"
	srcPort := "12345"
	dstPort := "53"
	payload := "Hello, World!"

	packetBytes, err := CraftUDPPacket(srcIP, dstIP, srcPort, dstPort, payload)
	if err != nil {
		t.Fatalf("Failed to craft UDP packet: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.Default)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatal("UDP layer not found in the crafted packet")
	}

	udpLayerData, _ := udpLayer.(*layers.UDP)
	if int(udpLayerData.SrcPort) != 12345 || int(udpLayerData.DstPort) != 53 {
		t.Fatal("UDP ports in the crafted packet do not match the expected values")
	}

	extractedPayload := udpLayerData.Payload
	if string(extractedPayload) != payload {
		t.Fatalf("Payload in the crafted packet does not match the expected value: %s", payload)
	}

}

func TestCraftTCPPacket(t *testing.T) {
	srcIP := "192.168.1.1"
	dstIP := "8.8.8.8"
	srcPort := "12345"
	dstPort := "80"
	payload := "Hello, World!"

	packetBytes, err := CraftTCPPacket(srcIP, dstIP, srcPort, dstPort, payload)
	if err != nil {
		t.Fatalf("Failed to craft TCP packet: %v", err)
	}
	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.Default)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		t.Fatal("TCP layer not found in the crafted packet")
	}

	tcpLayerData, _ := tcpLayer.(*layers.TCP)
	if int(tcpLayerData.SrcPort) != 12345 || int(tcpLayerData.DstPort) != 80 {
		t.Fatal("TCP ports in the crafted packet do not match the expected values")
	}

	payloadLayer := packet.Layer(gopacket.LayerTypePayload)
	if payloadLayer == nil {
		t.Fatal("Payload layer not found in the crafted packet")
	}

	payloadData := payloadLayer.LayerContents()
	if string(payloadData) != payload {
		t.Fatalf("Payload in the crafted packet does not match the expected value: %s", payload)
	}
}
