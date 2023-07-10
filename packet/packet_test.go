package packet

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestCraftDNSQueryPacket(t *testing.T) {
	srcIP := "192.168.1.10"
	dstIP := "192.168.1.1"
	srcPort := "5555"
	dstPort := "53"
	domain := "www.example.com"

	ipLayer, udpLayer, _, dnsLayer, err := CraftDNSQueryPacket(srcIP, dstIP, srcPort, dstPort, domain)
	if err != nil {
		t.Fatalf("CraftDNSQueryPacket() error = %v", err)
	}

	packetBytes, err := CraftPacket(ipLayer, udpLayer, dnsLayer)
	if err != nil {
		t.Fatalf("CraftPacket() error = %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.Default)

	// Retrieve IP layer
	ipLayerPacket := packet.Layer(layers.LayerTypeIPv4)
	if ipLayerPacket == nil {
		t.Fatal("IP layer missing")
	}
	ip, _ := ipLayerPacket.(*layers.IPv4)

	// Retrieve UDP layer
	packetUDPLayer := packet.Layer(layers.LayerTypeUDP)
	if packetUDPLayer == nil {
		t.Fatal("UDP layer missing")
	}
	packetUDP, _ := packetUDPLayer.(*layers.UDP)

	// Retrieve DNS layer
	dnsLayerPacket := packet.Layer(layers.LayerTypeDNS)
	if dnsLayerPacket == nil {
		t.Fatal("DNS layer missing")
	}
	dns, _ := dnsLayerPacket.(*layers.DNS)

	// Compare IP layer
	if ip.SrcIP.String() != srcIP {
		t.Errorf("srcIP = %v, want %v", ip.SrcIP.String(), srcIP)
	}

	if ip.DstIP.String() != dstIP {
		t.Errorf("dstIP = %v, want %v", ip.DstIP.String(), dstIP)
	}

	// Check the UDP layer
	if packetUDP.SrcPort != udpLayer.SrcPort {
		t.Errorf("srcPort = %s, want %s", packetUDP.SrcPort, udpLayer.SrcPort)
	}
	if packetUDP.DstPort != udpLayer.DstPort {
		t.Errorf("dstPort = %s, want %s", packetUDP.DstPort, udpLayer.DstPort)
	}

	// Compare DNS layer
	if string(dns.Questions[0].Name) != domain {
		t.Errorf("domain = %v, want %v", string(dns.Questions[0].Name), domain)
	}
}

func TestCraftDNSResponsePacket(t *testing.T) {
	srcIP := "8.8.8.8"
	dstIP := "192.168.1.10"
	srcPort := "53"
	dstPort := "5555"
	queryDomain := "www.example.com"
	answerIP := "93.184.216.34"
	transactionID := uint16(0xAAAA)

	// Create packet using our function
	ipLayer, udpLayer, payloadLayer, dnsLayer, err := CraftDNSResponsePacket(srcIP, dstIP, srcPort, dstPort, queryDomain, answerIP, transactionID)
	if err != nil {
		t.Fatalf("Failed to craft DNS response packet: %v", err)
	}

	craftedPacket, err := CraftPacket(ipLayer, udpLayer, payloadLayer, dnsLayer)
	if err != nil {
		t.Fatalf("Failed to serialize layers: %v", err)
	}

	// Decode the packet using gopacket
	packet := gopacket.NewPacket(craftedPacket, layers.LayerTypeIPv4, gopacket.Default)

	// Assert that the packet is not nil
	if packet == nil {
		t.Fatal("Packet is nil")
	}

	// Check the IP layer
	packetIPLayer := packet.Layer(layers.LayerTypeIPv4)
	if packetIPLayer == nil {
		t.Fatal("IP layer missing")
	}
	packetIP, _ := packetIPLayer.(*layers.IPv4)
	if packetIP.SrcIP.String() != srcIP {
		t.Errorf("srcIP = %s, want %s", packetIP.SrcIP.String(), srcIP)
	}
	if packetIP.DstIP.String() != dstIP {
		t.Errorf("dstIP = %s, want %s", packetIP.DstIP.String(), dstIP)
	}

	// Check the UDP layer
	packetUDPLayer := packet.Layer(layers.LayerTypeUDP)
	if packetUDPLayer == nil {
		t.Fatal("UDP layer missing")
	}
	packetUDP, _ := packetUDPLayer.(*layers.UDP)
	if packetUDP.SrcPort != udpLayer.SrcPort {
		t.Errorf("srcPort = %v, want %v", packetUDP.SrcPort, udpLayer.SrcPort)
	}
	if packetUDP.DstPort != udpLayer.DstPort {
		t.Errorf("dstPort = %v, want %v", packetUDP.DstPort, udpLayer.DstPort)
	}

	// Check the DNS layer
	packetDNSLayer := packet.Layer(layers.LayerTypeDNS)
	if packetDNSLayer == nil {
		t.Fatal("DNS layer missing")
	}
	packetDNS, _ := packetDNSLayer.(*layers.DNS)
	if string(packetDNS.Questions[0].Name) != queryDomain {
		t.Errorf("queryDomain = %s, want %s", packetDNS.Questions[0].Name, queryDomain)
	}
	if packetDNS.Answers[0].IP.String() != answerIP {
		t.Errorf("answerIP = %s, want %s", packetDNS.Answers[0].IP.String(), answerIP)
	}
}

func TestCraftARPPacketRequest(t *testing.T) {
	srcMAC := "00:0a:95:9d:68:16"
	dstMAC := "06:17:7f:2c:20:20"
	srcIP := "192.168.1.1"
	dstIP := "192.168.1.2"
	isReply := false

	arpLayer, err := CraftARPPacket(srcIP, dstIP, srcMAC, dstMAC, isReply)
	if err != nil {
		t.Fatalf("unexpected error crafting ARP packet: %v", err)
	}

	arp, err := CraftPacket(arpLayer)
	if err != nil {
		t.Fatalf("Failed to serialize layers: %v", err)
	}

	packet := gopacket.NewPacket(arp, layers.LayerTypeARP, gopacket.Default)

	arpPacket := packet.Layer(layers.LayerTypeARP).(*layers.ARP)

	if arpPacket.Operation != layers.ARPRequest {
		t.Errorf("operation = %v, want %v", arpPacket.Operation, layers.ARPRequest)
	}

	srcMACNet, err := net.ParseMAC(srcMAC)
	if err != nil {
		t.Errorf("Failed to parse srcMAC: %v", err)
	}

	if !bytes.Equal(arpPacket.SourceHwAddress, srcMACNet) {
		t.Errorf("srcMAC = %s, want %s", arpPacket.SourceHwAddress, srcMAC)
	}

	dstMACNet, err := net.ParseMAC(dstMAC)
	if err != nil {
		t.Errorf("Failed to parse dstMAC: %v", err)
	}

	if !bytes.Equal(arpPacket.DstHwAddress, dstMACNet) {
		t.Errorf("dstMAC = %s, want %s", arpPacket.DstHwAddress, dstMAC)
	}

	if !bytes.Equal(arpPacket.SourceProtAddress, net.ParseIP(srcIP).To4()) {
		t.Errorf("srcIP = %v, want %v", net.IP(arpPacket.SourceProtAddress).To4().String(), srcIP)
	}

	if !bytes.Equal(arpPacket.DstProtAddress, net.ParseIP(dstIP).To4()) {
		t.Errorf("dstIP = %v, want %v", net.IP(arpPacket.DstProtAddress).To4().String(), dstIP)
	}
}

func TestCraftARPPacketReply(t *testing.T) {
	srcMAC := "00:0a:95:9d:68:16"
	dstMAC := "06:17:7f:2c:20:20"
	srcIP := "192.168.1.1"
	dstIP := "192.168.1.2"
	isReply := true

	arpLayer, err := CraftARPPacket(srcIP, dstIP, srcMAC, dstMAC, isReply)
	if err != nil {
		t.Fatalf("unexpected error crafting ARP packet: %v", err)
	}

	arp, err := CraftPacket(arpLayer)
	if err != nil {
		t.Fatalf("Failed to serialize layers: %v", err)
	}

	packet := gopacket.NewPacket(arp, layers.LayerTypeARP, gopacket.Default)

	arpPacket := packet.Layer(layers.LayerTypeARP).(*layers.ARP)

	if arpPacket.Operation != layers.ARPReply {
		t.Errorf("operation = %v, want %v", arpPacket.Operation, layers.ARPRequest)
	}

	srcMACNet, err := net.ParseMAC(srcMAC)
	if err != nil {
		t.Errorf("Failed to parse srcMAC: %v", err)
	}

	if !bytes.Equal(arpPacket.SourceHwAddress, srcMACNet) {
		t.Errorf("srcMAC = %s, want %s", arpPacket.SourceHwAddress, srcMAC)
	}

	dstMACNet, err := net.ParseMAC(dstMAC)
	if err != nil {
		t.Errorf("Failed to parse dstMAC: %v", err)
	}

	if !bytes.Equal(arpPacket.DstHwAddress, dstMACNet) {
		t.Errorf("dstMAC = %s, want %s", arpPacket.DstHwAddress, dstMAC)
	}

	if !bytes.Equal(arpPacket.SourceProtAddress, net.ParseIP(srcIP).To4()) {
		t.Errorf("srcIP = %v, want %v", net.IP(arpPacket.SourceProtAddress).To4().String(), srcIP)
	}

	if !bytes.Equal(arpPacket.DstProtAddress, net.ParseIP(dstIP).To4()) {
		t.Errorf("dstIP = %v, want %v", net.IP(arpPacket.DstProtAddress).To4().String(), dstIP)
	}
}

func TestCraftEthernetPacket(t *testing.T) {

	srcMAC := "00:0a:95:9d:68:16"
	dstMAC := "06:17:7f:2c:20:20"

	ethernetLayer, err := CraftEthernetPacket(srcMAC, dstMAC)
	if err != nil {
		t.Fatalf("unexpected error crafting Ethernet packet: %v", err)
	}

	ethPacket, err := CraftPacket(ethernetLayer)
	if err != nil {
		t.Fatalf("unexpected error crafting Ethernet packet: %v", err)
	}

	packet := gopacket.NewPacket(ethPacket, layers.LayerTypeEthernet, gopacket.Default)

	ethernetPacket := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)

	srcMACNet, err := net.ParseMAC(srcMAC)
	if err != nil {
		t.Errorf("Failed to parse srcMAC: %v", err)
	}

	if !bytes.Equal(ethernetPacket.SrcMAC, srcMACNet) {
		t.Errorf("srcMAC = %s, want %s", ethernetPacket.SrcMAC.String(), srcMAC)
	}

	dstMACNet, err := net.ParseMAC(dstMAC)
	if err != nil {
		t.Errorf("Failed to parse dstMAC: %v", err)
	}

	if !bytes.Equal(ethernetPacket.DstMAC, dstMACNet) {
		t.Errorf("dstMAC = %s, want %s", ethernetPacket.DstMAC.String(), dstMAC)
	}

	if ethernetPacket.EthernetType != layers.EthernetTypeLLC {
		t.Errorf("EthernetType = %v, want %v", ethernetPacket.EthernetType, layers.EthernetTypeLLC)
	}
}
