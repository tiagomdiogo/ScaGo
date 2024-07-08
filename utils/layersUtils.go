package utils

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// GetARPLayer retrieves the ARP layer of a packet in format gopacket.Packet
func GetARPLayer(packet gopacket.Packet) *layers.ARP {
	// Get the ARP layer from this packet
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		// The packet has an ARP layer, return it.
		return arpLayer.(*layers.ARP)
	} else {
		// The packet does not have an ARP layer.
		return nil
	}
}

// GetSTPLayer retrieves the STP layer of a packet in format gopacket.Packet
func GetSTPLayer(packet gopacket.Packet) *layers.STP {
	// Get the ARP layer from this packet
	if stpLayer := packet.Layer(layers.LayerTypeSTP); stpLayer != nil {
		// The packet has an ARP layer, return it.
		return stpLayer.(*layers.STP)
	} else {
		// The packet does not have an ARP layer.
		return nil
	}
}

// GetUDPLayer retrieves the P lUDayer of a packet in format gopacket.Packet
func GetUDPLayer(packet gopacket.Packet) *layers.UDP {
	// Get the ARP layer from this packet
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		// The packet has an UDP layer, return it.
		return udpLayer.(*layers.UDP)
	} else {
		// The packet does not have an UDP layer.
		return nil
	}
}

// GetTCPLayer retrieves the TCP layer of a packet in format gopacket.Packet
func GetTCPLayer(packet gopacket.Packet) *layers.TCP {
	// Get the ARP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		// The packet has an TCP layer, return it.
		return tcpLayer.(*layers.TCP)
	} else {
		// The packet does not have an TCP layer.
		return nil
	}
}

func GetTLSLayer(packet gopacket.Packet) *layers.TLS {
	// Get the ARP layer from this packet
	if tlsLayer := packet.Layer(layers.LayerTypeTLS); tlsLayer != nil {
		// The packet has an TCP layer, return it.
		return tlsLayer.(*layers.TLS)
	} else {
		// The packet does not have an TCP layer.
		return nil
	}
}
