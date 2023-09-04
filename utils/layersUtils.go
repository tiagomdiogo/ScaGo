package utils

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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
