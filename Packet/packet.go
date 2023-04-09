package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// createCustomPacket creates a custom packet with the given layers and custom fields.
// It supports TCP, IP, UDP, DNS, Ethernet, and VLAN protocols.
func createCustomPacket(layersList []gopacket.SerializableLayer, customFields map[string]interface{}) ([]byte, error) {
	// Create a new buffer to store the packet data
	buf := gopacket.NewSerializeBuffer()

	// Initialize the layer variables
	var (
		ethLayer  *layers.Ethernet
		vlanLayer *layers.Dot1Q
		ipLayer   *layers.IPv4
		udpLayer  *layers.UDP
		tcpLayer  *layers.TCP
		dnsLayer  *layers.DNS
	)

	// Iterate over the layers and add them to the packet
	for _, l := range layersList {
		switch layer := l.(type) {
		case *layers.Ethernet:
			ethLayer = layer
		case *layers.Dot1Q:
			vlanLayer = layer
		case *layers.IPv4:
			ipLayer = layer
		case *layers.UDP:
			udpLayer = layer
		case *layers.TCP:
			tcpLayer = layer
		case *layers.DNS:
			dnsLayer = layer
		default:
			return nil, fmt.Errorf("unsupported layer type: %T", l)
		}
	}

	// Add custom fields to the layers
	if ethLayer != nil {
		if customFields["SrcMAC"] != nil {
			mac, err := net.ParseMAC(customFields["SrcMAC"].(string))
			if err != nil {
				return nil, fmt.Errorf("invalid MAC address: %v", customFields["SrcMAC"])
			}
			ethLayer.SrcMAC = mac
		}
		if customFields["DstMAC"] != nil {
			mac, err := net.ParseMAC(customFields["DstMAC"].(string))
			if err != nil {
				return nil, fmt.Errorf("invalid MAC address: %v", customFields["DstMAC"])
			}
			ethLayer.DstMAC = mac
		}
	}
	if ipLayer != nil {
		if customFields["SrcIP"] != nil {
			ip := net.ParseIP(customFields["SrcIP"].(string))
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %v", customFields["SrcIP"])
			}
			ipLayer.SrcIP = ip
		}
		if customFields["DstIP"] != nil {
			ip := net.ParseIP(customFields["DstIP"].(string))
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %v", customFields["DstIP"])
			}
			ipLayer.DstIP = ip
		}
	}
	if tcpLayer != nil {
		if customFields["SrcPort"] != nil {
			port := customFields["SrcPort"].(uint16)
			tcpLayer.SrcPort = layers.TCPPort(port)
		}
		if customFields["DstPort"] != nil {
			port := customFields["DstPort"].(uint16)
			tcpLayer.DstPort = layers.TCPPort(port)
		}
	}
	if udpLayer != nil {
		if customFields["SrcPort"] != nil {
			port := customFields["SrcPort"].(uint16)
			udpLayer.SrcPort = layers.UDPPort(port)
		}
		if customFields["DstPort"] != nil {
			port := customFields["DstPort"].(uint16)
			udpLayer.DstPort = layers.UDPPort(port)
		}
	}
	if dnsLayer != nil {
		if customFields["ID"] != nil {
			id := customFields["ID"].(uint16)
			dnsLayer.ID = id
		}
		if customFields["OpCode"] != nil {
			opcode := customFields["OpCode"].(layers.DNSOpCode)
			dnsLayer.OpCode = opcode
		}
	}

	// Serialize the packet layers into the buffer
	var options gopacket.SerializeOptions
	if vlanLayer != nil {
		options.FixLengths = true
	}
	err := gopacket.SerializeLayers(buf, options,
		ethLayer,
		vlanLayer,
		ipLayer,
		udpLayer,
		tcpLayer,
		dnsLayer,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize layers: %v", err)
	}

	// Return the packet data
	packetData := buf.Bytes()
	if len(packetData) == 0 {
		return nil, errors.New("packet is empty")
	}
	return packetData, nil
}
