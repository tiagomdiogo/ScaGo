package packet

import (
	"fmt"
	"github.com/google/gopacket"
	golayers "github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/ScaGo/higherlevel"
	"github.com/tiagomdiogo/ScaGo/utils"
)

func CraftPacket(layers ...gopacket.Layer) ([]byte, error) {

	layers2 := packetCheck(layers)

	buffer := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer, opts, layers2...)
	if err != nil {
		return nil, fmt.Errorf("error serializing layers: %v", err)
	}

	return buffer.Bytes(), nil
}

func packetCheck(layers []gopacket.Layer) []gopacket.SerializableLayer {
	hasEthernetLayer := false
	hasIPLayer := false
	var ipLayer *golayers.IPv4

	for _, layer := range layers {
		switch l := layer.(type) {
		case *golayers.Ethernet:
			hasEthernetLayer = true
		case *golayers.IPv4:
			hasIPLayer = true
			ipLayer = l
		case *golayers.UDP:
			if ipLayer != nil {
				l.SetNetworkLayerForChecksum(ipLayer)
			}
		case *golayers.TCP:
			if ipLayer != nil {
				l.SetNetworkLayerForChecksum(ipLayer)
			}
		}
	}

	ethLayer := EthernetLayer()
	if !hasEthernetLayer {
		if hasIPLayer {
			ethLayer.SetEthernetType(golayers.EthernetTypeIPv4)
			iface, _ := utils.GetInterfaceByIP(ipLayer.SrcIP)
			if iface != nil {
				ethLayer.SetSrcMAC(iface.HardwareAddr.String())
			}

			if utils.AreIPsInSameSubnet(ipLayer.SrcIP, ipLayer.DstIP) {
				dstMAC, _ := higherlevel.ARPScanHost(iface.Name, ipLayer.DstIP.String())
				ethLayer.SetDstMAC(dstMAC)
			} else {
				gatewayIP, _ := utils.GetDefaultGatewayIP()
				dstMAC, _ := higherlevel.ARPScanHost(iface.Name, gatewayIP.String())
				ethLayer.SetDstMAC(dstMAC)
			}
		}
	}

	layers = append([]gopacket.Layer{ethLayer.Layer()}, layers...)

	result := make([]gopacket.SerializableLayer, 0, len(layers))
	for _, layer := range layers {
		if slayer, ok := layer.(gopacket.SerializableLayer); ok {
			result = append(result, slayer)
		}
	}
	return result
}
