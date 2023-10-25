package packet

import (
	"fmt"
	"github.com/google/gopacket"
	golayers "github.com/google/gopacket/layers"
	communication "github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
	"net"
	"time"
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
				dstMAC, _ := ARPScanHost(iface.Name, ipLayer.DstIP.String())
				ethLayer.SetDstMAC(dstMAC)
			} else {
				gatewayIP, _ := utils.GetDefaultGatewayIP()
				dstMAC, _ := ARPScanHost(iface.Name, gatewayIP.String())
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

func ARPScanHost(iface string, targetIP string) (string, error) {
	srcMAC := utils.MacByInt(iface)
	srcIP := utils.IPbyInt(iface)

	ethLayer := EthernetLayer()
	ethLayer.SetSrcMAC(srcMAC)
	ethLayer.SetDstMAC("ff:ff:ff:ff:ff:ff")
	ethLayer.SetEthernetType(golayers.EthernetTypeARP)

	arpRequest := ARPLayer()
	arpRequest.SetSrcMac(srcMAC)
	arpRequest.SetSrcIP(srcIP)
	arpRequest.SetDstIP(targetIP)
	arpRequest.SetRequest()
	arpRequest.SetDstMac("ff:ff:ff:ff:ff:ff")

	arpRequestPacket, err := CraftPacket(ethLayer.Layer(), arpRequest.Layer())
	if err != nil {
		return "", err
	}

	for {
		pkt := communication.SendRecv(arpRequestPacket, iface)
		arpLayer := utils.GetARPLayer(pkt)
		if arpLayer != nil && arpLayer.Operation == golayers.ARPReply && net.IP(arpLayer.SourceProtAddress).String() == targetIP {
			return net.HardwareAddr(arpLayer.SourceHwAddress).String(), nil
		}

		time.Sleep(1 * time.Second)
	}

}
