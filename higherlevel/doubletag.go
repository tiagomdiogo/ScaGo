package higherlevel

import (
	golayers "github.com/google/gopacket/layers"
	craft "github.com/tiagomdiogo/ScaGo/packet"
	communication "github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
	"log"
)

func DoubleTagVlan(iface, dstIP string, vlanOut, vlanIn uint16) {

	//Create ETH Layer
	ethLayer := craft.EthernetLayer()
	ethLayer.SetSrcMAC(utils.ParseMACGen())
	ethLayer.SetDstMAC("ff:ff:ff:ff:ff:ff")
	ethLayer.SetEthernetType(golayers.EthernetTypeIPv4)

	//Create Dot1Q Layer
	dot1qLayer := craft.Dot1QLayer()
	dot1qLayer.SetVLANIdentifier(vlanIn)

	//Create another Dot1Q Layer
	dot1qLayer2 := craft.Dot1QLayer()
	dot1qLayer2.SetVLANIdentifier(vlanOut)
	dot1qLayer2.Layer().Type = golayers.EthernetTypeIPv4

	//Create IP Layer
	ipLayer := craft.IPv4Layer()
	ipLayer.SetSrcIP(utils.ParseIPGen("0.0.0.0/0"))
	ipLayer.SetDstIP(dstIP)
	ipLayer.SetProtocol(golayers.IPProtocolICMPv4)

	//Create ICMP Layer
	icmpLayer := craft.ICMPv4Layer()

	craftedPacket, err := craft.CraftPacket(ethLayer.Layer(), dot1qLayer.Layer(), dot1qLayer2.Layer(), ipLayer.Layer(), icmpLayer.Layer())
	if err != nil {
		log.Fatal(err)
	}

	communication.Send(craftedPacket, iface)
}
