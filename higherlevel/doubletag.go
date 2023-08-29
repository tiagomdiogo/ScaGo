package higherlevel

import (
	golayers "github.com/google/gopacket/layers"
	craft "github.com/tiagomdiogo/GoPpy/packet"
	"github.com/tiagomdiogo/GoPpy/supersocket"
	"github.com/tiagomdiogo/GoPpy/utils"
	"log"
)

func DoubleTagVlan(iface, dstIP string, vlanOut, vlanIn uint16, pktsize int) {

	//Create a supersocket
	SuperS, err := supersocket.NewSuperSocket(iface, "")
	if err != nil {
		log.Fatal(err)
	}
	defer SuperS.Close()

	//Create ETH Layer
	ethLayer := craft.EthernetLayer()
	ethLayer.SetSrcMAC(utils.RandomMAC())
	ethLayer.SetDstMAC("ff:ff:ff:ff:ff:ff")
	ethLayer.SetEthernetType(golayers.EthernetTypeDot1Q)

	//Create Dot1Q Layer
	dot1qLayer := craft.Dot1QLayer()
	dot1qLayer.SetVLANIdentifier(vlanOut)

	//Create another Dot1Q Layer
	dot1qLayer2 := craft.Dot1QLayer()
	dot1qLayer2.SetVLANIdentifier(vlanIn)

	//Create IP Layer
	ipLayer := craft.IPv4Layer()
	ipLayer.SetSrcIP(utils.RandomIP("0.0.0.0/0"))
	ipLayer.SetDstIP(dstIP)

	//Create ICMP Layer
	icmpLayer := craft.ICMPv4Layer()

	craftedPacket, err := craft.CraftPacket(ethLayer.Layer(), dot1qLayer.Layer(), dot1qLayer2.Layer(), ipLayer.Layer(), icmpLayer.Layer())
	if err != nil {
		log.Fatal(err)
	}

	SuperS.Send(craftedPacket)
}
