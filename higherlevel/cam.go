package higherlevel

import (
	"fmt"
	"sync"

	golayers "github.com/google/gopacket/layers"
	craft "github.com/tiagomdiogo/ScaGo/packet"
	communication "github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
)

func Cam(iface string, packetCount int) {
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

	communication.SendMultiplePackets(packets, iface, 10)
	if err != nil {
		fmt.Println("Error sending packets:", err)
		return
	}
}

func CamBatch(iface string, packetCount, batchSize int) {

	var wg sync.WaitGroup
	for start := 0; start < packetCount; start += batchSize {
		end := start + batchSize
		if end > packetCount {
			end = packetCount
		}

		packets := make([][]byte, end-start)

		for i := start; i < end; i++ {
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

				localIdx := i - start // adjust index for current batch
				packets[localIdx], err = craft.CraftPacket(etherLayer.Layer(), ipLayer.Layer())
				if err != nil {
					fmt.Println("Error crafting Ethernet packet:", err)
					return
				}
			}(i)
		}
		wg.Wait()

		communication.SendMultiplePackets(packets, iface, 10)
		if err != nil {
			fmt.Println("Error sending packets:", err)
			return
		}
	}
}

var err error = nil

func CamSequential(iface string, packetCount int) {

	packets := make([][]byte, packetCount)

	for i := 0; i < packetCount; i++ {
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
	}
	communication.SendMultiplePackets(packets, iface, 1)
}
