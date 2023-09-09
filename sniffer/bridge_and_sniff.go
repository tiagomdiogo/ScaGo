package sniffer

import (
	"github.com/google/gopacket"
	"github.com/tiagomdiogo/GoPpy/supersocket"
	"log"
)

func Bridge_and_Sniff(iface1, iface2 string) {

	superSocket1, err := supersocket.NewSuperSocket(iface1, "")
	superSocket2, err := supersocket.NewSuperSocket(iface2, "")
	if err != nil {
		log.Fatal(err)
	}

	go bridge_aux(superSocket1, superSocket2)
	go bridge_aux(superSocket2, superSocket1)

}

func bridge_aux(ss1, ss2 *supersocket.SuperSocket) {

	handle1 := gopacket.NewPacketSource(ss1.GetHandle(), ss1.GetHandle().LinkType())

	for packet := range handle1.Packets() {

		ss2.Send(packet.Data())
	}
}