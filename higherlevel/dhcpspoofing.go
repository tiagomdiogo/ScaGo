package higherlevel

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/GoPpy/packet"
	"github.com/tiagomdiogo/GoPpy/sniffer"
	"github.com/tiagomdiogo/GoPpy/supersocket"
	"github.com/tiagomdiogo/GoPpy/utils"
	"log"
	"net"
)

func generatePool(pool, netmask string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(pool + "/" + netmask)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, append(net.IP(nil), ip...)) // Add a copy of ip to ips
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func DHCPSpoofing(pool, mask, gateway, iface string) {

	availableIP, err := generatePool(pool, mask)
	fmt.Println(availableIP)
	newSniffer, err := sniffer.NewSniffer(iface, "udp and (port 67 or 68)")
	if err != nil {
		log.Fatal(err)
	}
	defer newSniffer.Stop()
	go newSniffer.Start()

	for _, packetAux := range newSniffer.GetPackets() {
		dhcpLayer := packetAux.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer != nil {
			dhcp, _ := dhcpLayer.(*layers.DHCPv4)

			if dhcp.Operation == layers.DHCPOpRequest {
				messageType := layers.DHCPMsgTypeUnspecified
				for _, opt := range dhcp.Options {
					if opt.Type == layers.DHCPOptMessageType {
						messageType = layers.DHCPMsgType(opt.Data[0])
						break
					}
				}

				switch messageType {
				case layers.DHCPMsgTypeDiscover:
					fmt.Println("Received a Discover package")
					//DHCPOffer(dhcp, iface, iface)
					fmt.Println("Sent an Offer package")
				case layers.DHCPMsgTypeRequest:
					fmt.Println("Received a Request package")
					//sendDHCPAck(dhcp, iface, iface)
					fmt.Println("Sent an ACK package")
				}
			}
		}
	}
}

func DHCPOffer(dhcp *layers.DHCPv4, iface string, availableIP net.IP, sourceIp net.IP) {

	ethLayer := packet.EthernetLayer()
	ethLayer.SetSrcMAC(utils.MacByInt(iface))
	ethLayer.SetDstMAC(dhcp.ClientHWAddr.String())
	ethLayer.SetEthernetType(layers.EthernetTypeIPv4)

	ipLayer := packet.IPv4Layer()
	ipLayer.SetSrcIP(sourceIp.String())
	ipLayer.SetDstIP(availableIP.String())
	ipLayer.SetProtocol(layers.IPProtocolUDP)

	udpLayer := packet.UDPLayer()
	udpLayer.SetSrcPort("67")
	udpLayer.SetDstPort("68")
	udpLayer.Layer().SetNetworkLayerForChecksum(ipLayer.Layer())

	dhcpLayer := packet.DHCPLayer()
	dhcpLayer.SetReply()
	dhcpLayer.SetDstMac(dhcp.ClientHWAddr.String())
	dhcpLayer.SetDstIP(availableIP.String())
	dhcpLayer.SetSrcIP(sourceIp.String())
	dhcpLayer.SetXid(dhcp.Xid)

}

func sendDHCPOffer(request *layers.DHCPv4, iface string, socketint *supersocket.SuperSocket) {
	//ethlayer
	srcMac := utils.MacByInt(iface)

	ethLayer := packet.EthernetLayer()
	ethLayer.SetSrcMAC(srcMac)
	ethLayer.SetDstMAC(request.ClientHWAddr.String())

	//iplayer
	srcIP := utils.IPbyInt(iface)
	ipv4Layer := packet.IPv4Layer()
	ipv4Layer.SetSrcIP(srcIP)
	ipv4Layer.SetDstIP(request.ClientIP.String())

	//DHCP Layer
	dhcpLayer := packet.DHCPLayer()
	dhcpLayer.SetReply()
	dhcpLayer.SetMsgType("offer")

	packetToSend, err := packet.CraftPacket(ethLayer.Layer(), ipv4Layer.Layer(), dhcpLayer.Layer())

	if err != nil {
		log.Fatal(err)
	}

	socketint.Send(packetToSend)
}

func sendDHCPAck(request *layers.DHCPv4, iface string, socketint *supersocket.SuperSocket) {

	//ethlayer
	srcMac := utils.MacByInt(iface)
	ethLayer := packet.EthernetLayer()
	ethLayer.SetSrcMAC(srcMac)
	ethLayer.SetDstMAC(request.ClientHWAddr.String())

	//iplayer
	srcIP := utils.IPbyInt(iface)
	ipv4Layer := packet.IPv4Layer()
	ipv4Layer.SetSrcIP(srcIP)
	ipv4Layer.SetDstIP(request.ClientIP.String())

	//DHCP Layer
	dhcpLayer := packet.DHCPLayer()
	dhcpLayer.SetReply()
	dhcpLayer.SetMsgType("ack")

	packetToSend, err := packet.CraftPacket(ethLayer.Layer(), ipv4Layer.Layer(), dhcpLayer.Layer())

	if err != nil {
		log.Fatal(err)
	}
	socketint.Send(packetToSend)
}
