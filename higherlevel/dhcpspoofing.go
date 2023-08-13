package higherlevel

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/GoPpy/packet"
	"github.com/tiagomdiogo/GoPpy/sniffer"
	"github.com/tiagomdiogo/GoPpy/supersocket"
	"github.com/tiagomdiogo/GoPpy/utils"
	"log"
)

func createSuperSocket(iface string) *supersocket.SuperSocket {
	socketInt, err := supersocket.NewSuperSocket(iface, "")
	if err != nil {
		fmt.Println("Error when creating supersocket")
	}
	return socketInt
}

func dhcpResponder(iface string) {
	newSniffer, err := sniffer.NewSniffer(iface, "udp and port 67", 100)
	socketint := createSuperSocket(iface)
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
					sendDHCPOffer(dhcp, iface, socketint)
					fmt.Println("Sent an Offer package")
				case layers.DHCPMsgTypeRequest:
					fmt.Println("Received a Request package")
					sendDHCPAck(dhcp, iface, socketint)
					fmt.Println("Sent an ACK package")
				}
			}
		}
	}
}

func sendDHCPOffer(request *layers.DHCPv4, iface string, socketint *supersocket.SuperSocket) {
	//ethlayer
	srcMac, err := utils.MacByInt(iface)
	if err != nil {
		fmt.Println("Error when getting Mac from provided interface")
	}
	ethLayer := packet.EthernetLayer()
	ethLayer.SetSrcMAC(srcMac)
	ethLayer.SetDstMAC(request.ClientHWAddr.String())

	//iplayer
	srcIP, err := utils.IPbyInt(iface)
	if err != nil {
		fmt.Println("Error when getting IP from provided interface")
	}
	ipv4Layer := packet.IPv4Layer()
	ipv4Layer.SetSrcIP(srcIP)
	ipv4Layer.SetDstIP(request.ClientIP.String())

	//DHCP Layer
	dhcpLayer := packet.NewDHCP()
	dhcpLayer.SetReply()
	dhcpLayer.SetMsgType("offer")

	packetToSend, err := packet.CraftPacket(ethLayer.Layer(), ipv4Layer.Layer(), dhcpLayer.Layer())

	socketint.Send(packetToSend)
}

func sendDHCPAck(request *layers.DHCPv4, iface string, socketint *supersocket.SuperSocket) {

	//ethlayer
	srcMac, err := utils.MacByInt(iface)
	if err != nil {
		fmt.Println("Error when getting Mac from provided interface")
	}
	ethLayer := packet.EthernetLayer()
	ethLayer.SetSrcMAC(srcMac)
	ethLayer.SetDstMAC(request.ClientHWAddr.String())

	//iplayer
	srcIP, err := utils.IPbyInt(iface)
	if err != nil {
		fmt.Println("Error when getting IP from provided interface")
	}
	ipv4Layer := packet.IPv4Layer()
	ipv4Layer.SetSrcIP(srcIP)
	ipv4Layer.SetDstIP(request.ClientIP.String())

	//DHCP Layer
	dhcpLayer := packet.NewDHCP()
	dhcpLayer.SetReply()
	dhcpLayer.SetMsgType("ack")

	packetToSend, err := packet.CraftPacket(ethLayer.Layer(), ipv4Layer.Layer(), dhcpLayer.Layer())

	socketint.Send(packetToSend)
}
