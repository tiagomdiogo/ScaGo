package sniffer

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	maxLenPacket int32         = 65535 //max size of a TCP Packet 64k
	promiscuous  bool          = false
	duration     time.Duration = -1 * time.Second
)

func CapturePacket(interface_name string) error {

	handle, err := pcap.OpenLive(interface_name, maxLenPacket, promiscuous, duration)
	if err != nil {
		log.Fatal(err)
		return err
	}

	defer handle.Close() //delay the execution of a function (Close handle) until the read finishes

	return PrintPackets(handle)

}

func PrintPackets(handle *pcap.Handle) error {
	packetReceived := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetReceived.Packets() {
		fmt.Println(packet)
	}

	return nil
}
