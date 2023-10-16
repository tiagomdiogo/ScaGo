package sniffer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"sync"
	"time"
)

type Sniffer struct {
	handle      *pcap.Handle
	packetList  []gopacket.Packet
	packetLock  sync.Mutex
	packetLimit int
}

func NewSniffer(dev string, filter string) (*Sniffer, error) {
	handle, err := pcap.OpenLive(dev, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, err
	}

	return &Sniffer{
		handle:     handle,
		packetList: make([]gopacket.Packet, 0),
	}, nil
}

func (s *Sniffer) Start() *gopacket.PacketSource {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

	for packet := range packetSource.Packets() {

		s.packetLock.Lock()
		if len(s.packetList) < s.packetLimit || s.packetLimit == 0 {

			s.packetList = append(s.packetList, packet)
		}
		s.packetLock.Unlock()
	}
	return packetSource
}

func (s *Sniffer) Stop() {
	s.handle.Close()
}

func (s *Sniffer) GetPackets() []gopacket.Packet {
	s.packetLock.Lock()
	defer s.packetLock.Unlock()

	packets := make([]gopacket.Packet, len(s.packetList))
	copy(packets, s.packetList)
	s.packetList = make([]gopacket.Packet, 0)
	return packets
}

func Sniff(iFace, filter string) {

	handle, err := pcap.OpenLive(iFace, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		log.Fatal(err)
	}

	snif := &Sniffer{
		handle:     handle,
		packetList: make([]gopacket.Packet, 0),
	}

	go snif.Start()

	for {
		packetsSniffer := snif.GetPackets()
		if len(packetsSniffer) > 0 {
			fmt.Println(packetsSniffer)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
