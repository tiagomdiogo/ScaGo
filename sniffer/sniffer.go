package sniffer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"sync"
)

type Sniffer struct {
	handle      *pcap.Handle
	packetList  []gopacket.Packet
	packetLock  sync.Mutex
	packetLimit int
}

func NewSniffer(dev string, filter string, packetLimit int) (*Sniffer, error) {
	handle, err := pcap.OpenLive(dev, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, err
	}

	return &Sniffer{
		handle:      handle,
		packetList:  make([]gopacket.Packet, 0),
		packetLimit: packetLimit,
	}, nil
}

func (s *Sniffer) Start() {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

	for packet := range packetSource.Packets() {
		s.packetLock.Lock()
		if len(s.packetList) < s.packetLimit {
			s.packetList = append(s.packetList, packet)
		}
		s.packetLock.Unlock()
	}
}

func (s *Sniffer) Stop() {
	s.handle.Close()
}

func (s *Sniffer) GetPackets() []gopacket.Packet {
	s.packetLock.Lock()
	defer s.packetLock.Unlock()

	packets := make([]gopacket.Packet, len(s.packetList))
	copy(packets, s.packetList)
	return packets
}
