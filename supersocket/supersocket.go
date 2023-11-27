package supersocket

import (
	"fmt"
	"log"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// SuperSocket structure contains the pointer to pcap.Handle and the interface to be used
type SuperSocket struct {
	handle *pcap.Handle
	iface  string
}

// NewSuperSocket Given the interface and the filter opens the socket connection
func NewSuperSocket(device string, bpfFilter string) (*SuperSocket, error) {
	// Open the device for capturing
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open device for capturing: %v", err)
	}

	// Apply the BPF filter
	if bpfFilter != "" {
		err = handle.SetBPFFilter(bpfFilter)
		if err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set BPF filter: %v", err)
		}
	}

	return &SuperSocket{handle: handle,
		iface: device}, nil
}

// Close closes the socket connection
func (ss *SuperSocket) Close() {
	ss.handle.Close()
}

// Send sends the array of bytes through the supersocket
func (ss *SuperSocket) Send(packetBytes []byte) error {
	return ss.handle.WritePacketData(packetBytes)
}

// Recv receives the bytes and transforms it into a gopacket.packet using the function NewPacket
func (ss *SuperSocket) Recv() (gopacket.Packet, error) {
	data, _, err := ss.handle.ZeroCopyReadPacketData()
	if err != nil {
		return nil, fmt.Errorf("failed to read packet data: %v", err)
	}
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	return packet, nil
}

// SendMultiplePackets Given an array of bytes, sends them using goroutines.
// The maxConcurrentSends defines the maximum number of threads to be created
func (ss *SuperSocket) SendMultiplePackets(packets [][]byte, maxConcurrentSends int) error {
	if maxConcurrentSends <= 0 {
		maxConcurrentSends = len(packets)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentSends)

	for _, packet := range packets {
		wg.Add(1)
		sem <- struct{}{}

		go func(p []byte) {
			defer wg.Done()
			defer func() { <-sem }()
			err := ss.Send(p)
			if err != nil {
				fmt.Printf("Failed to send packet: %v\n", err)
			}
		}(packet)
	}

	wg.Wait()

	return nil
}

// GetHandle returns the pointer to the pcap.Handle
func (ss *SuperSocket) GetHandle() *pcap.Handle {
	return ss.handle
}

// Send this function sends the array of bytes. It doesn't need to be called on a supersocket
// structure. This functions creates the supersocket automatically, allowing to have a more
// abstract usage.
func Send(packetBytes []byte, iface string) {
	superS, err := NewSuperSocket(iface, "")
	if err != nil {
		log.Fatal(err)
	}
	superS.Send(packetBytes)
	superS.Close()
}

// Recv this function receives the array of bytes. It doesn't need to be called on a supersocket
// structure. This functions creates the supersocket automatically, allowing to have a more
// abstract usage.
func Recv(iface string) gopacket.Packet {
	superS, err := NewSuperSocket(iface, "")
	defer superS.Close()
	if err != nil {
		log.Fatal(err)
	}
	packet, err := superS.Recv()
	return packet
}

// SendRecv this function Sends the array of bytes and receives its answer. It doesn't need to be called
// on a supersocket structure. This functions creates the supersocket automatically, allowing to have a more
// abstract usage.
func SendRecv(packetBytes []byte, iface string) gopacket.Packet {
	superS, err := NewSuperSocket(iface, "")
	if err != nil {
		log.Fatal(err)
	}
	superS.Send(packetBytes)
	packet, _ := superS.Recv()
	return packet
}

// SendMultiplePackets sends multiple packets concurrently. It doesn't need to be called
// on a supersocket structure. This functions creates the supersocket automatically, allowing to have a more
// abstract usage.
func SendMultiplePackets(packets [][]byte, iface string, maxConcurrentSends int) {
	ss, err := NewSuperSocket(iface, "")
	if err != nil {
		log.Fatal(err)
	}

	if maxConcurrentSends <= 0 {
		maxConcurrentSends = len(packets)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentSends)

	for _, packet := range packets {
		wg.Add(1)
		sem <- struct{}{}
		go func(p []byte) {
			defer wg.Done()
			defer func() { <-sem }()
			err := ss.Send(p)
			if err != nil {
				fmt.Printf("Failed to send packet: %v\n", err)
			}
		}(packet)
	}

	wg.Wait()
}
