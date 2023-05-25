package supersocket

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type SuperSocket struct {
	handle *pcap.Handle
}

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

	return &SuperSocket{handle: handle}, nil
}

func (ss *SuperSocket) Close() {
	ss.handle.Close()
}

func (ss *SuperSocket) Send(packetBytes []byte) error {
	return ss.handle.WritePacketData(packetBytes)
}

func (ss *SuperSocket) Recv() (gopacket.Packet, error) {
	data, _, err := ss.handle.ZeroCopyReadPacketData()
	if err != nil {
		return nil, fmt.Errorf("failed to read packet data: %v", err)
	}
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	return packet, nil
}
