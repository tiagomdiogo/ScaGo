package packet

import (
	"github.com/google/gopacket/layers"
	"net"
)

type STP struct {
	layers *layers.STP
}

func STPLayer() *STP {
	return &STP{
		layers: &layers.STP{
			ProtocolID: 0,
			Version:    0,
			Type:       0, // For Configuration BPDU
			TC:         false,
			TCA:        false,
			RouteID: layers.STPSwitchID{
				Priority: 0,
				SysID:    0,
				HwAddr:   nil,
			},
			Cost: 0,
			BridgeID: layers.STPSwitchID{
				Priority: 0,
				SysID:    0,
				HwAddr:   nil,
			},
			PortID:     0x8000,
			MessageAge: 0x0100,
			MaxAge:     0x2000,
			HelloTime:  0x0200,
			FDelay:     0x2000,
		},
	}
}

func (stp *STP) SetRootBridgeID(rootBridgeID uint16) {
	stp.layers.RouteID.SysID = rootBridgeID // Root Bridge ID
}

func (stp *STP) SetRootBridgePriority(priority uint16) {
	stp.layers.RouteID.Priority = priority // Priority
}

func (stp *STP) SetBridgePriority(priority uint16) {
	stp.layers.BridgeID.Priority = priority // Priority
}

func (stp *STP) SetBridgeID(bridgeID uint16) {
	stp.layers.BridgeID.SysID = bridgeID
}

// set Bridge Mac from a string
func (stp *STP) SetBridgeMacStr(bridgeMac string) {
	hwAddr, err := net.ParseMAC(bridgeMac)
	if err != nil {
		panic(err)
	}
	copy(stp.layers.BridgeID.HwAddr, hwAddr)
}

// set Root Mac from a string
func (stp *STP) SetRootBridgeMacStr(rootMac string) {
	hwAddr, err := net.ParseMAC(rootMac)
	if err != nil {
		panic(err)
	}
	copy(stp.layers.RouteID.HwAddr, hwAddr)
}
func (stp *STP) Layer() *layers.STP {
	return stp.layers
}
