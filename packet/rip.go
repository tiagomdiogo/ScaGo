package packet

import (
	"github.com/google/gopacket/layers"
	protocols "github.com/tiagomdiogo/ScaGo/protocols"
	"net"
)

type RIP struct {
	layer *protocols.RIPPacket
}

func RIPLayer() *RIP {
	layers.RegisterUDPPortLayerType(520, protocols.LayerTypeRip)
	return &RIP{
		layer: &protocols.RIPPacket{},
	}
}

func (r *RIP) SetCommand(command uint8) {
	r.layer.Command = command
}

func (r *RIP) SetVersion(version uint8) {
	r.layer.Version = version
}

func (r *RIP) AddEntry(aFI uint16, routeTag uint16, ipAddress, subnetMask, nextHop net.IP, metric uint32) error {
	entry := protocols.RIPEntry{
		AddressFamilyIdentifier: aFI,
		RouteTag:                routeTag,
		Metric:                  metric,
	}
	copy(entry.IPAddress[:], ipAddress.To4())
	copy(entry.SubnetMask[:], subnetMask.To4())
	copy(entry.NextHop[:], nextHop.To4())

	r.layer.Entries = append(r.layer.Entries, entry)
	return nil
}

func (r *RIP) Layer() *protocols.RIPPacket {
	return r.layer
}
