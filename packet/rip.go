package packet

import (
	"errors"
	protocols "github.com/tiagomdiogo/ScaGo/protocols"
	"net"
)

type RIP struct {
	layer *protocols.RIPPacket
}

func RIPLayer() *RIP {
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
	if len(ipAddress) != 4 || len(subnetMask) != 4 || len(nextHop) != 4 {
		return errors.New("invalid IP length for RIP entry")
	}

	entry := protocols.RIPEntry{
		AddressFamilyIdentifier: aFI,
		RouteTag:                routeTag,
		Metric:                  metric,
	}
	copy(entry.IPAddress[:], ipAddress)
	copy(entry.SubnetMask[:], subnetMask)
	copy(entry.NextHop[:], nextHop)

	r.layer.Entries = append(r.layer.Entries, entry)
	return nil
}

func (r *RIP) Layer() *protocols.RIPPacket {
	return r.layer
}
