package packet

import (
	"errors"
	"github.com/tiagomdiogo/GoPpy/protocols"
	"net"
)

type Dot3 struct {
	layer *protocols.Dot3
}

// NewDot3Layer creates a new Dot3 layer
func Dot3Layer() *Dot3 {
	return &Dot3{
		layer: &protocols.Dot3{
			// Initialize the necessary fields
			DstMAC:  net.HardwareAddr{},
			SrcMAC:  net.HardwareAddr{},
			Padding: nil,
			Payload: nil,
		},
	}
}

// SetDstMAC sets the destination MAC address
func (d *Dot3) SetDstMAC(macStr string) error {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return errors.New("invalid destination MAC address")
	}
	d.layer.DstMAC = mac
	return nil
}

// SetSrcMAC sets the source MAC address
func (d *Dot3) SetSrcMAC(macStr string) error {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return errors.New("invalid source MAC address")
	}
	d.layer.SrcMAC = mac
	return nil
}

// SetLength sets the length
func (d *Dot3) SetLength(length uint16) {
	d.layer.Length = length
}

// Layer returns the underlying Dot3 layer
func (d *Dot3) Layer() *protocols.Dot3 {
	return d.layer
}
