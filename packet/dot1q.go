package packet

import (
	"errors"
	golayers "github.com/google/gopacket/layers"
)

type Dot1Q struct {
	layer *golayers.Dot1Q
}

// Dot1QLayer Create a new Dot1Q layer with default values
func Dot1QLayer() *Dot1Q {
	return &Dot1Q{
		layer: &golayers.Dot1Q{
			VLANIdentifier: 1,                         // Default VLAN ID
			Type:           golayers.EthernetTypeIPv4, // Default Type
			Priority:       0,                         // Default Priority
			DropEligible:   false,                     // Default Drop Eligible Indicator
		},
	}
}

// SetVLANIdentifier Set the VLAN identifier
func (dot1q *Dot1Q) SetVLANIdentifier(id uint16) error {
	if id > 4095 {
		return errors.New("invalid VLAN ID, must be between 0 and 4095")
	}
	dot1q.layer.VLANIdentifier = id
	return nil
}

// SetType Set the Type field
func (dot1q *Dot1Q) SetType(etherType golayers.EthernetType) {
	dot1q.layer.Type = etherType
}

// SetPCP Set Priority Code Point (PCP)
func (dot1q *Dot1Q) SetPCP(pcp uint8) error {
	if pcp > 7 {
		return errors.New("invalid PCP, must be between 0 and 7")
	}
	dot1q.layer.Priority = pcp
	return nil
}

// SetDEI Set Drop Eligible Indicator (DEI)
func (dot1q *Dot1Q) SetDEI(dei bool) {
	dot1q.layer.DropEligible = dei
}

// Layer Get the underlying gopacket Dot1Q layer
func (dot1q *Dot1Q) Layer() *golayers.Dot1Q {
	return dot1q.layer
}
