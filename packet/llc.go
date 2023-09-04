package packet

import (
	"github.com/google/gopacket/layers"
)

type LLC struct {
	layer *layers.LLC
}

func LLCLayer() *LLC {
	return &LLC{
		layer: &layers.LLC{
			// Initialize the necessary fields
			DSAP:    0,
			SSAP:    0,
			Control: 0,
		},
	}
}

func (l *LLC) SetDSAP(dsap uint8) {
	l.layer.DSAP = dsap
}

func (l *LLC) SetSSAP(ssap uint8) {
	l.layer.SSAP = ssap
}

func (l *LLC) SetControl(control uint16) {
	l.layer.Control = control
}

func (l *LLC) Layer() *layers.LLC {
	return l.layer
}
