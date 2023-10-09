package packet

import (
	"errors"
	"strconv"

	golayers "github.com/google/gopacket/layers"
)

type TCP struct {
	layer *golayers.TCP
}

func TCPLayer() *TCP {
	return &TCP{
		layer: &golayers.TCP{
			Seq:    0,
			Window: 1505,
		},
	}
}

func (tcp *TCP) SetSrcPort(portStr string) error {
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return errors.New("invalid source port")
	}
	tcp.layer.SrcPort = golayers.TCPPort(port)
	return nil
}

func (tcp *TCP) SetDstPort(portStr string) error {
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return errors.New("invalid destination port")
	}
	tcp.layer.DstPort = golayers.TCPPort(port)
	return nil
}

func (tcp *TCP) SetSyn() {
	tcp.layer.SYN = true
}

func (tcp *TCP) SetAck() {
	tcp.layer.ACK = true
}

func (tcp *TCP) Layer() *golayers.TCP {
	return tcp.layer
}
