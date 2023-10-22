package packet

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"

	golayers "github.com/google/gopacket/layers"
)

type DHCP struct {
	layer *golayers.DHCPv4
}

func DHCPLayer() *DHCP {
	return &DHCP{
		layer: &golayers.DHCPv4{
			Operation:    golayers.DHCPOpRequest,
			HardwareType: golayers.LinkTypeEthernet,
			HardwareLen:  6,
			HardwareOpts: 0,
			Xid:          rand.Uint32(), // Transaction ID should be random
			Flags:        0x8000,
		},
	}
}

func (d *DHCP) SetDstMac(macStr string) error {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return errors.New("invalid source MAC address")
	}
	d.layer.ClientHWAddr = mac
	return nil
}

func (d *DHCP) SetXid(xid uint32) {
	d.layer.Xid = xid
}

func (d *DHCP) SetDstIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return errors.New("invalid client IP")
	}
	d.layer.ClientIP = ip
	return nil
}

func (d *DHCP) SetSrcIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return errors.New("invalid your IP")
	}
	d.layer.YourClientIP = ip
	return nil
}

func (d *DHCP) SetRequest() {
	d.layer.Operation = golayers.DHCPOpRequest
}

func (d *DHCP) SetReply() {
	d.layer.Operation = golayers.DHCPOpReply
}

func (d *DHCP) SetMsgType(msgType string) {
	var msg golayers.DHCPMsgType
	switch msgType {
	case "discover":
		msg = golayers.DHCPMsgTypeDiscover
	case "offer":
		msg = golayers.DHCPMsgTypeOffer
	case "request":
		msg = golayers.DHCPMsgTypeRequest
	case "ack":
		msg = golayers.DHCPMsgTypeAck

	}
	d.layer.Options = append(d.layer.Options, golayers.DHCPOption{
		Type:   golayers.DHCPOptMessageType,
		Length: 1,
		Data:   []byte{byte(msg)},
	})
}
func (d *DHCP) AddOption(optType string, data interface{}) {
	var dhcpOpt golayers.DHCPOpt
	var byteData []byte

	switch optType {
	case "msg_type":
		dhcpOpt = golayers.DHCPOptMessageType
	case "server_id":
		dhcpOpt = golayers.DHCPOptServerID
	case "subnet_mask":
		dhcpOpt = golayers.DHCPOptSubnetMask
	case "router":
		dhcpOpt = golayers.DHCPOptRouter
	case "lease_time":
		dhcpOpt = golayers.DHCPOptLeaseTime
	case "renewal_time":
		dhcpOpt = golayers.DHCPOptT1
	case "rebind_time":
		dhcpOpt = golayers.DHCPOptT2
	case "end":
		dhcpOpt = golayers.DHCPOptEnd
	default:
		return
	}

	switch v := data.(type) {
	case string:
		byteData = []byte(v)
	case int:
		tmpBuffer := make([]byte, 4) // Assuming a 32-bit integer
		binary.BigEndian.PutUint32(tmpBuffer, uint32(v))
		byteData = tmpBuffer
	case []byte:
		byteData = v
	default:
		return // or maybe log an error
	}

	d.layer.Options = append(d.layer.Options, golayers.DHCPOption{
		Type:   dhcpOpt,
		Length: uint8(len(byteData)),
		Data:   byteData,
	})
}
func (d *DHCP) SetType(linkType golayers.LinkType) {
	d.layer.HardwareType = linkType
}

func (d *DHCP) Layer() *golayers.DHCPv4 {
	return d.layer
}
