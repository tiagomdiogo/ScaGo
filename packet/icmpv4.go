package packet

import (
	"errors"
	"strconv"

	golayers "github.com/google/gopacket/layers"
)

type ICMPv4 struct {
	layer *golayers.ICMPv4
}

func ICMPv4Layer() *ICMPv4 {
	return &ICMPv4{
		layer: &golayers.ICMPv4{},
	}
}

func (icmp *ICMPv4) SetType(typeStr string) error {
	typ, err := strconv.Atoi(typeStr)
	if err != nil || typ < 0 || typ > 255 {
		return errors.New("invalid ICMPv4 type")
	}
	icmp.layer.TypeCode = golayers.ICMPv4TypeCode(uint16(typ)<<8 | uint16(icmp.layer.TypeCode))
	return nil
}

func (icmp *ICMPv4) SetCode(codeStr string) error {
	code, err := strconv.Atoi(codeStr)
	if err != nil || code < 0 || code > 255 {
		return errors.New("invalid ICMPv4 code")
	}
	icmp.layer.TypeCode = golayers.ICMPv4TypeCode(uint16(icmp.layer.TypeCode)&0xFF00 | uint16(code))
	return nil
}

func (icmp *ICMPv4) Layer() *golayers.ICMPv4 {
	return icmp.layer
}
