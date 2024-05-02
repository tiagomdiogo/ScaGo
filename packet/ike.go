package packet

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/ScaGo/protocols"
	"net"
)

// Structs
type IKEv1 struct {
	layer *protocols.IKEv1
}

type IKEPayloadHeader struct {
	layer *protocols.IKEPayloadHeader
}

type IKESAPayload struct {
	layer *protocols.IKESAPayload
}

type IKEProposal struct {
	layer *protocols.IKEProposal
}

type IKETransform struct {
	layer *protocols.IKETransform
}

type IKETransformAttr struct {
	layer *protocols.IKETransformAttr
}

type IKEKEPayload struct {
	layer *protocols.IKEKEPayload
}

type IKENoncePayload struct {
	layer *protocols.IKENoncePayload
}

type IKEIDPayload struct {
	layer *protocols.IKEIDPayload
}

// Constructors
func IKELayer() *IKEv1 {
	layers.RegisterUDPPortLayerType(500, protocols.LayerTypeIKEv1)
	return &IKEv1{
		layer: &protocols.IKEv1{
			Length: 28,
		},
	}
}

func IKEPayloadHeaderLayer() *IKEPayloadHeader {
	return &IKEPayloadHeader{
		layer: &protocols.IKEPayloadHeader{
			Length: 4,
		},
	}
}

func IKESALayer() *IKESAPayload {
	return &IKESAPayload{
		layer: &protocols.IKESAPayload{},
	}
}

func IKEProposalLayer() *IKEProposal {
	return &IKEProposal{
		layer: &protocols.IKEProposal{},
	}
}

func IKETransformLayer() *IKETransform {
	return &IKETransform{
		layer: &protocols.IKETransform{},
	}
}

func IKETransformAttrLayer() *IKETransformAttr {
	return &IKETransformAttr{
		layer: &protocols.IKETransformAttr{},
	}
}

func IKEKELayer() *IKEKEPayload {
	return &IKEKEPayload{
		layer: &protocols.IKEKEPayload{},
	}
}

func IKENonceLayer() *IKENoncePayload {
	return &IKENoncePayload{
		layer: &protocols.IKENoncePayload{},
	}
}

func IKEIDLayer() *IKEIDPayload {
	return &IKEIDPayload{
		layer: &protocols.IKEIDPayload{},
	}
}

// Generic functions
func SetIKENextPayload(nextPayload *protocols.IKEPayloadTypes, payload byte) error {
	if nxtPayload, err := protocols.IKEPayloadTypeMap[payload]; err {
		*nextPayload = nxtPayload
		return nil
	}
	return fmt.Errorf("Invalid Next Payload Value.")
}

func SetIKEFlags(payloadFlags *byte, flag byte) {
	*payloadFlags = flag
}

func SetIKEHeader(payloadHeader *protocols.IKEPayloadHeader, header *IKEPayloadHeader, length uint16) {
	payloadHeader.NextPayload = header.layer.NextPayload
	payloadHeader.Flags = header.layer.Flags
	payloadHeader.Length += length + header.layer.Length
}

func SetIKEPayload(nextpayload *protocols.IKEPayloadTypes, payload *interface{}, load interface{}) error {
	switch *nextpayload {
	case protocols.IKEPayloadSA:
		if l, err := load.(*IKESAPayload); err {
			newload := protocols.IKESAPayload{
				Header:    l.layer.Header,
				DOI:       l.layer.DOI,
				Situation: l.layer.Situation,
				Proposals: l.layer.Proposals,
				Payload:   l.layer.Payload,
			}
			*payload = newload
			return nil
		}
	case protocols.IKEPayloadKE:
		if l, err := load.(*IKEKEPayload); err {
			newload := protocols.IKEKEPayload{
				Header:  l.layer.Header,
				KE:      l.layer.KE,
				Payload: l.layer.Payload,
			}
			*payload = newload
			return nil
		}
	case protocols.IKEPayloadNonce:
		if l, err := load.(*IKENoncePayload); err {
			newload := protocols.IKENoncePayload{
				Header:  l.layer.Header,
				Nonce:   l.layer.Nonce,
				Payload: l.layer.Payload,
			}
			*payload = newload
			return nil
		}
	case protocols.IKEPayloadID:
		if l, err := load.(*IKEIDPayload); err {
			newload := protocols.IKEIDPayload{
				Header:     l.layer.Header,
				IDType:     l.layer.IDType,
				ProtocolID: l.layer.ProtocolID,
				Port:       0,
				Data:       l.layer.Data,
				Payload:    l.layer.Payload,
			}
			*payload = newload
			return nil
		}
	}
	return fmt.Errorf("Payload type does not match the type determined by NextPayload ")
}

func calculateIKEPayloadLengthRecursive(payload interface{}) uint32 {
	switch p := payload.(type) {
	case protocols.IKESAPayload:
		return uint32(p.Header.Length) + calculateIKEPayloadLengthRecursive(p.Payload)
	case protocols.IKEKEPayload:
		return uint32(p.Header.Length) + calculateIKEPayloadLengthRecursive(p.Payload)
	case protocols.IKENoncePayload:
		return uint32(p.Header.Length) + calculateIKEPayloadLengthRecursive(p.Payload)
	case protocols.IKEIDPayload:
		return uint32(p.Header.Length) + calculateIKEPayloadLengthRecursive(p.Payload)
	default:
		// Handle unknown payload type
		return 0
	}
}

// IKE Struct Functions
func (i *IKEv1) SetInitSPI(spi uint64) {
	binary.BigEndian.PutUint64(i.layer.InitSPI[:], spi)

}

func (i *IKEv1) SetRespSPI(spi uint64) {
	binary.BigEndian.PutUint64(i.layer.RespSPI[:], spi)
}

func (i *IKEv1) SetNextPayload(payload byte) error {
	return SetIKENextPayload(&i.layer.NextPayload, payload)
}

func (i *IKEv1) SetVersion(version byte) {
	i.layer.Version = version
}

func (i *IKEv1) SetExchType(payload byte) error {
	if exchType, err := protocols.IKEExchangeTypeMap[payload]; err {
		i.layer.ExchType = exchType
		return nil
	}
	return fmt.Errorf("Invalid Exchange Type Value.")
}

func (i *IKEv1) SetFlags(flag byte) {
	SetIKEFlags(&i.layer.Flags, flag)
}

func (i *IKEv1) SetID(id uint32) {
	i.layer.ID = id
}

func (i *IKEv1) SetLength(length uint32) {
	i.layer.Length = length
}

func (i *IKEv1) SetPayload(payload interface{}) error {
	return SetIKEPayload(&i.layer.NextPayload, &i.layer.Payload, payload)
}

func (i *IKEv1) CalculateLength() {
	i.layer.Length += calculateIKEPayloadLengthRecursive(i.layer.Payload)
}
func (i *IKEv1) Decode(data []byte, df gopacket.DecodeFeedback) {
	i.layer.DecodeFromBytes(data, df)
}

// IKEPayload Functions
func (i *IKEPayloadHeader) SetNextPayload(payload byte) error {
	return SetIKENextPayload(&i.layer.NextPayload, payload)
}

func (i *IKEPayloadHeader) SetFlags(flag byte) {
	SetIKEFlags(&i.layer.Flags, flag)
}

func (i *IKEPayloadHeader) SetLength(length uint16) {
	i.layer.Length = length
}

// IKESAPayload Functions
func (i *IKESAPayload) SetHeader(header *IKEPayloadHeader) {
	SetIKEHeader(&i.layer.Header, header, 8)
}

func (i *IKESAPayload) AddProposal(proposals ...*IKEProposal) {
	for _, proposal := range proposals {
		prop := protocols.IKEProposal{
			Header:     proposal.layer.Header,
			ProposalNb: proposal.layer.ProposalNb,
			ProtocolID: proposal.layer.ProtocolID,
			SPISize:    proposal.layer.SPISize,
			TransNb:    proposal.layer.TransNb,
			Transforms: proposal.layer.Transforms,
		}
		i.layer.Proposals = append(i.layer.Proposals, prop)
		i.layer.Header.Length += proposal.layer.Header.Length
	}
}

func (i *IKESAPayload) SetPayload(payload interface{}) error {
	return SetIKEPayload(&i.layer.Header.NextPayload, &i.layer.Payload, payload)
}

func (i *IKESAPayload) SetDOI(doi byte) error {
	if d, err := protocols.IKEDOITypesMap[doi]; err {
		i.layer.DOI = d
		return nil
	}
	return fmt.Errorf("Invalid DOI Value.")
}

func (i *IKESAPayload) SetSituation(situation byte) error {
	if s, err := protocols.IKESituationTypesMap[situation]; err {
		i.layer.Situation = s
		return nil
	}
	return fmt.Errorf("Invalid DOI Value.")
}

// IKEProposal Functions
func (i *IKEProposal) SetHeader(header *IKEPayloadHeader) {
	SetIKEHeader(&i.layer.Header, header, 4)
}

func (i *IKEProposal) SetProposalNb(number byte) {
	i.layer.ProposalNb = number
}

func (i *IKEProposal) SetProtocolID(id byte) error {
	if protocol, err := protocols.IKEProtocolTypesMap[id]; err {
		i.layer.ProtocolID = protocol
		return nil
	}
	return fmt.Errorf("Invalid Protocol ID Value.")
}

func (i *IKEProposal) SetSPISize(size byte) {
	i.layer.SPISize = size
}

func (i *IKEProposal) AddTransform(transforms ...*IKETransform) {
	for _, transform := range transforms {
		trans := protocols.IKETransform{
			Header:      transform.layer.Header,
			TransNb:     transform.layer.TransNb,
			Flag:        transform.layer.Flag,
			TransformId: transform.layer.TransformId,
			Attributes:  transform.layer.Attributes,
		}
		trans.TransNb = byte(len(i.layer.Transforms) + 1)
		i.layer.Transforms = append(i.layer.Transforms, trans)
		i.layer.TransNb += 1
		i.layer.Header.Length += transform.layer.Header.Length
	}
}

// IKETransform Functions
func (i *IKETransform) SetHeader(header *IKEPayloadHeader) {
	SetIKEHeader(&i.layer.Header, header, 4)

}

func (i *IKETransform) SetTransNb(number byte) {
	i.layer.TransNb = number
}

func (i *IKETransform) SetTransformID(transform byte) error {
	if trans, err := protocols.IKETransformIDMap[transform]; err {
		i.layer.TransformId = trans
		return nil
	}
	return fmt.Errorf("Invalid Transform ID Value.")
}

func (i *IKETransform) SetFlags(flags [2]byte) {
	i.layer.Flag = flags
}

func (i *IKETransform) AddAttr(attrs ...*IKETransformAttr) {
	for _, attr := range attrs {
		at := protocols.IKETransformAttr{
			Type:   attr.layer.Type,
			Length: attr.layer.Length,
			Value:  attr.layer.Value,
		}
		i.layer.Attributes = append(i.layer.Attributes, at)
		i.layer.Header.Length += uint16(2 + len(at.Type) + len(at.Value))
	}
}

// IKETransformAttr Functions
func (i *IKETransformAttr) SetType(format string, value byte) error {
	var temp byte
	var finalvalue uint16
	if t, err := protocols.IKETransformTypesMap[value]; err {
		temp = byte(t)
	} else {
		return fmt.Errorf("Transform Attribute Type Value not valid!")
	}
	if format == "TV" {
		finalvalue = uint16(temp) | 0x8000
	} else if format == "TLV" {
		finalvalue = uint16(temp)
	} else {
		return fmt.Errorf("Transform Attribute Type format not valid!")
	}

	binary.BigEndian.PutUint16(i.layer.Type[:], finalvalue)
	return nil
}

func (i *IKETransformAttr) SetLength(value uint16) error {
	if i.layer.Type[0] == 0 {
		i.layer.Length = value
		return nil
	} else {
		switch i.layer.Type[1] {
		case 1:
			if t, err := protocols.IKETransformType1Map[value]; err {
				i.layer.Length = uint16(t)
				return nil
			}
		case 2:
			if t, err := protocols.IKETransformType2Map[value]; err {
				i.layer.Length = uint16(t)
				return nil
			}
		case 3:
			if t, err := protocols.IKETransformType3Map[value]; err {
				i.layer.Length = uint16(t)
				return nil
			}
		case 4:
			if t, err := protocols.IKETransformType4Map[value]; err {
				i.layer.Length = uint16(t)
				return nil
			}
		case 5:
			if t, err := protocols.IKETransformType5Map[value]; err {
				i.layer.Length = uint16(t)
				return nil
			}
		case 11:
			if t, err := protocols.IKETransformType11Map[value]; err {
				i.layer.Length = uint16(t)
				return nil
			}
		default:
			i.layer.Length = value
			return nil
		}
	}
	return fmt.Errorf("Transform Attribute Length not valid!")
}

func (i *IKETransformAttr) SetValue(value uint32) error {
	if i.layer.Type[0] == 0 {
		i.layer.Value = make([]byte, i.layer.Length)
		binary.BigEndian.PutUint32(i.layer.Value[:i.layer.Length], value)
		return nil
	} else {
		return fmt.Errorf("Transform Attribute Type TV does not have Value field")
	}
}

// IKEKEPayload Functions
func (i *IKEKEPayload) SetHeader(header *IKEPayloadHeader) {
	SetIKEHeader(&i.layer.Header, header, 0)
}

func (i *IKEKEPayload) SetKE(ke []byte) {
	i.layer.KE = ke
	i.layer.Header.Length += uint16(len(ke))
}
func (i *IKEKEPayload) SetPayload(payload interface{}) error {
	return SetIKEPayload(&i.layer.Header.NextPayload, &i.layer.Payload, payload)
}

// IKENoncePayload Functions
func (i *IKENoncePayload) SetHeader(header *IKEPayloadHeader) {
	SetIKEHeader(&i.layer.Header, header, 0)
}

func (i *IKENoncePayload) SetNonce(nonce []byte) {
	i.layer.Nonce = nonce
	i.layer.Header.Length += uint16(len(nonce))
}

func (i *IKENoncePayload) SetPayload(payload interface{}) error {
	return SetIKEPayload(&i.layer.Header.NextPayload, &i.layer.Payload, payload)
}

// IKEIDPayload Functions
func (i *IKEIDPayload) SetHeader(header *IKEPayloadHeader) {
	SetIKEHeader(&i.layer.Header, header, 4)
}

func (i *IKEIDPayload) SetData(data string) {
	switch i.layer.IDType {
	case protocols.ID_IPV4_ADDR:
		ip := net.ParseIP(data)
		i.layer.Data = ip.To4()
		i.layer.Header.Length += 4
		return
	default:
		return
	}
}

func (i *IKEIDPayload) SetProtocolID(id byte) error {
	if protocol, err := protocols.IKEProtocolTypesMap[id]; err {
		i.layer.ProtocolID = protocol
		return nil
	}
	return fmt.Errorf("Invalid Protocol ID Value.")
}

func (i *IKEIDPayload) SetIDType(id byte) error {
	if idt, err := protocols.IKEIDTypesMap[id]; err {
		i.layer.IDType = idt
		return nil
	}
	return fmt.Errorf("Invalid ID Type Value.")
}

func (i *IKEIDPayload) SetPayload(payload interface{}) error {
	return SetIKEPayload(&i.layer.Header.NextPayload, &i.layer.Payload, payload)
}

// toString functions

func (i *IKEv1) String() string {
	return fmt.Sprintf("InitSPI: %v\nRespSPI: %v\nNextPayload: %v\nVersion: %v\nExchType: %v\nFlags: %v\nID: %v\nLength: %v\n%vPayload:\n\t%v",
		i.layer.InitSPI, i.layer.RespSPI, i.layer.NextPayload, i.layer.Version, i.layer.ExchType, i.layer.Flags, i.layer.ID, i.layer.Length, i.layer.NextPayload, i.layer.Payload)
}

func (i *IKEv1) Layer() *protocols.IKEv1 { return i.layer }
