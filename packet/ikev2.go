package packet

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/ScaGo/protocols"
)

// Structs
type IKEv2 struct {
	layer *protocols.IKEv2
}

type IKEv2PayloadHeader struct {
	layer *protocols.IKEv2PayloadHeader
}

type IKEv2SAPayload struct {
	layer *protocols.IKEv2SAPayload
}

type IKEv2Proposal struct {
	layer *protocols.IKEv2Proposal
}

type IKEv2Transform struct {
	layer *protocols.IKEv2Transform
}

type IKEv2KEPayload struct {
	layer *protocols.IKEv2KEPayload
}

type IKEv2NoncePayload struct {
	layer *protocols.IKEv2NoncePayload
}

// Constructors
func IKEv2Layer() *IKEv2 {
	layers.RegisterUDPPortLayerType(500, protocols.LayerTypeIKEv2)
	return &IKEv2{
		layer: &protocols.IKEv2{
			Length: 28,
		},
	}
}

func IKEv2PayloadHeaderLayer() *IKEv2PayloadHeader {
	return &IKEv2PayloadHeader{
		layer: &protocols.IKEv2PayloadHeader{
			Length: 4,
		},
	}
}

func IKEv2SALayer() *IKEv2SAPayload {
	return &IKEv2SAPayload{
		layer: &protocols.IKEv2SAPayload{},
	}
}

func IKEv2ProposalLayer() *IKEv2Proposal {
	return &IKEv2Proposal{
		layer: &protocols.IKEv2Proposal{},
	}
}

func IKEv2TransformLayer() *IKEv2Transform {
	return &IKEv2Transform{
		layer: &protocols.IKEv2Transform{},
	}
}

func IKEv2KELayer() *IKEv2KEPayload {
	return &IKEv2KEPayload{
		layer: &protocols.IKEv2KEPayload{},
	}
}

func IKEv2NonceLayer() *IKEv2NoncePayload {
	return &IKEv2NoncePayload{
		layer: &protocols.IKEv2NoncePayload{},
	}
}

// Generic functions
func SetNextPayload(nextPayload *protocols.IKEv2PayloadTypes, payload byte) error {
	if nxtPayload, err := protocols.IKEv2PayloadTypeMap[payload]; err {
		*nextPayload = nxtPayload
		return nil
	}
	return fmt.Errorf("Invalid Next Payload Value.")
}

func SetFlags(payloadFlags *byte, flag byte) {
	*payloadFlags = flag
}

func SetHeader(payloadHeader *protocols.IKEv2PayloadHeader, header *IKEv2PayloadHeader, length uint16) {
	payloadHeader.NextPayload = header.layer.NextPayload
	payloadHeader.Flags = header.layer.Flags
	payloadHeader.Length += length + header.layer.Length
}

func SetPayload(nextpayload *protocols.IKEv2PayloadTypes, payload *interface{}, load interface{}) error {
	switch *nextpayload {
	case protocols.IKEv2PayloadSA:
		if l, err := load.(*IKEv2SAPayload); err {
			newload := protocols.IKEv2SAPayload{
				Header:    l.layer.Header,
				Proposals: l.layer.Proposals,
				Payload:   l.layer.Payload,
			}
			*payload = newload
			return nil
		}
	case protocols.IKEv2PayloadKE:
		if l, err := load.(*IKEv2KEPayload); err {
			newload := protocols.IKEv2KEPayload{
				Header:  l.layer.Header,
				DHGroup: l.layer.DHGroup,
				Flag:    l.layer.Flag,
				KE:      l.layer.KE,
				Payload: l.layer.Payload,
			}
			*payload = newload
			return nil
		}
	case protocols.IKEv2PayloadNonce:
		if l, err := load.(*IKEv2NoncePayload); err {
			newload := protocols.IKEv2NoncePayload{
				Header:  l.layer.Header,
				Nonce:   l.layer.Nonce,
				Payload: l.layer.Payload,
			}
			*payload = newload
			return nil
		}
	}
	return fmt.Errorf("Payload type does not match the type determined by NextPayload ")
}

func calculatePayloadLengthRecursive(payload interface{}) uint32 {
	switch p := payload.(type) {
	case protocols.IKEv2SAPayload:
		return uint32(p.Header.Length) + calculatePayloadLengthRecursive(p.Payload)
	case protocols.IKEv2KEPayload:
		return uint32(p.Header.Length) + calculatePayloadLengthRecursive(p.Payload)
	case protocols.IKEv2NoncePayload:
		return uint32(p.Header.Length) + calculatePayloadLengthRecursive(p.Payload)
	default:
		// Handle unknown payload type
		return 0
	}
}

// IKEv2 Struct Functions
func (i *IKEv2) SetInitSPI(spi uint64) {
	binary.BigEndian.PutUint64(i.layer.InitSPI[:], spi)
}

func (i *IKEv2) SetRespSPI(spi uint64) {
	binary.BigEndian.PutUint64(i.layer.RespSPI[:], spi)
}

func (i *IKEv2) SetNextPayload(payload byte) error {
	return SetNextPayload(&i.layer.NextPayload, payload)
}

func (i *IKEv2) SetVersion(version byte) {
	i.layer.Version = version
}

func (i *IKEv2) SetExchType(payload byte) error {
	if exchType, err := protocols.IKEv2ExchangeTypeMap[payload]; err {
		i.layer.ExchType = exchType
		return nil
	}
	return fmt.Errorf("Invalid Exchange Type Value.")
}

func (i *IKEv2) SetFlags(flag byte) {
	SetFlags(&i.layer.Flags, flag)
}

func (i *IKEv2) SetID(id uint32) {
	i.layer.ID = id
}

func (i *IKEv2) SetLength(length uint32) {
	i.layer.Length = length
}

func (i *IKEv2) SetPayload(payload interface{}) error {
	return SetPayload(&i.layer.NextPayload, &i.layer.Payload, payload)
}

func (i *IKEv2) CalculateLength() {
	i.layer.Length += calculatePayloadLengthRecursive(i.layer.Payload)
}

// IKEv2Payload Functions
func (i *IKEv2PayloadHeader) SetNextPayload(payload byte) error {
	return SetNextPayload(&i.layer.NextPayload, payload)
}

func (i *IKEv2PayloadHeader) SetFlags(flag byte) {
	SetFlags(&i.layer.Flags, flag)
}

func (i *IKEv2PayloadHeader) SetLength(length uint16) {
	i.layer.Length = length
}

// IKEv2SAPayload Functions
func (i *IKEv2SAPayload) SetHeader(header *IKEv2PayloadHeader) {
	SetHeader(&i.layer.Header, header, 0)
}

func (i *IKEv2SAPayload) AddProposal(proposals ...*IKEv2Proposal) {
	for _, proposal := range proposals {
		prop := protocols.IKEv2Proposal{
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

func (i *IKEv2SAPayload) SetPayload(payload interface{}) error {
	return SetPayload(&i.layer.Header.NextPayload, &i.layer.Payload, payload)
}

// IKEv2Proposal Functions
func (i *IKEv2Proposal) SetHeader(header *IKEv2PayloadHeader) {
	SetHeader(&i.layer.Header, header, 4)
}

func (i *IKEv2Proposal) SetProposalNb(number byte) {
	i.layer.ProposalNb = number
}

func (i *IKEv2Proposal) SetProtocolID(id byte) error {
	if protocol, err := protocols.IKEv2ProtocolTypesMap[id]; err {
		i.layer.ProtocolID = protocol
		return nil
	}
	return fmt.Errorf("Invalid Protocol ID Value.")
}

func (i *IKEv2Proposal) SetSPISize(size byte) {
	i.layer.SPISize = size
}

func (i *IKEv2Proposal) SetTransNb(number byte) {
	i.layer.TransNb = number
}

func (i *IKEv2Proposal) AddTransform(transforms ...*IKEv2Transform) {
	for _, transform := range transforms {
		trans := protocols.IKEv2Transform{
			Header:        transform.layer.Header,
			TransformType: transform.layer.TransformType,
			Flag:          transform.layer.Flag,
			TransformId:   transform.layer.TransformId,
			KeyLength:     transform.layer.KeyLength,
		}
		i.layer.Transforms = append(i.layer.Transforms, trans)
		i.layer.TransNb += 1
		i.layer.Header.Length += transform.layer.Header.Length
	}
}

// IKEv2Transform Functions
func (i *IKEv2Transform) SetHeader(header *IKEv2PayloadHeader) {
	SetHeader(&i.layer.Header, header, 4)

}

func (i *IKEv2Transform) SetTransformType(transform byte) error {
	if trans, err := protocols.IKEv2TransformTypesMap[transform]; err {
		i.layer.TransformType = trans
		return nil
	}
	return fmt.Errorf("Invalid Transform Type Value.")
}

func (i *IKEv2Transform) SetTransformID(transform uint16, length ...int) error {
	switch i.layer.TransformType {
	case protocols.ENCR:
		if trans, err := protocols.IKEv2TransformType1Map[transform]; err {
			i.layer.TransformId = uint16(trans)
			if transform == 12 || transform == 13 {
				i.layer.KeyLength = uint32(0x800E)<<16 | uint32(length[0])
				i.layer.Header.Length += 4
			}
			return nil
		}
	case protocols.PRF:
		if trans, err := protocols.IKEv2TransformType2Map[transform]; err {
			i.layer.TransformId = uint16(trans)
			return nil
		}
	case protocols.INTEG:
		if trans, err := protocols.IKEv2TransformType3Map[transform]; err {
			i.layer.TransformId = uint16(trans)
			return nil
		}
	case protocols.DH:
		if trans, err := protocols.IKEv2TransformType4Map[transform]; err {
			i.layer.TransformId = uint16(trans)
			return nil
		}
	case protocols.ESN:
		if trans, err := protocols.IKEv2TransformType5Map[transform]; err {
			i.layer.TransformId = uint16(trans)
			return nil
		}
	}
	return fmt.Errorf("Invalid Transform ID Value.")
}

// IKEv2KEPayload Functions
func (i *IKEv2KEPayload) SetHeader(header *IKEv2PayloadHeader) {
	SetHeader(&i.layer.Header, header, 4)
}

func (i *IKEv2KEPayload) SetDHGroup(group uint16) error {
	if gr, err := protocols.IKEv2TransformType4Map[group]; err {
		i.layer.DHGroup = uint16(gr)
		return nil
	}
	return fmt.Errorf("Invalid Transform Type Value.")
}

func (i *IKEv2KEPayload) SetKE(ke []byte) {
	i.layer.KE = ke
	i.layer.Header.Length += uint16(len(ke))
}
func (i *IKEv2KEPayload) SetPayload(payload interface{}) error {
	return SetPayload(&i.layer.Header.NextPayload, &i.layer.Payload, payload)
}

// IKEv2NoncePayload Functions
func (i *IKEv2NoncePayload) SetHeader(header *IKEv2PayloadHeader) {
	SetHeader(&i.layer.Header, header, 0)
}

func (i *IKEv2NoncePayload) SetNonce(nonce []byte) {
	i.layer.Nonce = nonce
	i.layer.Header.Length += uint16(len(nonce))
}

func (i *IKEv2NoncePayload) SetPayload(payload interface{}) error {
	return SetPayload(&i.layer.Header.NextPayload, &i.layer.Payload, payload)
}

// toString functions

func (i *IKEv2) String() string {
	return fmt.Sprintf("InitSPI: %v\nRespSPI: %v\nNextPayload: %v\nVersion: %v\nExchType: %v\nFlags: %v\nID: %v\nLength: %v\n%vPayload:\n\t%v",
		i.layer.InitSPI, i.layer.RespSPI, i.layer.NextPayload, i.layer.Version, i.layer.ExchType, i.layer.Flags, i.layer.ID, i.layer.Length, i.layer.NextPayload, i.layer.Payload)
}

func (i *IKEv2) Layer() *protocols.IKEv2 { return i.layer }
