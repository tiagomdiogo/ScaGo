package protocols

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"math/big"
	"strings"
)

var LayerTypeSSH = gopacket.RegisterLayerType(8003, gopacket.LayerTypeMetadata{Name: "SSH", Decoder: gopacket.DecodeFunc(decodeSSH)})

type SSHMessageNumbers byte

const (
	SSH_MSG_DISCONNECT                SSHMessageNumbers = 1
	SSH_MSG_IGNORE                    SSHMessageNumbers = 2
	SSH_MSG_UNIMPLEMENTED             SSHMessageNumbers = 3
	SSH_MSG_DEBUG                     SSHMessageNumbers = 4
	SSH_MSG_SERVICE_REQUEST           SSHMessageNumbers = 5
	SSH_MSG_SERVICE_ACCEPT            SSHMessageNumbers = 6
	SSH_MSG_KEXINIT                   SSHMessageNumbers = 20
	SSH_MSG_NEWKEYS                   SSHMessageNumbers = 21
	SSH_MSG_KEYDH_INIT                SSHMessageNumbers = 30
	SSH_MSG_KEYDH_REPLY               SSHMessageNumbers = 31
	SSH_MSG_USERAUTH_REQUEST          SSHMessageNumbers = 50
	SSH_MSG_USERAUTH_FAILURE          SSHMessageNumbers = 51
	SSH_MSG_USERAUTH_SUCCESS          SSHMessageNumbers = 52
	SSH_MSG_USERAUTH_BANNER           SSHMessageNumbers = 53
	SSH_MSG_GLOBAL_REQUEST            SSHMessageNumbers = 80
	SSH_MSG_REQUEST_SUCCESS           SSHMessageNumbers = 81
	SSH_MSG_REQUEST_FAILURE           SSHMessageNumbers = 82
	SSH_MSG_CHANNEL_OPEN              SSHMessageNumbers = 90
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION SSHMessageNumbers = 91
	SSH_MSG_CHANNEL_OPEN_FAILURE      SSHMessageNumbers = 92
	SSH_MSG_CHANNEL_WINDOW_ADJUST     SSHMessageNumbers = 93
	SSH_MSG_CHANNEL_DATA              SSHMessageNumbers = 94
	SSH_MSG_CHANNEL_EXTENDED_DATA     SSHMessageNumbers = 95
	SSH_MSG_CHANNEL_EOF               SSHMessageNumbers = 96
	SSH_MSG_CHANNEL_CLOSE             SSHMessageNumbers = 97
	SSH_MSG_CHANNEL_REQUEST           SSHMessageNumbers = 98
	SSH_MSG_CHANNEL_SUCCESS           SSHMessageNumbers = 99
	SSH_MSG_CHANNEL_FAILURE           SSHMessageNumbers = 100
)

func (s SSHMessageNumbers) String() string {
	switch s {
	case SSH_MSG_DISCONNECT:
		return "SSH_MSG_DISCONNECT"
	case SSH_MSG_IGNORE:
		return "SSH_MSG_IGNORE"
	case SSH_MSG_UNIMPLEMENTED:
		return "SSH_MSG_UNIMPLEMENTED"
	case SSH_MSG_DEBUG:
		return "SSH_MSG_DEBUG"
	case SSH_MSG_SERVICE_REQUEST:
		return "SSH_MSG_SERVICE_REQUEST"
	case SSH_MSG_SERVICE_ACCEPT:
		return "SSH_MSG_SERVICE_ACCEPT"
	case SSH_MSG_KEXINIT:
		return "SSH_MSG_KEXINIT"
	case SSH_MSG_NEWKEYS:
		return "SSH_MSG_NEWKEYS"
	case SSH_MSG_USERAUTH_REQUEST:
		return "SSH_MSG_USERAUTH_REQUEST"
	case SSH_MSG_USERAUTH_FAILURE:
		return "SSH_MSG_USERAUTH_FAILURE"
	case SSH_MSG_USERAUTH_SUCCESS:
		return "SSH_MSG_USERAUTH_SUCCESS"
	case SSH_MSG_USERAUTH_BANNER:
		return "SSH_MSG_USERAUTH_BANNER"
	case SSH_MSG_GLOBAL_REQUEST:
		return "SSH_MSG_GLOBAL_REQUEST"
	case SSH_MSG_REQUEST_SUCCESS:
		return "SSH_MSG_REQUEST_SUCCESS"
	case SSH_MSG_REQUEST_FAILURE:
		return "SSH_MSG_REQUEST_FAILURE"
	case SSH_MSG_KEYDH_INIT:
		return "SSH_MSG_KEYDH_INIT"
	case SSH_MSG_KEYDH_REPLY:
		return "SSH_MSG_KEYDH_REPLY"
	case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
		return "SSH_MSG_CHANNEL_OPEN_CONFIRMATION"
	case SSH_MSG_CHANNEL_OPEN_FAILURE:
		return "SSH_MSG_CHANNEL_OPEN_FAILURE"
	case SSH_MSG_CHANNEL_CLOSE:
		return "SSH_MSG_CHANNEL_CLOSE"
	case SSH_MSG_CHANNEL_DATA:
		return "SSH_MSG_CHANNEL_DATA"
	case SSH_MSG_CHANNEL_EOF:
		return "SSH_MSG_CHANNEL_EOF"
	case SSH_MSG_CHANNEL_WINDOW_ADJUST:
		return "SSH_MSG_CHANNEL_WINDOW_ADJUST"
	case SSH_MSG_CHANNEL_SUCCESS:
		return "SSH_MSG_CHANNEL_SUCCESS"
	case SSH_MSG_CHANNEL_REQUEST:
		return "SSH_MSG_CHANNEL_REQUEST"
	default:
		return "SSH_MSG_UNKOWN"
	}
}

type SSH struct {
	layers.BaseLayer
	SSHRecords []SSHPacket
}

type SSHPacket struct {
	PacketLength  uint32
	PaddingLength uint8
	Payload       interface{}
	Padding       []byte
	MAC           []byte
}

type SSHEofMsg struct {
	SSHType       SSHMessageNumbers
	ChannelNumber uint32
}
type SSHKexInitMsg struct {
	SSHType                             SSHMessageNumbers
	Cookie                              []byte
	KexAlgorithms                       []string
	ServerHostKeyAlgorithms             []string
	EncryptionAlgorithmsClientToServer  []string
	EncryptionAlgorithmsServerToClient  []string
	MacAlgorithmsClientToServer         []string
	MacAlgorithmsServerToClient         []string
	CompressionAlgorithmsClientToServer []string
	CompressionAlgorithmsServerToClient []string
	LanguagesClientToServer             []string
	LanguagesServerToClient             []string
	FirstKexPacketFollows               bool
	Reserved                            uint32
}

type SSHGlobalRequest struct {
	SSHType     SSHMessageNumbers
	RequestName string
	WantReply   bool
	Data        []byte
}

type SSHKexDHInit struct {
	SSHType SSHMessageNumbers
	Pub     []byte
}

type SSHKexDHReply struct {
	SSHType       SSHMessageNumbers
	ServerHostKey []byte
	F             *big.Int
	Signature     []byte
}

type SSHNewKeys struct {
	SSHType SSHMessageNumbers
}

type SSHChannelOpen struct {
	SSHType           SSHMessageNumbers
	ChannelType       string
	SenderChannel     uint32
	InitialWindowSize uint32
	MaximumPacketSize uint32
	SpecificData      []byte
}

type SSHChannelOpenFailure struct {
	SSHType          SSHMessageNumbers
	RecipientChannel uint32
	ReasonCode       uint32
	Description      string
	LanguageTag      string
}

type SSHChannelOpenConfirmation struct {
	SSHType           SSHMessageNumbers
	RecipientChannel  uint32
	SenderChannel     uint32
	InitialWindowSize uint32
	MaximumPacketSize uint32
}

type SSHChannelClose struct {
	SSHType          SSHMessageNumbers
	RecipientChannel uint32
}

type SSHChannelData struct {
	SSHType          SSHMessageNumbers
	RecipientChannel uint32
	Data             []byte
}

type SSHChannelRequest struct {
	SSHType          SSHMessageNumbers
	RecipientChannel uint32
	RequestType      string
	WantReply        bool
	Command          []byte
}

type SSHChannelSuccess struct {
	SSHType          SSHMessageNumbers
	RecipientChannel uint32
}

type SSHUserAuthRequest struct {
	SSHType     SSHMessageNumbers
	UserName    string
	ServiceName string
	MethodName  string
	ChangeRe    bool
	Password    string
}
type SSHUserAuthSuccess struct {
	SSHType SSHMessageNumbers
}

type SSHUserAuthFailure struct {
	SSHType                        SSHMessageNumbers
	AuthenticationsThatCanContinue []string
	PartialSuccess                 bool
}

type SSHServiceRequest struct {
	SSHType     SSHMessageNumbers
	ServiceName string
}

type SSHServiceAccept struct {
	SSHType     SSHMessageNumbers
	ServiceName string
}

type SSHChannelWindowAdjust struct {
	SSHType          SSHMessageNumbers
	RecipientChannel uint32
	BytesToAdd       uint32
}

type SSHVersionMsg struct {
	VersionString string
}

func (t *SSH) LayerType() gopacket.LayerType { return LayerTypeSSH }

func decodeSSH(data []byte, p gopacket.PacketBuilder) error {
	s := &SSH{}
	err := s.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(s)
	p.SetApplicationLayer(s)
	return nil
}

func (s *SSH) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	s.BaseLayer.Contents = data
	s.BaseLayer.Payload = nil

	s.SSHRecords = s.SSHRecords[:0]

	return s.decodeSSHRecords(data, df)
}

func (s *SSH) decodeSSHRecords(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 5 {
		df.SetTruncated()
		return errors.New("SSH record too short")
	}

	// since there are no further layers, the baselayer's content is
	// pointing to this layer
	s.BaseLayer = layers.BaseLayer{Contents: data[:len(data)]}

	var sshType SSHMessageNumbers
	packetLength := binary.BigEndian.Uint32(data[0:4])
	paddingLength := data[4]
	sshType = SSHMessageNumbers(data[5])
	if sshType.String() == "SSH_MSG_UNKOWN" {
		return errors.New("Unknown SSH record type")
	}

	var r SSHPacket
	e := r.decodeFromBytes(sshType, data[:packetLength+4], packetLength+4, paddingLength, df)
	if e != nil {
		return e
	}
	s.SSHRecords = append(s.SSHRecords, r)

	if uint32(len(data)) == packetLength+4 {
		return nil
	}
	return s.decodeSSHRecords(data[packetLength+4:len(data)], df)
}

// CanDecode implements gopacket.DecodingLayer.
func (s *SSH) CanDecode() gopacket.LayerClass {
	return LayerTypeSSH
}

// NextLayerType implements gopacket.DecodingLayer.
func (s *SSH) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// Payload returns nil, since SSH encrypted payload is inside SSHRecord
func (s *SSH) Payload() []byte {
	return nil
}

func (s *SSHPacket) decodeFromBytes(sshType SSHMessageNumbers, data []byte, packetLength uint32, paddingLength byte, df gopacket.DecodeFeedback) error {
	s.PacketLength = packetLength
	s.PaddingLength = uint8(paddingLength)
	switch sshType {
	case SSH_MSG_KEXINIT:
		s.Payload = decodeKeyExchangeInit(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_KEYDH_INIT:
		s.Payload = decodeKeyDHInit(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_KEYDH_REPLY:
		s.Payload = decodeKeyDHReply(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_NEWKEYS:
		s.Payload = decodeNewkeys(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_CHANNEL_DATA:
		s.Payload = decodeChannelData(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_CHANNEL_OPEN:
		s.Payload = decodeChannelOpen(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_CHANNEL_REQUEST:
		s.Payload = decodeChannelRequest(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_CHANNEL_SUCCESS:
		s.Payload = decodeChannelSucess(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_USERAUTH_REQUEST:
		s.Payload = decodeUserAuthRequest(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_USERAUTH_SUCCESS:
		s.Payload = decodeUserAuthSuccess(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_USERAUTH_FAILURE:
		s.Payload = decodeUserAuthFailure(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
		s.Payload = decodeChannelOpenConfirmation(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_CHANNEL_OPEN_FAILURE:
		s.Payload = decodeChannelOpenFailure(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_CHANNEL_CLOSE:
		s.Payload = decodeChannelClose(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_SERVICE_REQUEST:
		s.Payload = decodeServiceRequest(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_SERVICE_ACCEPT:
		s.Payload = decodeServiceAccept(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_GLOBAL_REQUEST:
		s.Payload = decodeGlobalRequest(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_CHANNEL_EOF:
		s.Payload = decodeEOFMsg(data[6 : packetLength-uint32(paddingLength)])
	case SSH_MSG_CHANNEL_WINDOW_ADJUST:
		s.Payload = decodeWindowAdjust(data[6 : packetLength-uint32(paddingLength)])
	}
	return nil
}

func decodeKeyExchangeInit(data []byte) SSHKexInitMsg {
	k := SSHKexInitMsg{}
	k.SSHType = SSH_MSG_KEXINIT
	copy(k.Cookie[:], data[:16])
	off := 16

	k.KexAlgorithms, off = readNameList(data, off)
	k.ServerHostKeyAlgorithms, off = readNameList(data, off)
	k.EncryptionAlgorithmsClientToServer, off = readNameList(data, off)
	k.EncryptionAlgorithmsServerToClient, off = readNameList(data, off)
	k.MacAlgorithmsClientToServer, off = readNameList(data, off)
	k.MacAlgorithmsServerToClient, off = readNameList(data, off)
	k.CompressionAlgorithmsClientToServer, off = readNameList(data, off)
	k.CompressionAlgorithmsServerToClient, off = readNameList(data, off)
	k.LanguagesClientToServer, off = readNameList(data, off)
	k.LanguagesServerToClient, off = readNameList(data, off)

	firstKexPacketFollows := data[off]
	k.FirstKexPacketFollows = firstKexPacketFollows != 0
	off += 1

	k.Reserved = binary.BigEndian.Uint32(data[off:])
	return k
}

func decodeKeyDHInit(data []byte) SSHKexDHInit {
	k := SSHKexDHInit{}
	k.SSHType = SSH_MSG_KEYDH_INIT
	length := binary.BigEndian.Uint32(data[:])
	k.Pub = make([]byte, length)
	copy(k.Pub, data[4:4+length])
	return k
}

func decodeKeyDHReply(data []byte) SSHKexDHReply {
	k := SSHKexDHReply{}
	k.SSHType = SSH_MSG_KEYDH_REPLY
	var length uint32
	length = binary.BigEndian.Uint32(data[:4])
	off := 4
	k.ServerHostKey = make([]byte, length)
	copy(k.ServerHostKey, data[off:off+int(length)])
	off += int(length)
	length = binary.BigEndian.Uint32(data[off:])
	off += 4
	k.F = new(big.Int).SetBytes(data[off : off+int(length)])
	off += int(length)
	length = binary.BigEndian.Uint32(data[off:])
	off += 4
	k.Signature = make([]byte, length)
	copy(k.Signature, data[off:off+int(length)])
	return k
}

func decodeNewkeys(data []byte) SSHNewKeys {
	k := SSHNewKeys{}
	k.SSHType = SSH_MSG_NEWKEYS
	return k
}

func decodeChannelOpen(data []byte) SSHChannelOpen {
	msg := SSHChannelOpen{}
	msg.SSHType = SSH_MSG_CHANNEL_OPEN
	var length uint32
	length = binary.BigEndian.Uint32(data[:4])
	off := 4
	msg.ChannelType = string(data[off : off+int(length)])
	off += int(length)
	msg.SenderChannel = binary.BigEndian.Uint32(data[off:])
	off += 4
	msg.InitialWindowSize = binary.BigEndian.Uint32(data[off:])
	off += 4
	msg.MaximumPacketSize = binary.BigEndian.Uint32(data[off:])
	return msg
}

func decodeChannelData(data []byte) SSHChannelData {
	msg := SSHChannelData{}
	msg.SSHType = SSH_MSG_CHANNEL_DATA
	msg.RecipientChannel = binary.BigEndian.Uint32(data[:4])
	off := 4
	var length uint32
	length = binary.BigEndian.Uint32(data[off:])
	off += 4
	msg.Data = make([]byte, length)
	copy(msg.Data, data[off:off+int(length)])
	return msg
}

func decodeChannelSucess(data []byte) SSHChannelSuccess {
	msg := SSHChannelSuccess{}
	msg.SSHType = SSH_MSG_CHANNEL_SUCCESS
	msg.RecipientChannel = binary.BigEndian.Uint32(data[:4])
	return msg
}

func decodeChannelRequest(data []byte) SSHChannelRequest {
	msg := SSHChannelRequest{}
	msg.SSHType = SSH_MSG_CHANNEL_REQUEST
	msg.RecipientChannel = binary.BigEndian.Uint32(data[:4])
	off := 4
	var length uint32
	length = binary.BigEndian.Uint32(data[off:])
	off += 4
	msg.RequestType = string(data[off : off+int(length)])
	off += int(length)
	msg.WantReply = data[off] != 0
	off += 1
	length = binary.BigEndian.Uint32(data[off:])
	off += 4
	msg.Command = data[off : off+int(length)]
	return msg
}

func decodeUserAuthRequest(data []byte) SSHUserAuthRequest {
	msg := SSHUserAuthRequest{}
	msg.SSHType = SSH_MSG_USERAUTH_REQUEST
	var length uint32
	length = binary.BigEndian.Uint32(data[:4])
	off := 4
	msg.UserName = string(data[off : off+int(length)])
	off += int(length)
	length = binary.BigEndian.Uint32(data[off:])
	off += 4
	msg.ServiceName = string(data[off : off+int(length)])
	off += int(length)
	length = binary.BigEndian.Uint32(data[off:])
	off += 4
	msg.MethodName = string(data[off : off+int(length)])
	off += int(length)
	if msg.MethodName == "password" {
		length = binary.BigEndian.Uint32(data[off:])
		off += 4
		msg.Password = string(data[off : off+int(length)])
	}

	return msg
}

func decodeUserAuthFailure(data []byte) SSHUserAuthFailure {
	msg := SSHUserAuthFailure{}
	msg.SSHType = SSH_MSG_USERAUTH_FAILURE
	off := 0
	msg.AuthenticationsThatCanContinue, off = readNameList(data, off)
	if off >= len(data) {
		fmt.Errorf("invalid SSH_USERAUTH_FAILURE packet")
		return msg
	}
	msg.PartialSuccess = data[off] != 0
	return msg
}

func decodeUserAuthSuccess(data []byte) SSHUserAuthSuccess {
	msg := SSHUserAuthSuccess{}
	msg.SSHType = SSH_MSG_USERAUTH_SUCCESS
	return msg
}

func decodeChannelClose(data []byte) SSHChannelClose {
	msg := SSHChannelClose{}
	msg.SSHType = SSH_MSG_CHANNEL_CLOSE
	msg.RecipientChannel = binary.BigEndian.Uint32(data[:4])
	return msg
}

func decodeChannelOpenFailure(data []byte) SSHChannelOpenFailure {
	msg := SSHChannelOpenFailure{}
	msg.SSHType = SSH_MSG_CHANNEL_OPEN_FAILURE
	var length uint32
	msg.RecipientChannel = binary.BigEndian.Uint32(data[:4])
	off := 4
	msg.ReasonCode = binary.BigEndian.Uint32(data[off:])
	off += 4
	length = binary.BigEndian.Uint32(data[off:])
	off += 4
	msg.Description = string(data[off : off+int(length)])
	off += int(length)
	length = binary.BigEndian.Uint32(data[off:])
	off += 4
	msg.LanguageTag = string(data[off : off+int(length)])
	return msg
}

func decodeChannelOpenConfirmation(data []byte) SSHChannelOpenConfirmation {
	msg := SSHChannelOpenConfirmation{}
	msg.SSHType = SSH_MSG_CHANNEL_OPEN_CONFIRMATION
	msg.RecipientChannel = binary.BigEndian.Uint32(data[:4])
	off := 4
	msg.SenderChannel = binary.BigEndian.Uint32(data[off:])
	off += 4
	msg.InitialWindowSize = binary.BigEndian.Uint32(data[off:])
	off += 4
	msg.MaximumPacketSize = binary.BigEndian.Uint32(data[off:])
	return msg
}

func decodeServiceRequest(data []byte) SSHServiceRequest {
	msg := SSHServiceRequest{}
	msg.SSHType = SSH_MSG_SERVICE_REQUEST
	var length uint32
	length = binary.BigEndian.Uint32(data[:4])
	off := 4
	msg.ServiceName = string(data[off : off+int(length)])
	return msg
}

func decodeServiceAccept(data []byte) SSHServiceAccept {
	msg := SSHServiceAccept{}
	msg.SSHType = SSH_MSG_SERVICE_ACCEPT
	var length uint32
	length = binary.BigEndian.Uint32(data[:4])
	off := 4
	msg.ServiceName = string(data[off : off+int(length)])
	return msg
}

func decodeGlobalRequest(data []byte) SSHGlobalRequest {
	msg := SSHGlobalRequest{}
	msg.SSHType = SSH_MSG_GLOBAL_REQUEST
	var length uint32
	length = binary.BigEndian.Uint32(data[:4])
	off := 4
	msg.RequestName = string(data[off : off+int(length)])
	msg.WantReply = data[off+int(length)] != 0
	msg.Data = data[off+1+int(length):]
	return msg
}

func decodeEOFMsg(data []byte) SSHEofMsg {
	msg := SSHEofMsg{}
	msg.SSHType = SSH_MSG_CHANNEL_EOF
	msg.ChannelNumber = binary.BigEndian.Uint32(data[:])
	return msg
}

func decodeWindowAdjust(data []byte) SSHChannelWindowAdjust {
	msg := SSHChannelWindowAdjust{}
	msg.SSHType = SSH_MSG_CHANNEL_WINDOW_ADJUST
	msg.RecipientChannel = binary.BigEndian.Uint32(data[:])
	msg.BytesToAdd = binary.BigEndian.Uint32(data[4:])
	return msg
}

func (v *SSHVersionMsg) SerializeTo(data []byte) {
	copy(data[:], v.VersionString)
}

func (v *SSHVersionMsg) DecodeFromBytes(data []byte) {
	v.VersionString = string(data)
}

func (s *SSH) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	totalLength := 0
	for _, record := range s.SSHRecords {
		totalLength += 4 + int(record.PacketLength) // length field + record length
	}

	data, err := b.PrependBytes(totalLength)
	if err != nil {
		return err
	}
	off := 0
	for _, record := range s.SSHRecords {
		record.SerializeTo(data, off)
		off += int(record.PacketLength)
	}

	return nil
}

func (s *SSHPacket) SerializeTo(data []byte, off int) {
	binary.BigEndian.PutUint32(data[:4], s.PacketLength)
	data[off+4] = byte(s.PaddingLength)
	switch p := s.Payload.(type) {
	case SSHKexInitMsg:
		off = p.SerializeTo(data, off+5)
	case SSHKexDHInit:
		off = p.SerializeTo(data, off+5)
	case SSHKexDHReply:
		p.SerializeTo(data, off+5)
	case SSHNewKeys:
		off = p.SerializeTo(data, off+5)
	case SSHChannelData:
		p.SerializeTo(data, off+5)
	case SSHChannelOpen:
		off = p.SerializeTo(data, off+5)
	case SSHChannelRequest:
		off = p.SerializeTo(data, off+5)
	case SSHChannelSuccess:
		off = p.SerializeTo(data, off+5)
	case SSHUserAuthRequest:
		off = p.SerializeTo(data, off+5)
	case SSHChannelClose:
		p.SerializeTo(data, off+5)
	case SSHChannelOpenConfirmation:
		p.SerializeTo(data, off+5)
	case SSHChannelOpenFailure:
		p.SerializeTo(data, off+5)
	case SSHServiceAccept:
		p.SerializeTo(data, off+5)
	case SSHServiceRequest:
		off = p.SerializeTo(data, off+5)
	case SSHEofMsg:
		off = p.SerializeTo(data, off+5)
	}
	copy(data[off:], s.Padding)
	if s.MAC != nil {
		copy(data[off+int(s.PaddingLength):], s.MAC)
	}
}

func (k *SSHKexInitMsg) SerializeTo(data []byte, off int) int {
	data[off] = byte(k.SSHType)
	copy(data[off+1:], k.Cookie[:])
	off += 17
	off = writeNameList(data, off, k.KexAlgorithms)
	off = writeNameList(data, off, k.ServerHostKeyAlgorithms)
	off = writeNameList(data, off, k.EncryptionAlgorithmsClientToServer)
	off = writeNameList(data, off, k.EncryptionAlgorithmsServerToClient)
	off = writeNameList(data, off, k.MacAlgorithmsClientToServer)
	off = writeNameList(data, off, k.MacAlgorithmsServerToClient)
	off = writeNameList(data, off, k.CompressionAlgorithmsClientToServer)
	off = writeNameList(data, off, k.CompressionAlgorithmsServerToClient)
	off = writeNameList(data, off, k.LanguagesClientToServer)
	off = writeNameList(data, off, k.LanguagesServerToClient)
	if k.FirstKexPacketFollows {
		data[off] = 1
	} else {
		data[off] = 0
	}
	off += 1
	binary.BigEndian.PutUint32(data[off:], k.Reserved)
	return off + 4
}

func (k *SSHKexDHInit) SerializeTo(data []byte, off int) int {
	data[off] = byte(k.SSHType)
	binary.BigEndian.PutUint32(data[off+1:], uint32(len(k.Pub)))
	copy(data[off+5:off+5+len(k.Pub)], k.Pub)
	return off + 5 + len(k.Pub)
}

func (k *SSHKexDHReply) SerializeTo(data []byte, off int) {
	binary.BigEndian.PutUint32(data[off:], uint32(len(k.ServerHostKey)))
	off += 4
	copy(data[off:], k.ServerHostKey)
	off += len(k.ServerHostKey)
	fBytes := k.F.Bytes()
	binary.BigEndian.PutUint32(data[off:], uint32(len(fBytes)))
	off += 4
	copy(data[off:], fBytes)
	off += len(fBytes)
	binary.BigEndian.PutUint32(data[off:], uint32(len(k.Signature)))
	off += 4
	copy(data[off:], k.Signature)
}

func (k *SSHNewKeys) SerializeTo(data []byte, off int) int {
	data[off] = byte(k.SSHType)
	return off + 1
}

func (msg *SSHChannelData) SerializeTo(data []byte, off int) {
	binary.BigEndian.PutUint32(data[off:], msg.RecipientChannel)
	off += 4
	binary.BigEndian.PutUint32(data[off:], uint32(len(msg.Data)))
	off += 4
	copy(data[off:], msg.Data)
}

func (msg *SSHChannelOpen) SerializeTo(data []byte, off int) int {
	data[off] = byte(msg.SSHType)
	binary.BigEndian.PutUint32(data[off+1:], uint32(len(msg.ChannelType)))
	off += 5
	copy(data[off:], msg.ChannelType)
	off += len(msg.ChannelType)
	binary.BigEndian.PutUint32(data[off:], msg.SenderChannel)
	off += 4
	binary.BigEndian.PutUint32(data[off:], msg.InitialWindowSize)
	off += 4
	binary.BigEndian.PutUint32(data[off:], msg.MaximumPacketSize)
	off += 4
	binary.BigEndian.PutUint32(data[off:], uint32(len(msg.SpecificData)))
	off += 4
	copy(data[off:], msg.SpecificData)
	return off + len(msg.SpecificData)
}

func (msg *SSHChannelRequest) SerializeTo(data []byte, off int) int {
	data[off] = byte(msg.SSHType)
	binary.BigEndian.PutUint32(data[off+1:], msg.RecipientChannel)
	off += 5
	binary.BigEndian.PutUint32(data[off:], uint32(len(msg.RequestType)))
	off += 4
	copy(data[off:], msg.RequestType)
	off += len(msg.RequestType)
	if msg.WantReply {
		data[off] = 1
	} else {
		data[off] = 0
	}
	off += 1
	binary.BigEndian.PutUint32(data[off:], uint32(len(msg.Command)))
	off += 4
	copy(data[off:], msg.Command)
	return off + len(msg.Command)
}

func (msg *SSHChannelSuccess) SerializeTo(data []byte, off int) int {
	data[off] = byte(msg.SSHType)
	binary.BigEndian.PutUint32(data[off+1:], msg.RecipientChannel)
	return off + 5
}

func (msg *SSHEofMsg) SerializeTo(data []byte, off int) int {
	data[off] = byte(msg.SSHType)
	binary.BigEndian.PutUint32(data[off+1:], msg.ChannelNumber)
	return off + 5
}

func (msg *SSHUserAuthRequest) SerializeTo(data []byte, off int) int {
	data[off] = byte(msg.SSHType)
	binary.BigEndian.PutUint32(data[off+1:], uint32(len(msg.UserName)))
	off += 5
	copy(data[off:], msg.UserName)
	off += len(msg.UserName)
	binary.BigEndian.PutUint32(data[off:], uint32(len(msg.ServiceName)))
	off += 4
	copy(data[off:], msg.ServiceName)
	off += len(msg.ServiceName)
	binary.BigEndian.PutUint32(data[off:], uint32(len(msg.MethodName)))
	off += 4
	copy(data[off:], msg.MethodName)
	off += len(msg.MethodName)
	if msg.MethodName == "password" {
		if msg.ChangeRe {
			data[off] = 1
		} else {
			data[off] = 0
		}
		binary.BigEndian.PutUint32(data[off+1:], uint32(len(msg.Password)))
		off += 5
		copy(data[off:], msg.Password)
		return off + len(msg.Password)
	}
	return off
}

func (msg *SSHUserAuthSuccess) SerializeTo(data []byte, off int) {
	data[off] = byte(msg.SSHType)
}

func (msg *SSHUserAuthFailure) SerializeTo(data []byte, off int) {
	data[off] = byte(msg.SSHType)
	off += 1
	off = writeNameList(data, off, msg.AuthenticationsThatCanContinue)
	if msg.PartialSuccess {
		data[off] = 1
	} else {
		data[off] = 0
	}
}

func (msg *SSHChannelOpenFailure) SerializeTo(data []byte, off int) {
	binary.BigEndian.PutUint32(data[off:], msg.RecipientChannel)
	off += 4
	binary.BigEndian.PutUint32(data[off:], msg.ReasonCode)
	off += 4
	binary.BigEndian.PutUint32(data[off:], uint32(len(msg.Description)))
	off += 4
	copy(data[off:], msg.Description)
	off += len(msg.Description)
	binary.BigEndian.PutUint32(data[off:], uint32(len(msg.LanguageTag)))
	off += 4
	copy(data[off:], msg.LanguageTag)
}

func (msg *SSHChannelOpenConfirmation) SerializeTo(data []byte, off int) {
	binary.BigEndian.PutUint32(data[off:], msg.RecipientChannel)
	off += 4
	binary.BigEndian.PutUint32(data[off:], msg.SenderChannel)
	off += 4
	binary.BigEndian.PutUint32(data[off:], msg.InitialWindowSize)
	off += 4
	binary.BigEndian.PutUint32(data[off:], msg.MaximumPacketSize)
}

func (msg *SSHChannelClose) SerializeTo(data []byte, off int) {
	binary.BigEndian.PutUint32(data[off:], msg.RecipientChannel)
}

func (msg *SSHServiceAccept) SerializeTo(data []byte, off int) {
	binary.BigEndian.PutUint32(data[off:], uint32(len(msg.ServiceName)))
	off += 4
	copy(data[off:], msg.ServiceName)
}

func (msg *SSHServiceRequest) SerializeTo(data []byte, off int) int {
	data[off] = byte(msg.SSHType)
	binary.BigEndian.PutUint32(data[off+1:], uint32(len(msg.ServiceName)))
	off += 5
	copy(data[off:], msg.ServiceName)
	return off + len(msg.ServiceName)
}

func readNameList(data []byte, off int) ([]string, int) {
	var length uint32
	length = binary.BigEndian.Uint32(data[off:])
	off += 4
	nameList := make([]byte, length)
	copy(nameList, data[off:off+int(length)])
	return strings.Split(string(nameList), ","), off + int(length)
}

func writeNameList(data []byte, off int, nameList []string) int {
	combined := strings.Join(nameList, ",")
	length := uint32(len(combined))
	binary.BigEndian.PutUint32(data[off:], length)
	off += 4
	copy(data[off:], combined)
	return off + len(combined)
}
