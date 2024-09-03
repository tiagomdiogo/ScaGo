package session

import "C"
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/ScaGo/protocols"
	"github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
	"hash"
	"math/big"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

type SSHClient struct {
	conn             net.Conn
	sshLayer         *protocols.SSH
	handshakeState   *SSHHandshakeState
	peer             string
	clientVersion    string
	serverVersion    string
	clientCookie     []byte
	serverCookie     []byte
	clientWriteKey   []byte
	clientMACKey     []byte
	clientIV         []byte
	serverWriteKey   []byte
	serverMACKey     []byte
	serverIV         []byte
	clientKexInit    []byte
	serverKexInit    []byte
	serverHostKey    []byte
	clientDHPubValue *big.Int
	serverDHPubValue *big.Int
	sharedSecret     *big.Int
	exchangeHash     []byte
	sessionID        []byte
	socket           *supersocket.SuperSocket
	sendSeqNum       uint32
	recvSeqNum       uint32
	clientCipher     cipher.BlockMode
	serverCipher     cipher.BlockMode
	clientMAC        hash.Hash
	serverMAC        hash.Hash
}

type SSHHandshakeState struct {
	versionExchanged    bool
	keyExchangeInitSent bool
	keyExchangeInitRecv bool
	keyExchangeSent     bool
	keyExchangeRecv     bool
	newKeysSent         bool
	newKeysRecv         bool
	serviceRequestSent  bool
	serviceRequestRecv  bool
	userAuthRequestSent bool
	userAuthRequestRecv bool
	channelOpenSent     bool
	channelOpenRecv     bool
	channelRequestSent  bool
	channelRequestRecv  bool
	channelDataSent     bool
	channelDataRecv     bool
}

func NewSSHClient(conn net.Conn, ip string, socket *supersocket.SuperSocket) *SSHClient {
	sshLayer := &protocols.SSH{
		BaseLayer:  layers.BaseLayer{},
		SSHRecords: make([]protocols.SSHPacket, 0),
	}

	handshakeState := &SSHHandshakeState{
		versionExchanged:    false,
		keyExchangeInitSent: false,
		keyExchangeInitRecv: false,
		keyExchangeSent:     false,
		keyExchangeRecv:     false,
		newKeysSent:         false,
		newKeysRecv:         false,
		serviceRequestSent:  false,
		serviceRequestRecv:  false,
		userAuthRequestSent: false,
		userAuthRequestRecv: false,
		channelOpenSent:     false,
		channelOpenRecv:     false,
		channelRequestSent:  false,
		channelRequestRecv:  false,
		channelDataSent:     false,
		channelDataRecv:     false,
	}
	return &SSHClient{
		conn:           conn,
		sshLayer:       sshLayer,
		handshakeState: handshakeState,
		peer:           ip,
		socket:         socket,
		sendSeqNum:     0,
		recvSeqNum:     0,
	}
}

const versionString = "SSH-2.0-MySSHClient\r\n"
const userAuthServiceString = "ssh-userauth"

func (s *SSHClient) ResetSSHLayer() {
	s.sshLayer.SSHRecords = s.sshLayer.SSHRecords[:0]
}

func calculateStringsSize(strings []string) int {
	totalSize := 0
	for _, str := range strings {
		totalSize += len(str)
	}
	return totalSize
}

func calculatePayloadLength(payload interface{}) int {
	length := 0
	if k, ok := payload.(protocols.SSHKexInitMsg); ok {
		length += 62 // type + cookie + list_lengths + firstkex + reserved
		length += calculateStringsSize(k.KexAlgorithms)
		length += calculateStringsSize(k.ServerHostKeyAlgorithms)
		length += calculateStringsSize(k.EncryptionAlgorithmsClientToServer)
		length += calculateStringsSize(k.EncryptionAlgorithmsServerToClient)
		length += calculateStringsSize(k.MacAlgorithmsServerToClient)
		length += calculateStringsSize(k.MacAlgorithmsClientToServer)
		length += calculateStringsSize(k.CompressionAlgorithmsServerToClient)
		length += calculateStringsSize(k.CompressionAlgorithmsClientToServer)
		length += calculateStringsSize(k.LanguagesClientToServer)
		length += calculateStringsSize(k.LanguagesServerToClient)
		return length
	} else if k, ok := payload.(protocols.SSHKexDHInit); ok {
		length += 5 + len(k.Pub) //type + len + key
		return length
	} else if k, ok := payload.(protocols.SSHServiceRequest); ok {
		length += 5 + len(k.ServiceName) //type + len + service
		return length
	} else if k, ok := payload.(protocols.SSHUserAuthRequest); ok {
		length += 18 + len(k.MethodName) + len(k.ServiceName) + len(k.UserName) + len(k.Password) //type +lens + strings + bool
		return length
	} else if k, ok := payload.(protocols.SSHChannelOpen); ok {
		length += 17 + len(k.ChannelType) // type + values + string
		return length
	} else if k, ok := payload.(protocols.SSHChannelRequest); ok {
		length += 14 + len(k.Command) + len(k.RequestType) // type + values + strings + bool
		return length
	} else if _, ok := payload.(protocols.SSHChannelSuccess); ok {
		length += 5 // type + value
		return length
	} else if _, ok := payload.(protocols.SSHEofMsg); ok {
		length += 5 // type + value
		return length
	}
	return 0
}

func intToBytes(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

func encodeBigInt(b *big.Int) []byte {
	bBytes := b.Bytes()

	// Ensure positive numbers have a leading zero if the most significant bit is set
	if len(bBytes) > 0 && bBytes[0]&0x80 != 0 {
		bBytes = append([]byte{0x00}, bBytes...)
	}

	lengthBytes := intToBytes(uint32(len(bBytes)))
	return append(lengthBytes, bBytes...)
}

func encodeString(s []byte) []byte {
	lengthBytes := intToBytes(uint32(len(s)))
	return append(lengthBytes, s...)
}

// hashWithLetterSHA1 calculates the hash for key derivation using SHA-1.
func hashWithLetterSHA1(out, sharedSecret, exchangeHash, sessionID, letter []byte) {
	var digestsSoFar []byte
	h := sha1.New()
	for len(out) > 0 {
		h.Reset()
		h.Write(sharedSecret)
		h.Write(exchangeHash)

		if len(digestsSoFar) == 0 {
			h.Write(letter)
			h.Write(sessionID)
		} else {
			h.Write(digestsSoFar)
		}

		digest := h.Sum(nil)
		n := copy(out, digest)
		out = out[n:]
		if len(out) > 0 {
			digestsSoFar = append(digestsSoFar, digest...)
		}
	}
}

// calculateExchangeHashAndKeys calculates the exchange hash and derives session keys.
func (client *SSHClient) calculateExchangeHashAndKeys() error {
	// Compute the exchange hash H using SHA-1
	hashFunc := sha1.New()
	hashFunc.Write(encodeString([]byte(strings.TrimRight(client.clientVersion, "\r\n"))))
	hashFunc.Write(encodeString([]byte(strings.TrimRight(client.serverVersion, "\r\n"))))
	hashFunc.Write(encodeString(client.clientKexInit))
	hashFunc.Write(encodeString(client.serverKexInit))
	hashFunc.Write(encodeString(client.serverHostKey))
	hashFunc.Write(encodeBigInt(client.clientDHPubValue))
	hashFunc.Write(encodeBigInt(client.serverDHPubValue))
	hashFunc.Write(encodeBigInt(client.sharedSecret))

	client.exchangeHash = hashFunc.Sum(nil)
	if client.sessionID == nil {
		client.sessionID = client.exchangeHash
	}
	client.clientIV = make([]byte, 16)
	client.serverIV = make([]byte, 16)
	client.clientWriteKey = make([]byte, 16)
	client.serverWriteKey = make([]byte, 16)
	client.clientMACKey = make([]byte, 32)
	client.serverMACKey = make([]byte, 32)

	// Derive session keys using SHA-1 for IVs and encryption keys
	hashWithLetterSHA1(client.clientIV, encodeBigInt(client.sharedSecret), client.exchangeHash, client.sessionID, []byte{'A'})
	hashWithLetterSHA1(client.serverIV, encodeBigInt(client.sharedSecret), client.exchangeHash, client.sessionID, []byte{'B'})
	hashWithLetterSHA1(client.clientWriteKey, encodeBigInt(client.sharedSecret), client.exchangeHash, client.sessionID, []byte{'C'})
	hashWithLetterSHA1(client.serverWriteKey, encodeBigInt(client.sharedSecret), client.exchangeHash, client.sessionID, []byte{'D'})
	hashWithLetterSHA1(client.clientMACKey, encodeBigInt(client.sharedSecret), client.exchangeHash, client.sessionID, []byte{'E'})
	hashWithLetterSHA1(client.serverMACKey, encodeBigInt(client.sharedSecret), client.exchangeHash, client.sessionID, []byte{'F'})

	//Cipher initialization
	clientBlock, err := aes.NewCipher(client.clientWriteKey)
	if err != nil {
		return err
	}
	serverBlock, err := aes.NewCipher(client.serverWriteKey)
	if err != nil {
		return err
	}
	client.clientCipher = cipher.NewCBCEncrypter(clientBlock, client.clientIV)
	client.serverCipher = cipher.NewCBCDecrypter(serverBlock, client.serverIV)
	client.clientMAC = hmac.New(sha256.New, client.clientMACKey)
	client.serverMAC = hmac.New(sha256.New, client.serverMACKey)

	return nil
}

func (c *SSHClient) sendRcvVersion() error {
	c.ResetSSHLayer()
	c.clientVersion = versionString
	clientVersion := protocols.SSHVersionMsg{versionString}
	buf := gopacket.NewSerializeBuffer()
	buffer, _ := buf.PrependBytes(len(clientVersion.VersionString))
	clientVersion.SerializeTo(buffer)
	_, err := c.conn.Write(buffer)
	if err != nil {
		return err
	}
	response, err := c.socket.Recv()
	tcpLayer := utils.GetTCPLayer(response)
	serverVersion := protocols.SSHVersionMsg{}
	serverVersion.DecodeFromBytes(tcpLayer.Payload)
	c.serverVersion = serverVersion.VersionString
	c.handshakeState.versionExchanged = true
	return nil
}

func (c *SSHClient) sendRcvKeyInitMsg() error {
	c.ResetSSHLayer()
	cookie := make([]byte, 16)
	_, _ = rand.Read(cookie)
	c.clientCookie = make([]byte, 16)
	copy(c.clientCookie, cookie)
	keyInitMsg := protocols.SSHKexInitMsg{
		SSHType:                             protocols.SSH_MSG_KEXINIT,
		Cookie:                              cookie,
		KexAlgorithms:                       []string{"diffie-hellman-group14-sha1"},
		ServerHostKeyAlgorithms:             []string{"ssh-rsa"},
		EncryptionAlgorithmsClientToServer:  []string{"aes128-cbc"},
		EncryptionAlgorithmsServerToClient:  []string{"aes128-cbc"},
		MacAlgorithmsClientToServer:         []string{"hmac-sha2-256"},
		MacAlgorithmsServerToClient:         []string{"hmac-sha2-256"},
		CompressionAlgorithmsClientToServer: []string{"none"},
		CompressionAlgorithmsServerToClient: []string{"none"},
		LanguagesClientToServer:             []string{},
		LanguagesServerToClient:             []string{},
		FirstKexPacketFollows:               false,
		Reserved:                            0,
	}

	packetLength := calculatePayloadLength(keyInitMsg)

	paddingLength := 8 - ((packetLength + 5) % 8) // 5 bytes for PacketLength and PaddingLength fields
	if paddingLength < 4 {
		paddingLength += 8
	}
	packetLength += 1 + paddingLength
	keyInitRecord := protocols.SSHPacket{
		PacketLength:  uint32(packetLength),
		PaddingLength: byte(paddingLength),
		Payload:       keyInitMsg,
		Padding:       make([]byte, paddingLength),
		MAC:           nil,
	}
	c.sshLayer.SSHRecords = append(c.sshLayer.SSHRecords, keyInitRecord)
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, c.sshLayer)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(buf.Bytes())
	if err != nil {
		return err
	}
	c.clientKexInit = buf.Bytes()[5 : packetLength-1]
	c.handshakeState.keyExchangeInitSent = true
	c.sendSeqNum += 1

	response, err := c.socket.Recv()
	tcpLayer := utils.GetTCPLayer(response)
	sshLayer := protocols.SSH{}
	err = sshLayer.DecodeFromBytes(tcpLayer.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}
	for _, response := range sshLayer.SSHRecords {
		if k, ok := response.Payload.(protocols.SSHKexInitMsg); ok {
			c.serverCookie = make([]byte, 16)
			copy(c.serverCookie, k.Cookie)
			c.serverKexInit = tcpLayer.Payload[5 : response.PacketLength-uint32(response.PaddingLength)]
		}
	}

	c.handshakeState.keyExchangeInitRecv = true
	return nil
}

func (c *SSHClient) sendRcvKeyDH() error {
	c.ResetSSHLayer()

	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	g := big.NewInt(2)
	priv, err := rand.Int(rand.Reader, p)

	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}
	pub := new(big.Int).Exp(g, priv, p)
	c.clientDHPubValue = pub
	clientPub := pub.Bytes()

	dhInitMsg := protocols.SSHKexDHInit{
		SSHType: protocols.SSH_MSG_KEYDH_INIT,
		Pub:     make([]byte, len(clientPub)),
	}
	copy(dhInitMsg.Pub, clientPub)

	packetLength := calculatePayloadLength(dhInitMsg)
	paddingLength := 8 - ((packetLength + 5) % 8) // 5 bytes for PacketLength and PaddingLength fields
	if paddingLength < 4 {
		paddingLength += 8
	}
	packetLength += 1 + paddingLength

	dhInitPacket := protocols.SSHPacket{
		PacketLength:  uint32(packetLength),
		PaddingLength: byte(paddingLength),
		Payload:       dhInitMsg,
		Padding:       make([]byte, paddingLength),
		MAC:           nil,
	}

	c.sshLayer.SSHRecords = append(c.sshLayer.SSHRecords, dhInitPacket)
	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, c.sshLayer)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(buf.Bytes())
	if err != nil {
		return err
	}
	c.handshakeState.keyExchangeSent = true
	c.sendSeqNum += 1

	response, err := c.socket.Recv()
	tcpLayer := utils.GetTCPLayer(response)
	sshLayer := protocols.SSH{}
	err = sshLayer.DecodeFromBytes(tcpLayer.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}
	for _, response := range sshLayer.SSHRecords {
		if k, ok := response.Payload.(protocols.SSHKexDHReply); ok {
			c.serverHostKey = make([]byte, len(k.ServerHostKey))
			c.serverDHPubValue = k.F
			copy(c.serverHostKey, k.ServerHostKey)
		} else if _, ok := response.Payload.(protocols.SSHNewKeys); ok {
			c.handshakeState.newKeysRecv = true
		}
	}

	c.sharedSecret = new(big.Int).Exp(c.serverDHPubValue, priv, p)
	c.handshakeState.keyExchangeRecv = true
	return nil
}

func (c *SSHClient) sendRcvNewKeysMsg() error {
	c.ResetSSHLayer()
	newKeysMsg := protocols.SSHNewKeys{SSHType: protocols.SSH_MSG_NEWKEYS}
	packetLength := 1
	paddingLength := 8 - ((packetLength + 5) % 8) // 5 bytes for PacketLength and PaddingLength fields
	if paddingLength < 4 {
		paddingLength += 8
	}
	packetLength += 1 + paddingLength
	newKeysPacket := protocols.SSHPacket{
		PacketLength:  uint32(packetLength),
		PaddingLength: byte(paddingLength),
		Payload:       newKeysMsg,
		Padding:       make([]byte, paddingLength),
		MAC:           nil,
	}
	c.sshLayer.SSHRecords = append(c.sshLayer.SSHRecords, newKeysPacket)
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, c.sshLayer)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(buf.Bytes())
	if err != nil {
		return err
	}
	c.handshakeState.newKeysSent = true

	c.sendSeqNum += 1
	return nil
}

func (c *SSHClient) waitForHandshake() error {
	err := c.sendRcvVersion()
	if err != nil {
		return fmt.Errorf("Error sending/receiving SSH Version ", err)
	}
	if !c.handshakeState.versionExchanged {
		return fmt.Errorf("SSH Version not exchanged!")
	}
	err = c.sendRcvKeyInitMsg()
	if err != nil {
		return fmt.Errorf("Error sending/receiving SSH KeyInitMsg ", err)
	}
	if !c.handshakeState.keyExchangeInitSent || !c.handshakeState.keyExchangeInitRecv {
		return fmt.Errorf("SSH KeyInitMsg not exchanged!")
	}
	err = c.sendRcvKeyDH()
	if err != nil {
		return fmt.Errorf("Error sending/receiving SSH KeyDH ", err)
	}
	if !c.handshakeState.keyExchangeSent || !c.handshakeState.keyExchangeRecv {
		return fmt.Errorf("SSH KeyDH not exchanged!")
	}
	c.calculateExchangeHashAndKeys()
	err = c.sendRcvNewKeysMsg()
	if err != nil {
		return fmt.Errorf("Error sending/receiving SSH KeyDH ", err)
	}
	if !c.handshakeState.newKeysSent || !c.handshakeState.newKeysRecv {
		return fmt.Errorf("SSH NewKeys not exchanged!")
	}
	return nil
}

func (c *SSHClient) doUserAuthentication(user, pass string) error {
	err := c.sendRcvServiceRequest(userAuthServiceString)
	if err != nil {
		return err
	}

	err = c.sendRcvUserAuthRequest(user, pass)
	if err != nil {
		return err
	}

	return nil
}

func (c *SSHClient) sendRcvServiceRequest(service string) error {
	c.ResetSSHLayer()
	serviceRequest := protocols.SSHServiceRequest{
		SSHType:     protocols.SSH_MSG_SERVICE_REQUEST,
		ServiceName: service,
	}

	packet := protocols.SSHPacket{
		Payload: serviceRequest,
	}
	c.sshLayer.SSHRecords = append(c.sshLayer.SSHRecords, packet)
	err := c.encryptAndSendPacket(c.sshLayer)
	if err != nil {
		return err
	}

	responsePacket, err := c.receiveAndDecryptPacket()
	if err != nil {
		return err
	}

	sshLayer := protocols.SSH{}
	err = sshLayer.DecodeFromBytes(responsePacket, gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}

	for _, response := range sshLayer.SSHRecords {
		if _, ok := response.Payload.(protocols.SSHServiceAccept); ok {
			return nil
		}
	}
	return fmt.Errorf("Service Request Not Accepted")
}

func (c *SSHClient) sendRcvUserAuthRequest(user, pass string) error {
	c.ResetSSHLayer()
	userAuthRequest := protocols.SSHUserAuthRequest{
		SSHType:     protocols.SSH_MSG_USERAUTH_REQUEST,
		UserName:    user,
		ServiceName: "ssh-connection",
		MethodName:  "password",
		ChangeRe:    false,
		Password:    pass,
	}

	packet := protocols.SSHPacket{
		Payload: userAuthRequest,
	}
	c.sshLayer.SSHRecords = append(c.sshLayer.SSHRecords, packet)
	err := c.encryptAndSendPacket(c.sshLayer)
	if err != nil {
		return err
	}

	responsePacket, err := c.receiveAndDecryptPacket()
	if err != nil {
		return err
	}

	sshLayer := protocols.SSH{}
	err = sshLayer.DecodeFromBytes(responsePacket, gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}

	for _, response := range sshLayer.SSHRecords {
		if _, ok := response.Payload.(protocols.SSHUserAuthSuccess); ok {
			return nil
		}
	}

	return fmt.Errorf("User Authentication Failed")
}

func (c *SSHClient) receiveAndDecryptPacket() ([]byte, error) {
	response, err := c.socket.Recv()
	if err != nil {
		return nil, err
	}

	tcpLayer := utils.GetTCPLayer(response)
	payload := tcpLayer.Payload

	var decryptedData []byte

	blockSize := uint32(aes.BlockSize)

	for len(payload) > 0 {
		firstBlockLength := (5 + blockSize - 1) / blockSize * blockSize
		firstBlock := payload[:firstBlockLength]

		c.serverCipher.CryptBlocks(firstBlock, firstBlock)
		packetLength := binary.BigEndian.Uint32(firstBlock[:4])
		decryptedData = append(decryptedData, firstBlock...)

		recordLength := int(packetLength) + 4 + c.serverMAC.Size()

		record := payload[:recordLength]

		recordWithoutMAC := record[:recordLength-c.serverMAC.Size()]
		c.serverCipher.CryptBlocks(recordWithoutMAC[firstBlockLength:], recordWithoutMAC[firstBlockLength:])

		decryptedData = append(decryptedData, recordWithoutMAC[firstBlockLength:]...)

		// Move to the next SSH record
		payload = payload[recordLength:]

	}

	c.recvSeqNum++
	return decryptedData, nil
}
func maxUInt32(a, b int) uint32 {
	if a > b {
		return uint32(a)
	}
	return uint32(b)
}

func (c *SSHClient) encryptAndSendPacket(packet *protocols.SSH) error {
	blockSize := uint32(aes.BlockSize)
	payloadLength := uint32(calculatePayloadLength(packet.SSHRecords[0].Payload))

	encrLength := maxUInt32(5+int(payloadLength)+4, 4)
	encrLength = (encrLength + blockSize - 1) / blockSize * blockSize
	length := encrLength - 4
	paddingLength := uint8(length - (1 + payloadLength))
	packet.SSHRecords[0].PacketLength = length
	packet.SSHRecords[0].PaddingLength = paddingLength
	packet.SSHRecords[0].Padding = bytes.Repeat([]byte{paddingLength}, int(paddingLength))
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, packet)
	// Compute MAC
	seqNum := make([]byte, 4)
	binary.BigEndian.PutUint32(seqNum, c.sendSeqNum)
	c.clientMAC.Reset()
	c.clientMAC.Write(seqNum)
	c.clientMAC.Write(buf.Bytes())
	mac := c.clientMAC.Sum(nil)

	// Encrypt the packet
	c.clientCipher.CryptBlocks(buf.Bytes(), buf.Bytes())

	data := make([]byte, 0, len(buf.Bytes())+32)
	dataBuffer := bytes.NewBuffer(data)
	dataBuffer.Write(buf.Bytes())
	dataBuffer.Write(mac)

	_, err = c.conn.Write(dataBuffer.Bytes())
	if err != nil {
		return err
	}

	c.sendSeqNum++
	return nil
}

func (c *SSHClient) SendRcvCommand(commandType, command string) (string, error) {
	channelNumber, err := c.sendRcvOpenChannel()
	if err != nil {
		return "", err
	}

	err = c.sendRcvChannelRequest(channelNumber, commandType, command)
	if err != nil {
		return "", err
	}

	response, err2 := c.rcvChannelData(channelNumber)
	if err2 != nil {
		return "", err2
	}

	return response, nil
}

func (c *SSHClient) sendRcvOpenChannel() (uint32, error) {
	c.ResetSSHLayer()
	channelRequest := protocols.SSHChannelOpen{
		SSHType:           protocols.SSH_MSG_CHANNEL_OPEN,
		ChannelType:       "session",
		SenderChannel:     0,
		InitialWindowSize: 2097152,
		MaximumPacketSize: 32768,
	}

	packet := protocols.SSHPacket{
		Payload: channelRequest,
	}
	c.sshLayer.SSHRecords = append(c.sshLayer.SSHRecords, packet)
	err := c.encryptAndSendPacket(c.sshLayer)
	if err != nil {
		return 0, err
	}
	// Discard Global Request Packet
	responsePacket, err := c.receiveAndDecryptPacket()
	if err != nil {
		return 0, err
	}

	responsePacket, _ = c.receiveAndDecryptPacket()
	sshLayer := protocols.SSH{}
	err = sshLayer.DecodeFromBytes(responsePacket, gopacket.NilDecodeFeedback)
	if err != nil {
		return 0, err
	}

	for _, response := range sshLayer.SSHRecords {
		if k, ok := response.Payload.(protocols.SSHChannelOpenConfirmation); ok {
			return k.SenderChannel, nil
		}
	}
	return 0, fmt.Errorf("Channel not opened")
}

func (c *SSHClient) sendRcvChannelRequest(channelNumber uint32, commandType, command string) error {
	c.ResetSSHLayer()
	channelRequest := protocols.SSHChannelRequest{
		SSHType:          protocols.SSH_MSG_CHANNEL_REQUEST,
		RecipientChannel: channelNumber,
		RequestType:      commandType,
		WantReply:        true,
		Command:          []byte(command),
	}

	packet := protocols.SSHPacket{
		Payload: channelRequest,
	}
	c.sshLayer.SSHRecords = append(c.sshLayer.SSHRecords, packet)
	err := c.encryptAndSendPacket(c.sshLayer)
	if err != nil {
		return err
	}

	responsePacket, err := c.receiveAndDecryptPacket()
	if err != nil {
		return err
	}

	sshLayer := protocols.SSH{}
	err = sshLayer.DecodeFromBytes(responsePacket, gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}

	for _, response := range sshLayer.SSHRecords {
		if _, ok := response.Payload.(protocols.SSHChannelSuccess); ok {
			return nil
		}
	}
	return fmt.Errorf("Channel Request not succeded")
}

func (c *SSHClient) rcvChannelData(channelNumber uint32) (string, error) {
	c.ResetSSHLayer()
	eofRequest := protocols.SSHEofMsg{
		SSHType:       protocols.SSH_MSG_CHANNEL_REQUEST,
		ChannelNumber: channelNumber,
	}
	packet := protocols.SSHPacket{
		Payload: eofRequest,
	}
	c.sshLayer.SSHRecords = append(c.sshLayer.SSHRecords, packet)
	err := c.encryptAndSendPacket(c.sshLayer)
	if err != nil {
		return "", err
	}

	responsePacket, err := c.receiveAndDecryptPacket()
	if err != nil {
		return "", err
	}

	sshLayer := protocols.SSH{}
	err = sshLayer.DecodeFromBytes(responsePacket, gopacket.NilDecodeFeedback)
	if err != nil {
		return "", err
	}

	for _, response := range sshLayer.SSHRecords {
		if k, ok := response.Payload.(protocols.SSHChannelData); ok {
			if k.RecipientChannel == channelNumber {
				response := string(k.Data)
				return response, nil
			}
		}
	}
	return "", nil
}

func NewSSHClientSession(ip, user, pass string) (*SSHClient, error) {
	exec.Command("iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type", "destination-unreachable", "-j", "DROP").Run()
	conn, err := net.Dial("tcp", ip)
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	socket, _ := supersocket.NewSuperSocket("eth0", "dst host "+utils.IPbyInt("eth0")+" and tcp port "+
		strconv.Itoa(localAddr.Port)+" and (((ip[2:2] - ((ip[0] & 0xf) << 2)) - ((tcp[12] & 0xf0) >> 4 << 2)) > 0)")

	if err != nil {
		return nil, fmt.Errorf("Error connecting to server: ", err)
	}
	sshClient := NewSSHClient(conn, ip, socket)
	err = sshClient.waitForHandshake()
	if err != nil {
		return nil, fmt.Errorf("Error performing handshake: ", err)
	}
	fmt.Println("Handshake Finished")
	if user != "" {
		err = sshClient.doUserAuthentication(user, pass)
		if err != nil {
			return nil, fmt.Errorf("Error doing use authentication: ", err)
		}
		fmt.Println("User authenticated")
	}
	return sshClient, nil
}
