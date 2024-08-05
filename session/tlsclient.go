package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/ScaGo/protocols"
	"github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
	"net"
	"os/exec"
	"reflect"
	"strconv"
	"time"
)

type TLSClient struct {
	conn              net.Conn
	tlsLayer          *protocols.TLS
	handshakeState    *TLSHandshakeState
	peer              string
	messageHistory    [][]byte
	masterSecret      []byte
	clientRandom      []byte
	serverRandom      []byte
	clientWriteKey    []byte
	clientMACKey      []byte
	clientIV          []byte
	serverWriteKey    []byte
	serverMACKey      []byte
	serverIV          []byte
	serverCertificate []byte
	socket            *supersocket.SuperSocket
	sendSeqNum        uint64
	recvSeqNum        uint64
}

type TLSHandshakeState struct {
	clientHelloSent           bool
	serverHelloReceived       bool
	certificateReceived       bool
	serverKeyExchangeReceived bool
	serverHelloDoneReceived   bool
	clientKeyExchangeSent     bool
	changeCipherSpecSent      bool
	changeCipherSpecReceived  bool
	finishedSent              bool
	finishedReceived          bool
	applicationDataSent       bool
}

func NewTLSClient(conn net.Conn, ip string, socket *supersocket.SuperSocket) *TLSClient {
	tlsLayer := &protocols.TLS{
		BaseLayer:        layers.BaseLayer{},
		ChangeCipherSpec: make([]protocols.TLSChangeCipherSpecRecord, 0),
		Handshake:        make([]protocols.TLSHandshakeRecord, 0),
		AppData:          make([]protocols.TLSAppDataRecord, 0),
		Alert:            make([]protocols.TLSAlertRecord, 0),
		Heartbeat:        make([]protocols.TLSHeartbeatRecord, 0),
	}

	handshakeState := &TLSHandshakeState{
		clientHelloSent:           false,
		serverHelloReceived:       false,
		certificateReceived:       false,
		serverKeyExchangeReceived: false,
		serverHelloDoneReceived:   false,
		clientKeyExchangeSent:     false,
		changeCipherSpecSent:      false,
		changeCipherSpecReceived:  false,
		finishedSent:              false,
		finishedReceived:          false,
		applicationDataSent:       false,
	}
	return &TLSClient{
		conn:           conn,
		tlsLayer:       tlsLayer,
		handshakeState: handshakeState,
		peer:           ip,
		socket:         socket,
		sendSeqNum:     0,
		recvSeqNum:     0,
	}
}

func (c *TLSClient) SendClientHello() error {
	if c.handshakeState.clientHelloSent {
		return fmt.Errorf("ClientHello already sent")
	}
	c.ResetTlsLayer()
	random := make([]byte, 28)
	_, _ = rand.Read(random)

	clientHello := protocols.TLSHandshakeRecord{
		TLSRecordHeader: protocols.TLSRecordHeader{
			ContentType: protocols.TLSHandshake,
			Version:     0x0303,
			Length:      0,
		},
		ClientHello: protocols.ClientHello{
			Header: protocols.Header{
				ContentType: protocols.TLSClientHello,
				Version:     0x0303,
				Length:      0,
			},
			Gmt_Unix_Time:              uint32(time.Now().Unix()),
			Random:                     random,
			SessionIDLength:            0,
			CipherSuiteLength:          2,
			CipherSuite:                []protocols.TLSCipherSuite{protocols.TLS_RSA_WITH_AES_128_CBC_SHA256},
			CompressionAlgorithmLength: 1,
			CompressionAlgorithm:       0,
		},
	}
	clientHello.TLSRecordHeader.Length = 6 + 39    //header + packet
	clientHello.ClientHello.Header.Length = 2 + 39 //version + packet
	c.clientRandom = make([]byte, 32)
	var randomBytes bytes.Buffer
	binary.Write(&randomBytes, binary.BigEndian, clientHello.ClientHello.Gmt_Unix_Time)
	randomBytes.Write(random)
	copy(c.clientRandom, randomBytes.Bytes())
	c.tlsLayer.Handshake = append(c.tlsLayer.Handshake, clientHello)
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, c.tlsLayer)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(buf.Bytes())
	if err != nil {
		return err
	}
	c.handshakeState.clientHelloSent = true
	c.messageHistory = append(c.messageHistory, buf.Bytes()[5:])
	return nil
}

func (c *TLSClient) waitForHandshake() error {
	if !c.handshakeState.clientHelloSent {
		return fmt.Errorf("ClientHello not sent")
	}

	timeout := time.After(60 * time.Second)
	for {
		select {
		case <-timeout:
			return fmt.Errorf("Timeout waiting for handshake")
		default:
			response, err := c.socket.Recv()
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			if response == nil {
				continue
			}
			tcpLayer := utils.GetTCPLayer(response)

			if tcpLayer == nil {
				continue
			}
			tlsLayer := protocols.TLS{}
			if len(tcpLayer.Payload) == 0 {
				continue
			}
			err = tlsLayer.DecodeFromBytes(tcpLayer.Payload, gopacket.NilDecodeFeedback)
			if err != nil {
				return err
			}
			offset := 5
			if !c.handshakeState.changeCipherSpecReceived {
				for _, response := range tlsLayer.Handshake {
					if !reflect.DeepEqual(response.ServerHello, reflect.Zero(reflect.TypeOf(response.ServerHello)).Interface()) {
						c.handshakeState.serverHelloReceived = true
						c.serverRandom = make([]byte, 32)
						var randomBytes bytes.Buffer
						binary.Write(&randomBytes, binary.BigEndian, response.ServerHello.Gmt_Unix_Time)
						randomBytes.Write(response.ServerHello.Random)
						copy(c.serverRandom, randomBytes.Bytes())
						c.messageHistory = append(c.messageHistory, tcpLayer.Payload[offset:offset+int(response.Length)])
						offset += int(response.Length)
					} else if !reflect.DeepEqual(response.Certificate, reflect.Zero(reflect.TypeOf(response.Certificate)).Interface()) {
						c.handshakeState.certificateReceived = true
						c.serverCertificate = make([]byte, len(response.CertData))
						copy(c.serverCertificate[:], response.CertData[:])
						c.messageHistory = append(c.messageHistory, tcpLayer.Payload[offset+5:offset+5+int(response.Length)])
						offset = offset + 5 + int(response.Length)
					} else if !reflect.DeepEqual(response.ServerHelloDone, reflect.Zero(reflect.TypeOf(response.ServerHelloDone)).Interface()) {
						c.handshakeState.serverHelloDoneReceived = true
						c.messageHistory = append(c.messageHistory, tcpLayer.Payload[offset+5:offset+5+int(response.Length)])
						offset = offset + 5 + int(response.Length)
					} else {
						c.ProcessFinished(response.CipherData)
					}
				}
				for _, response := range tlsLayer.ChangeCipherSpec {
					c.recvSeqNum += 1
					if response.Message == 1 {
						c.handshakeState.changeCipherSpecReceived = true
					}
				}
			} else {
				fmt.Println("VIM AO ELSE VER RESPOSTA PARA DECIFRAR")
			}

			if c.handshakeState.serverHelloReceived && c.handshakeState.certificateReceived && c.handshakeState.serverHelloDoneReceived && !c.handshakeState.clientKeyExchangeSent {
				err := c.SendClientKeyExchange()
				if err != nil {
					return err
				}
			}
			if c.handshakeState.finishedReceived {
				return nil
			}
		}
	}
}

func (c *TLSClient) SendClientKeyExchange() error {
	if !c.handshakeState.serverHelloReceived || !c.handshakeState.certificateReceived || !c.handshakeState.serverHelloDoneReceived {
		return fmt.Errorf("ServerHello, Certificate, or ServerHelloDone not received")
	}
	c.ResetTlsLayer()

	// Generate the pre-master secret
	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = 0x03
	preMasterSecret[1] = 0x03
	_, err := rand.Read(preMasterSecret[2:])
	if err != nil {
		return err
	}
	// Use the public key from the server's certificate to encrypt the pre-master secret

	cert, _ := x509.ParseCertificate(c.serverCertificate)

	pubKey := cert.PublicKey
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}

	encryptedPreMasterSecret, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubKey, preMasterSecret)
	if err != nil {
		return err
	}

	// Create the ClientKeyExchange message
	clientKeyExchange := protocols.TLSHandshakeRecord{
		TLSRecordHeader: protocols.TLSRecordHeader{
			ContentType: protocols.TLSHandshake,
			Version:     0x0303,
			Length:      uint16(len(encryptedPreMasterSecret) + 6),
		},
		ClientKeyExchange: protocols.ClientKeyExchange{
			Header: protocols.Header{
				ContentType: protocols.TLSClientKeyExchange,
				Length:      uint32(len(encryptedPreMasterSecret) + 2),
			},
			EncryptedPreMasterSecretLength: uint16(len(encryptedPreMasterSecret)),
			EncryptedPreMasterSecret:       encryptedPreMasterSecret,
		},
	}

	// Calculate the master secret
	masterSecret := computeMasterSecret(preMasterSecret, c.clientRandom, c.serverRandom)
	c.clientMACKey, c.serverMACKey, c.clientWriteKey, c.serverWriteKey, c.clientIV, c.serverIV = DeriveKeys(masterSecret, c.clientRandom, c.serverRandom)
	c.masterSecret = masterSecret

	c.tlsLayer.Handshake = append(c.tlsLayer.Handshake, clientKeyExchange)
	// Serialize the ClientKeyExchange message
	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, c.tlsLayer)
	if err != nil {
		return err
	}

	// Send the ClientKeyExchange message
	_, err = c.conn.Write(buf.Bytes())
	if err != nil {
		return err
	}

	c.handshakeState.clientKeyExchangeSent = true
	c.messageHistory = append(c.messageHistory, buf.Bytes()[5:])
	c.SendChangeCipherSpec()
	return nil
}

func (c *TLSClient) SendChangeCipherSpec() error {
	if !c.handshakeState.clientKeyExchangeSent {
		return fmt.Errorf("ClientKeyExchange not sent")
	}
	c.ResetTlsLayer()

	// Create the ChangeCipherSpec message
	changeCipherSpecRecord := protocols.TLSChangeCipherSpecRecord{
		TLSRecordHeader: protocols.TLSRecordHeader{
			ContentType: protocols.TLSChangeCipherSpec,
			Version:     0x0303,
			Length:      1,
		},
		Message: protocols.TLSChangecipherspecMessage,
	}

	c.tlsLayer.ChangeCipherSpec = append(c.tlsLayer.ChangeCipherSpec, changeCipherSpecRecord)

	// Serialize the ChangeCipherSpec message
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, c.tlsLayer)
	if err != nil {
		return err
	}

	// Send the ChangeCipherSpec message
	_, err = c.conn.Write(buf.Bytes())
	if err != nil {
		return err
	}

	c.handshakeState.changeCipherSpecSent = true
	c.SendFinished()
	return nil
}

func (c *TLSClient) SendFinished() error {
	if !c.handshakeState.changeCipherSpecSent {
		return fmt.Errorf("ChangeCipherSpec not sent")
	}
	c.ResetTlsLayer()

	finishedData := c.ComputeFinishedData()
	encryptedFinishedData, err := c.encryptData(c.sendSeqNum, []byte{0x16, 0x03, 0x03, 0x00, 0x10}, append([]byte{0x14, 0x00, 0x00, 0x0C}, finishedData...))
	if err != nil {
		return err
	}
	encryptedWithIV := make([]byte, len(encryptedFinishedData)+len(c.clientIV))
	copy(encryptedWithIV, c.clientIV)
	copy(encryptedWithIV[len(c.clientIV):], encryptedFinishedData)
	// Create the Finished message
	finishedRecord := protocols.TLSHandshakeRecord{
		TLSRecordHeader: protocols.TLSRecordHeader{
			ContentType: protocols.TLSHandshake,
			Version:     0x0303,
			Length:      uint16(len(encryptedWithIV)),
		},
		Finished: protocols.Finished{
			Data: encryptedWithIV,
		},
	}
	c.tlsLayer.Handshake = append(c.tlsLayer.Handshake, finishedRecord)

	// Serialize the Finished message
	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, c.tlsLayer)
	if err != nil {
		return err
	}

	// Send the Finished message
	_, err = c.conn.Write(buf.Bytes())
	if err != nil {
		return err
	}

	c.handshakeState.finishedSent = true
	c.sendSeqNum += 1
	return nil
}

func (c *TLSClient) ProcessFinished(data []byte) error {
	decryptedData, _ := c.decryptData(data)
	if protocols.TLSType(decryptedData[0]) == protocols.TLSFinished {
		c.handshakeState.finishedReceived = true
		return nil
	}
	return nil
}

func (c *TLSClient) decryptData(data []byte) ([]byte, error) {
	serverIV := make([]byte, 16)
	copy(serverIV, data[:16])
	payload := data[16:]

	block, err := aes.NewCipher(c.serverWriteKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, serverIV)
	decryptedData := make([]byte, len(payload))
	mode.CryptBlocks(decryptedData, payload)
	paddingLen := int(decryptedData[len(decryptedData)-1] + 1)
	n := len(decryptedData) - 32 - paddingLen
	n = subtle.ConstantTimeSelect(int(uint32(n)>>31), 0, n)
	decryptedData = decryptedData[:n]
	return decryptedData, nil
}

func (c *TLSClient) encryptData(seqNum uint64, headerBytes, data []byte) ([]byte, error) {
	seqNumBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqNumBytes, seqNum)
	macInput := append(seqNumBytes, headerBytes...)
	macInput = append(macInput, data...)
	mac := hmacSHA256(c.clientMACKey, macInput)
	dataToEncrypt := append(data, mac...)
	paddedData := pkcs7Pad(dataToEncrypt, aes.BlockSize)

	// Encrypt the padded data
	block, err := aes.NewCipher(c.clientWriteKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, c.clientIV)
	encryptedData := make([]byte, len(paddedData))
	mode.CryptBlocks(encryptedData, paddedData)
	return encryptedData, nil
}

// pkcs7Pad pads the data according to the PKCS7 standard
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding - 1)}, padding)
	return append(data, padText...)
}

func (c *TLSClient) ComputeFinishedData() []byte {
	// Compute the finished data using the master secret and message history
	return tlsPRF(c.masterSecret, "client finished", finishedHash(c.messageHistory), 12)
}

func (c *TLSClient) ResetTlsLayer() {
	c.tlsLayer.Alert = c.tlsLayer.Alert[:0]
	c.tlsLayer.Handshake = c.tlsLayer.Handshake[:0]
	c.tlsLayer.ChangeCipherSpec = c.tlsLayer.ChangeCipherSpec[:0]
	c.tlsLayer.AppData = c.tlsLayer.AppData[:0]
	c.tlsLayer.Heartbeat = c.tlsLayer.Heartbeat[:0]
}

func computeMasterSecret(preMasterSecret, clientRandom, serverRandom []byte) []byte {
	seed := append(clientRandom, serverRandom...)
	return tlsPRF(preMasterSecret, "master secret", seed, 48)
}

func tlsPRF(secret []byte, label string, seed []byte, length int) []byte {
	labelAndSeed := append([]byte(label), seed...)
	return pHash(secret, labelAndSeed, length)
}

func pHash(secret, seed []byte, length int) []byte {
	result := make([]byte, length)
	h := hmac.New(sha256.New, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < length {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		copy(result[j:], b[:min(len(b), length-j)])
		j += len(b)

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
	return result
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func finishedHash(handshakeMessages [][]byte) []byte {
	var allMessages []byte
	for _, msg := range handshakeMessages {
		allMessages = append(allMessages, msg...)
	}
	hash := sha256.Sum256(allMessages)
	return hash[:]
}

func DeriveKeys(masterSecret, clientRandom, serverRandom []byte) (clientMACKey, serverMACKey, clientWriteKey, serverWriteKey, clientIV, serverIV []byte) {
	// Derive key material using the PRF
	keyMaterial := tlsPRF(masterSecret, "key expansion", append(serverRandom, clientRandom...), 128)

	keyLen := 16    // length of AES-128 key
	macKeyLen := 32 // length of HMAC-SHA256 key
	ivLen := 16     // length of IV for AES-CBC

	clientMACKey = keyMaterial[:macKeyLen]
	keyMaterial = keyMaterial[macKeyLen:]
	serverMACKey = keyMaterial[:macKeyLen]
	keyMaterial = keyMaterial[macKeyLen:]
	clientWriteKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverWriteKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	clientIV = keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]
	serverIV = keyMaterial[:ivLen]

	return clientMACKey, serverMACKey, clientWriteKey, serverWriteKey, clientIV, serverIV
}

func (c *TLSClient) SendRcvHeartBeat(length uint16, data string) (string, error) {
	c.ResetTlsLayer()
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, length)
	heartBeatData := make([]byte, 0, 3+len(data))
	dataBuffer := bytes.NewBuffer(heartBeatData)
	dataBuffer.WriteByte(byte(protocols.Heartbeat_Request))
	dataBuffer.Write(lengthBytes)
	dataBuffer.WriteString(data)

	headerLength := len(data) + 3
	binary.BigEndian.PutUint16(lengthBytes, uint16(headerLength))
	heartBeatHeader := make([]byte, 0, 5)
	headerBuffer := bytes.NewBuffer(heartBeatHeader)
	headerBuffer.WriteByte(byte(protocols.TLSHearbeat))
	headerBuffer.WriteByte(0x03)
	headerBuffer.WriteByte(0x03)
	headerBuffer.Write(lengthBytes)

	encryptedData, err := c.encryptData(c.sendSeqNum, headerBuffer.Bytes(), dataBuffer.Bytes())
	if err != nil {
		return "", err
	}
	encryptedWithIV := make([]byte, len(encryptedData)+len(c.clientIV))
	copy(encryptedWithIV, c.clientIV)
	copy(encryptedWithIV[len(c.clientIV):], encryptedData)

	heartBeatRecord := protocols.TLSHeartbeatRecord{
		TLSRecordHeader: protocols.TLSRecordHeader{
			ContentType: protocols.TLSHearbeat,
			Version:     0x0303,
			Length:      uint16(len(encryptedWithIV)),
		},
		EncryptedHeartBeatMessage: protocols.EncryptedHeartBeatMessage{
			CipherHeartBeat: encryptedWithIV,
		},
	}

	c.tlsLayer.Heartbeat = append(c.tlsLayer.Heartbeat, heartBeatRecord)

	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, c.tlsLayer)
	if err != nil {
		return "", err
	}
	_, err = c.conn.Write(buf.Bytes())
	if err != nil {
		return "", err
	}
	c.sendSeqNum += 1

	response, err := c.socket.Recv()
	tcpLayer := utils.GetTCPLayer(response)
	tlsLayer := protocols.TLS{}
	if len(tcpLayer.Payload) == 0 {
		return "", nil
	}
	err = tlsLayer.DecodeFromBytes(tcpLayer.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		return "", err
	}
	if len(tlsLayer.Heartbeat) > 0 {
		decryptedData, _ := c.decryptData(tlsLayer.Heartbeat[0].EncryptedHeartBeatMessage.CipherHeartBeat)
		heartBeatResponse := string(decryptedData[3:])
		return heartBeatResponse, nil
	} else if len(tlsLayer.Alert) > 0 {
		decryptedData, _ := c.decryptData(tlsLayer.Alert[0].EncryptedMsg)
		return string(decryptedData), nil
	}
	return "", nil
}

func (c *TLSClient) SendRcvAppData(data string) (string, error) {
	c.ResetTlsLayer()
	appData := make([]byte, 0, len(data))
	dataBuffer := bytes.NewBuffer(appData)
	dataBuffer.WriteString(data)

	lengthBytes := make([]byte, 2)
	headerLength := len(data)
	binary.BigEndian.PutUint16(lengthBytes, uint16(headerLength))
	appDataHeader := make([]byte, 0, 5)
	headerBuffer := bytes.NewBuffer(appDataHeader)
	headerBuffer.WriteByte(byte(protocols.TLSApplicationData))
	headerBuffer.WriteByte(0x03)
	headerBuffer.WriteByte(0x03)
	headerBuffer.Write(lengthBytes)

	encryptedData, err := c.encryptData(c.sendSeqNum, headerBuffer.Bytes(), dataBuffer.Bytes())
	if err != nil {
		return "", err
	}
	encryptedWithIV := make([]byte, len(encryptedData)+len(c.clientIV))
	copy(encryptedWithIV, c.clientIV)
	copy(encryptedWithIV[len(c.clientIV):], encryptedData)

	appDataRecord := protocols.TLSAppDataRecord{
		TLSRecordHeader: protocols.TLSRecordHeader{
			ContentType: protocols.TLSApplicationData,
			Version:     0x0303,
			Length:      uint16(len(encryptedWithIV)),
		},
		Payload: encryptedWithIV,
	}

	c.tlsLayer.AppData = append(c.tlsLayer.AppData, appDataRecord)

	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, c.tlsLayer)
	if err != nil {
		return "", err
	}
	_, err = c.conn.Write(buf.Bytes())
	if err != nil {
		return "", err
	}
	c.sendSeqNum += 1

	response, err := c.socket.Recv()
	tcpLayer := utils.GetTCPLayer(response)
	tlsLayer := protocols.TLS{}
	if len(tcpLayer.Payload) == 0 {
		return "", nil
	}
	err = tlsLayer.DecodeFromBytes(tcpLayer.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		return "", err
	}
	if len(tlsLayer.AppData) > 0 {
		decryptedData, _ := c.decryptData(tlsLayer.AppData[0].Payload)
		return string(decryptedData), nil
	} else if len(tlsLayer.Alert) > 0 {
		decryptedData, _ := c.decryptData(tlsLayer.Alert[0].EncryptedMsg)
		return string(decryptedData), nil
	}
	return "", nil
}

func NewTLSClientSession(ip string) (*TLSClient, error) {
	exec.Command("iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type", "destination-unreachable", "-j", "DROP").Run()

	// Connect to the server
	conn, err := net.Dial("tcp", ip)
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	socket, _ := supersocket.NewSuperSocket("eth0", "dst host "+utils.IPbyInt("eth0")+" and tcp port "+strconv.Itoa(localAddr.Port))

	if err != nil {
		return nil, fmt.Errorf("Error connecting to server: ", err)
	}

	// Create the TLS client
	tlsClient := NewTLSClient(conn, ip, socket)

	// Send the ClientHello message
	err = tlsClient.SendClientHello()
	if err != nil {
		return nil, fmt.Errorf("Error sending ClientHello: ", err)
	}

	// Wait for the handshake to complete
	err = tlsClient.waitForHandshake()
	if err != nil {
		return nil, fmt.Errorf("Error waiting for handshake: ", err)
	}
	fmt.Println("HANDSHAKE FINISHED")
	return tlsClient, nil
}
