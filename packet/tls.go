package packet

import (
	"crypto/rand"
	"fmt"
	"github.com/tiagomdiogo/ScaGo/protocols"
	"time"
)

type TLS struct {
	layer *protocols.TLS
}

type TLSRecordHeader struct {
	layer *protocols.TLSRecordHeader
}

type TLSAlert struct {
	layer *protocols.TLSAlertRecord
}
type TLSCipherChangeSpec struct {
	layer *protocols.TLSChangeCipherSpecRecord
}
type TLSHandashake struct {
	layer *protocols.TLSHandshakeRecord
}
type TLSAppData struct {
	layer *protocols.TLSAppDataRecord
}

type TLSServerHelloDone struct {
	layer *protocols.ServerHelloDone
}

type TLSClientHello struct {
	layer *protocols.ClientHello
}

type TLSServerHello struct {
	layer *protocols.ServerHello
}

type TLSServerKeyExchange struct {
	layer *protocols.ServerKeyExchange
}
type TLSClientKeyExchange struct {
	layer *protocols.ClientKeyExchange
}
type TLSFinished struct {
	layer *protocols.Finished
}

func TLSLayer() *TLS {
	return &TLS{
		layer: &protocols.TLS{},
	}
}

func TLSRecordHeaderLayer() *TLSRecordHeader {
	return &TLSRecordHeader{
		layer: &protocols.TLSRecordHeader{},
	}
}
func TLSChangeCipherSpecLayer() *TLSCipherChangeSpec {
	return &TLSCipherChangeSpec{
		layer: &protocols.TLSChangeCipherSpecRecord{},
	}
}
func TLSAlertLayer() *TLSAlert {
	return &TLSAlert{
		layer: &protocols.TLSAlertRecord{},
	}
}
func TLSHandshakeLayer() *TLSHandashake {
	return &TLSHandashake{
		layer: &protocols.TLSHandshakeRecord{},
	}
}
func TLSAppDataLayer() *TLSAppData {
	return &TLSAppData{
		layer: &protocols.TLSAppDataRecord{},
	}
}

func TLSClientHelloLayer() *TLSClientHello {
	random := make([]byte, 28)
	_, _ = rand.Read(random)
	return &TLSClientHello{
		layer: &protocols.ClientHello{
			Header: protocols.Header{
				ContentType: protocols.TLSClientHello,
				Version:     0x0303,
				Length:      0,
			},
			Gmt_Unix_Time:              uint32(time.Now().Unix()),
			Random:                     random,
			SessionIDLength:            0,
			CompressionAlgorithmLength: 1,
			CompressionAlgorithm:       0,
		},
	}
}

func TLSServerHelloLayer() *TLSServerHello {
	random := make([]byte, 28)
	_, _ = rand.Read(random)
	return &TLSServerHello{
		layer: &protocols.ServerHello{
			Header: protocols.Header{
				ContentType: protocols.TLSServerHello,
				Version:     0x0303,
				Length:      0,
			},
			Gmt_Unix_Time:        uint32(time.Now().Unix()),
			Random:               random,
			SessionIDLength:      0,
			CompressionAlgorithm: 0,
		},
	}
}

func TLSServerHelloDoneLayer() *TLSServerHelloDone {
	return &TLSServerHelloDone{
		layer: &protocols.ServerHelloDone{
			Header: protocols.Header{
				ContentType: protocols.TLSServerHelloDone,
				Length:      0,
			},
		},
	}
}

func TLSServerKeyExchangeLayer() *TLSServerKeyExchange {
	return &TLSServerKeyExchange{
		layer: &protocols.ServerKeyExchange{},
	}
}
func TLSClientKeyExchangeLayer() *TLSClientKeyExchange {
	return &TLSClientKeyExchange{
		layer: &protocols.ClientKeyExchange{},
	}
}
func TLSFinishedLayer() *TLSFinished {
	return &TLSFinished{
		layer: &protocols.Finished{},
	}
}

// Generic Functions
func setRecordHeader(layer *protocols.TLSRecordHeader, header TLSRecordHeader) {
	layer.Length = header.layer.Length
	layer.Version = header.layer.Version
	layer.ContentType = header.layer.ContentType
}

// TLS FUNCTIONS
func (t *TLS) AddRecords(records ...interface{}) {
	for _, record := range records {
		if r, err := record.(*TLSAlert); err {
			alert := protocols.TLSAlertRecord{
				TLSRecordHeader: r.layer.TLSRecordHeader,
				Level:           r.layer.Level,
				Description:     r.layer.Description,
				EncryptedMsg:    r.layer.EncryptedMsg,
			}
			t.layer.Alert = append(t.layer.Alert, alert)
		} else if r, err := record.(*TLSAppData); err {
			app := protocols.TLSAppDataRecord{
				TLSRecordHeader: r.layer.TLSRecordHeader,
				Payload:         r.layer.Payload,
			}
			t.layer.AppData = append(t.layer.AppData, app)
		} else if r, err := record.(*TLSCipherChangeSpec); err {
			cipher := protocols.TLSChangeCipherSpecRecord{
				TLSRecordHeader: r.layer.TLSRecordHeader,
				Message:         r.layer.Message,
			}
			t.layer.ChangeCipherSpec = append(t.layer.ChangeCipherSpec, cipher)
		} else if r, err := record.(*TLSHandashake); err {
			handshake := protocols.TLSHandshakeRecord{
				TLSRecordHeader:   r.layer.TLSRecordHeader,
				ClientHello:       r.layer.ClientHello,
				ServerHello:       r.layer.ServerHello,
				ServerHelloDone:   r.layer.ServerHelloDone,
				ClientKeyExchange: r.layer.ClientKeyExchange,
				ServerKeyExchange: r.layer.ServerKeyExchange,
				Finished:          r.layer.Finished,
			}
			t.layer.Handshake = append(t.layer.Handshake, handshake)
		} else {
			fmt.Errorf("Not Valid TLS Record Type")
			break
		}
	}

}

// TLSRECORD FUNCTIONS
func (t *TLSRecordHeader) SetContentType(content byte) {
	t.layer.ContentType = protocols.TLSType(content)
}

func (t *TLSRecordHeader) SetVersion(version uint16) {
	t.layer.Version = protocols.TLSVersion(version)
}

func (t *TLSRecordHeader) SetLength() {
	return
}

// TLSCHANGECIPHER FUNCTIONS
func (t *TLSCipherChangeSpec) SetRecordHeader(header TLSRecordHeader) {
	setRecordHeader(&t.layer.TLSRecordHeader, header)
}

func (t *TLSCipherChangeSpec) SetMessage(msg byte) {
	t.layer.Message = protocols.TLSchangeCipherSpec(msg)
}

// TLSALERT FUNCTIONS
func (t *TLSAlert) SetRecordHeader(header TLSRecordHeader) {
	setRecordHeader(&t.layer.TLSRecordHeader, header)
}

func (t *TLSAlert) SetLevel(level byte) {
	t.layer.Level = protocols.TLSAlertLevel(level)
}

func (t *TLSAlert) SetDescription(desc byte) {
	t.layer.Description = protocols.TLSAlertDescr(desc)
}

func (t *TLSAlert) SetEncryptedMsg(msg []byte) {
	t.layer.EncryptedMsg = msg
}

// TLSAPPDATA FUNCTIONS
func (t *TLSAppData) SetRecordHeader(header TLSRecordHeader) {
	setRecordHeader(&t.layer.TLSRecordHeader, header)
}

func (t *TLSAppData) SetPayload(payload []byte) {
	t.layer.Payload = payload
}

// TLSHANDSHAKE FUNCTIONS
func (t *TLSHandashake) SetRecordHeader(header TLSRecordHeader) {
	setRecordHeader(&t.layer.TLSRecordHeader, header)
}

func (t *TLSHandashake) SetPayload(payload interface{}) error {
	if l, err := payload.(*TLSClientHello); err {
		clientHello := protocols.ClientHello{
			Header: protocols.Header{
				ContentType: l.layer.Header.ContentType,
				Length:      l.layer.Header.Length,
				Version:     l.layer.Header.Version,
			},
			Gmt_Unix_Time:              l.layer.Gmt_Unix_Time,
			Random:                     l.layer.Random,
			SessionID:                  l.layer.SessionID,
			CipherSuiteLength:          l.layer.CipherSuiteLength,
			CipherSuite:                l.layer.CipherSuite,
			CompressionAlgorithmLength: l.layer.CompressionAlgorithm,
			CompressionAlgorithm:       l.layer.CompressionAlgorithmLength,
		}
		t.layer.ClientHello = clientHello
		return nil
	} else if l, err := payload.(*TLSServerHello); err {
		serverHello := protocols.ServerHello{
			Header: protocols.Header{
				ContentType: l.layer.Header.ContentType,
				Length:      l.layer.Header.Length,
				Version:     l.layer.Header.Version,
			},
			Gmt_Unix_Time:        l.layer.Gmt_Unix_Time,
			Random:               l.layer.Random,
			SessionID:            l.layer.SessionID,
			CipherSuite:          l.layer.CipherSuite,
			CompressionAlgorithm: l.layer.CompressionAlgorithm,
		}
		t.layer.ServerHello = serverHello
		return nil
	} /*else if l, err := payload.(*TLSServerKeyExchange); err {
		return nil
	} */else if l, err := payload.(*TLSServerHelloDone); err {
		serverHelloDone := protocols.ServerHelloDone{
			Header: protocols.Header{
				ContentType: l.layer.Header.ContentType,
				Length:      l.layer.Header.Length,
			},
		}
		t.layer.ServerHelloDone = serverHelloDone
		return nil
	} /*else if l, err := payload.(*TLSClientKeyExchange); err {
		return nil
	} else if l, err := payload.(*TLSFinished); err {
		return nil
	} */else {
		return fmt.Errorf("Payload type does not match the type determined by ContentType ")
	}
}

// CLIENT HELLO FUNCTIONS

func (t *TLSClientHello) SetCipherSuites(ciphers ...uint16) {
	for _, cipher := range ciphers {
		if c, err := protocols.TLSCipherSuiteMap[cipher]; err {
			t.layer.CipherSuite = append(t.layer.CipherSuite, c)
		}
	}
	t.layer.CipherSuiteLength = uint16(2 * len(t.layer.CipherSuite))
}

func (t *TLSClientHello) SetSessionID(id []byte) {
	sessionId := make([]byte, len(id))
	copy(sessionId, id)
	t.layer.SessionID = sessionId
	t.layer.SessionIDLength = byte(len(sessionId))
}

// SERVER HELLO FUNCTIONS

func (t *TLSServerHello) SetCipherSuites(cipher uint16) {
	if c, err := protocols.TLSCipherSuiteMap[cipher]; err {
		t.layer.CipherSuite = c
	}
}

func (t *TLSServerHello) SetSessionID(id []byte) {
	sessionId := make([]byte, len(id))
	copy(sessionId, id)
	t.layer.SessionID = sessionId
	t.layer.SessionIDLength = byte(len(sessionId))
}

func (t *TLS) Layer() *protocols.TLS {
	return t.layer
}
