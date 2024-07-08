// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package protocols

import (
	"encoding/binary"
	"errors"
	"github.com/google/gopacket"
	"reflect"
)

type TLSCipherSuite uint16

const (
	TLS_NULL_WITH_NULL_NULL             TLSCipherSuite = 0x0000
	TLS_RSA_WITH_NULL_MD5               TLSCipherSuite = 0x0001
	TLS_RSA_WITH_NULL_SHA               TLSCipherSuite = 0x0002
	TLS_RSA_WITH_NULL_SHA256            TLSCipherSuite = 0x003B
	TLS_RSA_WITH_RC4_128_MD5            TLSCipherSuite = 0x0004
	TLS_RSA_WITH_RC4_128_SHA            TLSCipherSuite = 0x0005
	TLS_RSA_WITH_3DES_EDE_CBC_SHA       TLSCipherSuite = 0x000A
	TLS_RSA_WITH_AES_128_CBC_SHA        TLSCipherSuite = 0x002F
	TLS_RSA_WITH_AES_256_CBC_SHA        TLSCipherSuite = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256     TLSCipherSuite = 0x003C
	TLS_RSA_WITH_AES_256_CBC_SHA256     TLSCipherSuite = 0x003D
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA    TLSCipherSuite = 0x000D
	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA    TLSCipherSuite = 0x0010
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA   TLSCipherSuite = 0x0013
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA   TLSCipherSuite = 0x0016
	TLS_DH_DSS_WITH_AES_128_CBC_SHA     TLSCipherSuite = 0x0030
	TLS_DH_RSA_WITH_AES_128_CBC_SHA     TLSCipherSuite = 0x0031
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA    TLSCipherSuite = 0x0032
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA    TLSCipherSuite = 0x0033
	TLS_DH_DSS_WITH_AES_256_CBC_SHA     TLSCipherSuite = 0x0036
	TLS_DH_RSA_WITH_AES_256_CBC_SHA     TLSCipherSuite = 0x0037
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA    TLSCipherSuite = 0x0038
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA    TLSCipherSuite = 0x0039
	TLS_DH_DSS_WITH_AES_128_CBC_SHA256  TLSCipherSuite = 0x003E
	TLS_DH_RSA_WITH_AES_128_CBC_SHA256  TLSCipherSuite = 0x003F
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 TLSCipherSuite = 0x0040
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 TLSCipherSuite = 0x0067
	TLS_DH_DSS_WITH_AES_256_CBC_SHA256  TLSCipherSuite = 0x0068
	TLS_DH_RSA_WITH_AES_256_CBC_SHA256  TLSCipherSuite = 0x0069
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 TLSCipherSuite = 0x006A
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 TLSCipherSuite = 0x006B
	TLS_DH_ANON_WITH_RC4_128_MD5        TLSCipherSuite = 0x0018
	TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA   TLSCipherSuite = 0x001B
	TLS_DH_ANON_WITH_AES_128_CBC_SHA    TLSCipherSuite = 0x0034
	TLS_DH_ANON_WITH_AES_256_CBC_SHA    TLSCipherSuite = 0x006A
	TLS_DH_ANON_WITH_AES_128_CBC_SHA256 TLSCipherSuite = 0x006C
	TLS_DH_ANON_WITH_AES_256_CBC_SHA256 TLSCipherSuite = 0x006D
)

var TLSCipherSuiteMap = map[uint16]TLSCipherSuite{
	0x0000: TLS_NULL_WITH_NULL_NULL,
	0x0001: TLS_RSA_WITH_NULL_MD5,
	0x0002: TLS_RSA_WITH_NULL_SHA,
	0x003B: TLS_RSA_WITH_NULL_SHA256,
	0x0004: TLS_RSA_WITH_RC4_128_MD5,
	0x0005: TLS_RSA_WITH_RC4_128_SHA,
	0x000A: TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	0x002F: TLS_RSA_WITH_AES_128_CBC_SHA,
	0x0035: TLS_RSA_WITH_AES_256_CBC_SHA,
	0x003C: TLS_RSA_WITH_AES_128_CBC_SHA256,
	0x003D: TLS_RSA_WITH_AES_256_CBC_SHA256,
	0x000D: TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
	0x0010: TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
	0x0013: TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
	0x0016: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	0x0030: TLS_DH_DSS_WITH_AES_128_CBC_SHA,
	0x0031: TLS_DH_RSA_WITH_AES_128_CBC_SHA,
	0x0032: TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	0x0033: TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	0x0036: TLS_DH_DSS_WITH_AES_256_CBC_SHA,
	0x0037: TLS_DH_RSA_WITH_AES_256_CBC_SHA,
	0x0038: TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
	0x0039: TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	0x003E: TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
	0x003F: TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
	0x0040: TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
	0x0067: TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
	0x0068: TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
	0x0069: TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
	0x006A: TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
	0x006B: TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	0x0018: TLS_DH_ANON_WITH_RC4_128_MD5,
	0x001B: TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA,
	0x0034: TLS_DH_ANON_WITH_AES_128_CBC_SHA,
	0x006C: TLS_DH_ANON_WITH_AES_128_CBC_SHA256,
	0x006D: TLS_DH_ANON_WITH_AES_256_CBC_SHA256,
}

// TLSHandshakeRecord defines the structure of a Handshare Record
type TLSHandshakeRecord struct {
	TLSRecordHeader
	ClientHello
	ServerHelloDone
	ServerHello
	Certificate
	ClientKeyExchange
	Finished
	EncryptedHandshakeMessage
}

type Header struct {
	ContentType TLSType
	Version     TLSVersion
	Length      uint32
}

type ServerHelloDone struct {
	Header
}

type ClientHello struct {
	Header
	Gmt_Unix_Time              uint32
	Random                     []byte
	SessionIDLength            byte
	SessionID                  []byte
	CipherSuiteLength          uint16
	CipherSuite                []TLSCipherSuite
	CompressionAlgorithmLength uint8
	CompressionAlgorithm       byte
}

type ServerHello struct {
	Header
	Gmt_Unix_Time        uint32
	Random               []byte
	SessionIDLength      byte
	SessionID            []byte
	CipherSuite          TLSCipherSuite
	CompressionAlgorithm byte
}

type Certificate struct {
	Header
	CertData  []byte
	PublicKey interface{}
}

type ClientKeyExchange struct {
	Header
	EncryptedPreMasterSecretLength uint16
	EncryptedPreMasterSecret       []byte
}

type Finished struct {
	Header
	Data []byte
}

type EncryptedHandshakeMessage struct {
	CipherData []byte
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.TLSRecordHeader.ContentType = h.ContentType
	t.TLSRecordHeader.Version = h.Version
	t.TLSRecordHeader.Length = h.Length

	contentType := TLSType(data[0])

	switch contentType {
	case TLSClientHello:
		var clientHello ClientHello
		e := clientHello.decodeFromBytes(data, df)
		if e != nil {
			return e
		}
		t.ClientHello = clientHello
		return nil
	case TLSServerHello:
		var serverHello ServerHello
		e := serverHello.decodeFromBytes(data, df)
		if e != nil {
			return e
		}
		t.ServerHello = serverHello
		return nil
	case TLSClientKeyExchange:
		var clientKeyExchange ClientKeyExchange
		e := clientKeyExchange.decodeFromBytes(data, df)
		if e != nil {
			return e
		}
		t.ClientKeyExchange = clientKeyExchange
		return nil
	case TLSCertificate:
		var certificate Certificate
		e := certificate.decodeFromBytes(data, df)
		if e != nil {
			return e
		}
		t.Certificate = certificate
		return nil
	case TLSServerHelloDone:
		var serverHelloDone ServerHelloDone
		e := serverHelloDone.decodeFromBytes(data, df)
		if e != nil {
			return e
		}
		t.ServerHelloDone = serverHelloDone
		return nil
	case TLSFinished:
		var finished Finished
		e := finished.decodeFromBytes(data, df)
		if e != nil {
			return e
		}
		t.Finished = finished
		return nil
	default:
		var encryptedHandshake EncryptedHandshakeMessage
		e := encryptedHandshake.decodeFromBytes(data, df)
		if e != nil {
			return e
		}
		t.EncryptedHandshakeMessage = encryptedHandshake
		return nil
	}
	return nil
}

func (c *ClientHello) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	c.Header.ContentType = TLSType(data[0])
	slice := make([]byte, 3)
	copy(slice, data[1:4])
	length := binary.BigEndian.Uint32(append([]byte{0x00}, slice...))
	c.Header.Length = length
	c.Header.Version = TLSVersion(binary.BigEndian.Uint16(data[4:6]))
	c.Gmt_Unix_Time = binary.BigEndian.Uint32(data[6:10])
	c.Random = make([]byte, 28)
	copy(c.Random, data[10:38])
	c.SessionIDLength = data[38]
	if c.SessionIDLength != 0 {
		copy(c.SessionID, data[39:39+c.SessionIDLength])
		off := uint16(39 + c.SessionIDLength)
		c.CipherSuiteLength = binary.BigEndian.Uint16(data[off : off+2])
		off += 2
		for i := uint16(2); i <= c.CipherSuiteLength; i += 2 {
			c.CipherSuite = append(c.CipherSuite, TLSCipherSuiteMap[binary.BigEndian.Uint16(data[off+i-2:off+i])])
		}
		off += c.CipherSuiteLength
		c.CompressionAlgorithmLength = data[off]
		c.CompressionAlgorithm = data[off+1]
		return nil
	}
	c.CipherSuiteLength = binary.BigEndian.Uint16(data[39:41])
	for i := uint16(2); i <= c.CipherSuiteLength; i += 2 {
		c.CipherSuite = append(c.CipherSuite, TLSCipherSuiteMap[binary.BigEndian.Uint16(data[41+i-2:41+i])])
	}
	c.CompressionAlgorithmLength = data[41+c.CipherSuiteLength]
	c.CompressionAlgorithm = data[42+c.CipherSuiteLength]

	return nil
}

func (s *ServerHello) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	s.Header.ContentType = TLSType(data[0])
	slice := make([]byte, 3)
	copy(slice, data[1:4])
	length := binary.BigEndian.Uint32(append([]byte{0x00}, slice...))
	s.Header.Length = length
	s.Header.Version = TLSVersion(binary.BigEndian.Uint16(data[4:6]))
	s.Gmt_Unix_Time = binary.BigEndian.Uint32(data[6:10])
	s.Random = make([]byte, 28)
	copy(s.Random, data[10:38])
	s.SessionIDLength = data[38]
	if s.SessionIDLength != 0 {
		copy(s.SessionID, data[39:39+s.SessionIDLength])
		s.CipherSuite = TLSCipherSuiteMap[binary.BigEndian.Uint16(data[39+s.SessionIDLength:41+s.SessionIDLength])]
		s.CompressionAlgorithm = data[41+s.SessionIDLength]
		return nil
	}
	s.CipherSuite = TLSCipherSuiteMap[binary.BigEndian.Uint16(data[39:41])]
	s.CompressionAlgorithm = data[41]

	return nil
}
func (c *ClientKeyExchange) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	c.Header.ContentType = TLSType(data[0])
	slice := make([]byte, 3)
	copy(slice, data[1:4])
	length := binary.BigEndian.Uint32(append([]byte{0x00}, slice...))
	c.Header.Length = length
	c.EncryptedPreMasterSecretLength = binary.BigEndian.Uint16(data[4:6])
	copy(c.EncryptedPreMasterSecret, data[6:6+c.EncryptedPreMasterSecretLength])
	return nil
}
func (c *Certificate) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	c.Header.ContentType = TLSType(data[0])
	slice := make([]byte, 3)
	copy(slice, data[1:4])
	length := binary.BigEndian.Uint32(append([]byte{0x00}, slice...))
	c.Header.Length = length

	cert_length := make([]byte, 3)
	copy(cert_length, data[7:10])
	cert_length_int := binary.BigEndian.Uint32(append([]byte{0x00}, cert_length...))
	c.CertData = make([]byte, cert_length_int)
	copy(c.CertData, data[10:10+cert_length_int])
	return nil
}
func (f *Finished) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	f.Data = make([]byte, len(data))
	copy(f.Data, data)
	return nil
}

func (e *EncryptedHandshakeMessage) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	e.CipherData = make([]byte, len(data))
	copy(e.CipherData, data)
	return nil
}

func (s *ServerHelloDone) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	s.Header.ContentType = TLSType(data[0])
	slice := make([]byte, 3)
	copy(slice, data[1:4])
	length := binary.BigEndian.Uint32(append([]byte{0x00}, slice...))
	s.Header.Length = length
	return nil
}

func (t *TLSHandshakeRecord) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions, data []byte, off int) error {
	switch {
	case !reflect.DeepEqual(t.ClientHello, ClientHello{}):
		t.ClientHello.SerializeTo(b, opts, data, off)
		return nil
	case !reflect.DeepEqual(t.ServerHello, ServerHello{}):
		t.ServerHello.SerializeTo(b, opts, data, off)
		return nil
	case !reflect.DeepEqual(t.ServerHelloDone, ServerHelloDone{}):
		t.ServerHelloDone.SerializeTo(b, opts, data, off)
		return nil
	case !reflect.DeepEqual(t.Certificate, Certificate{}):
		t.Certificate.SerializeTo(b, opts, data, off)
		return nil
	case !reflect.DeepEqual(t.ClientKeyExchange, ClientKeyExchange{}):
		t.ClientKeyExchange.SerializeTo(b, opts, data, off)
		return nil
	case !reflect.DeepEqual(t.Finished, Finished{}):
		t.Finished.SerializeTo(b, opts, data, off)
		return nil
	}
	return errors.New("Not supported TLS Handshake Type")
}

func (c *Certificate) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions, data []byte, off int) error {
	//TODO
	return nil
}

func (s *ServerHello) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions, data []byte, off int) error {
	offset := s.Header.SerializeTo(b, opts, data, off)
	binary.BigEndian.PutUint32(data[offset:], s.Gmt_Unix_Time)
	copy(data[offset+4:offset+32], s.Random)
	data[offset+32] = s.SessionIDLength
	if s.SessionIDLength != 0 {
		copy(data[offset+33:offset+33+int(s.SessionIDLength)], s.SessionID)
		binary.BigEndian.PutUint16(data[offset+33+int(s.SessionIDLength):], uint16(s.CipherSuite))
		data[offset+35+int(s.SessionIDLength)] = s.CompressionAlgorithm
		return nil
	}
	binary.BigEndian.PutUint16(data[offset+33:], uint16(s.CipherSuite))
	data[offset+35] = s.CompressionAlgorithm
	return nil
}

func (s *ServerHelloDone) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions, data []byte, off int) error {
	s.Header.SerializeTo(b, opts, data, off)
	return nil
}

func (c *ClientKeyExchange) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions, data []byte, off int) error {
	offset := c.Header.SerializeTo(b, opts, data, off)
	binary.BigEndian.PutUint16(data[offset:offset+2], c.EncryptedPreMasterSecretLength)
	copy(data[offset+2:offset+2+int(c.EncryptedPreMasterSecretLength)], c.EncryptedPreMasterSecret)
	return nil
}

func (f *Finished) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions, data []byte, off int) error {
	if f.Header.Length != 0 && f.Header.ContentType != 0 {
		offset := f.Header.SerializeTo(b, opts, data, off)
		copy(data[offset:offset+len(f.Data)], f.Data)
		return nil
	}
	copy(data[off:off+len(f.Data)], f.Data)
	return nil
}

func (c *ClientHello) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions, data []byte, off int) error {
	offset := c.Header.SerializeTo(b, opts, data, off)
	binary.BigEndian.PutUint32(data[offset:], c.Gmt_Unix_Time)
	copy(data[offset+4:offset+32], c.Random)
	data[offset+32] = c.SessionIDLength
	if c.SessionIDLength != 0 {
		copy(data[offset+33:offset+33+int(c.SessionIDLength)], c.SessionID)
		binary.BigEndian.PutUint16(data[offset+33+int(c.SessionIDLength):], c.CipherSuiteLength)
		for _, cipher := range c.CipherSuite {
			binary.BigEndian.PutUint16(data[offset+35+int(c.SessionIDLength):], uint16(cipher))
			offset += 2
		}
		data[offset+35+int(c.SessionIDLength)] = c.CompressionAlgorithmLength
		data[offset+36+int(c.SessionIDLength)] = c.CompressionAlgorithm
		return nil
	}
	binary.BigEndian.PutUint16(data[offset+33:], c.CipherSuiteLength)
	for _, cipher := range c.CipherSuite {
		binary.BigEndian.PutUint16(data[offset+35:], uint16(cipher))
		offset += 2
	}
	data[offset+35] = c.CompressionAlgorithmLength
	data[offset+36] = c.CompressionAlgorithm
	return nil
}

func (h *Header) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions, data []byte, off int) int {
	if h.Version == 0 {
		data[off] = byte(h.ContentType)
		data[off+1] = byte(h.Length >> 16)
		data[off+2] = byte(h.Length >> 8)
		data[off+3] = byte(h.Length)
		return off + 4
	}
	data[off] = byte(h.ContentType)
	data[off+1] = byte(h.Length >> 16)
	data[off+2] = byte(h.Length >> 8)
	data[off+3] = byte(h.Length)
	binary.BigEndian.PutUint16(data[off+4:], uint16(h.Version))
	return off + 6
}
