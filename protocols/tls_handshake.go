// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package protocols

import (
	"encoding/binary"
	"github.com/google/gopacket"
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
	ServerKeyExchange
	ClientKeyExchange
	Finished
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

type ServerKeyExchange struct {
	Header
}

type ClientKeyExchange struct {
	Header
}

type Finished struct {
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
	case TLSServerKeyExchange:
		var serverKeyExchange ServerKeyExchange
		e := serverKeyExchange.decodeFromBytes(data, df)
		if e != nil {
			return e
		}
		t.ServerKeyExchange = serverKeyExchange
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
	}
	return nil
}

func (c *ClientHello) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	c.Header.ContentType = TLSType(data[0])
	length := binary.BigEndian.Uint32(data[1:4])
	c.Header.Length = length & 0xFFFFFF
	c.Header.Version = TLSVersion(binary.BigEndian.Uint16(data[4:6]))
	c.Gmt_Unix_Time = binary.BigEndian.Uint32(data[6:10])
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
	length := binary.BigEndian.Uint32(data[1:4])
	s.Header.Length = length & 0xFFFFFF
	s.Header.Version = TLSVersion(binary.BigEndian.Uint16(data[4:6]))
	s.Gmt_Unix_Time = binary.BigEndian.Uint32(data[6:10])
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
	length := binary.BigEndian.Uint32(data[1:4])
	c.Header.Length = length & 0xFFFFFF
	return nil
}
func (s *ServerKeyExchange) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	s.Header.ContentType = TLSType(data[0])
	length := binary.BigEndian.Uint32(data[1:4])
	s.Header.Length = length & 0xFFFFFF
	return nil
}
func (f *Finished) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	return nil
}

func (s *ServerHelloDone) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	s.Header.ContentType = TLSType(data[0])
	length := binary.BigEndian.Uint32(data[1:4])
	s.Header.Length = length & 0xFFFFFF
	return nil
}
