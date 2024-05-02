package protocols

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LayerTypeIKEv2 = gopacket.RegisterLayerType(8000, gopacket.LayerTypeMetadata{Name: "IKEv2", Decoder: gopacket.DecodeFunc(decodeIKEv2Packet)})

type IKEv2PayloadTypes byte
type IKEv2ExchangeTypes byte
type IKEv2ProtocolTypes byte
type IKEv2TransformTypes byte
type IKEv2TransformType1 byte
type IKEv2TransformType2 byte
type IKEv2TransformType3 byte
type IKEv2TransformType4 byte
type IKEv2TransformType5 byte
type IKEv2NotifyMessagesType uint16

// see https://www.iana.org/assignments/ikev2-parameters for details
const (
	IKEv2PayloadNone          IKEv2PayloadTypes = 0
	IKEv2PayloadProposal      IKEv2PayloadTypes = 2  // used only inside the SA payload
	IKEv2PayloadTransform     IKEv2PayloadTypes = 3  // used only inside the SA payload
	IKEv2PayloadSA            IKEv2PayloadTypes = 33 // Security Association
	IKEv2PayloadKE            IKEv2PayloadTypes = 34 // Key Exchange
	IKEv2PayloadIDi           IKEv2PayloadTypes = 35 // ID Initiator
	IKEv2PayloadIDr           IKEv2PayloadTypes = 36 // ID Responder
	IKEv2PayloadCERT          IKEv2PayloadTypes = 37 // Certificate
	IKEv2PayloadCERTREQ       IKEv2PayloadTypes = 38 // Certificate Request
	IKEv2PayloadAUTH          IKEv2PayloadTypes = 39 // Authentication
	IKEv2PayloadNonce         IKEv2PayloadTypes = 40 // Nonce
	IKEv2PayloadNotify        IKEv2PayloadTypes = 41 // Notify
	IKEv2PayloadDelete        IKEv2PayloadTypes = 42 // Delete
	IKEv2PayloadVendorID      IKEv2PayloadTypes = 43 // Vendor ID
	IKEv2PayloadTSi           IKEv2PayloadTypes = 44 // Traffic Selector - Initiator
	IKEv2PayloadTSr           IKEv2PayloadTypes = 45 // Traffic Selector - Responder
	IKEv2PayloadEncrypted     IKEv2PayloadTypes = 46 // Encrypted Payload
	IKEv2PayloadCP            IKEv2PayloadTypes = 47 // Configuration Payload
	IKEv2PayloadEAP           IKEv2PayloadTypes = 48 // Extensible Authentication Protocol
	IKEv2PayloadGSPM          IKEv2PayloadTypes = 49 // Generic Secure Password Method
	IKEv2PayloadIDg           IKEv2PayloadTypes = 50 // Group ID
	IKEv2PayloadGSA           IKEv2PayloadTypes = 51 // Group Security Association
	IKEv2PayloadKD            IKEv2PayloadTypes = 52 // Key Download
	IKEv2PayloadEncryptedFrag IKEv2PayloadTypes = 53 // Encrypted Fragment
	IKEv2PayloadPS            IKEv2PayloadTypes = 54 // Payload Security
)

func (ip IKEv2PayloadTypes) String() string {
	switch ip {
	default:
		return "Unknown"
	case IKEv2PayloadNone:
		return "None"
	case IKEv2PayloadProposal:
		return "Proposal"
	case IKEv2PayloadTransform:
		return "Transform"
	case IKEv2PayloadSA:
		return "SA"
	case IKEv2PayloadKE:
		return "KE"
	case IKEv2PayloadIDi:
		return "IDi"
	case IKEv2PayloadIDr:
		return "IDr"
	case IKEv2PayloadCERT:
		return "CERT"
	case IKEv2PayloadCERTREQ:
		return "CERTREQ"
	case IKEv2PayloadAUTH:
		return "AUTH"
	case IKEv2PayloadNonce:
		return "Nonce"
	case IKEv2PayloadNotify:
		return "Notify"
	case IKEv2PayloadDelete:
		return "Delete"
	case IKEv2PayloadVendorID:
		return "VendorID"
	case IKEv2PayloadTSi:
		return "TSi"
	case IKEv2PayloadTSr:
		return "TSr"
	case IKEv2PayloadEncrypted:
		return "Encrypted"
	case IKEv2PayloadCP:
		return "CP"
	case IKEv2PayloadEAP:
		return "EAP"
	case IKEv2PayloadGSPM:
		return "GSPM"
	case IKEv2PayloadIDg:
		return "IDg"
	case IKEv2PayloadGSA:
		return "GSA"
	case IKEv2PayloadKD:
		return "KD"
	case IKEv2PayloadEncryptedFrag:
		return "Encrypted_Fragment"
	case IKEv2PayloadPS:
		return "PS"
	}
}

const (
	IKEv2SAInit        IKEv2ExchangeTypes = 34 // Identity Protection (Main Mode)
	IKEv2Auth          IKEv2ExchangeTypes = 35 // Authentication Only
	IKEv2CreateChild   IKEv2ExchangeTypes = 36 // Aggressive Mode
	IKEv2Informational IKEv2ExchangeTypes = 37 // Informational
	IKEv2SessionResume IKEv2ExchangeTypes = 38 // Transaction (Config Mode)
	IKEv2Intermediate  IKEv2ExchangeTypes = 43 // Quick Mode
	IKEv2FollowUpKE    IKEv2ExchangeTypes = 44 // Multiple Key Exchanges
)

func (ie IKEv2ExchangeTypes) String() string {
	switch ie {
	default:
		return "Unknown"
	case IKEv2SAInit:
		return "IKE_SA_INIT"
	case IKEv2Auth:
		return "IKE_AUTH"
	case IKEv2CreateChild:
		return "CREATE_CHILD_SA"
	case IKEv2Informational:
		return "INFORMATIONAL"
	case IKEv2SessionResume:
		return "IKE_SESSION_RESUME"
	case IKEv2Intermediate:
		return "IKE_INTERMEDIATE"
	case IKEv2FollowUpKE:
		return "IKE_FOLLOWUP_KE"
	}
}

const (
	IKE IKEv2ProtocolTypes = 1
	AH  IKEv2ProtocolTypes = 2
	ESP IKEv2ProtocolTypes = 3
)

func (ip IKEv2ProtocolTypes) String() string {
	switch ip {
	default:
		return "Unknown"
	case IKE:
		return "IKE"
	case AH:
		return "AH"
	case ESP:
		return "ESP"
	}
}

const (
	ENCR  IKEv2TransformTypes = 1 // Encryption Algorithm
	PRF   IKEv2TransformTypes = 2 // Pseudorandom Algorithm
	INTEG IKEv2TransformTypes = 3 // Integrity Algorithm
	DH    IKEv2TransformTypes = 4 // Diffie-Hellman Group
	ESN   IKEv2TransformTypes = 5 // Extended Sequence Numbers
)

func (it IKEv2TransformTypes) String() string {
	switch it {
	default:
		return "Unknown"
	case ENCR:
		return "Encryption"
	case PRF:
		return "Pseudorandom"
	case INTEG:
		return "Integrity"
	case DH:
		return "Diffie-Hellman Group"
	case ESN:
		return "Extended Sequence Numbers"
	}
}

const (
	ENCR_DES_IV64 IKEv2TransformType1 = 1
	ENCR_DES      IKEv2TransformType1 = 2
	ENCR_3DES     IKEv2TransformType1 = 3
	ENCR_RC5      IKEv2TransformType1 = 4
	ENCR_IDEA     IKEv2TransformType1 = 5
	ENCR_CAST     IKEv2TransformType1 = 6
	ENCR_BLOWFISH IKEv2TransformType1 = 7
	ENCR_3IDEA    IKEv2TransformType1 = 8
	ENCR_DES_IV32 IKEv2TransformType1 = 9
	ENCR_NULL     IKEv2TransformType1 = 11
	ENCR_AES_CBC  IKEv2TransformType1 = 12
	ENCR_AES_CTR  IKEv2TransformType1 = 13
)

func (it1 IKEv2TransformType1) String() string {
	switch it1 {
	default:
		return "Unknow"
	case ENCR_DES_IV64:
		return "DES-IV64"
	case ENCR_DES:
		return "DES"
	case ENCR_3DES:
		return "3DES"
	case ENCR_RC5:
		return "RC5"
	case ENCR_IDEA:
		return "IDEA"
	case ENCR_CAST:
		return "CAST"
	case ENCR_BLOWFISH:
		return "BLOWFISH"
	case ENCR_3IDEA:
		return "3IDEA"
	case ENCR_DES_IV32:
		return "DES-IV32"
	case ENCR_NULL:
		return "NULL"
	case ENCR_AES_CBC:
		return "AES-CBC"
	case ENCR_AES_CTR:
		return "AES-CTR"
	}
}

const (
	PRF_HMAC_MD5          IKEv2TransformType2 = 1
	PRF_HMAC_SHA1         IKEv2TransformType2 = 2
	PRF_HMAC_TIGER        IKEv2TransformType2 = 3
	PRF_AES128_XCBC       IKEv2TransformType2 = 4
	PRF_HMAC_SHA2_256     IKEv2TransformType2 = 5
	PRF_HMAC_SHA2_384     IKEv2TransformType2 = 6
	PRF_HMAC_SHA2_512     IKEv2TransformType2 = 7
	PRF_AES128_CMAC       IKEv2TransformType2 = 8
	PRF_HMAC_STREEBOG_512 IKEv2TransformType2 = 9
)

func (it2 IKEv2TransformType2) String() string {
	switch it2 {
	default:
		return "Unknow"
	case PRF_HMAC_MD5:
		return "PRF_HMAC_MD5"
	case PRF_HMAC_SHA1:
		return "PRF_HMAC_SHA1"
	case PRF_HMAC_TIGER:
		return "PRF_HMAC_TIGER"
	case PRF_AES128_XCBC:
		return "PRF_AES128_XCBC"
	case PRF_HMAC_SHA2_256:
		return "PRF_HMAC_SHA2_256"
	case PRF_HMAC_SHA2_384:
		return "PRF_HMAC_SHA2_384"
	case PRF_HMAC_SHA2_512:
		return "PRF_HMAC_SHA2_512"
	case PRF_AES128_CMAC:
		return "PRF_AES128_CMAC"
	case PRF_HMAC_STREEBOG_512:
		return "PRF_HMAC_STREEBOG_512"
	}
}

const (
	AUTH_NONE          IKEv2TransformType3 = 0
	AUTH_HMAC_MD5_96   IKEv2TransformType3 = 1
	AUTH_HMAC_SHA1_96  IKEv2TransformType3 = 2
	AUTH_DES_MAC       IKEv2TransformType3 = 3
	AUTH_KPDK_MD5      IKEv2TransformType3 = 4
	AUTH_AES_XCBC_96   IKEv2TransformType3 = 5
	AUTH_HMAC_MD5_128  IKEv2TransformType3 = 6
	AUTH_HMAC_SHA1_160 IKEv2TransformType3 = 7
	AUTH_AES_CMAC_96   IKEv2TransformType3 = 8
	AUTH_AES_128_GMAC  IKEv2TransformType3 = 9
	AUTH_AES_192_GMAC  IKEv2TransformType3 = 10
	AUTH_AES_256_GMAC  IKEv2TransformType3 = 11
	AUTH_SHA2_256_128  IKEv2TransformType3 = 12
	AUTH_SHA2_384_192  IKEv2TransformType3 = 13
	AUTH_SHA2_512_256  IKEv2TransformType3 = 14
)

func (it3 IKEv2TransformType3) String() string {
	switch it3 {
	default:
		return "Unknow"
	case AUTH_NONE:
		return "NONE"
	case AUTH_HMAC_MD5_96:
		return "AUTH_HMAC_MD5_96"
	case AUTH_HMAC_SHA1_96:
		return "AUTH_HMAC_SHA1_96"
	case AUTH_DES_MAC:
		return "AUTH_DES_MAC"
	case AUTH_KPDK_MD5:
		return "AUTH_KPDK_MD5"
	case AUTH_AES_XCBC_96:
		return "AUTH_AES_XCBC_96"
	case AUTH_HMAC_MD5_128:
		return "AUTH_HMAC_MD5_128"
	case AUTH_HMAC_SHA1_160:
		return "AUTH_HMAC_SHA1_160"
	case AUTH_AES_CMAC_96:
		return "AUTH_AES_CMAC_96"
	case AUTH_AES_128_GMAC:
		return "AUTH_AES_128_GMAC"
	case AUTH_AES_192_GMAC:
		return "AUTH_AES_192_GMAC"
	case AUTH_AES_256_GMAC:
		return "AUTH_AES_256_GMAC"
	case AUTH_SHA2_256_128:
		return "AUTH_SHA2_256_128"
	case AUTH_SHA2_384_192:
		return "AUTH_SHA2_384_192"
	case AUTH_SHA2_512_256:
		return "AUTH_SHA2_512_256"
	}
}

const (
	MODPGroupNONE IKEv2TransformType4 = 0
	MODPGroup768  IKEv2TransformType4 = 1
	MODPGroup1024 IKEv2TransformType4 = 2
	MODPGroup1536 IKEv2TransformType4 = 5
	MODPGroup2048 IKEv2TransformType4 = 14
	MODPGroup3072 IKEv2TransformType4 = 15
	MODPGroup4096 IKEv2TransformType4 = 16
	MODPGroup6144 IKEv2TransformType4 = 17
	MODPGroup8192 IKEv2TransformType4 = 18
)

func (it4 IKEv2TransformType4) String() string {
	switch it4 {
	default:
		return "Unknow"
	case MODPGroupNONE:
		return "NONE"
	case MODPGroup768:
		return "MODPGroup768"
	case MODPGroup1024:
		return "MODPGroup1024"
	case MODPGroup1536:
		return "MODPGroup1536"
	case MODPGroup2048:
		return "MODPGroup2048"
	case MODPGroup3072:
		return "MODPGroup3072"
	case MODPGroup4096:
		return "MODPGroup4096"
	case MODPGroup6144:
		return "MODPGroup6144"
	case MODPGroup8192:
		return "MODPGroup8192"

	}
}

const (
	NO_ESN  IKEv2TransformType5 = 0
	YES_ESN IKEv2TransformType5 = 1
)

func (it5 IKEv2TransformType5) String() string {
	switch it5 {
	default:
		return "Unknown"
	case NO_ESN:
		return "No Extended Sequence Numbers"
	case YES_ESN:
		return " Extended Sequence Numbers"
	}
}

const (
	UNSUPPORTED_CRITICAL_PAYLOAD  IKEv2NotifyMessagesType = 1
	INVALID_IKE_SPI               IKEv2NotifyMessagesType = 4
	INVALID_MAJOR_VERSION         IKEv2NotifyMessagesType = 5
	INVALID_SYNTAX                IKEv2NotifyMessagesType = 7
	INVALID_MESSAGE_ID            IKEv2NotifyMessagesType = 9
	INVALID_SPI                   IKEv2NotifyMessagesType = 11
	NO_PROPOSAL_CHOSEN            IKEv2NotifyMessagesType = 14
	INVALID_KE_PAYLOAD            IKEv2NotifyMessagesType = 17
	AUTHENTICATION_FAILED         IKEv2NotifyMessagesType = 24
	SINGLE_PAIR_REQUIRED          IKEv2NotifyMessagesType = 34
	NO_ADDITIONAL_SAS             IKEv2NotifyMessagesType = 35
	INTERNAL_ADDRESS_FAILURE      IKEv2NotifyMessagesType = 36
	FAILED_CP_REQUIRED            IKEv2NotifyMessagesType = 37
	TS_UNACCEPTABLE               IKEv2NotifyMessagesType = 38
	INVALID_SELECTORS             IKEv2NotifyMessagesType = 39
	TEMPORARY_FAILURE             IKEv2NotifyMessagesType = 43
	CHILD_SA_NOT_FOUND            IKEv2NotifyMessagesType = 44
	INITIAL_CONTACT               IKEv2NotifyMessagesType = 16384
	SET_WINDOW_SIZE               IKEv2NotifyMessagesType = 16385
	ADDITIONAL_TS_POSSIBLE        IKEv2NotifyMessagesType = 16386
	IPCOMP_SUPPORTED              IKEv2NotifyMessagesType = 16387
	NAT_DETECTION_SOURCE_IP       IKEv2NotifyMessagesType = 16388
	NAT_DETECTION_DESTINATION_IP  IKEv2NotifyMessagesType = 16389
	COOKIE                        IKEv2NotifyMessagesType = 16390
	USE_TRANSPORT_MODE            IKEv2NotifyMessagesType = 16391
	HTTP_CERT_LOOKUP_SUPPORTED    IKEv2NotifyMessagesType = 16392
	REKEY_SA                      IKEv2NotifyMessagesType = 16393
	ESP_TFC_PADDING_NOT_SUPPORTED IKEv2NotifyMessagesType = 16394
	NON_FIRST_FRAGMENTS_ALSO      IKEv2NotifyMessagesType = 16395
)

func (in IKEv2NotifyMessagesType) String() string {
	switch in {
	default:
		return "Unknown"
	case UNSUPPORTED_CRITICAL_PAYLOAD:
		return "UNSUPPORTED_CRITICAL_PAYLOAD"
	case INVALID_IKE_SPI:
		return "INVALID_IKE_SPI"
	case INVALID_MAJOR_VERSION:
		return "INVALID_MAJOR_VERSION"
	case INVALID_SYNTAX:
		return "INVALID_SYNTAX"
	case INVALID_MESSAGE_ID:
		return "INVALID_MESSAGE_ID"
	case INVALID_SPI:
		return "INVALID_SPI"
	case NO_PROPOSAL_CHOSEN:
		return "NO_PROPOSAL_CHOSEN"
	case INVALID_KE_PAYLOAD:
		return "INVALID_KE_PAYLOAD"
	case AUTHENTICATION_FAILED:
		return "AUTHENTICATION_FAILED"
	case SINGLE_PAIR_REQUIRED:
		return "SINGLE_PAIR_REQUIRED"
	case NO_ADDITIONAL_SAS:
		return "NO_ADDITIONAL_SAS"
	case INTERNAL_ADDRESS_FAILURE:
		return "INTERNAL_ADDRESS_FAILURE"
	case FAILED_CP_REQUIRED:
		return "FAILED_CP_REQUIRED"
	case TS_UNACCEPTABLE:
		return "TS_UNACCEPTABLE"
	case INVALID_SELECTORS:
		return "INVALID_SELECTORS"
	case TEMPORARY_FAILURE:
		return "TEMPORARY_FAILURE"
	case CHILD_SA_NOT_FOUND:
		return "CHILD_SA_NOT_FOUND"
	case INITIAL_CONTACT:
		return "INITIAL_CONTACT"
	case SET_WINDOW_SIZE:
		return "SET_WINDOW_SIZE"
	case ADDITIONAL_TS_POSSIBLE:
		return "ADDITIONAL_TS_POSSIBLE"
	case IPCOMP_SUPPORTED:
		return "IPCOMP_SUPPORTED"
	case NAT_DETECTION_SOURCE_IP:
		return "NAT_DETECTION_SOURCE_IP"
	case COOKIE:
		return "COOKIE"
	case USE_TRANSPORT_MODE:
		return "USE_TRANSPORT_MODE"
	case HTTP_CERT_LOOKUP_SUPPORTED:
		return "HTTP_CERT_LOOKUP_SUPPORTED"
	case REKEY_SA:
		return "REKEY_SA"
	case ESP_TFC_PADDING_NOT_SUPPORTED:
		return "ESP_TFC_PADDING_NOT_SUPPORTED"
	case NON_FIRST_FRAGMENTS_ALSO:
		return "NON_FIRST_FRAGMENTS_ALSO"
	}
}

var IKEv2PayloadTypeMap = map[byte]IKEv2PayloadTypes{
	0:  IKEv2PayloadNone,
	2:  IKEv2PayloadProposal,
	3:  IKEv2PayloadTransform,
	33: IKEv2PayloadSA,
	34: IKEv2PayloadKE,
	35: IKEv2PayloadIDi,
	36: IKEv2PayloadIDr,
	37: IKEv2PayloadCERT,
	38: IKEv2PayloadCERTREQ,
	39: IKEv2PayloadAUTH,
	40: IKEv2PayloadNonce,
	41: IKEv2PayloadNotify,
	42: IKEv2PayloadDelete,
	43: IKEv2PayloadVendorID,
	44: IKEv2PayloadTSi,
	45: IKEv2PayloadTSr,
	46: IKEv2PayloadEncrypted,
	47: IKEv2PayloadCP,
	48: IKEv2PayloadEAP,
	49: IKEv2PayloadGSPM,
	50: IKEv2PayloadIDg,
	51: IKEv2PayloadGSA,
	52: IKEv2PayloadKD,
	53: IKEv2PayloadEncryptedFrag,
	54: IKEv2PayloadPS,
}
var IKEv2ExchangeTypeMap = map[byte]IKEv2ExchangeTypes{
	34: IKEv2SAInit,
	35: IKEv2Auth,
	36: IKEv2CreateChild,
	37: IKEv2Informational,
	38: IKEv2SessionResume,
	43: IKEv2Intermediate,
	44: IKEv2FollowUpKE,
}
var IKEv2ProtocolTypesMap = map[byte]IKEv2ProtocolTypes{
	1: IKE,
	2: AH,
	3: ESP,
}
var IKEv2TransformTypesMap = map[byte]IKEv2TransformTypes{
	1: ENCR,
	2: PRF,
	3: INTEG,
	4: DH,
	5: ESN,
}
var IKEv2TransformType1Map = map[uint16]IKEv2TransformType1{
	1:  ENCR_DES_IV64,
	2:  ENCR_DES,
	3:  ENCR_3DES,
	4:  ENCR_RC5,
	5:  ENCR_IDEA,
	6:  ENCR_CAST,
	7:  ENCR_BLOWFISH,
	8:  ENCR_3IDEA,
	9:  ENCR_DES_IV32,
	11: ENCR_NULL,
	12: ENCR_AES_CBC,
	13: ENCR_AES_CTR,
}
var IKEv2TransformType2Map = map[uint16]IKEv2TransformType2{
	1: PRF_HMAC_MD5,
	2: PRF_HMAC_SHA1,
	3: PRF_HMAC_TIGER,
	4: PRF_AES128_XCBC,
	5: PRF_HMAC_SHA2_256,
	6: PRF_HMAC_SHA2_384,
	7: PRF_HMAC_SHA2_512,
	8: PRF_AES128_CMAC,
	9: PRF_HMAC_STREEBOG_512,
}
var IKEv2TransformType3Map = map[uint16]IKEv2TransformType3{
	0:  AUTH_NONE,
	1:  AUTH_HMAC_MD5_96,
	2:  AUTH_HMAC_SHA1_96,
	3:  AUTH_DES_MAC,
	4:  AUTH_KPDK_MD5,
	5:  AUTH_AES_XCBC_96,
	6:  AUTH_HMAC_MD5_128,
	7:  AUTH_HMAC_SHA1_160,
	8:  AUTH_AES_CMAC_96,
	9:  AUTH_AES_128_GMAC,
	10: AUTH_AES_192_GMAC,
	11: AUTH_AES_256_GMAC,
	12: AUTH_SHA2_256_128,
	13: AUTH_SHA2_384_192,
	14: AUTH_SHA2_512_256,
}
var IKEv2TransformType4Map = map[uint16]IKEv2TransformType4{
	0:  MODPGroupNONE,
	1:  MODPGroup768,
	2:  MODPGroup1024,
	5:  MODPGroup1536,
	14: MODPGroup2048,
	15: MODPGroup3072,
	16: MODPGroup4096,
	17: MODPGroup6144,
	18: MODPGroup8192,
}
var IKEv2TransformType5Map = map[uint16]IKEv2TransformType5{
	0: NO_ESN,
	1: YES_ESN,
}
var IKEv2NotifyMessagesTypeMap = map[uint16]IKEv2NotifyMessagesType{
	1:     UNSUPPORTED_CRITICAL_PAYLOAD,
	4:     INVALID_IKE_SPI,
	5:     INVALID_MAJOR_VERSION,
	7:     INVALID_SYNTAX,
	9:     INVALID_MESSAGE_ID,
	11:    INVALID_SPI,
	14:    NO_PROPOSAL_CHOSEN,
	17:    INVALID_KE_PAYLOAD,
	24:    AUTHENTICATION_FAILED,
	34:    SINGLE_PAIR_REQUIRED,
	35:    NO_ADDITIONAL_SAS,
	36:    INTERNAL_ADDRESS_FAILURE,
	37:    FAILED_CP_REQUIRED,
	38:    TS_UNACCEPTABLE,
	39:    INVALID_SELECTORS,
	43:    TEMPORARY_FAILURE,
	44:    CHILD_SA_NOT_FOUND,
	16384: INITIAL_CONTACT,
	16385: SET_WINDOW_SIZE,
	16386: ADDITIONAL_TS_POSSIBLE,
	16387: IPCOMP_SUPPORTED,
	16388: NAT_DETECTION_SOURCE_IP,
	16389: NAT_DETECTION_DESTINATION_IP,
	16390: COOKIE,
	16391: USE_TRANSPORT_MODE,
	16392: HTTP_CERT_LOOKUP_SUPPORTED,
	16393: REKEY_SA,
	16394: ESP_TFC_PADDING_NOT_SUPPORTED,
	16395: NON_FIRST_FRAGMENTS_ALSO,
}

type IKEv2 struct {
	layers.BaseLayer
	InitSPI     [8]byte            // XStrFixedLenField
	RespSPI     [8]byte            // XStrFixedLenField
	NextPayload IKEv2PayloadTypes  // ByteEnumField
	Version     byte               // XByteField
	ExchType    IKEv2ExchangeTypes // ByteEnumField
	Flags       byte               // FlagsField
	ID          uint32             // IntField
	Length      uint32             // IntField
	Payload     interface{}
}

type IKEv2PayloadHeader struct {
	NextPayload IKEv2PayloadTypes
	Flags       byte
	Length      uint16
}

type IKEv2SAPayload struct {
	Header    IKEv2PayloadHeader
	Proposals []IKEv2Proposal
	Payload   interface{}
}

type IKEv2Proposal struct {
	Header     IKEv2PayloadHeader
	ProposalNb byte
	ProtocolID IKEv2ProtocolTypes
	SPISize    byte
	TransNb    byte
	Transforms []IKEv2Transform
}

type IKEv2Transform struct {
	Header        IKEv2PayloadHeader
	TransformType IKEv2TransformTypes
	Flag          byte
	TransformId   uint16
	KeyLength     uint32
}

type IKEv2KEPayload struct {
	Header  IKEv2PayloadHeader
	DHGroup uint16
	Flag    uint16
	KE      []byte
	Payload interface{}
}

type IKEv2NoncePayload struct {
	Header  IKEv2PayloadHeader
	Nonce   []byte
	Payload interface{}
}

type IKEv2NotifyPayload struct {
	Header       IKEv2PayloadHeader
	ProtocolID   IKEv2ProtocolTypes
	SPISize      byte
	NotifyType   IKEv2NotifyMessagesType
	Notification []byte
	Payload      interface{}
}

func (i *IKEv2) LayerType() gopacket.LayerType { return LayerTypeIKEv2 }

// Decode Functions
func decodeIKEv2Packet(data []byte, p gopacket.PacketBuilder) error {
	ike := &IKEv2{}
	return ike.DecodeFromBytes(data, p)
}

func (i *IKEv2) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	copy(i.InitSPI[:], data[0:8])
	copy(i.RespSPI[:], data[8:16])
	i.NextPayload = IKEv2PayloadTypeMap[data[16]]
	i.Version = data[17]
	i.ExchType = IKEv2ExchangeTypeMap[data[18]]
	i.Flags = data[19]
	i.ID = binary.BigEndian.Uint32(data[20:24])
	i.Length = binary.BigEndian.Uint32(data[24:28])

	switch i.NextPayload {
	case IKEv2PayloadSA:
		i.Payload, _ = DecodeSAPayload(data, 28)
	case IKEv2PayloadKE:
		i.Payload, _ = DecodeKEPayload(data, 28)
	case IKEv2PayloadNonce:
		i.Payload, _ = DecodeNoncePayload(data, 28)
	case IKEv2PayloadNotify:
		i.Payload, _ = DecodeNotifyPayload(data, 28)
	default:
		// Handle unknown payload type
		fmt.Println("default")
		return nil
	}
	return nil
}

func DecodeSAPayload(data []byte, offset int) (IKEv2SAPayload, error) {
	header, off := DecodeHeader(data, offset)

	payload := IKEv2SAPayload{
		Header: header,
	}

	for i := off; i < len(data); {
		prop, nextoffset, _ := DecodeProposal(data, i)
		payload.Proposals = append(payload.Proposals, prop)
		if prop.Header.NextPayload == 0 {
			off = nextoffset
			break
		}
		i = nextoffset
	}

	switch payload.Header.NextPayload {
	case IKEv2PayloadSA:
		payload.Payload, _ = DecodeSAPayload(data, off)
	case IKEv2PayloadKE:
		payload.Payload, _ = DecodeKEPayload(data, off)
	case IKEv2PayloadNonce:
		payload.Payload, _ = DecodeNoncePayload(data, off)
	case IKEv2PayloadNotify:
		payload.Payload, _ = DecodeNotifyPayload(data, off)
	default:
		// Handle unknown payload type
		fmt.Println("default")
		return payload, nil
	}
	return payload, nil
}

func DecodeProposal(data []byte, offset int) (IKEv2Proposal, int, error) {
	header, off := DecodeHeader(data, offset)
	prop := IKEv2Proposal{
		Header:     header,
		ProposalNb: data[off],
		ProtocolID: IKEv2ProtocolTypesMap[data[off+1]],
		SPISize:    data[off+2],
		TransNb:    data[off+3],
	}

	for i := off + 4; i < len(data); {
		trans, nextoffset, _ := DecodeTransform(data, i)
		prop.Transforms = append(prop.Transforms, trans)
		if trans.Header.NextPayload == 0 {
			off = nextoffset
			break
		}
		i = nextoffset
	}
	return prop, off, nil
}

func DecodeTransform(data []byte, offset int) (IKEv2Transform, int, error) {
	header, off := DecodeHeader(data, offset)
	trans := IKEv2Transform{
		Header:        header,
		TransformType: IKEv2TransformTypesMap[data[off]],
		Flag:          data[off+1],
		TransformId:   binary.BigEndian.Uint16(data[off+2 : off+4]),
	}
	if trans.TransformId == 12 || trans.TransformId == 13 {
		trans.KeyLength = binary.BigEndian.Uint32(data[off+4 : off+8])
		return trans, off + 8, nil
	}
	return trans, off + 4, nil
}
func DecodeKEPayload(data []byte, offset int) (IKEv2KEPayload, error) {
	header, off := DecodeHeader(data, offset)
	ke := make([]byte, int(header.Length)-8)
	copy(ke, data[off+4:int(header.Length)+off+8])
	payload := IKEv2KEPayload{
		Header:  header,
		DHGroup: binary.BigEndian.Uint16(data[off : off+2]),
		Flag:    binary.BigEndian.Uint16(data[off+2 : off+4]),
		KE:      ke,
	}
	off += int(payload.Header.Length) - 4

	switch payload.Header.NextPayload {
	case IKEv2PayloadSA:
		payload.Payload, _ = DecodeSAPayload(data, off)
	case IKEv2PayloadKE:
		payload.Payload, _ = DecodeKEPayload(data, off)
	case IKEv2PayloadNonce:
		payload.Payload, _ = DecodeNoncePayload(data, off)
	case IKEv2PayloadNotify:
		payload.Payload, _ = DecodeNotifyPayload(data, off)
	default:
		// Handle unknown payload type
		fmt.Println("default")
		return payload, nil
	}
	return payload, nil
}
func DecodeNoncePayload(data []byte, offset int) (IKEv2NoncePayload, error) {
	header, off := DecodeHeader(data, offset)
	nonce := make([]byte, int(header.Length)-4)
	copy(nonce, data[off:int(header.Length)+off+4])
	payload := IKEv2NoncePayload{
		Header: header,
		Nonce:  nonce,
	}
	off += int(payload.Header.Length) - 4

	switch payload.Header.NextPayload {
	case IKEv2PayloadSA:
		payload.Payload, _ = DecodeSAPayload(data, off)
	case IKEv2PayloadKE:
		payload.Payload, _ = DecodeKEPayload(data, off)
	case IKEv2PayloadNonce:
		payload.Payload, _ = DecodeNoncePayload(data, off)
	case IKEv2PayloadNotify:
		payload.Payload, _ = DecodeNotifyPayload(data, off)
	default:
		// Handle unknown payload type
		fmt.Println("default")
		return payload, nil
	}
	return payload, nil
}

func DecodeNotifyPayload(data []byte, offset int) (IKEv2NotifyPayload, error) {
	header, off := DecodeHeader(data, offset)
	notification := make([]byte, int(header.Length)-8)
	copy(notification, data[off+4:off+12])
	payload := IKEv2NotifyPayload{
		Header:       header,
		ProtocolID:   IKEv2ProtocolTypesMap[data[off]],
		SPISize:      data[off+1],
		NotifyType:   IKEv2NotifyMessagesTypeMap[binary.BigEndian.Uint16(data[off+2:off+4])],
		Notification: notification,
	}
	off += int(payload.Header.Length) - 4

	switch payload.Header.NextPayload {
	case IKEv2PayloadSA:
		payload.Payload, _ = DecodeSAPayload(data, off)
	case IKEv2PayloadKE:
		payload.Payload, _ = DecodeKEPayload(data, off)
	case IKEv2PayloadNonce:
		payload.Payload, _ = DecodeNoncePayload(data, off)
	case IKEv2PayloadNotify:
		payload.Payload, _ = DecodeNotifyPayload(data, off)
	default:
		// Handle unknown payload type
		fmt.Println("default")
		return payload, nil
	}
	return payload, nil
}

func DecodeHeader(data []byte, offset int) (IKEv2PayloadHeader, int) {
	header := IKEv2PayloadHeader{
		NextPayload: IKEv2PayloadTypeMap[data[offset]],
		Flags:       data[offset+1],
		Length:      binary.BigEndian.Uint16(data[offset+2 : offset+4]),
	}
	return header, offset + 4
}

// Serialize Functions
func (i *IKEv2) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(int(i.Length))
	if err != nil {
		return err
	}
	copy(bytes[0:8], i.InitSPI[:])
	copy(bytes[8:16], i.RespSPI[:])
	bytes[16] = byte(i.NextPayload)
	bytes[17] = i.Version
	bytes[18] = byte(i.ExchType)
	bytes[19] = i.Flags
	binary.BigEndian.PutUint32(bytes[20:24], i.ID)
	binary.BigEndian.PutUint32(bytes[24:28], i.Length)
	switch p := i.Payload.(type) {
	case IKEv2SAPayload:
		p.SerializeSAPayload(bytes, 28)
	case IKEv2KEPayload:
		p.SerializeKEPayload(bytes, 28)
	case IKEv2NoncePayload:
		p.SerializeNoncePayload(bytes, 28)
	default:
		// Handle unknown payload type
		fmt.Println("default")
		return nil
	}
	return nil
}

func (i *IKEv2SAPayload) SerializeSAPayload(data []byte, offset int) error {
	off := i.Header.SerializeHeader(data, offset)
	for _, prop := range i.Proposals {
		off = prop.Header.SerializeHeader(data, off)
		off = prop.SerializeProposal(data, off)
	}

	switch p := i.Payload.(type) {
	case IKEv2SAPayload:
		p.SerializeSAPayload(data, off)
	case IKEv2KEPayload:
		p.SerializeKEPayload(data, off)
	case IKEv2NoncePayload:
		p.SerializeNoncePayload(data, off)
	default:
		// Handle unknown payload type
		return nil
	}
	return nil
}

func (i *IKEv2Proposal) SerializeProposal(data []byte, offset int) int {
	data[offset] = i.ProposalNb
	data[offset+1] = byte(i.ProtocolID)
	data[offset+2] = i.SPISize
	data[offset+3] = i.TransNb
	offset += 4

	for _, trans := range i.Transforms {
		offset = trans.Header.SerializeHeader(data, offset)
		offset = trans.SerializeTransform(data, offset)
	}

	return offset
}

func (i *IKEv2Transform) SerializeTransform(data []byte, offset int) int {
	data[offset] = byte(i.TransformType)
	data[offset+1] = i.Flag
	binary.BigEndian.PutUint16(data[offset+2:], i.TransformId)
	if i.KeyLength != 0 {
		binary.BigEndian.PutUint32(data[offset+4:], i.KeyLength)
		return offset + 8
	}
	return offset + 4
}

func (i *IKEv2KEPayload) SerializeKEPayload(data []byte, offset int) error {
	off := i.Header.SerializeHeader(data, offset)
	binary.BigEndian.PutUint16(data[off:], i.DHGroup)
	binary.BigEndian.PutUint16(data[off+2:], i.Flag)
	copy(data[off+4:], i.KE[:])
	off += 4 + len(i.KE)
	switch p := i.Payload.(type) {
	case IKEv2SAPayload:
		p.SerializeSAPayload(data, off)
	case IKEv2KEPayload:
		p.SerializeKEPayload(data, off)
	case IKEv2NoncePayload:
		p.SerializeNoncePayload(data, off)
	default:
		// Handle unknown payload type
		return nil
	}
	return nil
}

func (i *IKEv2NoncePayload) SerializeNoncePayload(data []byte, offset int) error {
	off := i.Header.SerializeHeader(data, offset)

	copy(data[off:], i.Nonce[:])
	off += len(i.Nonce)

	switch p := i.Payload.(type) {
	case IKEv2SAPayload:
		p.SerializeSAPayload(data, off)
	case IKEv2KEPayload:
		p.SerializeKEPayload(data, off)
	case IKEv2NoncePayload:
		p.SerializeNoncePayload(data, off)
	default:
		// Handle unknown payload type
		return nil
	}
	return nil
}

func (i *IKEv2PayloadHeader) SerializeHeader(data []byte, offset int) int {
	data[offset] = byte(i.NextPayload)
	data[offset+1] = i.Flags
	binary.BigEndian.PutUint16(data[offset+2:], i.Length)
	return offset + 4
}
