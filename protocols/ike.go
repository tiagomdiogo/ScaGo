package protocols

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LayerTypeIKEv1 = gopacket.RegisterLayerType(8001, gopacket.LayerTypeMetadata{Name: "IKE", Decoder: gopacket.DecodeFunc(decodeIKEPacket)})

type IKEPayloadTypes byte
type IKEExchangeTypes byte
type IKEProtocolTypes byte
type IKETransformTypes byte
type IKETransformType1 byte
type IKETransformType2 byte
type IKETransformType3 byte
type IKETransformType4 byte
type IKETransformType5 byte
type IKETransformType11 byte
type IKENotifyMessagesType uint16
type IKEDOITypes uint32
type IKESituationTypes uint32
type IKETransformID byte
type IKEIDType byte

// see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-18 for details
const (
	IKEPayloadNone      IKEPayloadTypes = 0
	IKEPayloadSA        IKEPayloadTypes = 1  // used only inside the SA payload
	IKEPayloadProposal  IKEPayloadTypes = 2  // used only inside the SA payload
	IKEPayloadTransform IKEPayloadTypes = 3  // Security Association
	IKEPayloadKE        IKEPayloadTypes = 4  // Key Exchange
	IKEPayloadID        IKEPayloadTypes = 5  // ID Initiator
	IKEPayloadCERT      IKEPayloadTypes = 6  // ID Responder
	IKEPayloadCERTREQ   IKEPayloadTypes = 7  // Certificate
	IKEPayloadHASH      IKEPayloadTypes = 8  // Certificate Request
	IKEPayloadSIG       IKEPayloadTypes = 9  // Authentication
	IKEPayloadNonce     IKEPayloadTypes = 10 // Nonce
	IKEPayloadNotify    IKEPayloadTypes = 11 // Notify
	IKEPayloadDelete    IKEPayloadTypes = 12 // Delete
	IKEPayloadVendorID  IKEPayloadTypes = 13 // Vendor ID
	IKEPayloadReserved  IKEPayloadTypes = 14 // Traffic Selector - Initiator
	IKEPayloadSAKEK     IKEPayloadTypes = 15 // Traffic Selector - Responder
	IKEPayloadSATEK     IKEPayloadTypes = 16 // Encrypted Payload
	IKEPayloadKD        IKEPayloadTypes = 17 // Configuration Payload
	IKEPayloadSEQ       IKEPayloadTypes = 18 // Extensible Authentication Protocol
	IKEPayloadPOP       IKEPayloadTypes = 19 // Generic Secure Password Method
	IKEPayloadNATD      IKEPayloadTypes = 20 // Group ID
	IKEPayloadNATOA     IKEPayloadTypes = 21 // Group Security Association
	IKEPayloadGAP       IKEPayloadTypes = 22 // Key Download
)

func (ip IKEPayloadTypes) String() string {
	switch ip {
	default:
		return "Unknown"
	case IKEPayloadNone:
		return "None"
	case IKEPayloadProposal:
		return "Proposal"
	case IKEPayloadTransform:
		return "Transform"
	case IKEPayloadSA:
		return "SA"
	case IKEPayloadKE:
		return "KE"
	case IKEPayloadID:
		return "ID"
	case IKEPayloadHASH:
		return "Hash"
	case IKEPayloadCERT:
		return "CERT"
	case IKEPayloadCERTREQ:
		return "CERTREQ"
	case IKEPayloadSIG:
		return "Signature"
	case IKEPayloadNonce:
		return "Nonce"
	case IKEPayloadNotify:
		return "Notify"
	case IKEPayloadDelete:
		return "Delete"
	case IKEPayloadVendorID:
		return "VendorID"
	case IKEPayloadReserved:
		return "Reserved"
	case IKEPayloadSAKEK:
		return "SA KEK"
	case IKEPayloadSATEK:
		return "SA TEK"
	case IKEPayloadSEQ:
		return "Sequence Number"
	case IKEPayloadPOP:
		return "Proof of Possession"
	case IKEPayloadNATD:
		return "NAT Discovery"
	case IKEPayloadNATOA:
		return "NAT Original Address"
	case IKEPayloadGAP:
		return "Group Associated Policy"
	case IKEPayloadKD:
		return "KD"
	}
}

const (
	IKENONE               IKEExchangeTypes = 0
	IKEBASE               IKEExchangeTypes = 1
	IKEIdentityProtection IKEExchangeTypes = 2
	IKEAuthOnly           IKEExchangeTypes = 3
	IKEAggressive         IKEExchangeTypes = 4
	IKEINFORMATIONAL      IKEExchangeTypes = 5
	QUICK_MODE            IKEExchangeTypes = 32
	NEW_GROUP_MODE        IKEExchangeTypes = 33
)

func (ie IKEExchangeTypes) String() string {
	switch ie {
	default:
		return "Unknown"
	case IKENONE:
		return "IKE_NONE"
	case IKEBASE:
		return "IKE_BASE"
	case IKEIdentityProtection:
		return "IKE_ID_PROTECT"
	case IKEAuthOnly:
		return "IKE_AUTH_ONLY"
	case IKEAggressive:
		return "IKE_AGGRESSIVE"
	case IKEINFORMATIONAL:
		return "IKE_INFORMATIONAL"
	case QUICK_MODE:
		return "QUICK MODE"
	case NEW_GROUP_MODE:
		return "NEW GROUP MODE"
	}
}

const (
	ISAKMP    IKEProtocolTypes = 1
	IPSEC_AH  IKEProtocolTypes = 2
	IPSEC_ESP IKEProtocolTypes = 3
	UDP       IKEProtocolTypes = 17
)

func (ip IKEProtocolTypes) String() string {
	switch ip {
	default:
		return "Unknown"
	case ISAKMP:
		return "ISAKMP"
	case IPSEC_AH:
		return "AH"
	case IPSEC_ESP:
		return "ESP"
	case UDP:
		return "UDP"
	}
}

const (
	RESERVED IKETransformID = 0
	KEY_IKE  IKETransformID = 1
)

func (it IKETransformID) String() string {
	switch it {
	default:
		return "Uknnown"
	case RESERVED:
		return "RESERVED"
	case KEY_IKE:
		return "KEY_IKE"
	}
}

const (
	ENCRY IKETransformTypes = 1
	HASH  IKETransformTypes = 2
	AUTH  IKETransformTypes = 3
	GD    IKETransformTypes = 4
	GT    IKETransformTypes = 5
	GP    IKETransformTypes = 6
	GGO   IKETransformTypes = 7
	GGT   IKETransformTypes = 8
	GCA   IKETransformTypes = 9
	GCB   IKETransformTypes = 10
	LT    IKETransformTypes = 11
	LD    IKETransformTypes = 12
	PRFT  IKETransformTypes = 13
	KL    IKETransformTypes = 14
	FS    IKETransformTypes = 15
	GO    IKETransformTypes = 16
)

func (it IKETransformTypes) String() string {
	switch it {
	default:
		return "Unknown"
	case ENCRY:
		return "Encryption Algorithm"
	case HASH:
		return "Hash Algorithm"
	case AUTH:
		return "Authentication Method"
	case GD:
		return "Group Description"
	case GT:
		return "Group Type"
	case GP:
		return "Group Prime"
	case GGO:
		return "Group Generator One"
	case GGT:
		return "Group Generator Two"
	case GCA:
		return "Group Curve A"
	case GCB:
		return "Group Curve B"
	case LT:
		return "Life Type"
	case LD:
		return "Life Duration"
	case PRFT:
		return "PRF"
	case KL:
		return "Key Length"
	case FS:
		return "Field Size"
	case GO:
		return "Group Order"
	}
}

const (
	DES_CBC         IKETransformType1 = 1
	IDEA_CBC        IKETransformType1 = 2
	BLOWFISH_CBC    IKETransformType1 = 3
	RC5_R16_B64_CBC IKETransformType1 = 4
	DES3_CBC        IKETransformType1 = 5
	CAST_CBC        IKETransformType1 = 6
	AES_CBC         IKETransformType1 = 7
	CAMELIA_CBC     IKETransformType1 = 8
)

func (it1 IKETransformType1) String() string {
	switch it1 {
	default:
		return "Unknow"
	case DES_CBC:
		return "DES-CBC"
	case IDEA_CBC:
		return "IDEA-CBC"
	case BLOWFISH_CBC:
		return "Blowfish-CBC"
	case RC5_R16_B64_CBC:
		return "RC5-R16-B64-CBC"
	case DES3_CBC:
		return "3DES-CBC"
	case CAST_CBC:
		return "CAST-CBC"
	case AES_CBC:
		return "AES-CBC"
	case CAMELIA_CBC:
		return "CAMELLIA-CBC"
	}
}

const (
	MD5      IKETransformType2 = 1
	SHA      IKETransformType2 = 2
	TIGER    IKETransformType2 = 3
	SHA2_256 IKETransformType2 = 4
	SHA2_384 IKETransformType2 = 5
	SHA2_512 IKETransformType2 = 6
)

func (it2 IKETransformType2) String() string {
	switch it2 {
	default:
		return "Unknow"
	case MD5:
		return "MD5"
	case SHA:
		return "SHA1"
	case TIGER:
		return "TIGER"
	case SHA2_256:
		return "SHA2_256"
	case SHA2_384:
		return "SHA2_384"
	case SHA2_512:
		return "SHA2_512"
	}
}

const (
	PRE_SHARED        IKETransformType3 = 1
	DSS_SIG           IKETransformType3 = 2
	RSA_SIG           IKETransformType3 = 3
	ENCR_RSA          IKETransformType3 = 4
	REV_ENCR_RSA      IKETransformType3 = 5
	ECDSA_SHA256_P256 IKETransformType3 = 9
	ECDSA_SHA384_P384 IKETransformType3 = 10
	ECDSA_SHA512_P521 IKETransformType3 = 11
)

func (it3 IKETransformType3) String() string {
	switch it3 {
	default:
		return "Unknow"
	case PRE_SHARED:
		return "Pre-Shared Key"
	case DSS_SIG:
		return "DSS signatures"
	case RSA_SIG:
		return "RSA signatures"
	case ENCR_RSA:
		return "Encryption with RSA"
	case REV_ENCR_RSA:
		return "Revised encryption with RSA"
	case ECDSA_SHA256_P256:
		return "ECDSA with SHA-256 on the P-256 curve"
	case ECDSA_SHA384_P384:
		return "ECDSA with SHA-384 on the P-384 curve"
	case ECDSA_SHA512_P521:
		return "ECDSA with SHA-512 on the P-521 curve"
	}
}

const (
	MODP_768       IKETransformType4 = 1
	MODP_1024      IKETransformType4 = 2
	EC2N_GP155     IKETransformType4 = 3
	EC2N_GP185     IKETransformType4 = 4
	MODP_1536      IKETransformType4 = 5
	MODP_2048      IKETransformType4 = 14
	MODP_3072      IKETransformType4 = 15
	MODP_4096      IKETransformType4 = 16
	MODP_6144      IKETransformType4 = 17
	MODP_8192      IKETransformType4 = 18
	ECP_RAND_256   IKETransformType4 = 19
	ECP_RAND_384   IKETransformType4 = 20
	ECP_RAND_512   IKETransformType4 = 21
	MODP_1024_160P IKETransformType4 = 22
	MODP_2048_224P IKETransformType4 = 23
	MODP_2048_256P IKETransformType4 = 24
	ECP_RAND_192   IKETransformType4 = 25
	ECP_RAND_224   IKETransformType4 = 26
	ECP_BRAIN_224  IKETransformType4 = 27
	ECP_BRAIN_256  IKETransformType4 = 28
	ECP_BRAIN_384  IKETransformType4 = 29
	ECP_BRAIN_512  IKETransformType4 = 30
)

func (it4 IKETransformType4) String() string {
	switch it4 {
	default:
		return "Unknow"
	case MODP_768:
		return "768-bit MODP"
	case MODP_1024:
		return "1024-bit MODP"
	case EC2N_GP155:
		return "EC2N group on GP[2^155]"
	case EC2N_GP185:
		return "EC2N group on GP[2^185]"
	case MODP_1536:
		return "1536-bit MODP "
	case MODP_2048:
		return "2048-bit MODP "
	case MODP_3072:
		return "3072-bit MODP "
	case MODP_4096:
		return "4096-bit MODP "
	case MODP_6144:
		return "6144-bit MODP "
	case MODP_8192:
		return "8192-bit MODP "
	case ECP_RAND_256:
		return "256-bit random ECP"
	case ECP_RAND_384:
		return "384-bit random ECP"
	case ECP_RAND_512:
		return "512-bit random ECP"
	case MODP_1024_160P:
		return "1024-bit MODP | 160-bit Prime"
	case MODP_2048_224P:
		return "2048-bit MODP | 224-bit Prime"
	case MODP_2048_256P:
		return "2048-bit MODP | 256-bit Prime"
	case ECP_RAND_192:
		return "192-bit Random ECP"
	case ECP_RAND_224:
		return "224-bit Random ECP"
	case ECP_BRAIN_224:
		return "224-bit Brainpool ECP"
	case ECP_BRAIN_256:
		return "256-bit Brainpool ECP"
	case ECP_BRAIN_384:
		return "384-bit Brainpool ECP"
	case ECP_BRAIN_512:
		return "512-bit Brainpool ECP"
	}
}

const (
	MODP IKETransformType5 = 1
	ECP  IKETransformType5 = 2
	EC2N IKETransformType5 = 3
)

func (it5 IKETransformType5) String() string {
	switch it5 {
	default:
		return "Unknown"
	case MODP:
		return "MODP (modular exponentiation group)"
	case ECP:
		return "ECP (elliptic curve group over GF[P])"
	case EC2N:
		return "EC2N (elliptic curve group over GF[2^N])"
	}
}

const (
	SEC IKETransformType11 = 1
	KB  IKETransformType11 = 2
)

func (it11 IKETransformType11) String() string {
	switch it11 {
	default:
		return "Unknown"
	case SEC:
		return "Seconds"
	case KB:
		return "Kilobbytes"
	}
}

const (
	INVALID_PAYLOAD_TYPE      IKENotifyMessagesType = 1
	DOI_NOT_SUPPORTED         IKENotifyMessagesType = 2
	SITUATION_NOT_SUPPORTED   IKENotifyMessagesType = 3
	INVALID_COOKIE            IKENotifyMessagesType = 4
	INVALID_MAJOR_V           IKENotifyMessagesType = 5
	INVALID_MINOR_VERSION     IKENotifyMessagesType = 6
	INVALID_EXCHANGE_TYPE     IKENotifyMessagesType = 7
	INVALID_FLAGS             IKENotifyMessagesType = 8
	INV_MESSAGE_ID            IKENotifyMessagesType = 9
	INVALID_PROTOCOL_ID       IKENotifyMessagesType = 10
	INV_SPI                   IKENotifyMessagesType = 11
	INVALID_TRANSFORM_ID      IKENotifyMessagesType = 12
	ATTRIBUTES_NOT_SUPPORTED  IKENotifyMessagesType = 13
	NO_PROPOSAL_CHOSE         IKENotifyMessagesType = 14
	BAD_PROPOSAL_SYNTAX       IKENotifyMessagesType = 15
	PAYLOAD_MALFORMED         IKENotifyMessagesType = 16
	INVALID_KEY_INFORMATION   IKENotifyMessagesType = 17
	INVALID_ID_INFORMATION    IKENotifyMessagesType = 18
	INVALID_CERT_ENCODING     IKENotifyMessagesType = 19
	INVALID_CERTIFICATE       IKENotifyMessagesType = 20
	CERT_TYPE_UNSUPPORTED     IKENotifyMessagesType = 21
	INVALID_CERT_AUTHORITY    IKENotifyMessagesType = 22
	INVALID_HASH_INFORMATION  IKENotifyMessagesType = 23
	AUTH_FAILED               IKENotifyMessagesType = 24
	INVALID_SIGNATURE         IKENotifyMessagesType = 25
	ADDRESS_NOTIFICATION      IKENotifyMessagesType = 26
	NOTIFY_SA_LIFETIME        IKENotifyMessagesType = 27
	CERTIFICATE_UNAVAILABLE   IKENotifyMessagesType = 28
	UNSUPPORTED_EXCHANGE_TYPE IKENotifyMessagesType = 29
	UNEQUAL_PAYLOAD_LENGTHS   IKENotifyMessagesType = 30
)

func (in IKENotifyMessagesType) String() string {
	switch in {
	default:
		return "Unknown"
	case INVALID_PAYLOAD_TYPE:
		return "INVALID_PAYLOAD_TYPE"
	case DOI_NOT_SUPPORTED:
		return "DOI_NOT_SUPPORTED"
	case SITUATION_NOT_SUPPORTED:
		return "SITUATION_NOT_SUPPORTED"
	case INVALID_COOKIE:
		return "INVALID_COOKIE"
	case INVALID_MAJOR_V:
		return "INVALID_MAJOR_VERSION"
	case INVALID_MINOR_VERSION:
		return "INVALID_MINOR_VERSION"
	case INVALID_EXCHANGE_TYPE:
		return "INVALID_EXCHANGE_TYPE"
	case INVALID_FLAGS:
		return "INVALID_FLAGS"
	case INV_MESSAGE_ID:
		return "INVALID_MESSAGE_ID"
	case INVALID_PROTOCOL_ID:
		return "INVALID_PROTOCOL_ID"
	case INV_SPI:
		return "INVALID_SPI"
	case INVALID_TRANSFORM_ID:
		return "INVALID_TRANSFORM_ID"
	case ATTRIBUTES_NOT_SUPPORTED:
		return "ATTRIBUTES_NOT_SUPPORTED"
	case NO_PROPOSAL_CHOSE:
		return "NO_PROPOSAL_CHOSEN"
	case BAD_PROPOSAL_SYNTAX:
		return "BAD_PROPOSAL_SYNTAX"
	case PAYLOAD_MALFORMED:
		return "PAYLOAD_MALFORMED"
	case INVALID_KEY_INFORMATION:
		return "INVALID_KEY_INFORMATION"
	case INVALID_ID_INFORMATION:
		return "INVALID_ID_INFORMATION"
	case INVALID_CERT_ENCODING:
		return "INVALID_CERT_ENCODING"
	case INVALID_CERTIFICATE:
		return "INVALID_CERTIFICATE"
	case CERT_TYPE_UNSUPPORTED:
		return "CERT_TYPE_UNSUPPORTED"
	case INVALID_CERT_AUTHORITY:
		return "INVALID_CERT_AUTHORITY"
	case INVALID_HASH_INFORMATION:
		return "INVALID_HASH_INFORMATION"
	case AUTH_FAILED:
		return "AUTHENTICATION_FAILED"
	case INVALID_SIGNATURE:
		return "INVALID_SIGNATURE"
	case ADDRESS_NOTIFICATION:
		return "ADDRESS_NOTIFICATION"
	case NOTIFY_SA_LIFETIME:
		return "NOTIFY_SA_LIFETIME"
	case CERTIFICATE_UNAVAILABLE:
		return "CERTIFICATE_UNAVAILABLE"
	case UNSUPPORTED_EXCHANGE_TYPE:
		return "UNSUPPORTED_EXCHANGE_TYPE"
	case UNEQUAL_PAYLOAD_LENGTHS:
		return "UNEQUAL_PAYLOAD_LENGTHS"

	}
}

const (
	DOI_ISAKMP IKEDOITypes = 0
	DOI_IPSEC  IKEDOITypes = 1
	DOI_GDOI   IKEDOITypes = 2
)

func (id IKEDOITypes) String() string {
	switch id {
	default:
		return "Uknown"
	case DOI_ISAKMP:
		return "ISAKMP"
	case DOI_IPSEC:
		return "IPSEC"
	case DOI_GDOI:
		return "GDOI"
	}
}

const (
	SIT_IDENTITY_ONLY IKESituationTypes = 1
	SIT_SECRECY       IKESituationTypes = 2
	SIT_INTEGRITY     IKESituationTypes = 4
)

func (is IKESituationTypes) String() string {
	switch is {
	default:
		return "Uknown"
	case SIT_IDENTITY_ONLY:
		return "SIT_IDENTITY_ONLY"
	case SIT_SECRECY:
		return "SIT_SECRECY"
	case SIT_INTEGRITY:
		return "SIT_INTEGRITY"
	}
}

const (
	ID_IPV4_ADDR        IKEIDType = 1
	ID_FQDN             IKEIDType = 2
	ID_USER_FQDN        IKEIDType = 3
	ID_IPV4_ADDR_SUBNET IKEIDType = 4
	ID_IPV6_ADDR        IKEIDType = 5
	ID_IPV6_ADDR_SUBNET IKEIDType = 6
	ID_IPV4_ADDR_RANGE  IKEIDType = 7
	ID_IPV6_ADDR_RANGE  IKEIDType = 8
	ID_DER_ASN1_DN      IKEIDType = 9
	ID_DER_ASN1_GN      IKEIDType = 10
	ID_KEY_ID           IKEIDType = 11
)

func (id IKEIDType) String() string {
	switch id {
	default:
		return "Unknown"
	case ID_FQDN:
		return "ID_FQDN"
	case ID_USER_FQDN:
		return "ID_USER_FQDN"
	case ID_IPV4_ADDR:
		return "ID_IPV4_ADDR"
	case ID_IPV4_ADDR_SUBNET:
		return "ID_IPV4_ADDR_SUBNET"
	case ID_IPV6_ADDR:
		return "ID_IPV6_ADDR"
	case ID_IPV6_ADDR_SUBNET:
		return "ID_IPV6_ADDR_SUBNET"
	case ID_IPV4_ADDR_RANGE:
		return "ID_IPV4_ADDR_RANGE"
	case ID_IPV6_ADDR_RANGE:
		return "ID_IPV6_ADDR_RANGE"
	case ID_DER_ASN1_DN:
		return "ID_DER_ASN1_DN"
	case ID_DER_ASN1_GN:
		return "ID_DER_ASN1_GN"
	case ID_KEY_ID:
		return "ID_KEY_ID"
	}
}

var IKEPayloadTypeMap = map[byte]IKEPayloadTypes{
	0:  IKEPayloadNone,
	1:  IKEPayloadSA,
	2:  IKEPayloadProposal,
	3:  IKEPayloadTransform,
	4:  IKEPayloadKE,
	5:  IKEPayloadID,
	6:  IKEPayloadCERT,
	7:  IKEPayloadCERTREQ,
	8:  IKEPayloadHASH,
	9:  IKEPayloadSIG,
	10: IKEPayloadNonce,
	11: IKEPayloadNotify,
	12: IKEPayloadDelete,
	13: IKEPayloadVendorID,
	14: IKEPayloadReserved,
	15: IKEPayloadSAKEK,
	16: IKEPayloadSATEK,
	17: IKEPayloadKD,
	18: IKEPayloadSEQ,
	19: IKEPayloadPOP,
	20: IKEPayloadNATD,
	21: IKEPayloadNATOA,
	22: IKEPayloadGAP,
}
var IKEExchangeTypeMap = map[byte]IKEExchangeTypes{
	0:  IKENONE,
	1:  IKEBASE,
	2:  IKEIdentityProtection,
	3:  IKEAuthOnly,
	4:  IKEAggressive,
	5:  IKEINFORMATIONAL,
	32: QUICK_MODE,
	33: NEW_GROUP_MODE,
}
var IKEProtocolTypesMap = map[byte]IKEProtocolTypes{
	1:  ISAKMP,
	2:  IPSEC_AH,
	3:  IPSEC_ESP,
	17: UDP,
}
var IKETransformIDMap = map[byte]IKETransformID{
	0: RESERVED,
	1: KEY_IKE,
}
var IKETransformTypesMap = map[byte]IKETransformTypes{
	1:  ENCRY,
	2:  HASH,
	3:  AUTH,
	4:  GD,
	5:  GT,
	6:  GP,
	7:  GGO,
	8:  GGT,
	9:  GCA,
	10: GCB,
	11: LT,
	12: LD,
	13: PRFT,
	14: KL,
	15: FS,
	16: GO,
}
var IKETransformType1Map = map[uint16]IKETransformType1{
	1: DES_CBC,
	2: IDEA_CBC,
	3: BLOWFISH_CBC,
	4: RC5_R16_B64_CBC,
	5: DES3_CBC,
	6: CAST_CBC,
	7: AES_CBC,
	8: CAMELIA_CBC,
}
var IKETransformType2Map = map[uint16]IKETransformType2{
	1: MD5,
	2: SHA,
	3: TIGER,
	4: SHA2_256,
	5: SHA2_384,
	6: SHA2_512,
}
var IKETransformType3Map = map[uint16]IKETransformType3{
	1: PRE_SHARED,
	2: DSS_SIG,
	3: RSA_SIG,
	4: ENCR_RSA,
	5: REV_ENCR_RSA,
	6: ECDSA_SHA256_P256,
	7: ECDSA_SHA384_P384,
	8: ECDSA_SHA512_P521,
}
var IKETransformType4Map = map[uint16]IKETransformType4{
	1:  MODP_768,
	2:  MODP_1024,
	3:  EC2N_GP155,
	4:  EC2N_GP185,
	5:  MODP_1536,
	14: MODP_2048,
	15: MODP_3072,
	16: MODP_4096,
	17: MODP_6144,
	18: MODP_8192,
	19: ECP_RAND_256,
	20: ECP_RAND_384,
	21: ECP_RAND_512,
	22: MODP_1024_160P,
	23: MODP_2048_224P,
	24: MODP_2048_256P,
	25: ECP_RAND_192,
	26: ECP_RAND_224,
	27: ECP_BRAIN_224,
	28: ECP_BRAIN_256,
	29: ECP_BRAIN_384,
	30: ECP_BRAIN_512,
}
var IKETransformType5Map = map[uint16]IKETransformType5{
	1: MODP,
	2: ECP,
	3: EC2N,
}

var IKETransformType11Map = map[uint16]IKETransformType11{
	1: SEC,
	2: KB,
}
var IKENotifyMessagesTypeMap = map[uint16]IKENotifyMessagesType{
	1:  INVALID_PAYLOAD_TYPE,
	2:  DOI_NOT_SUPPORTED,
	3:  SITUATION_NOT_SUPPORTED,
	4:  INVALID_COOKIE,
	5:  INVALID_MAJOR_V,
	6:  INVALID_MINOR_VERSION,
	7:  INVALID_EXCHANGE_TYPE,
	8:  INVALID_FLAGS,
	9:  INV_MESSAGE_ID,
	10: INVALID_PROTOCOL_ID,
	11: INV_SPI,
	12: INVALID_TRANSFORM_ID,
	13: ATTRIBUTES_NOT_SUPPORTED,
	14: NO_PROPOSAL_CHOSE,
	15: BAD_PROPOSAL_SYNTAX,
	16: PAYLOAD_MALFORMED,
	17: INVALID_KEY_INFORMATION,
	18: INVALID_ID_INFORMATION,
	19: INVALID_CERT_ENCODING,
	20: INVALID_CERTIFICATE,
	21: CERT_TYPE_UNSUPPORTED,
	22: INVALID_CERT_AUTHORITY,
	23: INVALID_HASH_INFORMATION,
	24: AUTH_FAILED,
	25: INVALID_SIGNATURE,
	26: ADDRESS_NOTIFICATION,
	27: NOTIFY_SA_LIFETIME,
	28: CERTIFICATE_UNAVAILABLE,
	29: UNSUPPORTED_EXCHANGE_TYPE,
	30: UNEQUAL_PAYLOAD_LENGTHS,
}

var IKEDOITypesMap = map[byte]IKEDOITypes{
	0: DOI_ISAKMP,
	1: DOI_IPSEC,
	2: DOI_GDOI,
}

var IKESituationTypesMap = map[byte]IKESituationTypes{
	1: SIT_IDENTITY_ONLY,
	2: SIT_SECRECY,
	4: SIT_INTEGRITY,
}

var IKEIDTypesMap = map[byte]IKEIDType{
	1:  ID_IPV4_ADDR,
	2:  ID_FQDN,
	3:  ID_USER_FQDN,
	4:  ID_IPV4_ADDR_SUBNET,
	5:  ID_IPV6_ADDR,
	6:  ID_IPV6_ADDR_SUBNET,
	7:  ID_IPV4_ADDR_RANGE,
	8:  ID_IPV6_ADDR_RANGE,
	9:  ID_DER_ASN1_DN,
	10: ID_DER_ASN1_GN,
	11: ID_KEY_ID,
}

type IKEv1 struct {
	layers.BaseLayer
	InitSPI     [8]byte          // XStrFixedLenField
	RespSPI     [8]byte          // XStrFixedLenField
	NextPayload IKEPayloadTypes  // ByteEnumField
	Version     byte             // XByteField
	ExchType    IKEExchangeTypes // ByteEnumField
	Flags       byte             // FlagsField
	ID          uint32           // IntField
	Length      uint32           // IntField
	Payload     interface{}
}

type IKEPayloadHeader struct {
	NextPayload IKEPayloadTypes
	Flags       byte
	Length      uint16
}

type IKESAPayload struct {
	Header    IKEPayloadHeader
	DOI       IKEDOITypes
	Situation IKESituationTypes
	Proposals []IKEProposal
	Payload   interface{}
}

type IKEProposal struct {
	Header     IKEPayloadHeader
	ProposalNb byte
	ProtocolID IKEProtocolTypes
	SPISize    byte
	TransNb    byte
	Transforms []IKETransform
}

type IKETransform struct {
	Header      IKEPayloadHeader
	TransNb     byte
	TransformId IKETransformID
	Flag        [2]byte
	Attributes  []IKETransformAttr
}

type IKETransformAttr struct {
	Type   [2]byte
	Length uint16
	Value  []byte
}

type IKEKEPayload struct {
	Header  IKEPayloadHeader
	KE      []byte
	Payload interface{}
}

type IKENoncePayload struct {
	Header  IKEPayloadHeader
	Nonce   []byte
	Payload interface{}
}

type IKEIDPayload struct {
	Header     IKEPayloadHeader
	IDType     IKEIDType
	ProtocolID IKEProtocolTypes
	Port       uint16
	Data       []byte
	Payload    interface{}
}

type IKENotifyPayload struct {
	Header       IKEPayloadHeader
	DOI          uint32
	ProtocolID   IKEProtocolTypes
	SPISize      byte
	NotifyType   IKENotifyMessagesType
	SPI          []byte
	Notification []byte
	Payload      interface{}
}

func (i *IKEv1) LayerType() gopacket.LayerType { return LayerTypeIKEv1 }

// Decode Functions
func decodeIKEPacket(data []byte, p gopacket.PacketBuilder) error {
	ike := &IKEv1{}
	return ike.DecodeFromBytes(data, p)
}

func (i *IKEv1) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	copy(i.InitSPI[:], data[0:8])
	copy(i.RespSPI[:], data[8:16])
	i.NextPayload = IKEPayloadTypeMap[data[16]]
	i.Version = data[17]
	i.ExchType = IKEExchangeTypeMap[data[18]]
	i.Flags = data[19]
	i.ID = binary.BigEndian.Uint32(data[20:24])
	i.Length = binary.BigEndian.Uint32(data[24:28])

	switch i.NextPayload {
	case IKEPayloadSA:
		i.Payload, _ = DecodeIKESAPayload(data, 28)
	case IKEPayloadNotify:
		i.Payload, _ = DecodeIKENotifyPayload(data, 28)
	case IKEPayloadKE:
		i.Payload, _ = DecodeKEPayload(data, 28)
	case IKEPayloadNonce:
		i.Payload, _ = DecodeNoncePayload(data, 28)
	case IKEPayloadID:
		i.Payload, _ = DecodeIKEIDPayload(data, 28)
	default:
		// Handle unknown payload type
		fmt.Println("default")
		return nil
	}
	return nil
}

func DecodeIKESAPayload(data []byte, offset int) (IKESAPayload, error) {
	header, off := DecodeIKEHeader(data, offset)

	payload := IKESAPayload{
		Header:    header,
		DOI:       IKEDOITypes(binary.BigEndian.Uint32(data[off : off+4])),
		Situation: IKESituationTypes(binary.BigEndian.Uint32(data[off+4 : off+8])),
	}
	off += 8
	for i := off; i < len(data); {
		prop, nextoffset, _ := DecodeIKEProposal(data, i)
		payload.Proposals = append(payload.Proposals, prop)
		if prop.Header.NextPayload == 0 {
			off = nextoffset
			break
		}
		i = nextoffset
	}

	switch payload.Header.NextPayload {
	case IKEPayloadSA:
		payload.Payload, _ = DecodeIKESAPayload(data, off)
	case IKEPayloadNotify:
		payload.Payload, _ = DecodeIKENotifyPayload(data, off)
	case IKEPayloadKE:
		payload.Payload, _ = DecodeKEPayload(data, off)
	case IKEPayloadNonce:
		payload.Payload, _ = DecodeNoncePayload(data, off)
	case IKEPayloadID:
		payload.Payload, _ = DecodeIKEIDPayload(data, off)
	default:
		// Handle unknown payload type
		fmt.Println("default")
		return payload, nil
	}
	return payload, nil
}

func DecodeIKEProposal(data []byte, offset int) (IKEProposal, int, error) {
	header, off := DecodeIKEHeader(data, offset)
	prop := IKEProposal{
		Header:     header,
		ProposalNb: data[off],
		ProtocolID: IKEProtocolTypesMap[data[off+1]],
		SPISize:    data[off+2],
		TransNb:    data[off+3],
	}

	for i := off + 4; i < len(data); {
		trans, nextoffset, _ := DecodeIKETransform(data, i)
		prop.Transforms = append(prop.Transforms, trans)
		if trans.Header.NextPayload == 0 {
			off = nextoffset
			break
		}
		i = nextoffset
	}
	return prop, off, nil
}

func DecodeIKETransform(data []byte, offset int) (IKETransform, int, error) {
	header, off := DecodeIKEHeader(data, offset)
	var flags [2]byte
	copy(flags[:], data[off+2:off+4])
	trans := IKETransform{
		Header:      header,
		TransNb:     data[off],
		TransformId: IKETransformIDMap[data[off+1]],
		Flag:        flags,
	}
	off += 4
	for i := off; i < len(data); {
		at, nextoffset, _ := DecodeIKEAttributes(data, i)
		trans.Attributes = append(trans.Attributes, at)
		if trans.Header.Length+4+uint16(offset) == uint16(nextoffset) {
			off = nextoffset
			break
		}
		i = nextoffset
	}

	return trans, off + 4, nil
}

func DecodeIKEAttributes(data []byte, offset int) (IKETransformAttr, int, error) {
	var tp [2]byte
	copy(tp[:], data[offset:offset+2])
	attr := IKETransformAttr{
		Type:   tp,
		Length: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
	}
	if attr.Type[0] == 0 {
		var value = make([]byte, attr.Length)
		copy(value, data[offset+4:offset+4+int(attr.Length)])
		attr.Value = value
		return attr, offset + 4 + int(attr.Length), nil
	}
	return attr, offset + 4, nil
}

func DecodeIKENotifyPayload(data []byte, offset int) (IKENotifyPayload, error) {
	header, off := DecodeIKEHeader(data, offset)
	notification := make([]byte, int(header.Length)-8)
	copy(notification, data[off+4:off+12])
	payload := IKENotifyPayload{
		Header:       header,
		ProtocolID:   IKEProtocolTypesMap[data[off]],
		SPISize:      data[off+1],
		NotifyType:   IKENotifyMessagesTypeMap[binary.BigEndian.Uint16(data[off+2:off+4])],
		Notification: notification,
	}
	off += int(payload.Header.Length) - 4

	switch payload.Header.NextPayload {
	case IKEPayloadSA:
		payload.Payload, _ = DecodeIKESAPayload(data, off)
	case IKEPayloadNotify:
		payload.Payload, _ = DecodeIKENotifyPayload(data, off)
	case IKEPayloadKE:
		payload.Payload, _ = DecodeKEPayload(data, off)
	case IKEPayloadNonce:
		payload.Payload, _ = DecodeNoncePayload(data, off)
	case IKEPayloadID:
		payload.Payload, _ = DecodeIKEIDPayload(data, off)
	default:
		// Handle unknown payload type
		fmt.Println("default")
		return payload, nil
	}
	return payload, nil
}

func DecodeIKENoncePayload(data []byte, offset int) (IKENoncePayload, error) {
	header, off := DecodeIKEHeader(data, offset)
	nonce := make([]byte, int(header.Length)-4)
	copy(nonce, data[off:int(header.Length)+off+4])
	payload := IKENoncePayload{
		Header: header,
		Nonce:  nonce,
	}
	off += int(payload.Header.Length) - 4

	switch payload.Header.NextPayload {
	case IKEPayloadSA:
		payload.Payload, _ = DecodeIKESAPayload(data, off)
	case IKEPayloadKE:
		payload.Payload, _ = DecodeIKEKEPayload(data, off)
	case IKEPayloadNonce:
		payload.Payload, _ = DecodeIKENoncePayload(data, off)
	case IKEPayloadNotify:
		payload.Payload, _ = DecodeIKENotifyPayload(data, off)
	case IKEPayloadID:
		payload.Payload, _ = DecodeIKEIDPayload(data, off)
	default:
		// Handle unknown payload type
		fmt.Println("default")
		return payload, nil
	}
	return payload, nil
}

func DecodeIKEKEPayload(data []byte, offset int) (IKEKEPayload, error) {
	header, off := DecodeIKEHeader(data, offset)
	ke := make([]byte, int(header.Length)-4)
	copy(ke, data[off:int(header.Length)+off+4])
	payload := IKEKEPayload{
		Header: header,
		KE:     ke,
	}
	off += int(payload.Header.Length) - 4

	switch payload.Header.NextPayload {
	case IKEPayloadSA:
		payload.Payload, _ = DecodeIKESAPayload(data, off)
	case IKEPayloadKE:
		payload.Payload, _ = DecodeIKEKEPayload(data, off)
	case IKEPayloadNonce:
		payload.Payload, _ = DecodeIKENoncePayload(data, off)
	case IKEPayloadNotify:
		payload.Payload, _ = DecodeIKENotifyPayload(data, off)
	case IKEPayloadID:
		payload.Payload, _ = DecodeIKEIDPayload(data, off)
	default:
		// Handle unknown payload type
		fmt.Println("default")
		return payload, nil
	}
	return payload, nil
}

func DecodeIKEIDPayload(data []byte, offset int) (IKEIDPayload, error) {
	header, off := DecodeIKEHeader(data, offset)
	iddata := make([]byte, int(header.Length)-4)
	copy(iddata, data[off+4:int(header.Length)+off+4])
	payload := IKEIDPayload{
		Header:     header,
		IDType:     IKEIDTypesMap[data[off]],
		ProtocolID: IKEProtocolTypesMap[data[off+1]],
		Port:       binary.BigEndian.Uint16(data[off+2 : off+4]),
		Data:       iddata,
	}
	off += int(payload.Header.Length) - 4

	switch payload.Header.NextPayload {
	case IKEPayloadSA:
		payload.Payload, _ = DecodeIKESAPayload(data, off)
	case IKEPayloadNotify:
		payload.Payload, _ = DecodeIKENotifyPayload(data, off)
	case IKEPayloadKE:
		payload.Payload, _ = DecodeKEPayload(data, off)
	case IKEPayloadNonce:
		payload.Payload, _ = DecodeNoncePayload(data, off)
	case IKEPayloadID:
		payload.Payload, _ = DecodeIKEIDPayload(data, off)
	default:
		// Handle unknown payload type
		fmt.Println("default")
		return payload, nil
	}
	return payload, nil
}

func DecodeIKEHeader(data []byte, offset int) (IKEPayloadHeader, int) {
	header := IKEPayloadHeader{
		NextPayload: IKEPayloadTypeMap[data[offset]],
		Flags:       data[offset+1],
		Length:      binary.BigEndian.Uint16(data[offset+2 : offset+4]),
	}
	return header, offset + 4
}

// Serialize Functions
func (i *IKEv1) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	case IKESAPayload:
		p.SerializeSAPayload(bytes, 28)
	case IKEKEPayload:
		p.SerializeKEPayload(bytes, 28)
	case IKENoncePayload:
		p.SerializeNoncePayload(bytes, 28)
	case IKEIDPayload:
		p.SerializeIDPayload(bytes, 28)
	default:
		// Handle unknown payload type
		fmt.Println("default")
		return nil
	}
	return nil
}

func (i *IKESAPayload) SerializeSAPayload(data []byte, offset int) error {
	off := i.Header.SerializeHeader(data, offset)
	binary.BigEndian.PutUint32(data[off:off+4], uint32(i.DOI))
	binary.BigEndian.PutUint32(data[off+4:off+8], uint32(i.Situation))
	for _, prop := range i.Proposals {
		off = prop.Header.SerializeHeader(data, off+8)
		off = prop.SerializeProposal(data, off)
	}

	switch p := i.Payload.(type) {
	case IKESAPayload:
		p.SerializeSAPayload(data, off)
	case IKEKEPayload:
		p.SerializeKEPayload(data, off)
	case IKENoncePayload:
		p.SerializeNoncePayload(data, off)
	case IKEIDPayload:
		p.SerializeIDPayload(data, off)
	default:
		// Handle unknown payload type
		return nil
	}
	return nil
}

func (i *IKEProposal) SerializeProposal(data []byte, offset int) int {
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

func (i *IKETransform) SerializeTransform(data []byte, offset int) int {
	data[offset] = i.TransNb
	data[offset+1] = byte(i.TransformId)
	copy(data[offset+2:offset+4], i.Flag[:])
	offset += 4
	for _, trans := range i.Attributes {
		offset = trans.SerializeAttributes(data, offset)
	}
	return offset
}

func (i *IKETransformAttr) SerializeAttributes(data []byte, offset int) int {
	copy(data[offset:offset+2], i.Type[:])
	binary.BigEndian.PutUint16(data[offset+2:offset+4], i.Length)
	if i.Type[0] == 0 {
		copy(data[offset+4:offset+4+int(i.Length)], i.Value[:])
		return offset + 4 + int(i.Length)
	}
	return offset + 4
}

func (i *IKEKEPayload) SerializeKEPayload(data []byte, offset int) error {
	off := i.Header.SerializeHeader(data, offset)
	copy(data[off:], i.KE[:])
	off += len(i.KE)
	switch p := i.Payload.(type) {
	case IKESAPayload:
		p.SerializeSAPayload(data, off)
	case IKEKEPayload:
		p.SerializeKEPayload(data, off)
	case IKENoncePayload:
		p.SerializeNoncePayload(data, off)
	case IKEIDPayload:
		p.SerializeIDPayload(data, off)
	default:
		// Handle unknown payload type
		return nil
	}
	return nil
}

func (i *IKENoncePayload) SerializeNoncePayload(data []byte, offset int) error {
	off := i.Header.SerializeHeader(data, offset)
	copy(data[off:], i.Nonce[:])
	off += len(i.Nonce)
	switch p := i.Payload.(type) {
	case IKESAPayload:
		p.SerializeSAPayload(data, off)
	case IKEKEPayload:
		p.SerializeKEPayload(data, off)
	case IKENoncePayload:
		p.SerializeNoncePayload(data, off)
	case IKEIDPayload:
		p.SerializeIDPayload(data, off)
	default:
		// Handle unknown payload type
		return nil
	}
	return nil
}

func (i *IKEIDPayload) SerializeIDPayload(data []byte, offset int) error {
	off := i.Header.SerializeHeader(data, offset)
	data[off] = byte(i.IDType)
	data[off+1] = byte(i.ProtocolID)
	binary.BigEndian.PutUint16(data[off+2:off+4], i.Port)
	copy(data[off+4:], i.Data[:])
	off += len(i.Data)
	switch p := i.Payload.(type) {
	case IKESAPayload:
		p.SerializeSAPayload(data, off)
	case IKEKEPayload:
		p.SerializeKEPayload(data, off)
	case IKENoncePayload:
		p.SerializeNoncePayload(data, off)
	case IKEIDPayload:
		p.SerializeIDPayload(data, off)
	default:
		// Handle unknown payload type
		return nil
	}
	return nil
}

func (i *IKEPayloadHeader) SerializeHeader(data []byte, offset int) int {
	data[offset] = byte(i.NextPayload)
	data[offset+1] = i.Flags
	binary.BigEndian.PutUint16(data[offset+2:], i.Length)
	return offset + 4
}
