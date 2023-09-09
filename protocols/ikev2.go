package protocols

type IKEv2PayloadTypes byte
type IKEv2ExchangeTypes byte

const (
	IKEv2PayloadNone          IKEv2PayloadTypes = 0
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

const (
	IKEv2SAInit        IKEv2ExchangeTypes = 34 // Identity Protection (Main Mode)
	IKEv2Auth          IKEv2ExchangeTypes = 35 // Authentication Only
	IKEv2CreateChild   IKEv2ExchangeTypes = 36 // Aggressive Mode
	IKEv2Informational IKEv2ExchangeTypes = 37 // Informational
	IKEv2SessionResume IKEv2ExchangeTypes = 38 // Transaction (Config Mode)
	IKEv2Intermediate  IKEv2ExchangeTypes = 43 // Quick Mode
)

type IKEv2 struct {
	InitSPI     [8]byte            // XStrFixedLenField
	RespSPI     [8]byte            // XStrFixedLenField
	NextPayload IKEv2PayloadTypes  // ByteEnumField
	Version     byte               // XByteField
	ExchType    IKEv2ExchangeTypes // ByteEnumField
	Flags       byte               // FlagsField
	ID          int32              // IntField
	Length      int32              // IntField
}
