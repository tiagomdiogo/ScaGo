package protocols

var IKEv2AttributeTypes = map[int]struct {
	Name       string
	Attributes map[int]string
}{
	1: {
		Name: "Encryption",
		Attributes: map[int]string{
			1:  "DES-IV64",
			2:  "DES",
			3:  "3DES",
			4:  "RC5",
			5:  "IDEA",
			6:  "CAST",
			7:  "Blowfish",
			8:  "3IDEA",
			9:  "DES-IV32",
			12: "AES-CBC",
			13: "AES-CTR",
			14: "AES-CCM-8",
			15: "AES-CCM-12",
			16: "AES-CCM-16",
			18: "AES-GCM-8ICV",
			19: "AES-GCM-12ICV",
			20: "AES-GCM-16ICV",
			23: "Camellia-CBC",
			24: "Camellia-CTR",
			25: "Camellia-CCM-8ICV",
			26: "Camellia-CCM-12ICV",
			27: "Camellia-CCM-16ICV",
			28: "ChaCha20-Poly1305",
			32: "Kuzneychik-MGM-KTREE",
			33: "MAGMA-MGM-KTREE",
		},
	},
	2: {
		Name: "PRF",
		Attributes: map[int]string{
			1: "PRF_HMAC_MD5",
			2: "PRF_HMAC_SHA1",
			3: "PRF_HMAC_TIGER",
			4: "PRF_AES128_XCBC",
			5: "PRF_HMAC_SHA2_256",
			6: "PRF_HMAC_SHA2_384",
			7: "PRF_HMAC_SHA2_512",
			8: "PRF_AES128_CMAC",
			9: "PRF_HMAC_STREEBOG_512",
		},
	},
	3: {
		Name: "Integrity",
		Attributes: map[int]string{
			1:  "HMAC-MD5-96",
			2:  "HMAC-SHA1-96",
			3:  "DES-MAC",
			4:  "KPDK-MD5",
			5:  "AES-XCBC-96",
			6:  "HMAC-MD5-128",
			7:  "HMAC-SHA1-160",
			8:  "AES-CMAC-96",
			9:  "AES-128-GMAC",
			10: "AES-192-GMAC",
			11: "AES-256-GMAC",
			12: "SHA2-256-128",
			13: "SHA2-384-192",
			14: "SHA2-512-256",
		},
	},
	4: {
		Name: "GroupDesc",
		Attributes: map[int]string{
			1:  "768MODPgr",
			2:  "1024MODPgr",
			5:  "1536MODPgr",
			14: "2048MODPgr",
			15: "3072MODPgr",
			16: "4096MODPgr",
			17: "6144MODPgr",
			18: "8192MODPgr",
			19: "256randECPgr",
			20: "384randECPgr",
			21: "521randECPgr",
			22: "1024MODP160POSgr",
			23: "2048MODP224POSgr",
			24: "2048MODP256POSgr",
			25: "192randECPgr",
			26: "224randECPgr",
			27: "brainpoolP224r1gr",
			28: "brainpoolP256r1gr",
			29: "brainpoolP384r1gr",
			30: "brainpoolP512r1gr",
			31: "curve25519gr",
			32: "curve448gr",
			33: "GOST3410_2012_256",
			34: "GOST3410_2012_512",
		},
	},
	5: {
		Name: "Extended Sequence Number",
		Attributes: map[int]string{
			0: "No ESN",
			1: "ESN",
		},
	},
}

var IKEv2ProtocolTypes = map[int]string{
	1: "IKE",
	2: "AH",
	3: "ESP",
}

var IKEv2AuthenticationTypes = map[int]string{
	0:  "Reserved",
	1:  "RSA Digital Signature",
	2:  "Shared Key Message Integrity Code",
	3:  "DSS Digital Signature",
	9:  "ECDSA with SHA-256 on the P-256 curve",
	10: "ECDSA with SHA-384 on the P-384 curve",
	11: "ECDSA with SHA-512 on the P-521 curve",
	12: "Generic Secure Password Authentication Method",
	13: "NULL Authentication",
	14: "Digital Signature",
}

var IKEv2NotifyMessageTypes = map[int]string{
	1: "UNSUPPORTED_CRITICAL_PAYLOAD",
	4: "INVALID_IKE_SPI",
	// ... Add remaining entries here
	16441: "IV2_NOTIFY_ADDITIONAL_KEY_EXCHANGE",
	16442: "IV2_NOTIFY_USE_AGGFRAG",
}

var IKEv2GatewayIDTypes = map[int]string{
	1: "IPv4_addr",
	2: "IPv6_addr",
	3: "FQDN",
}

var IKEv2CertificateEncodings = map[int]string{
	1: "PKCS #7 wrapped X.509 certificate",
	2: "PGP Certificate",
	// ... Add remaining entries here
	12: "Hash and URL of X.509 certificate",
	13: "Hash and URL of X.509 bundle",
}

var IKEv2TrafficSelectorTypes = map[int]string{
	7: "TS_IPV4_ADDR_RANGE",
	8: "TS_IPV6_ADDR_RANGE",
	9: "TS_FC_ADDR_RANGE",
}

var IKEv2ConfigurationPayloadCFGTypes = map[int]string{
	1: "CFG_REQUEST",
	2: "CFG_REPLY",
	3: "CFG_SET",
	4: "CFG_ACK",
}

var IKEv2ConfigurationAttributeTypes = map[int]string{
	1: "INTERNAL_IP4_ADDRESS",
	// ... Add remaining entries here
	25: "INTERNAL_DNS_DOMAIN",
	26: "INTERNAL_DNSSEC_TA",
}

var IPProtocolIDs = map[int]string{
	0: "All protocols",
	1: "Internet Control Message Protocol",
	// ... Add remaining entries here
	121: "Simple Message Protocol",
	122: "Simple Multicast Protocol",
	// Continue with the remaining entries
}
