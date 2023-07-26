package packet

import (
	golayers "github.com/google/gopacket/layers"
	"net"
)

type DNS struct {
	layer *golayers.DNS
}

func DNSLayer() *DNS {
	return &DNS{
		layer: &golayers.DNS{
			ID: 0xAAAA,
			QR: false,
		},
	}
}

func (dns *DNS) AddQuestion(name string) {
	dns.layer.QDCount = 1
	dns.layer.Questions = append(dns.layer.Questions, golayers.DNSQuestion{
		Name:  []byte(name),
		Type:  golayers.DNSTypeA,
		Class: golayers.DNSClassIN,
	})
}

func (dns *DNS) AddAnswer(name string, ipStr string) {
	dns.layer.QR = true
	dns.layer.ANCount = 1

	ip := net.ParseIP(ipStr)

	dns.layer.Answers = append(dns.layer.Answers, golayers.DNSResourceRecord{
		Name:  []byte(name),
		Type:  golayers.DNSTypeA,
		Class: golayers.DNSClassIN,
		TTL:   3600, // For example, a TTL of 1 hour
		IP:    ip,
	})

}

func (dns *DNS) Layer() *golayers.DNS {
	return dns.layer
}
