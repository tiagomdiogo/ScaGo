package supersocket

import (
	"bytes"
	"log"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/GoPpy/packet"
)

func TestSuperSocketARPCapture(t *testing.T) {
	// Replace "eth0" with the appropriate network device name on your system
	ss, err := NewSuperSocket("en0", "arp")
	if err != nil {
		log.Fatalf("Failed to create SuperSocket: %v", err)
	}
	defer ss.Close()

	// Replace the IP and MAC addresses with appropriate values for your network
	srcIP := "192.168.1.1"
	dstIP := "192.168.1.2"
	srcMAC := "08:00:27:01:02:03"
	dstMAC := "ff:ff:ff:ff:ff:ff"

	arpPacket, err := packet.CraftARPPacket(srcIP, dstIP, srcMAC, dstMAC)
	if err != nil {
		log.Fatalf("Failed to craft ARP packet: %v", err)
	}

	err = ss.Send(arpPacket)
	if err != nil {
		t.Fatalf("Failed to send ARP packet: %v", err)
	}

	timeout := time.After(5 * time.Second)
	received := make(chan bool)

	go func() {
		for {
			select {
			case <-timeout:
				return
			default:
				packet, err := ss.Recv()
				if err != nil {
					continue
				}

				arpLayer := packet.Layer(layers.LayerTypeARP)
				if arpLayer == nil {
					continue
				}

				arp := arpLayer.(*layers.ARP)
				if arp.Operation != layers.ARPReply {
					continue
				}

				if bytes.Equal(arp.SourceHwAddress, []byte{0x08, 0x00, 0x27, 0x01, 0x02, 0x04}) {
					received <- true
					return
				}
			}
		}
	}()

	select {
	case <-timeout:
		t.Fatal("Timeout waiting for ARP response")
	case <-received:
		t.Log("Received expected ARP response")
	}
}
