package packet

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/tiagomdiogo/GoPpy/supersocket"
	"log"
)

func CraftPacket(layers ...gopacket.SerializableLayer) ([]byte, error) {

	buffer := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer, opts, layers...)
	if err != nil {
		return nil, fmt.Errorf("error serializing layers: %v", err)
	}

	return buffer.Bytes(), nil
}

func Send(packetBytes []byte, iface string) {
	superS, err := supersocket.NewSuperSocket(iface, "")
	if err != nil {
		log.Fatal(err)
	}
	superS.Send(packetBytes)
	superS.Close()
}
