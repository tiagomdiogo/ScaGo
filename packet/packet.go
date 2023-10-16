package packet

import (
	"fmt"
	"github.com/google/gopacket"
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
