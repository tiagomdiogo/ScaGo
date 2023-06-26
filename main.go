package GoPpy

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	sniffer "github.com/tiagomdiogo/GoPpy/sniffer"
)

func execFunc(cmd string) {
	cmdString := strings.TrimSuffix(cmd, "\n")
	arrCmd := strings.Fields(cmdString)

	switch arrCmd[0] {
	case "sniffer":
		interface_name := arrCmd[1]
		sniffer.CapturePacket(interface_name)
	case "send":
	}
}

func main() {

	fmt.Println("Welcome to Go Sniffer. To get help in usage please use the -help argument.")

	//Creating a simple shell to read commands

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("$ ")
		cmd, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
			return
		}
		execFunc(cmd)
	}

}
