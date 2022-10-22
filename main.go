package main

import(
	"fmt"
	"os"

	"ping.go/sniffer"
)

func main(){

	fmt.Println("Welcome to Go Sniffer. To get help in usage please use the -help argument.")
	args := os.Args[1:]

	if len(args) != 0{
		if args[0] == "-help"{
			fmt.Println("Usage:\n go run main.go -i <interface_name> -o <Outputfile> -f <Filters>\n\nNote that -o and -f flags are optional.")
		}
		if args[0] == "-i"{
			interface_name := args[1]
			sniffer.CapturePacket(interface_name)
		}
	}

	//interface_name := args[1]
	//var output_file String
	
	
}