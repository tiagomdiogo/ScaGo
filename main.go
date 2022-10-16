package main

import(
	"fmt"
	"os"

	"ping.go/sniffer"
)

func main(){

	fmt.Println("Welcome to Go Sniffer. To get help in usage please use the -help argument.")
	args := os.Args[1:]

	if args[0] == "-help" {
		fmt.Println("Usage:\n go run main.go -i <interface_name> -o <Outputfile> -f <Filters>\n\nNote that -o and -f flags are optional.")
	}

	//interface_name := args[1]
	//var output_file String

	fmt.Println(sniffer.Greet1())
	
}