package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

func help() {
	fmt.Println("Available commands:")
	fmt.Println("sniff <interface name> - sniffs and shows packets to the desired interface")
	fmt.Println(":")
	fmt.Println("Available attacks:")
	fmt.Println("")
	fmt.Println("There are several developed attacks that you can perform by type the correct commands. The following attacks are available: ")
	fmt.Println("Arp Cache Poisoning - This attack consists of poisoning the victim's ARP table to be able to intercept any communication (MitM)")
	fmt.Println("To perform this attack type: arpcache <Victim1 IP> <Victim2 IP>")
	fmt.Println("")
	fmt.Println("CAM table overflow - Consists of overflowing the capacity of Cam table of a switch")
	fmt.Println("To perform this attack type: camoverflow <Interface> <Number of packets to be sent>")
	fmt.Println("")
	fmt.Println("Root Bridge takeover - Consists of taking the role of Root bridge on a LAN network")
	fmt.Println("To perform this attack type: rootbridge <Interface>")

}

func main() {

	fmt.Println("[*] Welcome to Goppy interactive shell")
	fmt.Println("[*] Too see available commands type the command: help")

	//Creating a simple shell to read commands

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("$Goppy Shell ")
		cmd, err := reader.ReadString('\n')
		cmd = strings.TrimSpace(cmd)
		if err != nil {
			log.Fatal(err)
			return
		}
		switch cmd {
		case "help":
			help()
		case "exit":
			os.Exit(0)
		case "arpcache":
			continue
		case "camoverflow":
			continue
		case "rootbridge":
			continue
		}

	}

}
