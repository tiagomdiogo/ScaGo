package main

import (
	"bufio"
	"fmt"
	"github.com/tiagomdiogo/ScaGo/higherlevel"
	"github.com/tiagomdiogo/ScaGo/sniffer"
	"log"
	"os"
	"strconv"
	"strings"
)

// help is an aux function to output all the available instructions on
// the shell mode
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
	fmt.Println("")
	fmt.Println("Root Bridge takeover 2 interfaces - Consists of taking the role of Root bridge with 2 interfaces on a LAN network")
	fmt.Println("To perform this attack type: rootbridge <Interface1> <Interface2>")
	fmt.Println("")
	fmt.Println("DHCP Spoofing - Consists of sending spoofed responses with malicious configurations")
	fmt.Println("To perform this attack type: dhcpspoofing <interface>")
	fmt.Println("")
	fmt.Println("Double tag - inject malicious data into a network by encapsulating packets with two VLAN tags, deceiving switches and gaining unauthorized access to traffic on different VLANs.")
	fmt.Println("To perform this attack type: doubletag <interface> <victimIP> <VlanOut> <vlanIn>")
	fmt.Println("")
	fmt.Println("TCP SYN - Consume server resources by sending SYN requests to make the system unresponsive to legitimate traffic.")
	fmt.Println("tcpsyn <Target IP> <TargetPort>")
	fmt.Println("")
	fmt.Println("IKEv1 DoS - Consists of performing a Denial of Service attack to IKEv1 tunnel through spoofed messages")
	fmt.Println("To perform this attack type: ikev1dos <flag> <number_of_packets> <destination_ip> <interface>")
	fmt.Println("Available flags: -c concurrent packets | -s sequential packets")
	fmt.Println("")
	fmt.Println("IKEv2 DoS - Consists of performing a Denial of Service attack to IKEv2 tunnel through spoofed messages")
	fmt.Println("Available flags: -c concurrent packets | -s sequential packets")
	fmt.Println("To perform this attack type: ikev2dos <flag> <number_of_packets> <destination_ip> <interface>")
	fmt.Println("")
}

// main function of the library, it launches a shell that can be used to
// start the several coded attacks.
func main() {

	fmt.Println("[*] Welcome to Goppy interactive shell")
	fmt.Println("[*] Too see available commands type the command: help")

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
		//switch case for each of the available functions
		//it launches the function if enough arguments are provided.
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
				higherlevel.TCPSYNFlood(cmdWords[1], cmdWords[2], "120", 10000)
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
		case "ikev1dos":
			if len(cmdWords) < 4 {
				fmt.Println("To use ikev1dos provide the following instructions:")
				fmt.Println("ikev1dos <flag> <number_of_packets> <destination_ip> <interface> <batch_size>")

			} else if cmdWords[1] == "-s" {
				npackets, err := strconv.Atoi(cmdWords[2])
				if err != nil {
					continue
				}
				go higherlevel.IKEv1DoSSequential(npackets, cmdWords[3], cmdWords[4])
			} else {
				npackets, err := strconv.Atoi(cmdWords[2])
				if err != nil {
					continue
				}
				go higherlevel.IKEv1DoS(npackets, cmdWords[3], cmdWords[4])
			}
		case "ikev2dos":
			if len(cmdWords) < 5 {
				fmt.Println("To use ikev2dos provide the following instructions:")
				fmt.Println("ikev2dos <flag> <number_of_packets> <destination_ip> <interface>")

			} else if cmdWords[1] == "-s" {
				npackets, err := strconv.Atoi(cmdWords[2])
				if err != nil {
					continue
				}
				go higherlevel.IKEv2DoSSequential(npackets, cmdWords[3], cmdWords[4])
			} else if cmdWords[1] == "-c" {
				npackets, err := strconv.Atoi(cmdWords[2])
				if err != nil {
					continue
				}
				go higherlevel.IKEv2DoS(npackets, cmdWords[3], cmdWords[4])
			} else {
				fmt.Println("Please use one of the available flags: -c concurrent | -b batch | -s sequential")
				fmt.Println("")
			}
		}

	}
}
