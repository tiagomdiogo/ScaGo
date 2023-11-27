/*
Package main provides an interactive shell to run the attacks in shell mode

Scago contains many sub-packages with additional functionality you may find
useful, including:
  - packet: This is the most important package of the whole library. It contains
    the structures for each supported layer. The structures have a pointer to
    the gopacket original structure and contain several functions that allow
    an easier modification of the attributes of each layer.
    To combine multiple layers the function CraftPacket() can be used. More
    documentation provided on the package documentation.
  - protocols: This package contains the new added layers that did not have support
    on the gopacket library. It implements the Serialize and Decode method from
    each of the layers.
  - supersocket: This package redifines the traditional Send and Recv from the pcap
    library. It provides an easier way to send and receive packets for the user
  - sniffer: This package provides sniffing capabilities using the pcap library.
  - utils: Utility functions that aid the library to achieve a higher abstraction
    level for the end user.
  - higherlevel: Pre-defined codes for the following security attacks: ARP cache
    poisoning, CAM table overflow, DHCP spoofing, DNS spoofing, VLAN double tag,
    RIP poison, STP root bridge hijack, TCP SYN flood.

Minimum go version required is 1.7 due to x/sys dependency.

All the code below assumes that you have imported both scago and scago/packet.

# Basic Usage

Scago allows a higher-level codification of packets. It uses gopacket as his basis and provides structures that will
allow an easier interaction/manipulation with network packets. It also provides higher level functions that codifies
certain network attacks.

Create an ethernet layer

	//Craft the Ethernet Layer
	ethLayer := packet.EthernetLayer()
	//Set Source and Destination Mac
	ethLayer.SetSrcMAC(""11:22:33:44:55:66:"")
	ethLayer.SetDstMAC("ff:ff:ff:ff:ff:ff")
*/
package main
