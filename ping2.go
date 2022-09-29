package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const target = "google.com"

func main() {
	for {
		time.Sleep(time.Second * 1)
		Ping(target)
	}
}

func Ping(target string) {
	ip, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		panic(err)
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Printf("Error on ListenPacket")
		panic(err)
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte(""),
		},
	}
	msg_bytes, err := msg.Marshal(nil)
	if err != nil {
		fmt.Printf("Error on Marshal %v", msg_bytes)
		panic(err)
	}

	// Write the message to the listening connection
	if _, err := conn.WriteTo(msg_bytes, ip); err != nil {
		fmt.Printf("Error on WriteTo %v", err)
		panic(err)
	}

	err = conn.SetReadDeadline(time.Now().Add(time.Second * 1))
	if err != nil {
		fmt.Printf("Error on SetReadDeadline %v", err)
		panic(err)
	}
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)

	if err != nil {
		fmt.Printf("Error on ReadFrom %v", err)
		panic(err)
	}
	parsed_reply, err := icmp.ParseMessage(1, reply[:n])

	if err != nil {
		fmt.Printf("Error on ParseMessage %v", err)
		panic(err)
	}

	switch parsed_reply.Code {
	case 0:
		// Got a reply so we can save this
		fmt.Printf("Got Reply from %s\n", target)
	case 3:
		fmt.Printf("Host %s is unreachable\n", target)
		// Given that we don't expect google to be unreachable, we can assume that our network is down
	case 11:
		// Time Exceeded so we can assume our network is slow
		fmt.Printf("Host %s is slow\n", target)
	default:
		// We don't know what this is so we can assume it's unreachable
		fmt.Printf("Host %s is unreachable\n", target)
	}
}
