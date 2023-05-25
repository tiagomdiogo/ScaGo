package utils

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// Function to generate a random IP address within a specified CIDR block
func RandomIP(cidr string) (string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}

	ip := ipNet.IP.To4()
	if ip == nil {
		return "", fmt.Errorf("CIDR block does not specify an IPv4 network")
	}

	for i := 0; i < 4; i++ {
		// We do not want to generate IPs with 0 or 255 in any octet
		ip[i] += byte(rand.Intn(254) + 1)
		if ip[i] >= ipNet.Mask[i] {
			ip[i] &= ipNet.Mask[i]
		}
	}

	return ip.String(), nil
}

// Function to generate a random MAC address
func RandomMAC() string {
	rand.Seed(time.Now().UnixNano())
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)

	// Set the local bit, unset the multicast bit
	buf[0] = (buf[0] | 2) & 0xfe

	return net.HardwareAddr(buf).String()
}

func ParseIPGen(ipStr string) (string, error) {
	if ipStr == "" || strings.Contains(ipStr, "/") {
		// Generate a random IP if no specific IP is provided or if the provided string is a network
		return RandomIP(ipStr)
	}
	return ipStr, nil
}

func ParseMACGen(macStr string) (string, error) {
	if macStr == "" || strings.Contains(macStr, "/") {
		// Generate a random MAC if no specific MAC is provided or if the provided string is a network
		return RandomMAC(), nil
	}
	return macStr, nil
}
