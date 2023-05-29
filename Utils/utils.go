package utils

import (
	"math/rand"
	"net"
	"strings"
	"time"
)

// Function to generate a random IP address within a specified CIDR block
func RandomIP(cidr string) (string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}

	ip := ipnet.IP.To4()
	randBytes := make([]byte, 4)
	_, err = rand.Read(randBytes)
	if err != nil {
		return "", err
	}

	for i := range ip {
		ip[i] = (ip[i] & ipnet.Mask[i]) | (randBytes[i] & ^ipnet.Mask[i])
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
