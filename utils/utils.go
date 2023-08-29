package utils

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Function to generate a random IP address within a specified CIDR block
func RandomIP(network string) string {
	ip, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return ""
	}

	for i := 0; i < len(ip); i++ {
		ip[i] = ip[i] | (ipNet.IP[i] &^ ipNet.Mask[i])
	}

	if ip := ip.To4(); ip != nil {
		ip[1] = byte(rand.Intn(255))
		ip[2] = byte(rand.Intn(255))
		ip[3] = byte(rand.Intn(255))
		return ip.String()
	} else if ip := ip.To16(); ip != nil {
		for i := 8; i < 16; i++ {
			ip[i] = byte(rand.Intn(255))
		}
		return ip.String()
	}

	return ""
}

// Function to generate a random MAC address
func RandomMAC() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

func ParseIPGen(ipStr string) string {
	if ipStr == "" || strings.Contains(ipStr, "/") {
		// Generate a random IP if no specific IP is provided or if the provided string is a network
		return RandomIP(ipStr)
	}
	return ipStr
}

func ParseMACGen(macStr string) (string, error) {
	if macStr == "" || strings.Contains(macStr, "/") {
		// Generate a random MAC if no specific MAC is provided or if the provided string is a network
		return RandomMAC(), nil
	}
	return macStr, nil
}

func MacByInt(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", err
	}

	return iface.HardwareAddr.String(), nil
}

func IPbyInt(interfaceName string) (string, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	if len(addrs) > 0 {
		return addrs[0].(*net.IPNet).IP.String(), nil
	}
	return "", fmt.Errorf("No IP found for interface: %s", interfaceName)
}

func RandomPort() string {
	return strconv.Itoa(rand.Intn(65535))
}

func GetRouteInterface(dstIP net.IP) (string, error) {
	// Prepare the command
	cmd := exec.Command("ip", "route", "get", dstIP.String())

	// Execute the command and capture its output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	// Use a regex to find the interface in the output
	re := regexp.MustCompile(`dev\s+(\S+)`)
	match := re.FindStringSubmatch(string(output))
	if match == nil {
		return "", errors.New("could not find interface in routing table")
	}

	return match[1], nil
}
