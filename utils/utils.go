package utils

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

func ParseIPGen(cidr ...string) string {
	rand.Seed(time.Now().UnixNano())

	if len(cidr) > 0 {
		_, network, err := net.ParseCIDR(cidr[0])
		if err != nil {
			return ""
		}

		// Convert IP network to bytes
		ip := network.IP.To4()
		mask := network.Mask

		// Randomize the host part
		for i := 0; i < len(mask); i++ {
			ip[i] |= (mask[i] ^ 0xFF) & byte(rand.Intn(256))
		}

		return ip.String()
	}

	// Generate a completely random IP
	ip := make(net.IP, 4)
	rand.Read(ip)
	return ip.String()
}

func GeneratePool(pool, mask string) ([]net.IP, error) {
	ip := net.ParseIP(mask)
	if ip == nil {
		return nil, nil
	}

	ipv4Mask := ip.To4()
	if ipv4Mask == nil {
		return nil, nil
	}

	count := 0
	for _, b := range ipv4Mask {
		for i := 0; i < 8; i++ {
			if (b & (1 << uint(7-i))) != 0 {
				count++
			}
		}
	}

	ip, ipnet, err := net.ParseCIDR(pool + "/" + strconv.Itoa(count))
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, append(net.IP(nil), ip...))
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ParseMACGen(cidr ...string) string {
	if len(cidr) > 0 {
		return cidr[0]
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))

}

func MacByInt(ifaceName string) string {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatal(err)
	}

	return iface.HardwareAddr.String()
}

func IPbyInt(interfaceName string) string {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatal(err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		log.Fatal(err)
	}
	if len(addrs) > 0 {
		return addrs[0].(*net.IPNet).IP.String()
	}
	return ""
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
