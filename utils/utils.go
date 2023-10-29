package utils

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
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
	return ips[1:], nil
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

func GetInterfaceByIP(ip net.IP) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 { // Skip loopback interfaces
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}

			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok && ipNet.IP.Equal(ip) {
					return &iface, nil
				}
			}
		}
	}
	return nil, nil
}

func AreIPsInSameSubnet(ip1, ip2 net.IP) bool {
	mask := ip1.DefaultMask()
	return ip1.Mask(mask).Equal(ip2.Mask(mask))
}

func GetDefaultGatewayInterface() (*net.Interface, error) {
	gatewayIP, err := GetDefaultGatewayIP()
	if err != nil {
		return nil, err
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok && ipNet.Contains(gatewayIP) {
					return &iface, nil
				}
			}
		}
	}
	return nil, errors.New("interface for default gateway not found")
}

func GetDefaultGatewayIP() (net.IP, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("route", "print", "0.0.0.0")
	case "linux", "darwin":
		cmd = exec.Command("ip", "route")
	default:
		return nil, errors.New("unsupported operating system")
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	output := string(out)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 1 && (fields[0] == "default" || fields[0] == "0.0.0.0") {
			return net.ParseIP(fields[2]), nil
		}
	}
	return nil, errors.New("default gateway not found")
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
