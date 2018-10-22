package main

import (
	"fmt"
	"log"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/jpicht/ethtool"
	"github.com/jpicht/gopacket"
	"github.com/jpicht/gopacket/layers"
	"github.com/jpicht/gopacket/pcap"
	flag "github.com/ogier/pflag"
)

var (
	device            = "eth0"
	outputFile        string
	captureBufferSize = 1024
	promiscuous       = true
	err               error
	timeout           = "100ms"
	handle            *pcap.Handle
)

func main() {
	flag.StringVarP(&device, "device", "d", "eth0", "Device to capture")
	flag.StringVarP(&outputFile, "output", "o", "/var/www/html/portview/index.html", "HTML output file")
	flag.IntVarP(&captureBufferSize, "capture-buffer", "b", 1024*1024, "Capture buffer size")
	flag.StringVarP(&timeout, "timeout", "t", "100ms", "Maximum time waiting for the buffer to be filled")
	flag.Parse()

	var bufferSize int32
	if captureBufferSize > 2147483647 || captureBufferSize < 0 {
		bufferSize = 2147483647
	} else {
		bufferSize = int32(captureBufferSize)
	}

	var duration time.Duration
	duration, err = time.ParseDuration(timeout)
	if err != nil {
		log.Fatalf("Invalid duration '%s'", timeout)
	}
	if duration < 0*time.Second {
		log.Fatalf("Cannot wait for negative amount of time: '%s'", timeout)
	}

	handle, err = pcap.OpenLive(device, bufferSize, promiscuous, duration)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		panic(err.Error())
	}

	o := NewOutput(outputFile)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for {
			// Retrieve tx from eth0
			link, err := ethHandle.LinkStatus(device)
			if err != nil {
				panic(err.Error())
			}
			o.SetLinkState(link)
			<-ticker.C
		}
	}()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		for _, layer := range packet.Layers()[2:] {
			handleLayer(o, layer)
		}
	}
}

func handleLayer(o Output, l gopacket.Layer) {
	switch t := l.(type) {
	case *layers.CiscoDiscovery:
		o.SetCiscoTTL(time.Duration(uint8(t.TTL)) * time.Second)
	case *layers.CiscoDiscoveryInfo:
		o.SetCiscoDiscoveryInfo(t)
		fmt.Print("--- CDP")
		fmt.Printf(" Version %d\n", t.CDPHello.Version)
		fmt.Printf(" Device: %s\n", t.DeviceID)
		fmt.Printf(" Port  : %s\n", t.PortID)
		fmt.Printf(" IPs   : %s\n", t.Addresses)
	case *layers.DHCPv4:
		switch t.Operation {
		case layers.DHCPOpRequest:
			fmt.Println("--- DHCP REQUEST")
			fmt.Printf(" Source  : %s (%s)\n", t.ClientHWAddr, t.ClientIP)
			for _, opt := range t.Options {
				switch opt.Type {
				case layers.DHCPOptHostname:
					fmt.Printf(" Hostname: %s\n", opt.Data)
					o.AddDHCPHost(string(opt.Data))
				}
			}
		case layers.DHCPOpReply:
			fmt.Println("--- DHCP REPLY")
		}
	case *layers.DHCPv6:
	case *layers.DNS:
	case *layers.ICMPv4:
		// sublayers not implemented in lib
	case *layers.ICMPv6:
	case *layers.ICMPv6RouterSolicitation:
		/* weird stuff happening, not decoded correctly
		for _, opt := range t.Options {
			switch opt.Type {
			case layers.ICMPv6OptSourceAddress:
				o.AddIPv6Neighbour(opt.Data)
			}
		}
		*/
	case *layers.ICMPv6NeighborSolicitation:
		o.AddIPv6Neighbour(t.TargetAddress)
	case *layers.IPv6HopByHop:
	case *layers.MLDv2MulticastListenerReportMessage:
	case *layers.NTP:
	case *layers.SNAP:
	case *layers.STP:
		// TODO
	case *layers.TCP:
	case *layers.UDP:

	default:
		fmt.Print("--- PACKET")
		spew.Dump(t)

	case *gopacket.DecodeFailure:
	case *gopacket.Payload:
	}
}
