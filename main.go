package main

import (
	"fmt"
	"log"
	"os"
	"text/template"
	"time"

	"github.com/jpicht/ethtool"
	"github.com/jpicht/gopacket"
	"github.com/jpicht/gopacket/layers"
	"github.com/jpicht/gopacket/pcap"
	flag "github.com/ogier/pflag"
)

var (
	device            = "eth0"
	captureBufferSize = 1024
	promiscuous       = true
	err               error
	timeout           = "100ms"
	handle            *pcap.Handle
)

const NoLinkTemplate = `
<html>
<head><meta http-equiv="refresh" content="1"></head>
<style>
body {
	font-size: 200%;
}
</style>
<body>
<h1>NO LINK</h1>
<h3>{{.Ts}}</h3>
</body>
</html>
`

const CDPTemplate = `
<html>
<head><meta http-equiv="refresh" content="1"></head>
<style>
body {
	font-size: 200%;
}
</style>
<body>
<h1>CDP v{{.CDP.CDPHello.Version}}</h1>
<h3>{{.Ts}}</h3>
<h2>Switch: {{.CDP.DeviceID}}<br>
Port: {{.CDP.PortID}}</h2>
<h2>{{.CDP.Platform}}</h2>
<pre>{{.CDP.Version}}</pre>
</body>
</html>
`

var (
	tplCdp, _    = template.New("").Parse(CDPTemplate)
	tplNoLink, _ = template.New("").Parse(NoLinkTemplate)
)

func render(tpl *template.Template, t interface{}) {
	f, _ := os.OpenFile(
		"/var/www/html/portview/temp.html",
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
		os.FileMode(0644),
	)
	defer func() {
		f.Close()
		os.Rename("/var/www/html/portview/temp.html", "/var/www/html/portview/index.html")
	}()
	tpl.Execute(f, t)
}

func main() {
	flag.StringVarP(&device, "device", "d", "eth0", "Device to capture")
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

	go func() {
		for range time.NewTicker(1 * time.Second).C {
			// Retrieve tx from eth0
			link, err := ethHandle.LinkStatus(device)
			if err != nil {
				panic(err.Error())
			}
			if !link {
				render(tplNoLink, struct {
					Ts string
				}{time.Now().String()})
			}
		}
	}()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println(handle.LinkType().String())
	for packet := range packetSource.Packets() {
		//fmt.Println("--- PACKET ---")
		for _, layer := range packet.Layers()[2:] {
			//fmt.Printf("--- LAYER %d ---\n", layerNum+2)
			//fmt.Println(reflect.TypeOf(layer))
			handleLayer(layer)
			//fmt.Println(gopacket.LayerDump(layer))
		}
	}
}

func handleLayer(l gopacket.Layer) {
	switch t := l.(type) {
	case *layers.STP:
		return
		// spew.Dump(t)
	case *layers.CiscoDiscoveryInfo:
		// spew.Dump(t)
		//FIXME
		render(tplCdp, struct {
			CDP *layers.CiscoDiscoveryInfo
			Ts  string
		}{t, time.Now().String()})
		fmt.Print("--- CDP")
		fmt.Printf(" Version %d\n", t.CDPHello.Version)
		fmt.Printf(" Device: %s\n", t.DeviceID)
		fmt.Printf(" Port  : %s\n", t.PortID)
		fmt.Printf(" IPs   : %s\n", t.Addresses)
		/*
			fmt.Printf(" VLAN  : native: %d\n", t.NativeVLAN)
			if t.FullDuplex {
				fmt.Println(" Duplex: FULL")
			} else {
				fmt.Println(" Duplex: HALF")
			}
		*/
	default:
	}
}
