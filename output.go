package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"text/template"
	"time"

	"github.com/jpicht/gopacket/layers"
)

const templateString = `
<html>
<head><meta http-equiv="refresh" content="1"></head>
<head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head>
<style>
body {
	font-size: 200%;
}
</style>
<body>
{{if .Link}}
{{if .HaveCDP}}
<h1>CDP v{{.CDP.CDPHello.Version}} - TTL {{.CDPAge}}</h1>
<h2>{{.CDP.Platform}}</h2>
<h2>Switch: {{.CDP.DeviceID}}<br>
Port: {{.CDP.PortID}}</h2>
{{end}}
{{else}}
<h1>NO LINK</h1>
{{end}}
<div>
	DHCP: {{range .DHCP}}
	<span class="dhcp">{{.}}</span>
	{{else}}
	no requests seen
	{{end}}
</div>
<div>
	IPv6: {{range .IPv6}}
	<span class="ipv6">{{.}}</span>
	{{else}}
	none seen
	{{end}}
</div>
<h3>Last update {{.Ts}}</h3>
</body>
</html>
`

type output struct {
	lock     sync.Mutex
	notify   chan struct{}
	fileName string

	linkStatus     bool
	cdpData        *layers.CiscoDiscoveryInfo
	cdpTime        time.Time
	cdpTTL         time.Duration
	cdpTimer       *time.Timer
	ipv6Neighbours []net.IP
	dhcp           []string

	tpl *template.Template
}

// Output renderer
type Output interface {
	AddDHCPHost(string)
	AddIPv6Neighbour(net.IP)
	SetLinkState(bool)
	SetCiscoTTL(time.Duration)
	SetCiscoDiscoveryInfo(*layers.CiscoDiscoveryInfo)

	Stop()
}

// NewOutput creates a new output renderer
func NewOutput(fileName string) Output {
	var tpl, err = template.New("").Parse(templateString)
	if err != nil {
		log.Fatal(err)
	}

	o := &output{
		lock:     sync.Mutex{},
		notify:   make(chan struct{}),
		fileName: fileName,

		linkStatus:     false,
		cdpData:        nil,
		cdpTTL:         60 * time.Second,
		cdpTimer:       time.NewTimer(60 * time.Second),
		ipv6Neighbours: make([]net.IP, 0),
		dhcp:           make([]string, 0),

		tpl: tpl,
	}
	o.render()
	go o.run()
	return o
}

func (o *output) run() {
	for {
		select {
		case <-o.notify:
			o.render()
		case <-o.cdpTimer.C:
			o.cdpData = nil
		}
	}
}

func (o *output) AddDHCPHost(host string) {
	o.lock.Lock()
	if len(o.dhcp) > 3 {
		o.dhcp = append([]string{host}, o.dhcp[1:2]...)
	} else {
		o.dhcp = append([]string{host}, o.dhcp...)
	}
	o.lock.Unlock()
	o.notify <- struct{}{}
}

func (o *output) AddIPv6Neighbour(ip net.IP) {
	o.lock.Lock()
	o.ipv6Neighbours = append(o.ipv6Neighbours, ip)
	o.lock.Unlock()
	o.notify <- struct{}{}
}

func (o *output) SetLinkState(value bool) {
	o.lock.Lock()
	oldState := o.linkStatus
	o.linkStatus = value
	if !value {
		o.cdpData = nil
		o.ipv6Neighbours = make([]net.IP, 0)
		o.dhcp = make([]string, 0)
	}
	o.lock.Unlock()
	if value != oldState {
		o.notify <- struct{}{}
	}
}

func (o *output) SetCiscoDiscoveryInfo(cdp *layers.CiscoDiscoveryInfo) {
	o.lock.Lock()
	o.cdpData = cdp
	o.cdpTimer.Reset(o.cdpTTL)
	o.cdpTime = time.Now()
	o.lock.Unlock()
	o.notify <- struct{}{}
}

func (o *output) SetCiscoTTL(ttl time.Duration) {
	o.lock.Lock()
	age := time.Now().Sub(o.cdpTime)
	if age > ttl {
		o.cdpData = nil
	}
	o.cdpTTL = ttl
	o.lock.Unlock()
}

func (o *output) render() {
	tempFileName := o.fileName + ".tmp"
	f, err := os.OpenFile(
		tempFileName,
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
		os.FileMode(0644),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		f.Close()
		err := os.Rename(tempFileName, o.fileName)
		if err != nil {
			log.Fatal(err)
		}
	}()

	o.lock.Lock()
	now := time.Now()
	err = o.tpl.Execute(f, struct {
		Ts      string
		HaveCDP bool
		CDP     *layers.CiscoDiscoveryInfo
		CDPAge  string
		Link    bool
		DHCP    []string
		IPv6    []net.IP
	}{
		now.Format("15:04:05"),
		o.cdpData != nil,
		o.cdpData,
		fmt.Sprintf("%.0fs", (o.cdpTTL - now.Sub(o.cdpTime)).Seconds()),
		o.linkStatus,
		o.dhcp,
		o.ipv6Neighbours,
	})
	o.lock.Unlock()
	if err != nil {
		log.Fatal(err)
	}
}

func (o *output) Stop() {
	o.lock.Lock()
	o.cdpTimer.Stop()
	close(o.notify)
}
