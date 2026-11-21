package settings

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Chitakasa/om/internal/netdetect"
)

// VPNInterfaces returns the trusted VPN interfaces: OM_VPN lists interfaces or addresses, and an address maps
// to its interface. Items that match no candidate are dropped.
func (s Settings) VPNInterfaces(det *netdetect.Detector) []string {
	cands := det.VPNCandidates()
	var out []string
	for _, item := range netdetect.VPNItems(s.Get("OM_VPN", "")) {
		name, found := item, false
		for _, c := range cands {
			if item == c.Name || item == c.IP {
				if !found {
					name = c.Name
				}
				found = true
			}
		}
		if found {
			out = append(out, name)
		}
	}
	return unique(out)
}

// VPNPeers returns the IPv4 addresses of the other devices on the trusted VPNs, from the kernel's routes through
// each VPN interface — no VPN product's tool: a mesh VPN routes every peer (one host route each), a hub VPN
// routes a small subnet (scanned, ≤ /24, keeping addresses its DNS names), a layer-2 VPN has neighbours.
func (s Settings) VPNPeers(det *netdetect.Detector, resolved Resolved) []string {
	own := map[string]bool{}
	for _, ip := range resolved.VPNIPs {
		own[ip] = true
	}
	for _, ns := range det.Nameservers() {
		own[ns] = true
	}
	hosts := map[string]bool{}
	var ranges []netip.Prefix
	for _, iface := range s.VPNInterfaces(det) {
		var dsts []string
		switch det.OS {
		case "linux":
			dsts = linuxRoutes(det, iface, hosts)
		case "darwin":
			dsts = netdetect.MacOSRoutes(iface, det.Run([]string{"netstat", "-rn", "-f", "inet"}).Stdout)
		default:
			dsts = strings.Fields(det.Powershell("(Get-NetRoute -AddressFamily IPv4 -InterfaceAlias '" + iface + "').DestinationPrefix"))
		}
		for _, d := range dsts {
			if d == "default" {
				d = "0.0.0.0/0"
			}
			n, ok := ParseNetwork(d)
			if !ok {
				continue
			}
			p, err := netip.ParsePrefix(n)
			if err != nil || !p.Addr().Is4() {
				continue
			}
			switch {
			case p.Bits() == 32:
				hosts[p.Addr().String()] = true
			case p.Bits() >= 24:
				ranges = append(ranges, p)
			}
		}
	}
	if len(ranges) > 0 && len(hosts) == 0 { // a hub VPN: which addresses of its subnet does its DNS know?
		for _, ip := range scanRanges(det, ranges) {
			hosts[ip] = true
		}
	}
	var out []netip.Addr
	for h := range hosts {
		a, err := netip.ParseAddr(h)
		if err != nil || own[h] || a.IsMulticast() {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	res := make([]string, len(out))
	for i, a := range out {
		res[i] = a.String()
	}
	return res
}

// linuxRoutes reads `ip -j` routes (destinations returned) and neighbours (added to hosts) for an interface.
// A malformed answer drops the routes, as the Python try/except does.
func linuxRoutes(det *netdetect.Detector, iface string, hosts map[string]bool) []string {
	r := det.Run([]string{"ip", "-j", "-4", "route", "show", "table", "all", "dev", iface})
	n := det.Run([]string{"ip", "-j", "-4", "neigh", "show", "dev", iface})
	var routes []map[string]any
	if json.Unmarshal([]byte(orList(r.Stdout)), &routes) != nil {
		return nil
	}
	var dsts []string
	for _, x := range routes {
		if t, has := x["type"]; !has || t == "unicast" {
			d, _ := x["dst"].(string)
			dsts = append(dsts, d)
		}
	}
	var neigh []struct {
		Dst string `json:"dst"`
	}
	if json.Unmarshal([]byte(orList(n.Stdout)), &neigh) != nil {
		return nil
	}
	for _, x := range neigh {
		if x.Dst != "" {
			hosts[x.Dst] = true
		}
	}
	return dsts
}

func orList(s string) string {
	if s == "" {
		return "[]"
	}
	return s
}

// scanRanges asks the VPN's DNS (PTR) which addresses of small subnets it names; at most 512 addresses.
func scanRanges(det *netdetect.Detector, ranges []netip.Prefix) []string {
	servers := det.Nameservers()
	var cands []string
	for _, p := range ranges {
		cands = append(cands, hostAddrs(p)...)
		if len(cands) >= 512 {
			break
		}
	}
	if len(cands) > 512 {
		cands = cands[:512]
	}
	named := make([]string, len(cands))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for i, ip := range cands {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, sv := range servers {
				if det.PTR(ip, sv, time.Second) != "" {
					named[i] = ip
					return
				}
			}
		}(i, ip)
	}
	wg.Wait()
	var out []string
	for _, ip := range named {
		if ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

// hostAddrs is ipaddress.IPv4Network.hosts(): every address but the network and broadcast ones (a /31 has both).
func hostAddrs(p netip.Prefix) []string {
	var out []string
	first, last := p.Masked().Addr(), lastAddr(p)
	if p.Bits() <= 30 {
		first, last = first.Next(), last.Prev()
	}
	for a := first; a.IsValid() && a.Compare(last) <= 0; a = a.Next() {
		out = append(out, a.String())
	}
	return out
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= (uint32(1) << host) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
