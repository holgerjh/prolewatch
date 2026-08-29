package egress

import (
	"fmt"
	"net"
)

// Enumeration seams. The failure this constructor now refuses to ignore cannot
// be produced on a working host, so it is injected instead of hoped for.
var (
	networkInterfaces     = net.Interfaces
	networkInterfaceAddrs = (*net.Interface).Addrs
)

// AddressPolicy decides whether an IP address may be contacted at all.
//
// It is a type rather than a broker method because the proxy broker and the
// trusted-side acquisition fetcher must apply an identical rule. One shared
// reserved-range list prevents the two paths from diverging.
type AddressPolicy struct {
	addresses []net.IP
	subnets   []*net.IPNet
	// permitAll exists so tests can drive the real fetch path against a
	// loopback server. It is never set outside tests, and TestAcquireRefuses
	// NonPublicDestinations exercises the real policy against that same server
	// to prove the seam is not the thing being tested.
	permitAll bool
}

// NewAddressPolicy captures the host's own interface addresses and directly
// attached subnets, which the generic reserved-range checks cannot identify.
// Even a globally routable-looking address is denied when it belongs to this
// machine or its LAN.
//
// An enumeration that fails is an error rather than an empty local list. The
// reserved-range checks would still pass, so the policy keeps working and looks
// complete - while a service on the host's own globally routable address, or on
// a directly attached public subnet, silently reads as "public". That is the
// whole class of address this constructor exists to find, so a policy that could
// not enumerate them is not a weaker policy, it is the wrong one.
func NewAddressPolicy() (*AddressPolicy, error) {
	policy := &AddressPolicy{}
	interfaces, err := networkInterfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate local interfaces: %w", err)
	}
	for _, iface := range interfaces {
		addresses, err := networkInterfaceAddrs(&iface)
		if err != nil {
			return nil, fmt.Errorf("enumerate addresses of %s: %w", iface.Name, err)
		}
		for _, address := range addresses {
			ip, network, err := net.ParseCIDR(address.String())
			if err == nil {
				policy.addresses = append(policy.addresses, ip)
				policy.subnets = append(policy.subnets, network)
			}
		}
	}
	return policy, nil
}

// Port reports whether a destination port may be contacted. Only the two web
// ports are reachable: a declared source is an HTTP fetch, and every other port
// is a service the build has no business speaking to.
func (p *AddressPolicy) Port(port int) bool {
	if p != nil && p.permitAll {
		return port > 0 && port <= MaxTCPPort
	}
	return port == HTTPPort || port == HTTPSPort
}

// Public reports whether the address is in globally routable public space and
// is not one of this host's own addresses or subnets.
func (p *AddressPolicy) Public(ip net.IP) bool {
	if p != nil && p.permitAll {
		return ip != nil
	}
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	for _, network := range nonPublicNetworks {
		if network.Contains(ip) {
			return false
		}
	}
	if v4 := ip.To4(); v4 != nil {
		// 0xc0 masks the top two bits of the second octet; equality with 64
		// recognizes 100.64.0.0/10, the carrier-grade NAT range.
		if v4[0] == 0 || v4[0] == 127 || (v4[0] == 100 && v4[1]&0xc0 == 64) ||
			(v4[0] == 169 && v4[1] == 254) || v4[0] >= 224 {
			return false
		}
	}
	if p == nil {
		return true
	}
	for _, local := range p.addresses {
		if local.Equal(ip) {
			return false
		}
	}
	for _, subnet := range p.subnets {
		if subnet.Contains(ip) {
			return false
		}
	}
	return true
}
