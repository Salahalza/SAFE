package ioc

import (
	"net"
	"strings"
)

var (
	// internalIPv4Nets are private network ranges (RFC 1918, localhost, APIPA).
	internalIPv4Nets = []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
	}

	// parsedInternalNets caches the parsed CIDR blocks.
	parsedInternalNets []*net.IPNet

	// wellKnownBenignDomains contains the base set of domains to suppress.
	// Note: github.com is intentionally omitted — adversaries abuse it for C2 and hosting.
	wellKnownBenignDomains = map[string]bool{
		"google.com":        true,
		"microsoft.com":     true,
		"windowsupdate.com": true,
		"apple.com":         true,
		"amazon.com":        true,
	}
)

func init() {
	for _, cidr := range internalIPv4Nets {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet != nil {
			parsedInternalNets = append(parsedInternalNets, ipNet)
		}
	}
}

// IsBenignIP returns true for private/internal/broadcast addresses that should
// be suppressed during IOC extraction.
func IsBenignIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// BUG 2 enhancement: also suppress the all-zeros and broadcast addresses
	if ip.Equal(net.IPv4zero) || ip.Equal(net.IPv4bcast) {
		return true
	}
	for _, network := range parsedInternalNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// IsBenignDomain returns true if the domain (or any of its parent labels) matches
// the well-known benign domain list.
func IsBenignDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if wellKnownBenignDomains[domain] {
		return true
	}
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		baseDomain := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if wellKnownBenignDomains[baseDomain] {
			return true
		}
	}
	return false
}
