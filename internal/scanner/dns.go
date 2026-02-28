package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var bogusNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
	} {
		_, n, _ := net.ParseCIDR(cidr)
		bogusNets = append(bogusNets, n)
	}
}

func isBogusIP(ip net.IP) bool {
	for _, n := range bogusNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseRcode converts a human-readable rcode name to its integer value.
// Supported names: nxdomain, servfail, refused, formerr.
func ParseRcode(name string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "nxdomain":
		return dns.RcodeNameError, nil
	case "servfail":
		return dns.RcodeServerFailure, nil
	case "refused":
		return dns.RcodeRefused, nil
	case "formerr":
		return dns.RcodeFormatError, nil
	default:
		return 0, fmt.Errorf("unknown rcode %q (supported: nxdomain, servfail, refused, formerr)", name)
	}
}

func query(resolver, domain string, qtype uint16, timeout time.Duration, ignoreRcodes []int) (*dns.Msg, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = timeout
	c.IgnoreRcodes = ignoreRcodes

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	r, _, err := c.ExchangeContext(ctx, m, resolver+":53")
	if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
		return nil, false
	}
	return r, true
}

func QueryA(resolver, domain string, timeout time.Duration, ignoreRcodes []int) bool {
	r, ok := query(resolver, domain, dns.TypeA, timeout, ignoreRcodes)
	if !ok {
		return false
	}
	if len(r.Answer) == 0 {
		return false
	}
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			if isBogusIP(a.A) {
				return false
			}
		}
	}
	return true
}

func QueryNS(resolver, domain string, timeout time.Duration, ignoreRcodes []int) ([]string, bool) {
	r, ok := query(resolver, domain, dns.TypeNS, timeout, ignoreRcodes)
	if !ok {
		return nil, false
	}
	var hosts []string
	for _, ans := range r.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			hosts = append(hosts, ns.Ns)
		}
	}
	if len(hosts) == 0 {
		return nil, false
	}
	return hosts, true
}
