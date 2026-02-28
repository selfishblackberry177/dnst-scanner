package scanner

import (
	"context"
	"net"
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

func query(resolver, domain string, qtype uint16, timeout time.Duration) (*dns.Msg, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = timeout

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	r, _, err := c.ExchangeContext(ctx, m, resolver+":53")
	if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
		return nil, false
	}
	return r, true
}

func QueryA(resolver, domain string, timeout time.Duration) bool {
	r, ok := query(resolver, domain, dns.TypeA, timeout)
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

func QueryNS(resolver, domain string, timeout time.Duration) ([]string, bool) {
	r, ok := query(resolver, domain, dns.TypeNS, timeout)
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
