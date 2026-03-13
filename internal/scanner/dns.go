package scanner

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

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
	return len(r.Answer) > 0
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

// QueryTunnel sends an NS query for the tunnel domain and returns true if the
// query reached the tunnel server. DNSTT servers typically return NXDOMAIN or
// NOERROR — both prove the resolver routed the query to the tunnel server.
// SERVFAIL means the resolver couldn't reach the tunnel server (e.g., it's down),
// and timeouts mean the resolver itself is unreachable or blocked.
func QueryTunnel(resolver, domain string, timeout time.Duration) bool {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = timeout

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	r, _, err := c.ExchangeContext(ctx, m, resolver+":53")
	if err != nil || r == nil {
		return false
	}
	// SERVFAIL means the resolver couldn't reach the tunnel server
	return r.Rcode != dns.RcodeServerFailure
}
