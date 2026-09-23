package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// Split out so one concern lives in one file. Same package.

func (s *DNSSolver) authoritativeExchange() func(*dns.Msg, string) (*dns.Msg, error) {
	return func(msg *dns.Msg, server string) (*dns.Msg, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return s.exchange(ctx, msg, server)
	}
}

func (s *DNSSolver) findZone(ctx context.Context, fqdn string) (string, error) {
	for _, domain := range domainSequence(fqdn) {
		msg := new(dns.Msg)
		msg.SetQuestion(domain, dns.TypeSOA)
		msg.RecursionDesired = true
		resp, err := s.queryRecursive(ctx, msg)
		if err != nil || resp == nil || resp.Rcode == dns.RcodeNameError {
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			return "", fmt.Errorf("SOA lookup for %s returned %s", domain, dns.RcodeToString[resp.Rcode])
		}
		for _, rr := range resp.Answer {
			if soa, ok := rr.(*dns.SOA); ok {
				zone := dns.Fqdn(soa.Hdr.Name)
				if suffix, _ := publicsuffix.PublicSuffix(strings.TrimSuffix(zone, ".")); suffix != "" &&
					zone == dns.Fqdn(suffix) {
					// The SOA walk climbed all the way to the public suffix itself (a
					// typo'd exmaple.com ends up at the com. SOA). That "zone" can never
					// hold the TXT record, so treating it as found burns the whole
					// propagation budget querying TLD nameservers for nothing. Fail fast
					// with the likely cause instead.
					return "", fmt.Errorf(
						"%s has no hosted zone: the SOA walk stopped at the public suffix %s; check the domain for typos",
						fqdn, zone)
				}
				return zone, nil
			}
		}
	}
	return "", fmt.Errorf("could not find an SOA for %s via recursive resolvers %s", fqdn, strings.Join(s.recursiveNameservers, ","))
}

// nsServer is one address of one authoritative nameserver.
//
// The name is carried alongside the address because the propagation rule counts SERVERS, and one
// server commonly owns several addresses: DNSPod's pools publish three A records per NS name, and a
// dual-stack name publishes an A and an AAAA. Counting addresses instead made a single multi-homed
// authority look like two independent servers.
func (s *DNSSolver) authoritativeNS(ctx context.Context, zone string) ([]nsServer, int, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeNS)
	msg.RecursionDesired = true
	resp, err := s.queryRecursive(ctx, msg)
	if err != nil {
		return nil, 0, fmt.Errorf("lookup NS for %s: %w", zone, err)
	}
	var names []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			names = append(names, dns.Fqdn(ns.Ns))
		}
	}
	if len(names) == 0 {
		return nil, 0, fmt.Errorf("%s has no NS records", zone)
	}

	var servers []nsServer
	seen := make(map[string]bool)
	for _, ns := range names {
		ips, err := s.lookupHost(ctx, ns)
		if err != nil {
			s.log.Warn("could not resolve an authoritative nameserver; skipping it", "ns", ns, "err", err)
			continue
		}
		for _, ip := range ips {
			addr := net.JoinHostPort(ip, "53")
			if !seen[addr] {
				seen[addr] = true
				servers = append(servers, nsServer{ns: ns, addr: addr})
			}
		}
	}
	if len(servers) == 0 {
		return nil, 0, fmt.Errorf("none of %s's nameservers resolve to an address", zone)
	}
	return servers, len(names), nil
}

func (s *DNSSolver) probeRecords(servers []nsServer, delegated int, recs []DNSRecord) []recordProbe {
	return probeRecordsWithExchange(servers, delegated, recs, s.authoritativeExchange())
}

func (s *DNSSolver) queryRecursive(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	var errs []error
	for _, resolver := range s.recursiveNameservers {
		resp, err := s.exchange(ctx, msg.Copy(), resolver)
		if err == nil && resp != nil && resp.Truncated {
			// exchangeDNS hands back the UDP answer when its TCP retry fails, with Truncated still
			// set so the caller can decide -- the probe paths do decide. Callers of this one read
			// the answer structurally (authoritativeNS builds the server list out of resp.Answer),
			// so accepting it would silently shrink the authority set, and a reduced set is how the
			// "two independent servers must agree" rule degrades into the single-authority
			// exemption it exists to avoid. Ask the next resolver instead.
			errs = append(errs, fmt.Errorf("%s: truncated answer (TCP retry failed)", resolver))
			continue
		}
		if err == nil && resp != nil && (resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError) {
			return resp, nil
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", resolver, err))
		} else if resp == nil {
			errs = append(errs, fmt.Errorf("%s: empty response", resolver))
		} else {
			errs = append(errs, fmt.Errorf("%s: DNS response %s", resolver, dns.RcodeToString[resp.Rcode]))
		}
	}
	return nil, fmt.Errorf("all configured recursive resolvers failed: %w", errors.Join(errs...))
}

func (s *DNSSolver) lookupHost(ctx context.Context, host string) ([]string, error) {
	var ips []string
	var errs []error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg := new(dns.Msg)
		msg.SetQuestion(host, qtype)
		msg.RecursionDesired = true
		resp, err := s.queryRecursive(ctx, msg)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, rr := range resp.Answer {
			switch r := rr.(type) {
			case *dns.A:
				ips = append(ips, r.A.String())
			case *dns.AAAA:
				ips = append(ips, r.AAAA.String())
			}
		}
	}
	if len(ips) == 0 {
		if len(errs) == 0 {
			return nil, errors.New("no A or AAAA records")
		}
		return nil, fmt.Errorf("no A or AAAA records: %w", errors.Join(errs...))
	}
	return ips, nil
}

func recursiveNameservers(configured []string) ([]string, error) {
	if len(configured) > 0 {
		return append([]string(nil), configured...), nil
	}
	resolv, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read recursive nameservers from /etc/resolv.conf: %w", err)
	}
	if len(resolv.Servers) == 0 {
		return nil, errors.New("/etc/resolv.conf contains no nameservers")
	}
	servers := make([]string, 0, len(resolv.Servers))
	for _, server := range resolv.Servers {
		servers = append(servers, net.JoinHostPort(server, resolv.Port))
	}
	return servers, nil
}

// exchangeDNS asks one server, retrying over TCP when the UDP answer was truncated.
//
// The TCP attempt does not replace the UDP answer on failure. The two share the caller's 3-second
// context, and a server that is slow to accept TCP is exactly the case this retry exists for, so
// overwriting `resp` there meant discarding a truncated-but-real answer -- including one whose
// answer section already carried the value being looked for -- and reporting the server as
// unreachable. The truncated answer is returned instead, with Truncated still set, and the caller
// decides: probeTXT classifies it as unreachable (an incomplete answer is not a denial) rather than
// reading the missing record as "not propagated".
type nsServer struct {
	ns   string
	addr string
}

// authoritativeNS resolves the public NS delegation through the configured recursive resolver set.
//
// The second return value is the number of NS names in the delegation, INCLUDING the names that
// did not resolve to an address. Skipping an unresolvable name (with the warning below) is right
// for the probe list, but the propagation rule's single-authority exemption must be keyed on the
// delegation itself: a zone that delegates to two nameservers and resolves only one is not a
// single-authority zone, and the server this host cannot resolve may be exactly the one the CA
// reaches.
