package acme

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// lookupHarness drives DNSSolver.LookupTXT with a scripted resolver and one
// authoritative nameserver, so the test says nothing about the network.
type lookupHarness struct {
	solver *DNSSolver
	fqdn   string
	value  string
	// authoritative is what the zone's NS answers with for the TXT query.
	authoritative func(msg *dns.Msg) (*dns.Msg, error)
	// recursiveTXT is what the recursive resolver answers for the TXT query --
	// normally an empty (cached-negative) answer.
	recursiveTXT func(msg *dns.Msg) *dns.Msg
	queries      []string
}

func newLookupHarness(t *testing.T, domain, keyAuth string) *lookupHarness {
	t.Helper()
	// GetChallengeInfo chases the CNAME over the network unless this is set.
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")

	const (
		resolver  = "192.0.2.53:53"
		authority = "198.51.100.53:53"
	)

	info := dns01.GetChallengeInfo(domain, keyAuth)
	h := &lookupHarness{
		fqdn:  info.FQDN,
		value: info.Value,
		recursiveTXT: func(msg *dns.Msg) *dns.Msg {
			return dnsReply(msg) // NODATA: exactly what a cached negative looks like
		},
	}
	h.solver = &DNSSolver{
		recursiveNameservers: []string{resolver},
		log:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	h.solver.exchange = func(_ context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
		q := msg.Question[0]
		h.queries = append(h.queries, server+"|"+dns.TypeToString[q.Qtype])
		switch server {
		case resolver:
			switch q.Qtype {
			case dns.TypeSOA:
				if q.Name == "example.com." {
					return dnsReply(msg, &dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Ns: "ns1.example.net."}), nil
				}
				resp := dnsReply(msg)
				resp.Rcode = dns.RcodeNameError
				return resp, nil
			case dns.TypeNS:
				return dnsReply(msg, &dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns1.example.net."}), nil
			case dns.TypeA:
				return dnsReply(msg, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{198, 51, 100, 53}}), nil
			case dns.TypeAAAA:
				return dnsReply(msg), nil
			case dns.TypeTXT:
				return h.recursiveTXT(msg), nil
			}
		case authority:
			if q.Qtype == dns.TypeTXT && h.authoritative != nil {
				return h.authoritative(msg)
			}
			resp := dnsReply(msg)
			resp.Authoritative = true
			return resp, nil
		}
		return nil, fmt.Errorf("unexpected query %s %s to %s", q.Name, dns.TypeToString[q.Qtype], server)
	}
	return h
}

// The regression this pins: the record is up and the authoritative server says so, while
// the recursive resolver still serves a cached negative. The old implementation asked the
// resolver only, answered "not found", and reclaimUnpresentedTXT then deleted the row that
// held the record's value -- orphaning a TXT that was really there.
func TestLookupTXTIgnoresTheRecursiveCache(t *testing.T) {
	h := newLookupHarness(t, "shared.example.com", "keyauth(tok)")
	h.authoritative = func(msg *dns.Msg) (*dns.Msg, error) {
		resp := dnsReply(msg, &dns.TXT{
			Hdr: dns.RR_Header{Name: h.fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
			Txt: []string{h.value},
		})
		resp.Authoritative = true
		return resp, nil
	}

	rec, found, err := h.solver.LookupTXT(context.Background(), "shared.example.com", "keyauth(tok)")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if !found {
		t.Fatal("the authoritative nameserver confirms the record, so a cached negative must not win")
	}
	if rec.Value != h.value {
		t.Errorf("record value = %q, want %q", rec.Value, h.value)
	}
	if !containsQuery(h.queries, "198.51.100.53:53|TXT") {
		t.Errorf("the authoritative nameserver must have been asked, got %v", h.queries)
	}
}

// Confirmed absence is the only outcome that lets the caller delete the authorization row,
// so it must be reported as such: found=false with no error.
func TestLookupTXTReportsAuthoritativeAbsence(t *testing.T) {
	h := newLookupHarness(t, "shared.example.com", "keyauth(tok)")
	h.authoritative = func(msg *dns.Msg) (*dns.Msg, error) {
		resp := dnsReply(msg)
		resp.Authoritative = true
		return resp, nil
	}

	_, found, err := h.solver.LookupTXT(context.Background(), "shared.example.com", "keyauth(tok)")
	if err != nil {
		t.Fatalf("an authoritative denial is not an error: %v", err)
	}
	if found {
		t.Error("nothing carries the value, so found must be false")
	}
}

// Nothing authoritative answered: that is "cannot tell", not "absent". Returning found=false
// with a nil error here would license deleting the only record of the value.
func TestLookupTXTUnansweredIsNotAbsence(t *testing.T) {
	h := newLookupHarness(t, "shared.example.com", "keyauth(tok)")
	h.authoritative = func(*dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("connection refused")
	}

	_, found, err := h.solver.LookupTXT(context.Background(), "shared.example.com", "keyauth(tok)")
	if err == nil {
		t.Fatalf("no authoritative answer must be reported as an error, got found=%v", found)
	}
	if !strings.Contains(err.Error(), "cannot tell") {
		t.Errorf("the error must say the answer is unknown, got: %v", err)
	}
}

// A non-authoritative TXT answer from an NS address is not evidence either: it is a
// resolver forwarding someone else's cache.
func TestLookupTXTRejectsNonAuthoritativeAnswer(t *testing.T) {
	h := newLookupHarness(t, "shared.example.com", "keyauth(tok)")
	h.authoritative = func(msg *dns.Msg) (*dns.Msg, error) {
		// Answers with the value, but does not claim authority.
		return dnsReply(msg, &dns.TXT{
			Hdr: dns.RR_Header{Name: h.fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
			Txt: []string{h.value},
		}), nil
	}

	if _, found, err := h.solver.LookupTXT(context.Background(), "shared.example.com", "keyauth(tok)"); err == nil || found {
		t.Fatalf("a non-authoritative answer must be treated as no answer, got found=%v err=%v", found, err)
	}
}

func containsQuery(queries []string, want string) bool {
	for _, q := range queries {
		if q == want {
			return true
		}
	}
	return false
}
