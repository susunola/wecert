package acme

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

// txtResponse builds a response containing the given TXT records.
func txtResponse(values ...string) *dns.Msg {
	m := new(dns.Msg)
	for _, v := range values {
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   "_acme-challenge.example.com.",
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
			},
			Txt: []string{v},
		})
	}
	return m
}

// probeRecords must put each result back at its own index.
//
// This is the one place the concurrent rewrite can easily go wrong: each goroutine
// writes only its own slot, so a crossed index shows up as "propagation waiting never
// passes for a few names while the rest are fine" -- hell to diagnose, worse with more SANs.
//
// Driven by an empty NS list: no network requests, but the whole concurrent path runs.
func TestProbeRecordsPreservesOrder(t *testing.T) {
	const n = 20 // deliberately above maxProbeConcurrency to force queueing

	recs := make([]DNSRecord, 0, n)
	for i := 0; i < n; i++ {
		recs = append(recs, DNSRecord{
			FQDN:  fmt.Sprintf("_acme-challenge.host%02d.example.com.", i),
			Value: fmt.Sprintf("value-%02d", i),
		})
	}

	got := probeRecords(nil, recs)

	if len(got) != n {
		t.Fatalf("got %d results, want %d", len(got), n)
	}
	for i, res := range got {
		if res.record.FQDN != recs[i].FQDN || res.record.Value != recs[i].Value {
			t.Errorf("index %d crossed: got %s=%s, want %s=%s",
				i, res.record.FQDN, res.record.Value, recs[i].FQDN, recs[i].Value)
		}
		if res.ready {
			t.Errorf("index %d must not be reported ready when there are no authoritative NS", i)
		}
		if res.summary == "" {
			t.Errorf("index %d is missing a diagnostic summary", i)
		}
	}
}

func TestProbeRecordsEmpty(t *testing.T) {
	if got := probeRecords(nil, nil); len(got) != 0 {
		t.Errorf("empty input should yield an empty result, got %d", len(got))
	}
}

// A single record must not break on the concurrency pool's edge handling.
func TestProbeRecordsSingle(t *testing.T) {
	got := probeRecords(nil, []DNSRecord{{FQDN: "_acme-challenge.a.example.com.", Value: "v"}})
	if len(got) != 1 {
		t.Fatalf("got %d results", len(got))
	}
	if got[0].record.Value != "v" {
		t.Errorf("record mismatch: %+v", got[0].record)
	}
}

// probeReady's rule: no reachable NS denies the value, and at least 2 confirm it.
// This exercises the rule itself, with no real DNS involved.
func TestProbeReadyJudgement(t *testing.T) {
	// No reachable NS: neither confirmed nor allowed through.
	ready, summary := probeReady(nil, "_acme-challenge.example.com.", "v")
	if ready {
		t.Error("letting it through with zero NS probed makes CA validation fail and burns quota")
	}
	if summary == "" {
		t.Error("a human-readable summary should be returned")
	}
}

// responseHasTXT must handle a TXT value split into several string segments,
// and pick the matching one out of several TXT records (as when wildcard + apex coexist).
func TestResponseHasTXT(t *testing.T) {
	// Two TXT records on the same name is the normal wildcard + apex case.
	if !responseHasTXT(txtResponse("other-value", "wanted-value"), "wanted-value") {
		t.Error("the matching value should be found among several TXT records")
	}
	if responseHasTXT(txtResponse("other-value"), "wanted-value") {
		t.Error("a value that is not present must not count as a hit")
	}

	// A TXT record over 255 bytes is split into segments; join them first, then compare.
	// Skip it and a long key authorization reads as "not propagated", then waits out the timeout for nothing.
	segmented := &dns.Msg{}
	segmented.Answer = append(segmented.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: []string{"wanted-", "value"},
	})
	if !responseHasTXT(segmented, "wanted-value") {
		t.Error("a segmented TXT must be joined before comparison")
	}

	if responseHasTXT(txtResponse(), "anything") {
		t.Error("an empty response must not count as a hit")
	}
}
