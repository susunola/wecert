package acme

import (
	"context"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// Split out so one concern lives in one file. Same package.

func (s *DNSSolver) Present(ctx context.Context, domain, token, keyAuth string) (DNSRecord, error) {
	provider, err := s.newProvider(ctx)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("get the DNS provider: %w", err)
	}

	info := dns01.GetChallengeInfo(domain, keyAuth)
	rec := DNSRecord{
		FQDN:  dns.Fqdn(info.EffectiveFQDN),
		Value: info.Value,
	}

	// Register the lease under the same per-name lock that CleanUp holds across its
	// delete call, so a cleanup can never slip a delete-all in between "this name has no
	// live values" and the write landing. See challengeLeases.
	mu, release := challengeLeases.lock(rec.FQDN)
	defer release()
	mu.Lock()
	defer mu.Unlock()

	// Resolve the zone before handing the write to the provider, so its answer is ours to
	// report. lego does the same SOA walk internally but has no guard against the walk
	// climbing to the public suffix: when the resolver answers for `com.` but not for the
	// domain, lego concludes the zone is `com.` and the write fails with "zone com. not found
	// in dnspod for domain ...", which reads like a DNSPod account problem and is not. This
	// costs one short SOA walk (findZone already refuses to return a public suffix) and only
	// runs when a record is about to be written.
	if _, err := s.findZone(ctx, rec.FQDN); err != nil {
		return DNSRecord{}, fmt.Errorf("present TXT: %w", err)
	}

	if err := provider.Present(domain, token, keyAuth); err != nil {
		return DNSRecord{}, fmt.Errorf("present TXT: %w", err)
	}
	challengeLeases.add(rec.FQDN, rec.Value)
	return rec, nil
}

// WaitAll waits until every record is visible on all authoritative NS of its zone.
//
// It deduplicates by (FQDN, Value), and resolves each zone's authoritative NS list once.
func (s *DNSSolver) WaitAll(ctx context.Context, records []DNSRecord) error {
	byZone := map[string][]DNSRecord{}
	seen := map[string]bool{}

	for _, r := range records {
		key := r.FQDN + "|" + r.Value
		if seen[key] {
			continue
		}
		seen[key] = true

		// A resumed order reuses records a previous process wrote, so Present never runs
		// for them in this process and the lease registry would not know they are live.
		// WaitAll sees every record a round depends on, so this is where those leases get
		// re-registered -- otherwise a concurrent certificate's cleanup could delete-all
		// the name right out from under this one (see challengeLeases).
		//
		// Under the name's mutex, not just the registry lock: CleanUp checks "is any other
		// value live?" and then deletes while holding that mutex, so an add outside it can
		// land in the window and have its value deleted (see addUnderLock).
		challengeLeases.addUnderLock(r.FQDN, r.Value)

		zone, err := s.findZone(ctx, r.FQDN)
		if err != nil {
			return fmt.Errorf("find the zone for %s: %w", r.FQDN, err)
		}
		byZone[zone] = append(byZone[zone], r)
	}

	if len(byZone) == 0 {
		return nil
	}

	// The budget is global: every zone shares one deadline, so the overall wait does not inflate
	// linearly as zones are added. That is deliberate (the contract test pins it), but it means a
	// zone reached after the deadline has already passed must not be entered at all -- it would get
	// one probe round and then fail with a message blaming it for a wait that was not its own.
	start := time.Now()
	deadline := start.Add(s.timeout)

	// byZone is a map, so the order is random: without this, which zone is starved changes from
	// pass to pass, which is worse than a fixed order because it looks intermittent.
	for zone, recs := range byZone {
		waitStart := time.Now()
		if !waitStart.Before(deadline) {
			return fmt.Errorf("TXT propagation was not confirmed before the %s budget ran out "+
				"(zone %s was not reached; %s was spent on the zones before it)",
				s.timeout, zone, waitStart.Sub(start).Round(time.Second))
		}
		servers, delegated, err := s.authoritativeNS(ctx, zone)
		if err != nil {
			return err
		}
		if err := s.waitZone(ctx, zone, servers, delegated, recs, zoneBudget{
			passStart: start, zoneStart: waitStart, deadline: deadline,
		}); err != nil {
			return err
		}
	}
	return nil
}

// maxProbeConcurrency caps how many record probes are in flight at once.
//
// Each record then probes all the authoritative NS of its zone concurrently, so real
// concurrency is this number x the NS count. Set it too high and we fire off thousands
// of DNS queries in an instant, which is exactly how you get rate limited or dropped.
