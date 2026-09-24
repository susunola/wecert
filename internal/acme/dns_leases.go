package acme

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// Split out so one concern lives in one file. Same package.

func newTXTLeases() *txtLeases {
	return &txtLeases{entries: map[string]*txtLease{}}
}

// lock returns the per-name mutex plus a release function; every caller must hold the
// mutex across its provider call and run release afterwards.
//
// The reference count is taken under l.mu **before** the caller locks the per-name
// mutex, and that is what makes pruning safe: an entry is dropped (in release) only once
// no goroutine references it, so nobody can be between "got the mutex pointer" and
// "locked it" when the entry disappears. Pruning without the count would open exactly
// that window -- the name gets re-created under a **different** mutex while the old one
// is still in use, and two goroutines then run their provider calls concurrently at the
// same name, which is the race the mutex exists to prevent.
func (l *txtLeases) lock(fqdn string) (*sync.Mutex, func()) {
	l.mu.Lock()
	e := l.entries[fqdn]
	if e == nil {
		e = &txtLease{values: map[string]bool{}}
		l.entries[fqdn] = e
	}
	e.refs++
	l.mu.Unlock()

	var once sync.Once
	return &e.mu, func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			e.refs--
			if e.refs == 0 && len(e.values) == 0 {
				// Nothing live at the name and nobody using the mutex: drop the entry,
				// so a long-running process does not accumulate one mutex per FQDN
				// forever.
				delete(l.entries, fqdn)
			}
		})
	}
}

// add records that this process relies on the value staying in DNS. Set semantics: a
// re-registration (a resumed order re-presenting nothing) must not inflate a count that
// CleanUp then never balances.
func (s *DNSSolver) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn := dns.Fqdn(info.EffectiveFQDN)

	mu, release := challengeLeases.lock(fqdn)
	defer release()
	mu.Lock()
	defer mu.Unlock()

	// Remove this value's lease first, then decide whether the provider may be called.
	//
	// The deferral below is only correct for a provider whose CleanUp deletes **every** value at
	// the name (dnspod and tencentcloud do): the last leaver's single call then removes whatever
	// the earlier ones skipped. A value-scoped provider (route53, cloudflare — see
	// cleanupIsValueScoped) removes only the record it is called for, so deferring there leaves
	// the skipped value in DNS with nobody left to remove it, and buys nothing: calling it per
	// value is exactly what it is built for.
	othersLive := challengeLeases.remove(fqdn, info.Value)
	if othersLive && !s.valueScopedCleanup {
		s.log.Info("another challenge is still live at the TXT name; leaving its cleanup to the last leaver",
			"name", fqdn)
		return nil
	}
	if othersLive {
		s.log.Info("another challenge is still live at the TXT name, but this provider removes only the "+
			"record it is called for; cleaning this one up now", "name", fqdn)
	}

	provider, err := s.newProvider(ctx)
	if err != nil {
		return fmt.Errorf("get the DNS provider: %w", err)
	}
	// Same bound as Present: this call holds the per-name lease mutex. See callProviderBounded.
	err = callProviderBounded("cleanup TXT", func() error {
		return s.callLegoProviderResolvers(func() error { return provider.CleanUp(domain, token, keyAuth) })
	})
	if err == nil || s.recoverCloudflareTXT == nil || !providerForgotRecordError(err) {
		return err
	}
	zone, zoneErr := s.findZone(ctx, fqdn)
	if zoneErr != nil {
		return fmt.Errorf("%w (and could not locate the Cloudflare zone for recovery: %v)", err, zoneErr)
	}
	if recoverErr := s.recoverCloudflareTXT(ctx, zone, DNSRecord{FQDN: fqdn, Value: info.Value}); recoverErr != nil {
		return fmt.Errorf("%w (Cloudflare restart recovery: %v)", err, recoverErr)
	}
	s.log.Info("removed a Cloudflare TXT record left by an earlier process", "name", fqdn)
	return nil
}

// LookupTXT asks the zone's **authoritative** nameservers whether this challenge's TXT
// record is currently in DNS, returning the record's identity either way so callers can
// persist it.
//
// It backs the two crash-recovery probes: a pass that died between the DNS write and the
// state persist left the record up while the authorization row denies it -- re-Present
// would duplicate the record, and deleting the row would orphan it.
//
// The answer is deliberately not taken from the recursive resolvers, even though they are
// cheaper. "found == false" is what licenses deleting the only row that records a value,
// and a recursive resolver's "no such record" is not evidence of absence:
//   - a negative answer can come from its cache, and DNSPod's 600s TTL floor applies to
//     the negative entry too, so a record written minutes ago can still be hidden;
//   - one name can carry several TXT values (two certificates, or a wildcard and its
//     apex, share one challenge name), and the cached answer may hold only some of them.
//
// The rules mirror probeReady's:
//   - confirmed by at least one authoritative server -> found, no error;
//   - denied by at least one and confirmed by none   -> absent (found=false, no error);
//   - nothing authoritative answered                 -> error, meaning "cannot tell".
//
// The last case must not be folded into "absent": the caller keeps the authorization row,
// which is the only record of the value, and retries next round.
func (s *DNSSolver) LookupTXT(ctx context.Context, domain, keyAuth string) (DNSRecord, bool, error) {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	rec := DNSRecord{
		FQDN:  dns.Fqdn(info.EffectiveFQDN),
		Value: info.Value,
	}

	zone, err := s.findZone(ctx, rec.FQDN)
	if err != nil {
		return rec, false, fmt.Errorf("find the zone of %s: %w", rec.FQDN, err)
	}
	servers, _, err := s.authoritativeNS(ctx, zone)
	if err != nil {
		return rec, false, fmt.Errorf("list the authoritative nameservers of %s: %w", zone, err)
	}

	results := probeTXTWithExchange(servers, rec.FQDN, rec.Value, s.authoritativeExchange())
	var confirmed, denied, unanswered int
	for _, r := range results {
		switch {
		case r.err != nil, !r.authoritative:
			unanswered++
		case r.hasValue:
			confirmed++
		default:
			denied++
		}
	}

	switch {
	case confirmed > 0:
		return rec, true, nil
	case denied > 0:
		return rec, false, nil
	default:
		return rec, false, fmt.Errorf(
			"cannot tell whether %s still carries the record: none of its %d authoritative nameservers answered",
			rec.FQDN, len(results))
	}
}

// authoritativeExchange is the exchange used for the authoritative probes: a short
// per-server deadline, and it ignores the caller's context on purpose.
//
// It must not inherit a cancelled context: the probes run during cleanup, and a shutdown
// racing them would turn a knowable answer into "cannot tell", which keeps rows around.
// The deadline is what bounds them instead.
