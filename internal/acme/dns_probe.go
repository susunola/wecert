package acme

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Split out so one concern lives in one file. Same package.

func probeRecordsWithExchange(servers []nsServer, delegated int, recs []DNSRecord, exchange func(*dns.Msg, string) (*dns.Msg, error)) []recordProbe {
	out := make([]recordProbe, len(recs))
	if len(recs) == 0 {
		return out
	}

	limit := maxProbeConcurrency
	if len(recs) < limit {
		limit = len(recs)
	}

	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup

	for i, r := range recs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, r DNSRecord) {
			defer wg.Done()
			defer func() { <-sem }()

			ready, summary := probeReadyWithDelegation(servers, delegated, r.FQDN, r.Value, exchange)
			// Each goroutine writes only its own index; no overlap, so no lock is needed.
			out[i] = recordProbe{record: r, ready: ready, summary: summary}
		}(i, r)
	}
	wg.Wait()

	return out
}

func probeRecords(servers []nsServer, recs []DNSRecord) []recordProbe {
	return probeRecordsWithExchange(servers, delegatedCount(servers), recs, func(msg *dns.Msg, server string) (*dns.Msg, error) {
		client := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(msg, server)
		return resp, err
	})
}

// waitZone polls the zone's authoritative NS until the records are confirmed propagated.
// zoneBudget is the propagation budget as it applies to one zone.
//
// Two timestamps rather than one because the message has to be honest about both: how long THIS zone
// waited, and how much of the shared budget was already gone when it was entered. Reporting the pass
// elapsed as if it were the zone's own wait is what the old message did, and it points the operator
// at the wrong zone -- the one that happens to sort last in a map iteration.
func (s *DNSSolver) waitZone(
	ctx context.Context, zone string, servers []nsServer, delegated int, recs []DNSRecord, b zoneBudget,
) error {
	for {
		results := s.probeRecords(servers, delegated, recs)

		// Summarise only the records that are **not ready yet**.
		//
		// This used to unconditionally reuse the last record's summary, so with the two
		// same-name TXT records of wildcard + apex, as soon as the second one was ready
		// the timeout error printed "confirmed 9 / denied 0 / unreachable 0" -- a summary
		// that looks perfectly healthy, and is the most baffling kind of log there is.
		var pending []string
		for _, res := range results {
			if res.ready {
				continue
			}
			pending = append(pending,
				fmt.Sprintf("%s = %s (%s)", res.record.FQDN, res.record.Value, res.summary))
		}

		if len(pending) == 0 {
			// The authoritative servers agree. That is necessary but not sufficient: the CA
			// validates through a recursive resolver, so ask that path too before telling the CA
			// to look (see probeRecursive for why the two views can disagree).
			if ready, why := s.recursiveReady(ctx, recs); !ready {
				pending = why
			}
		}

		if len(pending) == 0 {
			// The evidence goes into the success line too, not just into the timeout error.
			//
			// This verdict is a lower bound on global propagation and it is derived from this
			// host's view: a lagging authority that happens to be unreachable from here
			// contributes nothing, while the CA's own resolver may reach it and be told the
			// record does not exist. That asymmetry is exactly what turned a "propagated" verdict
			// into an NXDOMAIN at the CA in production, and with only a server count in the log
			// there was no way to see afterwards how thin the evidence had been. Every round
			// re-probes every address, so the summary printed here is the state of the round that
			// decided it.
			readiness := make([]string, 0, len(results))
			for _, res := range results {
				readiness = append(readiness, fmt.Sprintf("%s = %s (%s)",
					res.record.FQDN, res.record.Value, res.summary))
			}
			// A cancellation that landed during the recursive probe must not read as
			// "propagated". recursiveReady degrades "no resolver answered" to a warning (a host
			// without public DNS egress must still be able to issue), and a cancelled context
			// makes every resolver unreachable -- so a shutdown would otherwise walk out of here
			// with a success verdict nobody verified.
			if err := ctx.Err(); err != nil {
				return err
			}
			s.log.Info("TXT propagated",
				"zone", zone, "nameservers", len(servers), "records", len(recs),
				"evidence", strings.Join(readiness, " | "))
			return nil
		}

		// The context is checked BEFORE the budget.
		//
		// With the budget first, a cancellation that landed during the final probe round was
		// reported as a propagation timeout -- and upstream a timeout is a business failure:
		// solveChallenges calls markResumedUnpresented and recordFailure books a
		// consecutive_failures increment and a backoff for what was actually a shutdown. Both of
		// those rules ("a stop signal is not a failure", "a cancelled wait says nothing about DNS")
		// depend on the cancellation being visible here.
		if err := ctx.Err(); err != nil {
			return err
		}
		if !time.Now().Before(b.deadline) {
			return fmt.Errorf(
				"TXT propagation not confirmed: this zone waited %s, entering it %s into the %s "+
					"budget; zone=%s, ns=%d, %d/%d records still not ready: %s",
				time.Since(b.zoneStart).Round(time.Second),
				b.zoneStart.Sub(b.passStart).Round(time.Second), s.timeout,
				zone, len(servers), len(pending), len(recs),
				strings.Join(pending, " | "))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.interval):
		}
	}
}

// dnsProbeAttempts is how many times one authoritative ADDRESS may be asked within a single round
// before the round records it as unreachable. The first attempt is included in the count.
//
// Why a round must not be decided by one dropped packet, measured on a real machine (Route 53 +
// Cloudflare, Let's Encrypt staging, four runs of the same zone): the same zone confirmed "2/4" or
// "3/4" servers and issued in some runs, and in others ended the five-minute budget with a single
// independent nameserver confirming -- which fails the verdict, because it requires two independent
// servers to agree. The addresses that answered in one run were reported "unreachable" in the next.
// The traffic itself is lossy: an authoritative address is probed ONCE per round, so one dropped
// UDP packet (and an unanswered TCP fallback) costs that address the entire round -- and with a
// small delegation that round is the verdict.
//
// The extra attempts are cheap because every address of every record is already probed
// concurrently (see probeTXTWithExchange and probeRecords), so the added wall-clock time is
// bounded by the delay alone, not by the number of addresses. Two attempts add dnsProbeRetryDelay
// once per round: 250ms against a 5-minute budget (dns.propagationTimeout, default 5m) is 250ms of
// 300000ms, under 0.1% of it -- and because attempts x addresses run concurrently, a round grows by
// at most (attempts-1) x delay no matter how many addresses the delegation has. The polling interval
// between rounds is untouched.
const dnsProbeAttempts = 2

// dnsProbeRetryDelay is the pause before asking the same address again.
//
// var rather than const so a test can shorten it: the retry itself is what the tests are about, and
// the shipped value is the named constant above.
var dnsProbeRetryDelay = 250 * time.Millisecond

// nsProbe is the probe result for one address of one authoritative NS.
//
// ns is the nameserver NAME this address belongs to, and it is not decoration: a name with both an
// A and an AAAA record is one server, and the propagation rule requires two *servers* to agree. See
// probeReadyWithExchange.
func probeTXTWithExchange(servers []nsServer, fqdn, want string, exchange func(*dns.Msg, string) (*dns.Msg, error)) []nsProbe {
	results := make([]nsProbe, len(servers))

	var wg sync.WaitGroup
	for i, server := range servers {
		wg.Add(1)
		go func(i int, server nsServer) {
			defer wg.Done()
			results[i] = nsProbe{ns: server.ns, server: server.addr}

			// An exchange that produced no answer at all is retried a small, bounded number of
			// times before this address is called unreachable (see dnsProbeAttempts).
			//
			// Only "no answer came back" is retried -- a transport failure, or an exchange that
			// returned nothing at all, which is also what a truncated answer whose TCP retry failed
			// leaves behind (exchangeDNS keeps that response, and the Truncated branch below still
			// classifies it). A RESPONSE is an answer and is never retried, whatever its rcode:
			// NXDOMAIN is a definitive denial, REFUSED and SERVFAIL are inconclusive but real
			// answers, and re-asking them would burn the budget and blur the three buckets the
			// summary exists to separate. So a retry can only change how many attempts an address
			// gets -- never what counts as an answer.
			var resp *dns.Msg
			var err error
			for attempt := 1; ; attempt++ {
				// A fresh message per attempt: miekg's client writes the query id into the
				// message it sends, and reusing one across attempts is not what a real resolver
				// receives.
				m := new(dns.Msg)
				m.SetQuestion(fqdn, dns.TypeTXT)
				m.RecursionDesired = false
				// Without EDNS0 the answer is capped at 512 bytes (miekg falls back to
				// MinMsgSize), and a challenge name shared by a wildcard and its apex plus a
				// leftover value from the previous round gets close to that. Asking for a bigger
				// buffer is what keeps the answer whole rather than truncated.
				m.SetEdns0(4096, false)

				resp, err = exchange(m, server.addr)
				// exchangeDNS already retried this same attempt over TCP when UDP came back
				// truncated or silent, so whatever is here is what both transports produced.
				if err == nil && resp != nil {
					break
				}
				if attempt >= dnsProbeAttempts {
					break
				}
				// The sleep is what makes this cheap: every address is probed in its own
				// goroutine, so the retries overlap and one round grows by one delay per retry,
				// not by delay x addresses.
				time.Sleep(dnsProbeRetryDelay)
			}
			if err != nil {
				results[i].err = err
				return
			}
			if resp == nil {
				results[i].err = errors.New("no response")
				return
			}
			// Rcode decides what kind of answer this is, and the three kinds are not
			// interchangeable:
			//
			//   NOERROR   -- answered; look for the value.
			//   NXDOMAIN  -- answered definitively: the name does not exist, so the value is not
			//                there. A denial, which is a real answer.
			//   anything  -- SERVFAIL, REFUSED, ... The server has not answered the question.
			//     else       Treating that as "the record is not there" is a false denial, and in
			//                LookupTXT's branch a false denial is what licenses deleting the
			//                authorization row of a name that is still being validated. It is not
			//                a confirmation either, so it stays inconclusive -- but it is
			//                recorded as a code, not as a transport failure, so the summary can
			//                say which of the two happened.
			switch resp.Rcode {
			case dns.RcodeSuccess:
			case dns.RcodeNameError:
				results[i].authoritative = resp.Authoritative
				results[i].hasValue = false
				return
			default:
				results[i].rcode = dns.RcodeToString[resp.Rcode]
				return
			}
			// A truncated answer may be missing the very record being looked for, so it can
			// neither confirm nor deny. exchangeDNS retries over TCP; this is the case where
			// that failed too.
			if resp.Truncated {
				results[i].err = errors.New("truncated answer (TCP retry failed)")
				return
			}
			results[i].authoritative = resp.Authoritative
			results[i].hasValue = results[i].authoritative && responseHasTXT(resp, want)
		}(i, server)
	}
	wg.Wait()

	return results
}

// probeReady decides whether a record can count as propagated, and returns a
// plain-language summary.
//
// The rule: **no reachable NS denies the value**, and at least one confirms it. When the
// zone has multiple authorities, at least 2 must confirm independently, so "only one
// server was reachable" cannot slip through.
//
// Not requiring all 9 to be reachable is deliberate: any single NS being unreachable
// from here would make "everything agrees" permanently unsatisfiable -- and that has
// nothing to do with whether the record propagated. LE validates from several of its own
// locations, so an NS we cannot reach may be reachable for LE.
//
// Conversely, if even one reachable NS plainly says "no such value", we must never let it
// through -- that really is propagation incomplete, and letting it through burns a
// failed-validation quota slot (5 per hour) for nothing.
//
// A single-authority zone has to be able to pass: requiring 2 confirmations would leave
// such a zone waiting for propagation forever.
func probeReadyWithExchange(servers []nsServer, fqdn, want string, exchange func(*dns.Msg, string) (*dns.Msg, error)) (bool, string) {
	return probeReadyWithDelegation(servers, delegatedCount(servers), fqdn, want, exchange)
}

// delegatedCount counts the distinct NS names in a server list. Callers that never went through
// authoritativeNS (tests, mostly) have no delegation count of their own, and for them the list
// IS the delegation: every name in it resolved.
func delegatedCount(servers []nsServer) int {
	names := make(map[string]bool, len(servers))
	for _, s := range servers {
		names[s.ns] = true
	}
	return len(names)
}

// probeReadyWithDelegation is probeReadyWithExchange with the delegation count made explicit.
//
// delegated is the number of NS names the zone delegates to, INCLUDING the names this host
// could not resolve to an address: authoritativeNS skips an unresolvable name with a warning,
// and keying the single-authority exemption on the names that resolved would let a two-NS zone
// with one broken A record pass on a single confirmation -- while the unresolvable server may
// be exactly the one the CA reaches and be told the record does not exist.
func probeReadyWithDelegation(servers []nsServer, delegated int, fqdn, want string, exchange func(*dns.Msg, string) (*dns.Msg, error)) (bool, string) {
	results := probeTXTWithExchange(servers, fqdn, want, exchange)

	var confirmed, missing, nonAuthoritative, unreachable, refused, failed int
	// Counted per NS NAME, not per address: one server answering on both its A and its AAAA
	// record is one server, and the rule below is about how many independent servers agree.
	//
	// This cuts both ways, and both were wrong before. Counting addresses let a single
	// multi-homed authority satisfy "two independent confirmations" -- the guard the comment
	// promises is exactly what it lost. It also made a single-authority zone whose name has an
	// unreachable second address permanently unconfirmable, because the "one authority is exempt"
	// branch was keyed on the address count.
	confirmingNS := map[string]bool{}
	authorities := map[string]bool{}
	for _, r := range results {
		authorities[r.ns] = true
		switch {
		case r.rcode == dns.RcodeToString[dns.RcodeRefused]:
			// The server answered and refused. On a network that intercepts port 53 this is
			// the signature -- a middlebox refusing on the authority's behalf -- and it is a
			// different problem from a path that swallows packets.
			refused++
		case r.rcode != "":
			failed++
		case r.err != nil:
			unreachable++
		case !r.authoritative:
			nonAuthoritative++
		case r.hasValue:
			confirmed++
			confirmingNS[r.ns] = true
		default:
			missing++
		}
	}

	// The delegation is the authority count, not the subset of it that resolved. delegated can
	// only ever be the larger one; the max keeps a hand-built server list (delegated inferred
	// from it) from ever shrinking the count below what the probes actually saw.
	authorityCount := delegated
	if len(authorities) > authorityCount {
		authorityCount = len(authorities)
	}

	summary := fmt.Sprintf("confirmed %d/%d server(s) / denied %d / non-authoritative %d / refused %d / failed %d / unreachable %d (of %d addresses)",
		len(confirmingNS), authorityCount, missing, nonAuthoritative, refused, failed, unreachable, len(results))

	// Any reachable server that answers "no such value" -> not propagated yet. Checked per
	// address on purpose: one address of one authority denying the value is enough to hold the
	// whole thing back.
	if missing > 0 {
		return false, summary
	}
	// Not a single confirmation (everything unreachable) -> must not let it through.
	if confirmed == 0 {
		return false, summary
	}
	// With more than one authority, require two of them to confirm, so "only one server was
	// reachable" cannot slip through. A zone with a single authority is exempt, whoever many
	// addresses that authority has.
	if authorityCount >= 2 && len(confirmingNS) < 2 {
		return false, summary
	}
	return true, summary
}

func probeReady(servers []nsServer, fqdn, want string) (bool, string) {
	return probeReadyWithExchange(servers, fqdn, want, func(msg *dns.Msg, server string) (*dns.Msg, error) {
		client := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(msg, server)
		return resp, err
	})
}

// recursiveVerdict is what the CA-shaped view says about one record.
//
// A validator resolves through a recursive resolver, not by asking authoritative servers
// directly, so this is the closest thing wecert has to the CA's own view -- and the two views
// can disagree. Observed on a real account: the authoritative probe saw every reachable server
// confirm the value while the CA was told NXDOMAIN for the same name, because a lagging
// authority was unreachable from wecert's host and reachable from the CA's resolver. The cost
// of that disagreement is a failed-validation quota slot (5 per hour per identifier), spent on
// a round that could simply have waited.
func (s *DNSSolver) probeRecursive(ctx context.Context, fqdn, want string) recursiveVerdict {
	v := recursiveVerdict{}
	notes := make([]string, 0, len(s.recursiveNameservers))
	for _, resolver := range s.recursiveNameservers {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
		msg.RecursionDesired = true
		msg.SetEdns0(4096, false)

		resp, err := s.exchange(ctx, msg, resolver)
		switch {
		case err != nil:
			notes = append(notes, resolver+" unreachable")
		case resp == nil:
			notes = append(notes, resolver+" no response")
		case resp.Truncated:
			notes = append(notes, resolver+" truncated answer (TCP retry failed)")
		case resp.Rcode == dns.RcodeSuccess:
			v.reachable++
			if responseHasTXT(resp, want) {
				v.confirmed = true
				notes = append(notes, resolver+" has the value")
			} else {
				v.denied = true
				notes = append(notes, resolver+" answered NOERROR without the value")
			}
		case resp.Rcode == dns.RcodeNameError:
			v.reachable++
			v.denied = true
			notes = append(notes, resolver+" answered NXDOMAIN")
		default:
			notes = append(notes, resolver+" answered "+dns.RcodeToString[resp.Rcode])
		}
	}
	v.summary = fmt.Sprintf("recursive: confirmed=%t denied=%t reachable=%d/%d (%s)",
		v.confirmed, v.denied, v.reachable, len(s.recursiveNameservers), strings.Join(notes, "; "))
	return v
}

// recursiveReady reports whether the CA-shaped view permits the verdict, and why not.
func (s *DNSSolver) recursiveReady(ctx context.Context, recs []DNSRecord) (bool, []string) {
	var pending []string
	for _, r := range recs {
		v := s.probeRecursive(ctx, r.FQDN, r.Value)
		if v.denied {
			pending = append(pending, fmt.Sprintf(
				"%s = %s (a recursive resolver, which is what the CA talks to, answered without the value: %s)",
				r.FQDN, r.Value, v.summary))
			continue
		}
		if !v.confirmed && v.reachable == 0 && len(s.recursiveNameservers) > 0 {
			// Not one resolver could answer. Refusing here would make issuance impossible on a
			// host without public DNS egress -- a configuration wecert supports -- and the
			// authoritative verdict above already passed, so this is a warning, not a blocker.
			s.log.Warn("no recursive resolver could answer; falling back to the authoritative verdict alone",
				"name", r.FQDN)
			continue
		}
		if !v.confirmed {
			pending = append(pending, fmt.Sprintf(
				"%s = %s (no recursive resolver returned the value yet: %s)", r.FQDN, r.Value, v.summary))
		}
	}
	return len(pending) == 0, pending
}

// challengeLeases tracks, per effective challenge FQDN, the TXT values this process
// currently relies on.
//
// It exists because the comment that used to sit on CleanUp was a lie: lego's
// dnspod/tencentcloud CleanUp does **not** locate one record by the (domain, token,
// keyAuth) triple -- it deletes **every** TXT record at the challenge name. Config
// dedups certificate names, not domains, so two certificates can legitimately share
// _acme-challenge.example.com; reconciled concurrently (a webhook trigger overlapping a
// scheduled pass), certificate A's cleanup would then kill certificate B's still-pending
// challenge record.
//
// True value-scoped deletion is not reachable at this layer: lego hands out only the
// challenge.Provider interface, and the record-level API client behind it is unexported.
// What this layer can guarantee is that the delete-all call never fires while any value
// at the name is still live: the last leaver's cleanup removes every record in one call,
// including the records earlier leavers had to skip. That suffices because the state
// store's exclusive lock (internal/state) already guarantees a single wecert process per
// state directory, so every writer of these records passes through this registry.
//
// The per-name mutex must be held across the provider call on both sides (Present and
// CleanUp): without that, a Present could land between CleanUp's "no live values" check
// and its delete-all, and the fresh record would die with the rest.
