// Package reconcile drives the overall convergence loop.
package reconcile

import (
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/spec"
)

// Split from reconcile.go so one concern is one file. Same package.

func (r *Reconciler) reclaimStaleProbeSeries(res *spec.Result) {
	p := r.getProber()
	if p == nil {
		return
	}
	all, ok := p.(interface{ ProbedHosts() []string })
	if !ok {
		return
	}

	// Judge each candidate host against the desired state the pass already resolved.
	//
	// This used to resolve per host (inside hostIsUnconfirmed): every stale host paid a full
	// resolve -- a file read, a YAML decode, a validation pass and a sha256 of the document.
	// The scale work in round 11 measured the result at the default probe cap: 500 certificates, a
	// pass that reclaims stale hosts took 27.8 s against 0.18 s for the same pass with nothing to
	// reclaim (155x), and it is exactly O(staleHosts x fleetSize): 0.41/1.48/5.66/22.9 s at
	// 25/50/100/200 certificates. The hosts are also what a shrinking probe set produces -- removed
	// certificates or names -- so this is the shape of an ordinary fleet edit, not a corner case.
	//
	// hostOwner is nil when there is no store to judge deployment state from (a partially built
	// reconciler in tests): every stale host is then reclaimed, which is what the old helper did
	// for that case.
	var (
		hostOwner    map[string]string
		desiredNames map[string]bool
	)
	if r.store != nil {
		if res == nil {
			// No desired state: keep the series rather than deleting evidence.
			//
			// And keep the record of what was probed too. The per-round set used to be cleared
			// above, before this return, so "keep the evidence" threw away the very thing that
			// says which hosts are live: the next pass that DID resolve a document judged
			// every host last round probed -- and this round did not -- as stale, and deleted
			// the series this branch exists to preserve. One unreadable document was enough to
			// turn a whole round's probe evidence into deletions.
			return
		}
		hostOwner = make(map[string]string, len(res.Certificates))
		desiredNames = make(map[string]bool, len(res.Certificates))
		for i := range res.Certificates {
			c := &res.Certificates[i]
			desiredNames[c.Name] = true
			for _, d := range probeHosts(c.Domains, len(c.Domains)) {
				// First certificate wins, matching the old helper's "return on the first match"
				// order: a host covered by two certificates must be judged by the one the document
				// lists first, not by whichever happened to be written last into the map.
				if _, seen := hostOwner[d]; !seen {
					hostOwner[d] = c.Name
				}
			}
		}
	}
	// The probe record and the claim set are read under ONE hold of the claim lock.
	//
	// The record is per-round, so it is taken and reset only now that the round is really
	// being judged -- see the res == nil branch above.
	//
	// Reading the two separately was a check-then-act across two locks: the snapshot ran under
	// probeMu and the per-host in-flight check under mu, so a pass that recorded the host
	// after the snapshot but released its claim before the check read as "not in flight,
	// not probed this round" -- and the sweep deleted the series that pass had just written.
	// probeCert's record happens-before its claim's release (probeCert waits for its
	// goroutines before reconcileOne returns), so holding mu across both reads makes them
	// atomic with respect to acquire/release: a host probed this round is either IN the
	// snapshot, or its certificate's claim is held and shows up in inFlight. probeMu nests
	// inside mu here and is never held while taking mu (the probe record path touches only
	// probeMu), so there is no lock-order cycle.
	r.mu.Lock()
	r.probeMu.Lock()
	current := r.probedHosts
	r.probedHosts = map[string]struct{}{}
	r.probeMu.Unlock()
	inFlight := make(map[string]bool, len(r.running))
	orphanPassInFlight := false
	for n := range r.running {
		inFlight[n] = true
		// A pass for a certificate the desired state no longer lists: the only in-flight
		// pass that can still be about a host that has no owner here.
		if !desiredNames[n] {
			orphanPassInFlight = true
		}
	}
	r.mu.Unlock()

	for _, h := range all.ProbedHosts() {
		if _, live := current[h]; live {
			continue
		}
		// A host the runner has seen but this round did not probe is only stale if
		// nothing is still working on the certificate it belongs to.
		//
		// This round's probe set is not the whole picture. Two things keep a host out of
		// it while it is still being probed: a certificate whose pass is in flight right
		// now is skipped by the loop above, and a pass that has not reached probeCert yet
		// has not recorded anything. Deleting on that basis makes the series of a live
		// host disappear and reappear, which is exactly the flicker this function's own
		// contract says it avoids -- and a probe_match series that blinks is a false
		// alert for whoever is paging on it.
		//
		// Judged PER CERTIFICATE, not globally. The guard used to be "is any pass anywhere in
		// flight", which meant a single webhook-triggered pass -- and those run for minutes
		// while the timer's own pass walks past them -- suspended reclamation for the whole
		// fleet. A host whose certificate had already left the desired state then kept its
		// series anyway, which is the permanent false alert this function exists to remove.
		// Only the host's own certificate being mid-pass justifies waiting.
		name, inDesiredState := hostOwner[h]
		if inDesiredState {
			if inFlight[name] {
				continue
			}
			// And a certificate that is merely UNCONFIRMED is still being worked on.
			//
			// probeCert returns early for a certificate whose deployment is not confirmed (the
			// honest thing: there is no "deployed certificate" to compare against), so a host
			// disappears from this round's probe set during exactly the window a renewal is
			// mid-rebind -- which can last until the next binding check, up to six hours.
			// Deleting there made probe_match, probe_not_after and probe_trusted flicker once
			// per renewal, and for a rebind that then FAILED it was worse than flicker: the
			// series a `probe_match == 0` alert would fire on were gone, so the documented
			// alert stayed silent for the failure it exists to catch.
			st, err := r.store.GetCert(name)
			if err != nil || st == nil || !st.DeployConfirmed {
				continue
			}
		} else if orphanPassInFlight {
			// No owner in the desired state -- but a pass can still be running for the
			// certificate this host belonged to before it was removed, and that pass may
			// not have reached probeCert yet. Wait for THAT one rather than deleting a
			// series a live pass is about to write. A pass for a certificate the desired
			// state still lists is not a reason to wait: it cannot be about this host.
			continue
		}
		metrics.DeleteProbeSeries(h)
		// The runner's transition memory has to go with the series. Its own comment says
		// both are needed -- otherwise a host that leaves a SAN set leaks an entry there and
		// strands a gauge here -- and only the gauge was being reclaimed, so `last` grew
		// with every host ever dropped from a certificate, and certificate names churn by
		// design.
		//
		// p, not r.getProber(): the snapshot taken at the top of this function is the one
		// ProbedHosts() was read from. Re-reading could see nil after a concurrent
		// SetProber(nil) and panic on the method call.
		p.Forget(h)
	}
}

// RunCert processes exactly one named certificate. An unknown name returns an
// error; one already being processed returns ErrAlreadyRunning. Unlike a whole pass,
// the certificate's own error is propagated: a caller that asked for one specific
// certificate needs to hear that it failed, not a bare "accepted".
//
// This is the SYNCHRONOUS, test- and tooling-oriented entry point: it runs the pass on
// the caller's goroutine and deliberately bypasses Drain's bookkeeping -- it neither
// consults draining nor registers with the background group, so a shutdown will not
// wait for it and it can even start mid-drain. The webhook therefore uses StartCert /
// StartNamed, which are drain-safe; a production caller that cannot accept that must
// not switch to RunCert.
