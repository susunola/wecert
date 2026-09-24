package acme

import (
	"context"
	"time"

	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/metrics"
)

// binderPatroller is the deploy side of the full-binding patrol.
type binderPatroller interface {
	PatrolBindings(ctx context.Context, known []deploy.KnownCert) ([]deploy.PatrolFinding, error)
}

// bindingPatrolEvery bounds how often the account-wide enumeration runs.
// DescribeCertificates plus one bind-resource task per certificate is an API
// storm at the pass rate -- the pass already probes each certificate's bindings
// once; this is the account-wide audit that catches console changes and orphan
// uploads, which can wait hours.
const bindingPatrolEvery = 6 * time.Hour

// PatrolBindings runs the full-binding audit and publishes kind -> count.
//
// Safe to call on every wrap-up: it self-throttles to bindingPatrolEvery and
// returns the last counts without calling the API in between.
func (m *Manager) PatrolBindings(ctx context.Context) (map[string]int, error) {
	m.patrolMu.Lock()
	if !m.now().IsZero() && !m.patrolAfter.IsZero() && m.now().Before(m.patrolAfter) {
		last := m.patrolLast
		m.patrolMu.Unlock()
		return last, nil
	}
	m.patrolMu.Unlock()

	p, ok := m.deployer.(binderPatroller)
	if !ok {
		return nil, nil
	}
	known, err := m.store.ListCertNames()
	if err != nil {
		return nil, err
	}
	var certs []deploy.KnownCert
	for _, name := range known {
		st, err := m.store.GetCert(name)
		if err != nil || st == nil {
			continue
		}
		certs = append(certs, deploy.KnownCert{Name: name, DeployedID: st.DeployedCertID})
	}
	findings, err := p.PatrolBindings(ctx, certs)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, f := range findings {
		counts[string(f.Kind)]++
		// confirmed is the common case and floods the journal at Info; anything else
		// is what an operator needs to read.
		if f.Kind != deploy.PatrolConfirmed {
			m.log.Warn("binding patrol finding",
				"kind", string(f.Kind), "cert", f.CertName, "certId", f.CertID, "detail", f.Detail)
		}
	}
	// Publish every kind so a zero is visible (absent series reads as "no answer").
	for _, k := range []string{
		string(deploy.PatrolConfirmed), string(deploy.PatrolIncomplete), string(deploy.PatrolDrift),
		string(deploy.PatrolOrphanUpload), string(deploy.PatrolUnmanaged),
	} {
		metrics.BindingPatrolFindings.WithLabelValues(k).Set(float64(counts[k]))
	}
	metrics.BindingPatrolLastRun.Set(float64(m.now().Unix()))

	m.patrolMu.Lock()
	m.patrolLast = counts
	m.patrolAfter = m.now().Add(bindingPatrolEvery)
	m.patrolMu.Unlock()
	return counts, nil
}
