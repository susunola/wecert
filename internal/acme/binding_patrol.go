package acme

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/metrics"
)

// binderPatroller is the deploy side of the full-binding patrol.
type binderPatroller interface {
	PatrolBindings(ctx context.Context, known []deploy.KnownCert) ([]deploy.PatrolFinding, error)
}

// The daemon builds *deploy.LazyTencentCLB and hands it over as a plain Deployer; this capability
// is reached by assertion. Asserting it here, at compile time, is what keeps a missing forward from
// disabling the patrol silently -- it did exactly that once, and the only visible symptom was a
// binding column that showed a count and nothing else.
var _ binderPatroller = (*deploy.LazyTencentCLB)(nil)

// warnUnsupportedPatrolOnce keeps the "this deployer cannot patrol" warning to one line per process.
var warnUnsupportedPatrolOnce sync.Once

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
		// Loud once. A deployer that cannot patrol leaves every binding row in the read-only
		// inventory degraded to the state store's count -- which an operator cannot tell apart
		// from "not bound", the exact question that column exists to answer.
		warnUnsupportedPatrolOnce.Do(func() {
			m.log.Warn("the configured deployer does not support the binding patrol: binding details "+
				"in the inventory will stay store-side", "deployer", fmt.Sprintf("%T", m.deployer))
		})
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
