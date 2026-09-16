// Package spec defines the contract for the desired state.
//
// The contract rests on one discipline: **this layer never infers**.
// wecert only reads a desired state that has already been written down and can
// be diffed, then converges toward it. Inference belongs to the onboarding
// component -- it can be swapped, experimented on and thrown away at any time,
// whereas certificate lifecycle must stay stable.
//
// The split is driven by failure modes: a source failure only leaves the
// desired state **un-updated** (safe, keeps the status quo). If wecert instead
// enumerated sources itself, one API blip could be read as "all these domains
// are gone", after which it would strip them from the certificate and TLS
// handshakes in production would fail immediately.
package spec

import (
	"context"
	"time"

	"github.com/susunola/wecert/internal/config"
)

// Decision records why a single hostname was kept or dropped.
//
// It must answer "I added a domain, why wasn't it issued?" -- the number one
// question once a system like this is live. Without it, troubleshooting means
// digging through logs, and logs get rotated away.
type Decision struct {
	Hostname string `json:"hostname" yaml:"hostname"`

	// Included reports whether the name ended up in some certificate's SAN.
	Included bool `json:"included" yaml:"included"`

	// Reason is a plain-language explanation, such as
	// "covered by declared wildcard *.example.com" / "no CLB rule" /
	// "source unknown, freezing".
	Reason string `json:"reason" yaml:"reason"`

	// Certificate is the certificate name it ended up in (when it did).
	Certificate string `json:"certificate,omitempty" yaml:"certificate,omitempty"`

	Details map[string]any `json:"details,omitempty" yaml:"details,omitempty"`
}

// Result is the complete outcome of one desired-state evaluation.
type Result struct {
	Certificates []config.Certificate `json:"certificates" yaml:"certificates"`
	Decisions    []Decision           `json:"decisions,omitempty" yaml:"decisions,omitempty"`

	// Revision fingerprints the content and answers "is this round the same as
	// the last one?". It covers only certificates, no timestamps -- otherwise
	// every run would change it.
	Revision string `json:"revision,omitempty" yaml:"revision,omitempty"`

	// GeneratedAt is when the document was written, present only for document
	// sources. Zero means the notion does not apply to the source.
	GeneratedAt time.Time `json:"generatedAt,omitempty" yaml:"generatedAt,omitempty"`

	// Frozen means reading the source failed this round and the last usable
	// revision was returned instead.
	//
	// This is not an error but deliberate behaviour: when the source cannot be
	// read, the correct answer is to **keep the status quo**, never "desired
	// state is empty". The latter makes wecert strip domains from certificates.
	// Freezing is safer than acting.
	Frozen bool `json:"frozen,omitempty" yaml:"frozen,omitempty"`

	// FreezeReason explains why the state is frozen.
	FreezeReason string `json:"freezeReason,omitempty" yaml:"freezeReason,omitempty"`

	// Shadow is set only in observe mode: the "what would the shadow source do"
	// comparison. nil means there is no shadow source (static / enforce modes).
	Shadow *ShadowReport `json:"shadow,omitempty" yaml:"shadow,omitempty"`
}

// Provider is a source of desired state.
//
// Implementations must be:
//  1. Idempotent: identical input always yields identical output, in the same order
//  2. Name-stable: names derive only from the grouping key, never from the domain set
type Provider interface {
	Desired(ctx context.Context) ([]config.Certificate, error)
}

// ReportingProvider is the recommended interface: alongside the desired state
// itself it explains why each hostname is where it is.
type ReportingProvider interface {
	Provider

	// DesiredWithReasons is the recommended entry point; Desired is just its
	// simplified form.
	DesiredWithReasons(ctx context.Context) (*Result, error)
}

// Named lets a source report who it is, for logs and diagnostic endpoints.
type Named interface {
	Kind() string
}

// Desired evaluates a provider, preferring the path that carries reasons.
func Desired(ctx context.Context, p Provider) (*Result, error) {
	if rp, ok := p.(ReportingProvider); ok {
		return rp.DesiredWithReasons(ctx)
	}

	certs, err := p.Desired(ctx)
	if err != nil {
		return nil, err
	}
	return &Result{Certificates: certs, Revision: Revision(certs)}, nil
}

// KindOf returns the source name, or "unknown" when Named is not implemented.
func KindOf(p Provider) string {
	if n, ok := p.(Named); ok {
		return n.Kind()
	}
	return "unknown"
}

// CertNames returns the names of all certificates in the result, in result order.
func (r *Result) CertNames() []string {
	names := make([]string, 0, len(r.Certificates))
	for i := range r.Certificates {
		names = append(names, r.Certificates[i].Name)
	}
	return names
}

// Find looks up one certificate by name.
func (r *Result) Find(name string) *config.Certificate {
	for i := range r.Certificates {
		if r.Certificates[i].Name == name {
			return &r.Certificates[i]
		}
	}
	return nil
}

// decisionsFor annotates a static desired state with "why it is here".
func decisionsFor(certs []config.Certificate, reason string) []Decision {
	var out []Decision
	for i := range certs {
		c := &certs[i]
		for _, d := range c.Domains {
			out = append(out, Decision{
				Hostname:    d,
				Included:    true,
				Reason:      reason,
				Certificate: c.Name,
			})
		}
	}
	return out
}
