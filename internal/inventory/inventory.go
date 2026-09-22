// Package inventory assembles a read-only view of certificates, names, expiry
// and (when known) bindings.
//
// It does not talk to Tencent Cloud or ACME. Callers pass what they already
// have: the desired-state snapshot, rows from state.db, optional probe samples.
// Serving PEM or keys in the resulting JSON is a bug — those fields stay off
// the exported structs.
package inventory

import (
	"crypto/x509"
	"encoding/pem"
	"sort"
	"strings"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

const (
	StatusFrozen            = "frozen"
	StatusRateLimited       = "rate_limited"
	StatusRevokePending     = "revoke_pending"
	StatusWaitingManualBind = "waiting_manual_bind"
	StatusProbeMismatch     = "probe_mismatch"
	StatusBindingUnknown    = "binding_unknown"
	StatusFailing           = "failing"
	StatusExpiring          = "expiring"
	StatusOK                = "ok"
)

const (
	DriftWaitingManualBind   = "waiting_for_first_clb_console_bind"
	DriftDesiredNamesMissing = "desired_names_not_on_issued_cert"
	DriftIssuedNotConfirmed  = "issued_cert_not_confirmed_on_cloud"
	DriftServedNotAfter      = "served_cert_not_after_mismatch"
	DriftServedNames         = "served_names_mismatch"
	DriftBindingIncomplete   = "binding_enumeration_incomplete"
	DriftDesiredFrozen       = "desired_state_frozen"
	DriftConsecutiveFailures = "consecutive_failures"
)

const (
	FreshnessStore       = "store"
	FreshnessCached      = "cached"
	FreshnessLive        = "live"
	FreshnessUnavailable = "unavailable"
)

const defaultRenewBefore = 30 * 24 * time.Hour

// Input is everything Assemble needs. Nil maps are treated as empty.
type Input struct {
	Now           time.Time
	Desired       *spec.Result
	Names         []string
	Certs         map[string]*state.CertState
	CertErrors    map[string]string
	RevokePending map[string]bool
	RateLimited   map[string]bool
	ProbeEnabled  bool
	Probes        map[string][]HostSample
	ResourceTypes []string
	// UIN is the Tencent Cloud account this process deploys into. Copied onto
	// every row unless the desired-state certificate sets its own.
	UIN string
}

// HostSample is one probe of a concrete name covered by the certificate.
type HostSample struct {
	Host        string    `json:"host"`
	Match       bool      `json:"match"`
	Trusted     bool      `json:"trusted"`
	NotAfter    time.Time `json:"notAfter,omitempty"`
	ProblemKind string    `json:"problemKind,omitempty"`
}

// Snapshot is the JSON body of GET /api/inventory.
type Snapshot struct {
	Time         string        `json:"time"`
	Desired      DesiredView   `json:"desired"`
	Summary      Summary       `json:"summary"`
	Certificates []Certificate `json:"certificates"`
}

type DesiredView struct {
	Revision     string `json:"revision,omitempty"`
	Frozen       bool   `json:"frozen"`
	FreezeReason string `json:"freezeReason,omitempty"`
	GeneratedAt  string `json:"generatedAt,omitempty"`
}

type Summary struct {
	Certificates      int `json:"certificates"`
	WaitingManualBind int `json:"waitingManualBind"`
	Failing           int `json:"failing"`
	Expiring          int `json:"expiring"`
	ProbeMismatch     int `json:"probeMismatch"`
	BindingUnknown    int `json:"bindingUnknown"`
}

// Certificate is one row. No PEM, no keys.
type Certificate struct {
	Name                string    `json:"name"`
	UIN                 string    `json:"uin,omitempty"`
	Status              string    `json:"status"`
	Profile             string    `json:"profile,omitempty"`
	KeyType             string    `json:"keyType,omitempty"`
	Domains             []string  `json:"domains,omitempty"`
	NotAfter            string    `json:"notAfter,omitempty"`
	DaysLeft            *int      `json:"daysLeft,omitempty"`
	IssuedAt            string    `json:"issuedAt,omitempty"`
	Uploaded            bool      `json:"uploaded"`
	DeployConfirmed     bool      `json:"deployConfirmed"`
	DeployedCertID      string    `json:"deployedCertId,omitempty"`
	Bindings            Bindings  `json:"bindings"`
	Probe               ProbeView `json:"probe"`
	ARI                 *ARIView  `json:"ari,omitempty"`
	ConsecutiveFailures int       `json:"consecutiveFailures"`
	NextAttemptAt       string    `json:"nextAttemptAt,omitempty"`
	LastError           string    `json:"lastError,omitempty"`
	Error               string    `json:"error,omitempty"`
	Drift               []string  `json:"drift,omitempty"`
}

type Bindings struct {
	ResourceTypes []string      `json:"resourceTypes,omitempty"`
	Count         int           `json:"count"`
	Complete      bool          `json:"complete"`
	Freshness     string        `json:"freshness"`
	Items         []BindingItem `json:"items"`
}

type BindingItem struct {
	ResourceType   string `json:"resourceType"`
	Region         string `json:"region,omitempty"`
	LoadBalancerID string `json:"loadBalancerId,omitempty"`
	ListenerID     string `json:"listenerId,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	Port           int    `json:"port,omitempty"`
	SNIDomain      string `json:"sniDomain,omitempty"`
	Role           string `json:"role,omitempty"`
	Complete       bool   `json:"complete"`
}

type ProbeView struct {
	Enabled bool         `json:"enabled"`
	OK      *bool        `json:"ok"`
	Hosts   []HostSample `json:"hosts"`
}

type ARIView struct {
	WindowStart string `json:"windowStart,omitempty"`
	WindowEnd   string `json:"windowEnd,omitempty"`
}

// Assemble builds the inventory snapshot. Certificates is never nil.
func Assemble(in Input) Snapshot {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	names := collectNames(in)
	out := Snapshot{
		Time:         now.UTC().Format(time.RFC3339),
		Certificates: make([]Certificate, 0, len(names)),
	}
	if in.Desired != nil {
		out.Desired.Revision = in.Desired.Revision
		out.Desired.Frozen = in.Desired.Frozen
		out.Desired.FreezeReason = in.Desired.FreezeReason
		if !in.Desired.GeneratedAt.IsZero() {
			out.Desired.GeneratedAt = in.Desired.GeneratedAt.UTC().Format(time.RFC3339)
		}
	}
	for _, name := range names {
		row := assembleOne(in, name, now)
		out.Certificates = append(out.Certificates, row)
		switch row.Status {
		case StatusWaitingManualBind:
			out.Summary.WaitingManualBind++
		case StatusFailing:
			out.Summary.Failing++
		case StatusExpiring:
			out.Summary.Expiring++
		case StatusProbeMismatch:
			out.Summary.ProbeMismatch++
		case StatusBindingUnknown:
			out.Summary.BindingUnknown++
		}
	}
	out.Summary.Certificates = len(out.Certificates)
	sortCertificates(out.Certificates)
	return out
}

func collectNames(in Input) []string {
	seen := map[string]struct{}{}
	var names []string
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	if in.Desired != nil {
		for i := range in.Desired.Certificates {
			add(in.Desired.Certificates[i].Name)
		}
	}
	for _, name := range in.Names {
		add(name)
	}
	return names
}

func assembleOne(in Input, name string, now time.Time) Certificate {
	row := Certificate{
		Name: name,
		UIN:  in.UIN,
		Bindings: Bindings{
			ResourceTypes: append([]string(nil), in.ResourceTypes...),
			Freshness:     FreshnessStore,
			Items:         []BindingItem{},
		},
		Probe: ProbeView{Enabled: in.ProbeEnabled, Hosts: []HostSample{}},
	}
	var desired *config.Certificate
	if in.Desired != nil {
		desired = in.Desired.Find(name)
	}
	if desired != nil {
		row.Profile = desired.Profile
		row.KeyType = desired.KeyType
		row.Domains = append([]string(nil), desired.Domains...)
		if desired.UIN != "" {
			row.UIN = desired.UIN
		}
	}
	if errText := in.CertErrors[name]; errText != "" {
		row.Error = errText
		row.Status = StatusBindingUnknown
		row.Drift = []string{DriftBindingIncomplete}
		return row
	}
	st := in.Certs[name]
	var issued []string
	if st != nil {
		if !st.NotAfter.IsZero() {
			row.NotAfter = st.NotAfter.UTC().Format(time.RFC3339)
			days := config.DaysUntil(st.NotAfter, now)
			row.DaysLeft = &days
		}
		if !st.IssuedAt.IsZero() {
			row.IssuedAt = st.IssuedAt.UTC().Format(time.RFC3339)
		}
		row.Uploaded = st.DeployedCertID != ""
		row.DeployConfirmed = st.DeployConfirmed
		row.DeployedCertID = st.DeployedCertID
		row.ConsecutiveFailures = st.ConsecutiveFailures
		row.LastError = st.LastError
		if !st.NextAttemptAt.IsZero() {
			row.NextAttemptAt = st.NextAttemptAt.UTC().Format(time.RFC3339)
		}
		if !st.ARIWindowStart.IsZero() || !st.ARIWindowEnd.IsZero() {
			ari := &ARIView{}
			if !st.ARIWindowStart.IsZero() {
				ari.WindowStart = st.ARIWindowStart.UTC().Format(time.RFC3339)
			}
			if !st.ARIWindowEnd.IsZero() {
				ari.WindowEnd = st.ARIWindowEnd.UTC().Format(time.RFC3339)
			}
			row.ARI = ari
		}
		issued = namesFromPEM(st.CertPEM)
	}
	if row.DeployConfirmed {
		row.Bindings.Count = 1
		row.Bindings.Complete = true
	} else {
		row.Bindings.Count = 0
		row.Bindings.Complete = true
	}
	samples := in.Probes[name]
	if samples == nil {
		samples = []HostSample{}
	}
	row.Probe.Hosts = samples
	if len(samples) > 0 {
		ok := true
		for _, h := range samples {
			if !h.Match {
				ok = false
				break
			}
		}
		row.Probe.OK = &ok
	}
	row.Drift = driftOf(in, desired, st, issued, samples)
	row.Status = statusOf(in, name, st, samples, now, desired)
	return row
}

func driftOf(in Input, desired *config.Certificate, st *state.CertState, issued []string, samples []HostSample) []string {
	var d []string
	if in.Desired != nil && in.Desired.Frozen {
		d = append(d, DriftDesiredFrozen)
	}
	if st != nil && st.DeployedCertID != "" && !st.DeployConfirmed {
		d = append(d, DriftWaitingManualBind)
	}
	if st != nil && !st.NotAfter.IsZero() && !st.DeployConfirmed {
		d = append(d, DriftIssuedNotConfirmed)
	}
	if desired != nil && len(issued) > 0 && !coversAll(issued, desired.Domains) {
		d = append(d, DriftDesiredNamesMissing)
	}
	if st != nil && st.ConsecutiveFailures > 0 {
		d = append(d, DriftConsecutiveFailures)
	}
	for _, h := range samples {
		switch h.ProblemKind {
		case "not_after":
			d = appendUnique(d, DriftServedNotAfter)
		case "names_missing", "names_extra", "not_covered":
			d = appendUnique(d, DriftServedNames)
		}
		if !h.Match && h.ProblemKind == "" {
			d = appendUnique(d, DriftServedNames)
		}
	}
	if len(d) == 0 {
		return nil
	}
	return d
}

func statusOf(in Input, name string, st *state.CertState, samples []HostSample, now time.Time, desired *config.Certificate) string {
	if in.Desired != nil && in.Desired.Frozen {
		return StatusFrozen
	}
	if in.RateLimited[name] {
		return StatusRateLimited
	}
	if in.RevokePending[name] {
		return StatusRevokePending
	}
	if st != nil && st.DeployedCertID != "" && !st.DeployConfirmed {
		return StatusWaitingManualBind
	}
	for _, h := range samples {
		if !h.Match {
			return StatusProbeMismatch
		}
	}
	if in.ProbeEnabled && st != nil && st.DeployConfirmed && len(samples) == 0 {
		return StatusBindingUnknown
	}
	if st != nil && st.ConsecutiveFailures > 0 {
		return StatusFailing
	}
	if st != nil && !st.NotAfter.IsZero() {
		window := defaultRenewBefore
		if desired != nil && desired.RenewBeforeDur > 0 {
			window = desired.RenewBeforeDur
		}
		if !st.NotAfter.After(now.Add(window)) {
			return StatusExpiring
		}
	}
	return StatusOK
}

func namesFromPEM(derPEM []byte) []string {
	if len(derPEM) == 0 {
		return nil
	}
	block, _ := pem.Decode(derPEM)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	names := append([]string(nil), cert.DNSNames...)
	if cert.Subject.CommonName != "" {
		names = appendUnique(names, cert.Subject.CommonName)
	}
	return names
}

func coversAll(issued, desired []string) bool {
	for _, want := range desired {
		if !covers(issued, want) {
			return false
		}
	}
	return true
}

func covers(issued []string, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, have := range issued {
		have = strings.ToLower(strings.TrimSuffix(have, "."))
		if have == name {
			return true
		}
		if strings.HasPrefix(have, "*.") {
			suffix := have[1:]
			rest := strings.TrimSuffix(name, suffix)
			if rest != name && rest != "" && !strings.Contains(rest, ".") {
				return true
			}
		}
	}
	return false
}

func appendUnique(in []string, v string) []string {
	for _, e := range in {
		if e == v {
			return in
		}
	}
	return append(in, v)
}

func sortCertificates(rows []Certificate) {
	rank := map[string]int{
		StatusWaitingManualBind: 0,
		StatusProbeMismatch:     1,
		StatusFailing:           2,
		StatusBindingUnknown:    3,
		StatusExpiring:          4,
		StatusRateLimited:       5,
		StatusRevokePending:     6,
		StatusFrozen:            7,
		StatusOK:                8,
	}
	sort.SliceStable(rows, func(i, j int) bool {
		ri, rj := rank[rows[i].Status], rank[rows[j].Status]
		if ri != rj {
			return ri < rj
		}
		di, dj := 1<<30, 1<<30
		if rows[i].DaysLeft != nil {
			di = *rows[i].DaysLeft
		}
		if rows[j].DaysLeft != nil {
			dj = *rows[j].DaysLeft
		}
		if di != dj {
			return di < dj
		}
		return rows[i].Name < rows[j].Name
	})
}
