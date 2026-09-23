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
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// The primary status of a row. Exactly one applies, first match wins (see statusOf).
//
// The list distinguishes three things the page used to merge into one wrong answer:
// "no certificate exists yet" is not `ok`, "the endpoint could not be dialled" is not
// `probe_mismatch`, and "the cloud has not confirmed the upload" is not `ok` either.
const (
	StatusFrozen            = "frozen"
	StatusRateLimited       = "rate_limited"
	StatusRevokePending     = "revoke_pending"
	StatusStateUnreadable   = "state_unreadable"
	StatusNotIssued         = "not_issued"
	StatusWaitingManualBind = "waiting_manual_bind"
	StatusPendingDeploy     = "pending_deploy"
	StatusProbeMismatch     = "probe_mismatch"
	StatusProbeUnreachable  = "probe_unreachable"
	StatusBindingUnknown    = "binding_unknown"
	StatusProbeUnknown      = "probe_unknown"
	StatusFailing           = "failing"
	StatusExpiring          = "expiring"
	StatusOK                = "ok"
)

const (
	DriftStateUnreadable     = "state_unreadable"
	DriftWaitingManualBind   = "waiting_for_first_clb_console_bind"
	DriftDesiredNamesMissing = "desired_names_not_on_issued_cert"
	DriftIssuedNotConfirmed  = "issued_cert_not_confirmed_on_cloud"
	DriftServedNotAfter      = "served_cert_not_after_mismatch"
	DriftServedNames         = "served_names_mismatch"
	DriftServedUntrusted     = "served_chain_untrusted"
	DriftServedValidityShort = "served_validity_below_floor"
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
	// Probes holds the answers the prober recorded this process life, keyed by
	// certificate name. Empty means "no answer yet", which is not "match".
	Probes map[string][]HostSample
	// LiveBindings is the parsed bind-resource cache, keyed by certificate name.
	//
	// It is applied while the row is built rather than patched in afterwards: the
	// status and the summary are derived from the bindings, so a row that was
	// assembled store-side and then had live rows attached would keep claiming "ok"
	// for a certificate whose enumeration came back incomplete.
	LiveBindings  map[string]Bindings
	ResourceTypes []string
	// UIN is the Tencent Cloud account this process deploys into. Copied onto
	// every row unless the desired-state certificate sets its own.
	UIN string
}

// HostSample is one probe of a concrete name covered by the certificate.
type HostSample struct {
	Host  string `json:"host"`
	Match bool   `json:"match"`
	// Trusted is the chain verdict, and NotAfter is the expiry of the certificate the
	// probe actually read. Both are absent when the probe could not read one: the
	// zero time would otherwise be published as year one.
	Trusted     bool       `json:"trusted"`
	NotAfter    *time.Time `json:"notAfter,omitempty"`
	ProblemKind string     `json:"problemKind,omitempty"`
}

// Snapshot is the JSON body of GET /api/inventory.
type Snapshot struct {
	Time         string        `json:"time"`
	Desired      DesiredView   `json:"desired"`
	Summary      Summary       `json:"summary"`
	Certificates []Certificate `json:"certificates"`
}

// DesiredView describes the desired-state document.
//
// Frozen is a pointer because "the document has not been read" and "the document is
// not frozen" are different answers, and only the second one may be reported as
// false: the page used to print "frozen: false" for a daemon that had never managed
// to read the document at all, while /hook/desired answered 503 for the same state.
type DesiredView struct {
	Revision     string `json:"revision,omitempty"`
	Frozen       *bool  `json:"frozen"`
	FreezeReason string `json:"freezeReason,omitempty"`
	GeneratedAt  string `json:"generatedAt,omitempty"`
}

type Summary struct {
	Certificates      int `json:"certificates"`
	WaitingManualBind int `json:"waitingManualBind"`
	PendingDeploy     int `json:"pendingDeploy"`
	NotIssued         int `json:"notIssued"`
	Unreadable        int `json:"unreadable"`
	Failing           int `json:"failing"`
	Expiring          int `json:"expiring"`
	ProbeMismatch     int `json:"probeMismatch"`
	ProbeUnreachable  int `json:"probeUnreachable"`
	ProbeUnknown      int `json:"probeUnknown"`
	BindingUnknown    int `json:"bindingUnknown"`
}

// Certificate is one row. No PEM, no keys.
type Certificate struct {
	Name    string   `json:"name"`
	UIN     string   `json:"uin,omitempty"`
	Status  string   `json:"status"`
	Profile string   `json:"profile,omitempty"`
	KeyType string   `json:"keyType,omitempty"`
	Domains []string `json:"domains,omitempty"`
	// Regions is where this certificate was OBSERVED bound, taken from the live
	// binding rows. Absent means unknown, which is not the same as "no region": the
	// store cannot enumerate bindings, and one certificate can be bound in several
	// regions. A Tencent Cloud SSL certificate is not itself regional -- the regions
	// are the load balancers it is attached to.
	Regions             []string  `json:"regions,omitempty"`
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
	ResourceTypes []string `json:"resourceTypes,omitempty"`
	Count         int      `json:"count"`
	Complete      bool     `json:"complete"`
	Freshness     string   `json:"freshness"`
	// ObservedAt is when a live enumeration produced these rows. Empty on
	// store-side rows, which were never observed on the cloud: their count is what
	// this program deployed, not what exists.
	ObservedAt string        `json:"observedAt,omitempty"`
	Items      []BindingItem `json:"items"`
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
		frozen := in.Desired.Frozen
		out.Desired.Frozen = &frozen
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
		case StatusPendingDeploy:
			out.Summary.PendingDeploy++
		case StatusNotIssued:
			out.Summary.NotIssued++
		case StatusStateUnreadable:
			out.Summary.Unreadable++
		case StatusFailing:
			out.Summary.Failing++
		case StatusExpiring:
			out.Summary.Expiring++
		case StatusProbeMismatch:
			out.Summary.ProbeMismatch++
		case StatusProbeUnreachable:
			out.Summary.ProbeUnreachable++
		case StatusProbeUnknown:
			out.Summary.ProbeUnknown++
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
		// A state read that failed is not a binding problem: reporting
		// "binding_unknown" for it sends the operator to the load-balancer console
		// for a database error. The message itself travels in Error.
		row.Error = errText
		row.Status = StatusStateUnreadable
		row.Drift = []string{DriftStateUnreadable}
		row.Bindings = bindingsFor(in, name, nil)
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
	row.Bindings = bindingsFor(in, name, st)
	row.Regions = bindingRegions(row.Bindings)
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
	row.Drift = driftOf(in, desired, st, issued, samples, row.Bindings)
	row.Status = statusOf(in, name, &row, st, samples, now, desired)
	return row
}

// bindingsFor fills the binding view: the parsed live snapshot when the reconciler
// has one for this certificate, otherwise the store-side lower bound.
//
// The store cannot enumerate bindings. It knows what this program deployed, which is
// a lower bound -- an operator can bind the same certificate to further listeners,
// and a console bind that has not been confirmed yet is invisible here. So count is
// what is known, complete says whether that is the whole set, and freshness names the
// source. None of the three may be turned into a confident "bound nowhere".
func bindingsFor(in Input, name string, st *state.CertState) Bindings {
	if live, ok := in.LiveBindings[name]; ok {
		if live.Items == nil {
			live.Items = []BindingItem{}
		}
		if live.Freshness == "" {
			live.Freshness = FreshnessCached
		}
		if live.ResourceTypes == nil {
			live.ResourceTypes = append([]string(nil), in.ResourceTypes...)
		}
		return live
	}
	b := Bindings{
		ResourceTypes: append([]string(nil), in.ResourceTypes...),
		Freshness:     FreshnessStore,
		Items:         []BindingItem{},
	}
	if st != nil && st.DeployConfirmed {
		b.Count = 1
	}
	return b
}

func driftOf(in Input, desired *config.Certificate, st *state.CertState, issued []string, samples []HostSample, bindings Bindings) []string {
	var d []string
	// Only a live enumeration can be incomplete. A store-side count is a lower bound
	// by construction, and flagging every row the daemon has not enumerated would
	// turn the drift column into noise.
	if (bindings.Freshness == FreshnessCached || bindings.Freshness == FreshnessLive) && !bindings.Complete {
		d = append(d, DriftBindingIncomplete)
	}
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
		if h.Match {
			continue
		}
		// Only what the probe actually reported becomes a drift token. An earlier
		// version turned "not a match, no kind given" into a names mismatch, which
		// asserts a cause nobody observed -- and a chain that does not verify, or a
		// served certificate with less validity left than the floor, produced no
		// token at all while still reading "probe mismatch".
		switch h.ProblemKind {
		case string(probe.ProblemNotAfter):
			d = appendUnique(d, DriftServedNotAfter)
		case string(probe.ProblemNamesMissing), string(probe.ProblemNamesExtra), string(probe.ProblemNotCovered):
			d = appendUnique(d, DriftServedNames)
		case string(probe.ProblemUntrusted):
			d = appendUnique(d, DriftServedUntrusted)
		case string(probe.ProblemMinValidFor):
			d = appendUnique(d, DriftServedValidityShort)
		}
	}
	if len(d) == 0 {
		return nil
	}
	return d
}

func statusOf(in Input, name string, row *Certificate, st *state.CertState, samples []HostSample, now time.Time, desired *config.Certificate) string {
	if in.Desired != nil && in.Desired.Frozen {
		return StatusFrozen
	}
	if in.RateLimited[name] {
		return StatusRateLimited
	}
	if in.RevokePending[name] {
		return StatusRevokePending
	}
	if st == nil || (st.NotAfter.IsZero() && st.DeployedCertID == "") {
		// Nothing has been issued for this name. This is the answer that used to be
		// "ok", which is how a certificate whose issuance had never run -- or had
		// failed before anything was stored -- was reported as healthy.
		return StatusNotIssued
	}
	// A deployment with deploy.enabled: false never uploads, so "not uploaded yet"
	// and "no probe answer" are not problems there.
	deployEnabled := desired == nil || desired.Deploy.Enabled
	if deployEnabled && st.DeployedCertID == "" && !st.DeployConfirmed {
		return StatusPendingDeploy
	}
	if st.DeployedCertID != "" && !st.DeployConfirmed {
		return StatusWaitingManualBind
	}
	// Probe answers first: they are the only evidence about the endpoint itself.
	// "Could not dial the name" and "dialled it and got the wrong certificate" are
	// different problems with different owners, so they are different statuses.
	var unreachable bool
	for _, h := range samples {
		if h.Match {
			continue
		}
		switch h.ProblemKind {
		case string(probe.ProblemUnreachable), string(probe.ProblemNoCertificate):
			unreachable = true
		default:
			return StatusProbeMismatch
		}
	}
	if unreachable {
		return StatusProbeUnreachable
	}
	if liveIncomplete(row.Bindings) {
		return StatusBindingUnknown
	}
	if in.ProbeEnabled && deployEnabled && st.DeployConfirmed && len(samples) == 0 {
		// Probing is on and this certificate is deployed, but this process has not
		// read a served certificate for it yet. Unverified is not "ok", and it is not
		// a binding problem either -- that word was wrong here and sent operators to
		// the load-balancer console.
		return StatusProbeUnknown
	}
	if st.ConsecutiveFailures > 0 {
		return StatusFailing
	}
	window := defaultRenewBefore
	if desired != nil && desired.RenewBeforeDur > 0 {
		window = desired.RenewBeforeDur
	}
	if !st.NotAfter.IsZero() && !st.NotAfter.After(now.Add(window)) {
		// Exact-instant comparison, deliberately: this is the same test the renewer
		// uses before it places an order, while daysLeft is rounded up for display.
		// A row can therefore read "Expiring · 30d" when the window is 30 days.
		return StatusExpiring
	}
	return StatusOK
}

// liveIncomplete reports whether a live enumeration came back incomplete with no
// binding at all. Store-side rows never qualify: their count is a lower bound from
// what this program deployed, not a failed enumeration, and calling that "binding
// unknown" would label every certificate the daemon has not enumerated.
func liveIncomplete(b Bindings) bool {
	if b.Freshness != FreshnessCached && b.Freshness != FreshnessLive {
		return false
	}
	return !b.Complete && b.Count == 0
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

// bindingRegions is the sorted set of regions the binding rows mention. Empty when
// nothing was enumerated, so the page can say "unknown" rather than pick a region.
func bindingRegions(b Bindings) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, it := range b.Items {
		r := strings.TrimSpace(it.Region)
		if r == "" {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	sort.Strings(out)
	return out
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
		StatusFrozen:            0,
		StatusRateLimited:       1,
		StatusRevokePending:     2,
		StatusStateUnreadable:   3,
		StatusNotIssued:         4,
		StatusWaitingManualBind: 5,
		StatusPendingDeploy:     6,
		StatusProbeMismatch:     7,
		StatusProbeUnreachable:  8,
		StatusBindingUnknown:    9,
		StatusProbeUnknown:      10,
		StatusFailing:           11,
		StatusExpiring:          12,
		StatusOK:                13,
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
