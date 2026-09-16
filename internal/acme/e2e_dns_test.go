//go:build pebble && lego_dns

// A real DNS-01 end-to-end: a real ACME server validates a real challenge record that it reads
// from a real authoritative DNS server, after wecert wrote it through its real solver and waited
// for its real propagation check.
//
// What makes this different from TestPebbleFullIssuance next door. That test runs pebble with
// PEBBLE_VA_ALWAYS_VALID, so nothing ever validates the challenge: it covers the ORDER protocol
// (account binding, authorization polling, CSR finalize, chain download) and nothing about DNS.
// Its own comment explains why -- "making pebble validate against a local authority needs the
// authority on port 53, which needs root" -- and that is exactly the gap this file closes.
//
// Port 53 is the crux. A DNS delegation carries no port, so both sides have to agree on 53:
// wecert's propagation probe dials the zone's nameserver address on 53 (authoritativeNS), and
// pebble's validator asks whatever `-dnsserver` names. An authoritative server on 0.0.0.0:53 is
// reachable as 127.0.0.1:53 for both, and on macOS/BSD binding it unprivileged works. On Linux it
// needs CAP_NET_BIND_SERVICE (`--cap-add=NET_BIND_SERVICE` in a container, or the suite runs as
// root); without it the test SKIPS with that instruction rather than pretending to have run.
//
// Everything else is the production path, unchanged:
//
//   - the solver is NewDNSSolver with `dns.provider: lego` + `legoProvider: httpreq`, so the
//     provider is a real one from lego's registry talking HTTP to the test's control API -- the
//     same code path a real provider takes, minus the vendor;
//   - the zone walk, the TXT query, the authoritative-only rule, the write-all/verify-all/clean-up
//     and the propagation wait are all the shipping implementation;
//   - the state database is a real one on disk, and the certificates come back over the wire.
//
// What is NOT real here, and is reported as such: the cloud deploy step (deploy.Noop, because
// there are no Tencent Cloud credentials in a test environment) and the CA (pebble, not Let's
// Encrypt). Both have their own acceptance path -- scripts/run-stage-ab.sh for the cloud side and
// docs/lifecycle-acceptance.md for the staging CA.
//
// Run it with: make test-e2e
package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/miekg/dns"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// ── the authoritative DNS server ─────────────────────────────────────────────────────

// testZone is the zone the whole run lives in.
//
// It must sit under a real public suffix: findZone's own guard refuses a zone whose SOA walk
// stops at the suffix itself, and "example" is treated as a suffix by the public-suffix list. So
// the zone is a third-level name under example.com, which is ordinary and unambiguous.
const (
	// testZoneName is the form a config uses; testZone is the FQDN form DNS needs. The config
	// rejects a trailing dot on a domain, which is how this distinction first showed up.
	testZoneName = "e2e.example.com"
	testZone     = testZoneName + "."
	testNSTail   = "ns1." + testZone
)

// authDNS is a minimal authoritative nameserver for one zone, plus the record API a provider
// writes through.
//
// It is deliberately strict rather than permissive: AA is set only on answers it actually owns,
// an unknown name gets NOERROR with no records (not NXDOMAIN), and TXT queries are answered from
// the live record set. A permissive server would let a broken propagation check pass.
type authDNS struct {
	udp   *dns.Server
	tcp   *dns.Server
	api   *http.Server
	addr  string
	apiAt string
	// reachable and unreachable record which transports answered a self-probe.
	reachable   []string
	unreachable []string

	mu sync.Mutex
	// txt is the live record set: name -> values.
	txt map[string][]string
	// maxValues remembers the most values ever seen at one name at the same time, which is how
	// the wildcard+apex case proves both values were up together rather than one after the other.
	maxValues map[string]int
	// mutations is every write and delete the provider API performed, in order.
	//
	// The live set and the peak count cannot answer "did THIS pass write its records and clean
	// them up again": a renewal writes the same _acme-challenge names the issuance wrote, so by
	// the time it starts the peak is already above zero and the peak cannot rise again. The
	// mutation log can, because it is a sequence rather than a high-water mark.
	mutations []dnsMutation
	// queries is every question the server was asked, in order: evidence for the report.
	queries []string
}

// dnsMutation is one add or delete of a TXT value, as the provider API requested it.
type dnsMutation struct {
	name  string
	value string
	add   bool
}

func (s *authDNS) record(proto string, q dns.Question) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, fmt.Sprintf("%s %s %s", proto, q.Name, dns.TypeToString[q.Qtype]))
}

func (s *authDNS) addTXT(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.txt[name] {
		if v == value {
			return
		}
	}
	s.txt[name] = append(s.txt[name], value)
	s.mutations = append(s.mutations, dnsMutation{name: name, value: value, add: true})
	if n := len(s.txt[name]); n > s.maxValues[name] {
		s.maxValues[name] = n
	}
}

func (s *authDNS) delTXT(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.txt[name][:0]
	for _, v := range s.txt[name] {
		if v != value {
			kept = append(kept, v)
		}
	}
	// Logged even when the name was already empty: lego's provider deletes whatever it is
	// asked to delete, and "the cleanup call happened" is the fact worth having.
	s.mutations = append(s.mutations, dnsMutation{name: name, value: value, add: false})
	if len(kept) == 0 {
		delete(s.txt, name)
		return
	}
	s.txt[name] = kept
}

// mutationCount marks a position in the mutation log, and mutationsSince returns everything
// after it, so a case can speak about the writes one pass made rather than the whole run's.
func (s *authDNS) mutationCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.mutations)
}

func (s *authDNS) mutationsSince(mark int) []dnsMutation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mark < 0 || mark > len(s.mutations) {
		return nil
	}
	return append([]dnsMutation(nil), s.mutations[mark:]...)
}

// snapshot returns the live record set and the peak value count per name.
func (s *authDNS) snapshot() (live map[string][]string, peak map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	live = make(map[string][]string, len(s.txt))
	for k, v := range s.txt {
		live[k] = append([]string(nil), v...)
	}
	peak = make(map[string]int, len(s.maxValues))
	for k, v := range s.maxValues {
		peak[k] = v
	}
	return live, peak
}

// sawTXTFor reports whether any TXT question arrived for the given name, over any transport.
func (s *authDNS) sawTXTFor(name string) bool {
	return s.sawTXTForOver(name, "")
}

// sawTXTForOver is the same question for one transport.
//
// The transport is what identifies the asker here: wecert's propagation probe speaks UDP
// (dns.Client's default), while pebble's validator speaks TCP the moment a custom resolver is
// configured. So "did the CA really read the record" is answerable from the query log.
func (s *authDNS) sawTXTForOver(name, transport string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	name = dns.Fqdn(name)
	for _, q := range s.queries {
		if transport != "" && !strings.HasPrefix(q, transport+" ") {
			continue
		}
		if strings.HasSuffix(q, " "+name+" "+dns.TypeToString[dns.TypeTXT]) {
			return true
		}
	}
	return false
}

func (s *authDNS) answer(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = false
	if len(r.Question) != 1 {
		return m
	}
	q := r.Question[0]
	name := dns.Fqdn(q.Name)
	inZone := name == testZone || strings.HasSuffix(name, "."+testZone)

	switch q.Qtype {
	case dns.TypeSOA:
		// Only the zone apex owns an SOA. A name further up gets an empty NOERROR so findZone
		// keeps climbing, and the apex is where it stops.
		if name == testZone {
			m.Authoritative = true
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr:    dns.RR_Header{Name: testZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns:     testNSTail,
				Mbox:   "hostmaster." + testZone,
				Serial: 1, Refresh: 60, Retry: 60, Expire: 600, Minttl: 60,
			})
		}
		return m

	case dns.TypeNS:
		if name == testZone {
			m.Authoritative = true
			m.Answer = append(m.Answer, &dns.NS{
				Hdr: dns.RR_Header{Name: testZone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  testNSTail,
			})
		}
		return m

	case dns.TypeA:
		// Exactly one address for the nameserver, so the zone has ONE authority. A second
		// address here would make the two-confirmation rule apply and the run would depend on
		// whichever of them answered first.
		if inZone {
			m.Authoritative = true
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1"),
			})
		}
		return m

	case dns.TypeTXT:
		if !inZone {
			return m
		}
		s.mu.Lock()
		values := append([]string(nil), s.txt[name]...)
		s.mu.Unlock()
		m.Authoritative = true
		for _, v := range values {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
				Txt: []string{v},
			})
		}
		return m

	default:
		// CNAME included: an empty authoritative NOERROR ends lego's CNAME walk at the literal
		// challenge name, which is what a zone with no delegation should produce.
		if inZone {
			m.Authoritative = true
		}
		return m
	}
}

// transportWorks reports whether the self-probe got an answer over this transport.
func (s *authDNS) transportWorks(transport string) bool {
	for _, t := range s.reachable {
		if t == transport {
			return true
		}
	}
	return false
}

// startAuthDNS binds the authoritative server on port 53 and the control API on a free port.
func startAuthDNS(t *testing.T) *authDNS {
	t.Helper()

	s := &authDNS{txt: map[string][]string{}, maxValues: map[string]int{}}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 1 {
			proto := "udp"
			if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
				proto = "tcp"
			}
			s.record(proto, r.Question[0])
		}
		_ = w.WriteMsg(s.answer(r))
	})

	// 0.0.0.0 rather than 127.0.0.1: on macOS and the BSDs an unprivileged process may bind the
	// wildcard on a privileged port but not a specific address, and a wildcard bind answers on
	// 127.0.0.1 anyway. On Linux neither is allowed without CAP_NET_BIND_SERVICE.
	pc, err := net.ListenPacket("udp", "0.0.0.0:53")
	if err != nil {
		t.Skipf("cannot bind port 53 (%v).\n"+
			"A DNS delegation carries no port, so both wecert's propagation probe and pebble's "+
			"validator need the authority on 53. Run this suite with CAP_NET_BIND_SERVICE "+
			"(docker run --cap-add=NET_BIND_SERVICE ...), as root, or on macOS/BSD where an "+
			"unprivileged wildcard bind on 53 is permitted.", err)
	}
	ln, err := net.Listen("tcp", "0.0.0.0:53")
	if err != nil {
		_ = pc.Close()
		t.Skipf("cannot bind TCP port 53 (%v); see the UDP message for what this needs", err)
	}

	s.udp = &dns.Server{PacketConn: pc, Handler: handler}
	s.tcp = &dns.Server{Listener: ln, Handler: handler}
	go func() { _ = s.udp.ActivateAndServe() }()
	go func() { _ = s.tcp.ActivateAndServe() }()
	s.addr = "127.0.0.1:53"

	// Binding a port and being reachable on it are different things, and the difference decides
	// whether this run can validate for real. Sandboxes routinely allow the bind and drop the
	// traffic: on the machine this was developed on, UDP/53 works and TCP/53 times out, which
	// matters because pebble's validator forces TCP whenever -dnsserver is set
	// (va.go: `if customResolverAddr != "" { va.dnsClient.Net = "tcp" }`).
	//
	// So probe both transports rather than assume, and let the report say which mode ran.
	probe := new(dns.Msg)
	probe.SetQuestion(testZone, dns.TypeSOA)
	for _, transport := range []string{"udp", "tcp"} {
		c := &dns.Client{Net: transport, Timeout: 3 * time.Second}
		if _, _, err := c.Exchange(probe, s.addr); err != nil {
			s.unreachable = append(s.unreachable, fmt.Sprintf("%s: %v", transport, err))
			continue
		}
		s.reachable = append(s.reachable, transport)
	}
	if !s.transportWorks("udp") {
		t.Skipf("the authoritative server on %s answers neither transport (%v), so nothing about "+
			"the DNS path can be tested here", s.addr, s.unreachable)
	}

	// The record API, which is what lego's httpreq provider posts to.
	mux := http.NewServeMux()
	record := func(w http.ResponseWriter, r *http.Request, add bool) {
		var msg struct {
			FQDN  string `json:"fqdn"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&msg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if msg.FQDN == "" || msg.Value == "" {
			http.Error(w, "fqdn and value are required", http.StatusBadRequest)
			return
		}
		name := dns.Fqdn(msg.FQDN)
		if add {
			s.addTXT(name, msg.Value)
		} else {
			s.delTXT(name, msg.Value)
		}
		w.WriteHeader(http.StatusOK)
	}
	mux.HandleFunc("/present", func(w http.ResponseWriter, r *http.Request) { record(w, r, true) })
	mux.HandleFunc("/cleanup", func(w http.ResponseWriter, r *http.Request) { record(w, r, false) })
	mux.HandleFunc("/records", func(w http.ResponseWriter, _ *http.Request) {
		live, peak := s.snapshot()
		_ = json.NewEncoder(w).Encode(map[string]any{"live": live, "peak": peak})
	})

	apiLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.apiAt = "http://" + apiLn.Addr().String()
	s.api = &http.Server{Handler: mux}
	go func() { _ = s.api.Serve(apiLn) }()

	t.Cleanup(func() {
		_ = s.api.Close()
		_ = s.udp.Shutdown()
		_ = s.tcp.Shutdown()
	})
	return s
}

// ── what actually left this process ──────────────────────────────────────────────────

// apiTrace records the ACME requests Manager really sent, and passes every one of them through
// unchanged: each call reaches the real server over the real client, and each response comes
// back byte for byte (the renewalInfo body it has to read is replayed to the caller).
//
// It exists because two of the properties below cannot be read off the signed certificate:
//
//   - "the profile name reached the CA": pebble picks a profile at RANDOM for an order that
//     carries none -- `profileName = profNames[rand.Intn(len(profiles))]` (wfe.go:1767) -- so a
//     plumbing bug that dropped the name would show up as the wrong lifetime only two runs in
//     three. The recorded newOrder arguments turn that into a certainty instead of a coin toss.
//   - "this pass really consulted ARI": the window the CA suggests is what decides when the
//     renewal runs, and a successful download clears ARIWindowStart/End and ARICheckedAt for the
//     next cycle (manager_done.go:228-231), so the state left behind cannot show that the pass
//     asked. The recorded renewalInfo exchange can.
//
// It is observation only: nothing here decides anything, and the Manager's behaviour is
// identical to a run without it.
type apiTrace struct {
	API

	mu sync.Mutex
	tr traced
}

// traced is everything one pass asked the CA for, as it left this process.
type traced struct {
	orders   []tracedOrder
	ari      []tracedARI
	authzs   []tracedAuthz
	accepted []string
}

// tracedOrder is one newOrder request as it left this process.
type tracedOrder struct {
	domains  []string
	profile  string
	replaces string
}

// tracedARI is one renewalInfo exchange: the certID asked about, and the body the CA returned.
type tracedARI struct {
	certID string
	body   string
	err    error
}

// tracedAuthz is one authorization the CA returned, with the status it was in at that moment.
// A "valid" authorization is one the CA kept from an earlier order for the same account and
// identifier (RFC 8555 §7.5.2), which is the difference between a pass that has to solve a
// challenge for a name and one that does not.
//
// Every read is recorded, in order: the polling loop reads the same authorization again as it
// turns valid, and the caller has to look at the first read alone to know what the pass decided.
type tracedAuthz struct {
	identifier string
	status     string
}

func (a *apiTrace) NewOrder(domains []string, opts *api.OrderOptions) (legoacme.ExtendedOrder, error) {
	t := tracedOrder{domains: append([]string(nil), domains...)}
	if opts != nil {
		t.profile, t.replaces = opts.Profile, opts.ReplacesCertID
	}
	a.mu.Lock()
	a.tr.orders = append(a.tr.orders, t)
	a.mu.Unlock()
	return a.API.NewOrder(domains, opts)
}

func (a *apiTrace) GetAuthorization(authzURL string) (legoacme.Authorization, error) {
	authz, err := a.API.GetAuthorization(authzURL)
	if err == nil {
		a.mu.Lock()
		a.tr.authzs = append(a.tr.authzs, tracedAuthz{identifier: authz.Identifier.Value, status: authz.Status})
		a.mu.Unlock()
	}
	return authz, err
}

func (a *apiTrace) GetRenewalInfo(certID string) (*http.Response, error) {
	resp, err := a.API.GetRenewalInfo(certID)
	if err != nil {
		a.recordARI(tracedARI{certID: certID, err: err})
		return resp, err
	}
	// Read the body, then hand the same bytes on: a recorder that consumed them would change
	// the code path it is watching.
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	a.recordARI(tracedARI{certID: certID, body: string(body), err: readErr})
	return resp, nil
}

// AcceptChallenge is recorded because it answers "did this pass have to solve a challenge at
// all": a CA that reuses a still-valid authorization returns the order already authorized, so
// no challenge is ever accepted and nothing is written to DNS.
func (a *apiTrace) AcceptChallenge(challengeURL string) error {
	a.mu.Lock()
	a.tr.accepted = append(a.tr.accepted, challengeURL)
	a.mu.Unlock()
	return a.API.AcceptChallenge(challengeURL)
}

func (a *apiTrace) recordARI(t tracedARI) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tr.ari = append(a.tr.ari, t)
}

// reset forgets everything recorded so far, so the next snapshot describes one pass.
func (a *apiTrace) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tr = traced{}
}

// snapshot returns what has been recorded since the last reset.
func (a *apiTrace) snapshot() traced {
	a.mu.Lock()
	defer a.mu.Unlock()
	return traced{
		orders:   append([]tracedOrder(nil), a.tr.orders...),
		ari:      append([]tracedARI(nil), a.tr.ari...),
		authzs:   append([]tracedAuthz(nil), a.tr.authzs...),
		accepted: append([]string(nil), a.tr.accepted...),
	}
}

// ── the run ──────────────────────────────────────────────────────────────────────────

// e2eCase is one scenario's result, and the shape the HTML report renders.
type e2eCase struct {
	Name     string        `json:"name"`
	What     string        `json:"what"`
	Verdict  string        `json:"verdict"`
	Evidence []string      `json:"evidence,omitempty"`
	Failure  string        `json:"failure,omitempty"`
	Duration time.Duration `json:"duration_ns"`
}

type e2eReport struct {
	Started    time.Time `json:"started"`
	Finished   time.Time `json:"finished"`
	Cases      []e2eCase `json:"cases"`
	NotRun     []e2eCase `json:"not_run"`
	DNSQueries []string  `json:"dns_queries"`
	// ValidationNote explains the CA-validation mode in prose; Versions carries the short form.
	ValidationNote string            `json:"validation_note"`
	PeakTXT        map[string]int    `json:"peak_txt"`
	Versions       map[string]string `json:"versions"`
}

// runCase executes one scenario, recording the verdict rather than aborting the run: a report
// that stops at the first failure hides the four cases behind it.
func (r *e2eReport) runCase(t *testing.T, name, what string, fn func(t *testing.T, ev *[]string)) {
	t.Helper()
	start := time.Now()
	c := e2eCase{Name: name, What: what}

	// A subtest so a failure is contained, but the verdict is copied out afterwards.
	ok := t.Run(name, func(t *testing.T) {
		var ev []string
		defer func() { c.Evidence = ev }()
		fn(t, &ev)
	})
	c.Duration = time.Since(start)
	if ok {
		c.Verdict = "pass"
	} else {
		c.Verdict = "fail"
	}
	r.Cases = append(r.Cases, c)
}

// TestRealDNS01Lifecycle is the suite: every scenario below shares one pebble, one authoritative
// DNS server and one state database, because that is what a deployment looks like.
func TestRealDNS01Lifecycle(t *testing.T) {
	dnsSrv := startAuthDNS(t)

	// Real validation needs the validator to reach the authority, and pebble reaches it over TCP
	// whenever a custom resolver is configured (va.go: `if customResolverAddr != "" {
	// va.dnsClient.Net = "tcp" }`). Where that transport is impossible the suite runs in a
	// degraded mode that still exercises everything on wecert's side -- the real solver writes
	// real records, the real propagation check reads them over UDP, the real order and CSR go to
	// the CA -- and says so in the report rather than implying validation happened.
	validate := dnsSrv.transportWorks("tcp")
	dirURL, client := startPebbleRealValidation(t, dnsSrv.addr, validate)

	// Two strings, because they answer different questions: a short form for the table, and the
	// reasoning for the note under it. Putting the paragraph in both made the report repeat
	// itself.
	validationMode := "real validation: the CA read the challenge record from the authority itself"
	validationNote := "pebble was started with -dnsserver pointing at the test authority and without " +
		"PEBBLE_VA_ALWAYS_VALID, so the certificate was only issued after the CA's own validator " +
		"fetched the TXT record over the wire."
	if !validate {
		validationMode = "validation DEGRADED (the CA did not read the record)"
		validationNote = "pebble's validator forces TCP whenever a custom resolver is configured " +
			"(va.go: if customResolverAddr is non-empty, va.dnsClient.Net = \"tcp\"), and this host " +
			"cannot carry TCP on port 53: the bind succeeds and the traffic never arrives (" +
			strings.Join(dnsSrv.unreachable, "; ") + "). So the CA accepted the challenges without " +
			"reading them, and PEBBLE_VA_ALWAYS_VALID was set for this run. Everything on wecert's " +
			"side is still real -- the solver wrote the records through a real lego provider, and " +
			"the production propagation check read them back over UDP, which the per-case evidence " +
			"below shows -- but \"the CA validated the record\" is NOT one of the things this run " +
			"proves. On a host where TCP/53 works (Linux with CAP_NET_BIND_SERVICE, for example " +
			"docker run --cap-add=NET_BIND_SERVICE) the same suite runs with real validation and " +
			"the report says so."
	}
	t.Logf("pebble %s; validation: %s", dirURL, validationMode)

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{}
	cfg.ACME.Directory = dirURL
	cfg.ACME.Email = "e2e@example.test"

	core, err := EnsureAccount(cfg, store, client)
	if err != nil {
		t.Fatalf("register an account against a real ACME server: %v", err)
	}

	// The DNS configuration under test: lego's httpreq provider, pointed at the test authority's
	// record API. `t.Setenv` so the provider picks it up the way a real deployment's environment
	// would carry CLOUDFLARE_DNS_API_TOKEN.
	t.Setenv("HTTPREQ_ENDPOINT", dnsSrv.apiAt)

	mkSolver := func(t *testing.T) *DNSSolver {
		t.Helper()
		solver, err := NewDNSSolver(config.DNS{
			Provider:             config.DNSProviderLego,
			LegoProvider:         "httpreq",
			RecursiveNameservers: []string{"127.0.0.1:53"},
			Propagation:          60 * time.Second,
			Polling:              2 * time.Second,
		}, config.Tencent{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatalf("build the real solver: %v", err)
		}
		return solver
	}

	newCfgCert := func(name string, domains []string) *config.Certificate {
		certs := []config.Certificate{{
			Name: name, Domains: domains,
			Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256,
		}}
		if err := config.NormalizeCertificates(certs); err != nil {
			t.Fatal(err)
		}
		return &certs[0]
	}

	// newTLSServerCert is the same for the 45-day tlsserver profile. renewBefore is an argument
	// because the renewal case needs the profile's own default (empty means "leave it alone")
	// and, in one place, a value that puts the local fallback far away from the ARI window.
	newTLSServerCert := func(name string, domains []string, renewBefore string) *config.Certificate {
		certs := []config.Certificate{{
			Name: name, Domains: domains, RenewBefore: renewBefore,
			Profile: config.ProfileTLSServer, KeyType: config.KeyTypeECDSAP256,
		}}
		if err := config.NormalizeCertificates(certs); err != nil {
			t.Fatal(err)
		}
		return &certs[0]
	}

	mkManager := func(t *testing.T) *Manager {
		t.Helper()
		return newManager(store, NewAPI(core), mkSolver(t), core, deploy.Noop{},
			slog.New(slog.NewTextHandler(io.Discard, nil)))
	}

	rep := &e2eReport{
		Started:        time.Now(),
		ValidationNote: validationNote,
		Versions: map[string]string{
			"acme_server":  "pebble, " + validationMode,
			"transports":   "authority answered over " + strings.Join(dnsSrv.reachable, ",") + "; tcp: " + strings.Join(dnsSrv.unreachable, "; "),
			"dns":          "authoritative test server on 127.0.0.1:53",
			"dns_provider": "lego httpreq -> the test authority's /present, /cleanup",
			"deploy":       "disabled (deploy.Noop): no Tencent Cloud credentials in a test environment",
		},
	}

	domains := []string{"a." + testZoneName, "b." + testZoneName}
	cert := newCfgCert("e2e-basic", domains)

	// ── case 1: first issuance, with the CA really reading the record ────────────────
	rep.runCase(t, "issue-over-real-validation",
		"Place an order, write the challenge records through the real solver, wait for the real propagation check, and let a real ACME server validate them over DNS and sign the certificate.",
		func(t *testing.T, ev *[]string) {
			m := mkManager(t)
			if err := m.Reconcile(context.Background(), cert); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			st, err := store.GetCert(cert.Name)
			if err != nil || st == nil || st.NotAfter.IsZero() {
				t.Fatalf("no certificate was recorded: %v %+v", err, st)
			}
			leaf, err := ParseLeaf(st.CertPEM)
			if err != nil {
				t.Fatalf("the downloaded chain does not parse: %v", err)
			}
			if err := VerifyCoverage(leaf, domains); err != nil {
				t.Errorf("the issued certificate does not cover the requested names: %v", err)
			}
			if err := VerifyKeyMatch(leaf, st.KeyPEM); err != nil {
				t.Errorf("the certificate does not belong to the stored key: %v", err)
			}
			if leaf.Issuer.CommonName == "" {
				t.Error("the leaf has no issuer, so it is not a real chain")
			}
			// Two separate facts, because only one of them holds in every environment.
			//
			// (a) wecert's own propagation check really read the record back from the authority
			//     over UDP. This is the production code path and it must hold wherever the suite
			//     runs at all -- a pass cannot succeed without it.
			// (b) with real validation, the CA's validator read it too, over TCP.
			for _, d := range domains {
				name := "_acme-challenge." + d
				if !dnsSrv.sawTXTFor(name) {
					t.Errorf("nothing ever queried %s, so the pass cannot have waited for the "+
						"record to appear", name)
				}
				*ev = append(*ev, "propagation probe queried TXT "+name+" over UDP")
				if validate {
					if !dnsSrv.sawTXTForOver(name, "tcp") {
						t.Errorf("the CA's validator never queried %s (no TCP question in the "+
							"authority's log), so validation was not real after all", name)
					}
					*ev = append(*ev, "the CA's validator queried TXT "+name+" over TCP")
				}
			}
			live, _ := dnsSrv.snapshot()
			if len(live) != 0 {
				t.Errorf("challenge records were left behind: %v", live)
			}
			if o, _ := store.GetOrder(cert.Name); o != nil {
				t.Errorf("the order was left behind after a successful issuance: %+v", o)
			}
			*ev = append(*ev,
				fmt.Sprintf("issued %s..%s, %d SAN(s)", leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339), len(leaf.DNSNames)),
				fmt.Sprintf("issuer %q", leaf.Issuer.CommonName),
				"challenge records cleaned up: none left in the zone")
		})

	// ── case 2: a second pass must not place a second order ─────────────────────────
	rep.runCase(t, "second-pass-places-no-order",
		"Reconcile again immediately: a fresh certificate must not be reissued, and the ARI window must have been recorded so the next renewal is CA-coordinated.",
		func(t *testing.T, ev *[]string) {
			before, _ := store.GetCert(cert.Name)
			m := mkManager(t)
			if err := m.Reconcile(context.Background(), cert); err != nil {
				t.Fatalf("second Reconcile: %v", err)
			}
			after, _ := store.GetCert(cert.Name)
			if !after.NotAfter.Equal(before.NotAfter) {
				t.Errorf("the certificate was reissued on a pass that had nothing to do: "+
					"notAfter moved from %s to %s", before.NotAfter, after.NotAfter)
			}
			if after.ARICheckedAt.IsZero() {
				t.Error("no ARI lookup was recorded, so the renewal is not CA-coordinated")
			}
			if o, _ := store.GetOrder(cert.Name); o != nil {
				t.Errorf("an order was left in flight with nothing to do: %+v", o)
			}
			*ev = append(*ev,
				"notAfter unchanged: "+after.NotAfter.Format(time.RFC3339),
				"ARI window recorded at "+after.ARICheckedAt.Format(time.RFC3339))
		})

	// ── case 3: adding a domain reissues immediately ────────────────────────────────
	rep.runCase(t, "domain-drift-reissues",
		"Add a name to the certificate and reconcile: the SAN set is the desired state, so it must reissue at once instead of waiting for the renewal window.",
		func(t *testing.T, ev *[]string) {
			before, _ := store.GetCert(cert.Name)
			grown := newCfgCert("e2e-basic", append(append([]string(nil), domains...), "c."+testZoneName))
			m := mkManager(t)
			if err := m.Reconcile(context.Background(), grown); err != nil {
				t.Fatalf("Reconcile after adding a domain: %v", err)
			}
			after, _ := store.GetCert(cert.Name)
			if after.NotAfter.Equal(before.NotAfter) {
				t.Fatal("the certificate was not reissued after its domain set changed")
			}
			leaf, err := ParseLeaf(after.CertPEM)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyCoverage(leaf, grown.Domains); err != nil {
				t.Errorf("the reissued certificate does not cover the new set: %v", err)
			}
			*ev = append(*ev, "reissued for "+strings.Join(grown.Domains, ", "))
		})

	// ── case 4: wildcard and apex share one TXT name ────────────────────────────────
	rep.runCase(t, "wildcard-and-apex-share-one-name",
		"A wildcard and its apex hash to the same _acme-challenge name, so both values must be up at the same time: write all, verify all, and only then let the CA validate.",
		func(t *testing.T, ev *[]string) {
			wcert := newCfgCert("e2e-wildcard", []string{testZoneName, "*." + testZoneName})
			m := mkManager(t)
			if err := m.Reconcile(context.Background(), wcert); err != nil {
				t.Fatalf("Reconcile for apex+wildcard: %v", err)
			}
			shared := "_acme-challenge." + testZone
			_, peak := dnsSrv.snapshot()
			if peak[shared] < 2 {
				t.Errorf("%s never held both values at once (peak %d), so the apex and the "+
					"wildcard were not presented together; one of them would have failed "+
					"validation", shared, peak[shared])
			}
			st, _ := store.GetCert(wcert.Name)
			if st == nil {
				t.Fatal("no certificate recorded for the wildcard case")
			}
			leaf, err := ParseLeaf(st.CertPEM)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyCoverage(leaf, wcert.Domains); err != nil {
				t.Errorf("the issued certificate does not cover apex+wildcard: %v", err)
			}
			live, _ := dnsSrv.snapshot()
			if len(live) != 0 {
				t.Errorf("challenge records were left behind: %v", live)
			}
			*ev = append(*ev,
				fmt.Sprintf("%s held %d values simultaneously", shared, peak[shared]),
				"issued for "+strings.Join(wcert.Domains, ", "))
		})

	// ── case 5: the profile name reaches the CA, and is honoured ────────────────────
	//
	// The profile is what decides how long a certificate lives, how many names it may carry
	// and how far ahead of expiry renewal begins, and on the CA's side all of that is keyed by
	// the name wecert puts in the new-order request. If that name were dropped in the plumbing,
	// nothing would error: the order would simply be issued under some other profile. So the
	// claim is split into its two halves -- the request carried the name verbatim, and the
	// certificate that came back lives exactly the period this suite's pebble configures for
	// "tlsserver" (3888000s), not the classic profile's 7776000s.
	//
	// The first half is checked on the recorded request rather than on the lifetime alone,
	// because pebble picks a profile at random when the order carries none (see apiTrace): a
	// dropped name would come back as a wrong lifetime only two runs in three.
	rep.runCase(t, "tlsserver-profile-issuance",
		"Issue under the tlsserver profile: the new-order request must carry the profile name verbatim, and the certificate must come back with that profile's 45-day validity instead of the 90-day classic default.",
		func(t *testing.T, ev *[]string) {
			// The same numbers the pebble config in pebble_integration_test.go gives the three
			// profiles; the tlsserver one is what this case is about.
			const tlsserverValiditySeconds = 3888000

			pdomains := []string{"p1." + testZoneName, "p2." + testZoneName}
			pcert := newTLSServerCert("e2e-profile", pdomains, "")

			m := mkManager(t)
			trace := &apiTrace{API: m.core}
			m.core = trace

			if err := m.Reconcile(context.Background(), pcert); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}
			st, err := store.GetCert(pcert.Name)
			if err != nil || st == nil || st.NotAfter.IsZero() {
				t.Fatalf("no certificate was recorded: %v %+v", err, st)
			}
			leaf, err := ParseLeaf(st.CertPEM)
			if err != nil {
				t.Fatalf("the downloaded chain does not parse: %v", err)
			}
			if err := VerifyCoverage(leaf, pdomains); err != nil {
				t.Errorf("the issued certificate does not cover the requested names: %v", err)
			}
			if err := VerifyKeyMatch(leaf, st.KeyPEM); err != nil {
				t.Errorf("the certificate does not belong to the stored key: %v", err)
			}

			// Half one: the name left this process verbatim.
			seen := trace.snapshot()
			if len(seen.orders) != 1 {
				t.Fatalf("the issuance placed %d orders, want exactly 1", len(seen.orders))
			}
			if seen.orders[0].profile != config.ProfileTLSServer {
				t.Errorf("the new-order request carried profile %q, not %q, so whatever profile the CA applied it was not the one this certificate asked for",
					seen.orders[0].profile, config.ProfileTLSServer)
			}
			// Both names are new to this CA, so both authorizations had to be validated: this is
			// what says the certificate below came from a real DNS-01 order rather than from an
			// authorization the CA happened to still consider valid.
			if len(seen.accepted) != len(pdomains) {
				t.Errorf("the issuance accepted %d challenges for %d names", len(seen.accepted), len(pdomains))
			}

			// Half two: the CA honoured it, which is visible as the certificate's own lifetime.
			want := time.Duration(tlsserverValiditySeconds) * time.Second
			got := leaf.NotAfter.Sub(leaf.NotBefore)
			// pebble computes notAfter = notBefore + (validityPeriod-1)s (ca.go:296), so the
			// exact span is one second short of the configured 3888000s. The tolerance is a
			// minute: it absorbs that arithmetic without coming anywhere near the tens of days
			// that separate this profile from classic (90d) or shortlived (6d).
			if d := got - want; d > time.Minute || d < -time.Minute {
				t.Errorf("the certificate lives %s, not the tlsserver profile's %s (pebble's validityPeriod is %ds): "+
					"the CA issued it under a different profile",
					got.Round(time.Second), want, tlsserverValiditySeconds)
			}

			// For the report only: the same CA, in the same run, issued the classic certificate
			// that much longer, which is the comparison that makes "45 days" mean something.
			if bst, _ := store.GetCert("e2e-basic"); bst != nil {
				if bleaf, berr := ParseLeaf(bst.CertPEM); berr == nil {
					*ev = append(*ev, fmt.Sprintf("same CA, same run: the classic certificate e2e-basic lives %s against this one's %s",
						bleaf.NotAfter.Sub(bleaf.NotBefore).Round(time.Second), got.Round(time.Second)))
				}
			}

			if o, _ := store.GetOrder(pcert.Name); o != nil {
				t.Errorf("the order was left behind after a successful issuance: %+v", o)
			}
			live, _ := dnsSrv.snapshot()
			if len(live) != 0 {
				t.Errorf("challenge records were left behind: %v", live)
			}
			*ev = append(*ev,
				fmt.Sprintf("the new-order request carried profile %q verbatim", seen.orders[0].profile),
				fmt.Sprintf("issued validity %s (%s..%s) against the configured validityPeriod of %ds",
					got.Round(time.Second),
					leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339),
					tlsserverValiditySeconds),
				fmt.Sprintf("issuer %q, %d SAN(s), key matched to the stored private key", leaf.Issuer.CommonName, len(leaf.DNSNames)),
				"challenge records cleaned up: none left in the zone")
		})

	// ── case 6: a complete renewal cycle, with nobody watching ──────────────────────
	//
	// What decides WHEN a wecert instance renews is the CA's own renewal window: renewalDecision
	// reads renewalInfo first and only falls back to notAfter-renewBefore when ARI is
	// unavailable (manager_renew.go:33-78), and the instant it picks inside that window is
	// deterministic (RenewalTime). So this case does not push the clock forward in the hope of
	// crossing a threshold; it sets the clock to the instant the CA's window implies, which is
	// the same instant the manager computes for itself.
	//
	// renewBefore is 24h for one reason: the local fallback then sits at notAfter-24h plus its
	// jitter, while the CA's window ends at notAfter-(validity/3)+24h -- notAfter-14d for this
	// profile -- so the two candidate instants are at least thirteen days apart and a renewal
	// that happens a fortnight before expiry cannot be the fallback rule firing. Without that
	// the two rules point at roughly the same fortnight, by design, since both renew at about
	// two thirds of the lifetime, and the case could not tell which one renewed. The premise is
	// asserted below rather than assumed.
	rep.runCase(t, "automatic-renewal-of-a-tlsserver-certificate",
		"Issue a tlsserver certificate, let one pass record the CA's ARI window, then move the clock to the instant that window implies and reconcile ONCE: the pass alone must place the order, validate over the test authority, promote the replacement and clean up after itself.",
		func(t *testing.T, ev *[]string) {
			ctx := context.Background()
			rdomains := []string{"r1." + testZoneName, "r2." + testZoneName}
			rcert := newTLSServerCert("e2e-renewal", rdomains, "24h")

			// One manager for the whole case: SetNow moves this manager's clock, so the pass that
			// renews has to be run by the same instance.
			m := mkManager(t)
			trace := &apiTrace{API: m.core}
			m.core = trace

			// (a) issue it, and (b) record what is live now.
			if err := m.Reconcile(ctx, rcert); err != nil {
				t.Fatalf("the first Reconcile (issuance): %v", err)
			}
			before, err := store.GetCert(rcert.Name)
			if err != nil || before == nil || before.NotAfter.IsZero() {
				t.Fatalf("no certificate was recorded: %v %+v", err, before)
			}
			beforeLeaf, err := ParseLeaf(before.CertPEM)
			if err != nil {
				t.Fatalf("the issued chain does not parse: %v", err)
			}
			if err := VerifyCoverage(beforeLeaf, rdomains); err != nil {
				t.Errorf("the issued certificate does not cover the requested names: %v", err)
			}
			if err := VerifyKeyMatch(beforeLeaf, before.KeyPEM); err != nil {
				t.Errorf("the certificate does not belong to the stored key: %v", err)
			}
			// The certID is what the renewal's `replaces` is built from; without it there is no
			// ARI coordination for this case to test at all.
			if before.ARICertID == "" {
				t.Fatalf("the issued certificate has no ARI certID, so this renewal could never be CA-coordinated")
			}

			// (c) one pass inside the validity period: it must decide to wait, and it must
			// record the window it is waiting for. That window is read back from the state the
			// production code wrote -- not from a private ARI call made here -- so the clock
			// below is derived from exactly what the renewal pass will see.
			trace.reset()
			if err := m.Reconcile(ctx, rcert); err != nil {
				t.Fatalf("the pass inside the validity period: %v", err)
			}
			st, err := store.GetCert(rcert.Name)
			if err != nil || st == nil {
				t.Fatalf("the certificate state disappeared: %v %+v", err, st)
			}
			if !st.NotAfter.Equal(before.NotAfter) {
				t.Errorf("a pass with %s of validity left renewed the certificate (notAfter %s -> %s): the CA's window is not being waited for",
					st.NotAfter.Sub(m.now()).Round(time.Hour), before.NotAfter, st.NotAfter)
			}
			if st.ARICheckedAt.IsZero() {
				t.Error("the pass recorded no ARI lookup (ARICheckedAt is still zero), so the renewal would not be CA-coordinated")
			}
			if st.ARIWindowStart.IsZero() || !st.ARIWindowEnd.After(st.ARIWindowStart) {
				t.Fatalf("the CA's suggested window was not recorded (start=%s end=%s): with no ARI instant to renew at, the clock below would be a guess",
					st.ARIWindowStart, st.ARIWindowEnd)
			}
			if seen := trace.snapshot(); len(seen.ari) != 1 {
				t.Errorf("the pass made %d renewalInfo lookups, want exactly 1", len(seen.ari))
			}

			// The instant inside the CA's window. RenewalTime is the manager's own function, so
			// this is the same answer the renewal pass will reach for itself.
			renewAt := RenewalTime(rcert.Name, st.ARIWindowStart, st.ARIWindowEnd)
			fallbackAt := DeterministicTime(rcert.Name, st.NotAfter.Add(-rcert.RenewBeforeDur), rcert.RenewBeforeDur/8)

			// Three guards on this case's own premise. If any of them fails the run could not
			// tell ARI from the local rule, and the case would prove nothing -- so it fails
			// loudly here rather than reporting a pass it did not earn.
			if renewAt.Before(st.ARIWindowStart) || renewAt.After(st.ARIWindowEnd) {
				t.Fatalf("the renewal instant %s is outside the CA's window [%s .. %s]", renewAt, st.ARIWindowStart, st.ARIWindowEnd)
			}
			if !renewAt.Before(st.NotAfter) {
				t.Fatalf("the renewal instant %s is not before the certificate's expiry %s: this clock would be set past expiry", renewAt, st.NotAfter)
			}
			if !renewAt.Before(fallbackAt) {
				t.Fatalf("the renewal instant %s is not before the local fallback instant %s, so a renewal here would not prove the CA's window decided it",
					renewAt, fallbackAt)
			}

			// (d) the renewal itself: clock to that instant, then ONE pass. Nothing else happens
			// in between -- no second Reconcile, no order placed by hand, no re-run.
			m.SetNow(func() time.Time { return renewAt })
			trace.reset()
			dnsMark := dnsSrv.mutationCount()
			if err := m.Reconcile(ctx, rcert); err != nil {
				t.Fatalf("the renewal pass: %v", err)
			}

			after, err := store.GetCert(rcert.Name)
			if err != nil || after == nil || after.NotAfter.IsZero() {
				t.Fatalf("no certificate is recorded after the renewal pass: %v %+v", err, after)
			}
			afterLeaf, err := ParseLeaf(after.CertPEM)
			if err != nil {
				t.Fatalf("the renewed chain does not parse: %v", err)
			}

			// The live certificate changed, and still covers the same names.
			if afterLeaf.SerialNumber.Cmp(beforeLeaf.SerialNumber) == 0 {
				t.Errorf("the live certificate is still the one this case issued (serial %s): the renewal pass did not renew",
					beforeLeaf.SerialNumber)
			}
			if afterLeaf.NotAfter.Before(beforeLeaf.NotAfter) {
				t.Errorf("the renewal's notAfter (%s) is earlier than the certificate it replaced (%s)",
					afterLeaf.NotAfter, beforeLeaf.NotAfter)
			}
			if err := VerifyCoverage(afterLeaf, rdomains); err != nil {
				t.Errorf("the renewed certificate does not cover the same names: %v", err)
			}
			if drifted, detail := CoverageDrift(afterLeaf, rdomains); drifted {
				t.Errorf("the renewed certificate's SAN set is not the configured one: %s", detail)
			}
			if err := VerifyKeyMatch(afterLeaf, after.KeyPEM); err != nil {
				t.Errorf("the renewed certificate does not belong to the key recorded with it: %v", err)
			}
			if span := afterLeaf.NotAfter.Sub(afterLeaf.NotBefore); span < 45*24*time.Hour-time.Minute || span > 45*24*time.Hour+time.Minute {
				t.Errorf("the renewal was issued under a different profile: it lives %s, not the tlsserver profile's 45 days",
					span.Round(time.Second))
			}

			// The renewal pass itself, from the requests it sent: it re-read the CA's window
			// (the one on file was stale by weeks) and placed exactly one order, carrying the ARI
			// `replaces` value of the certificate it supersedes.
			seen := trace.snapshot()
			if len(seen.ari) != 1 {
				t.Errorf("the renewal pass made %d renewalInfo lookups, want exactly 1: a stored window that stale has to be re-read, or the renewal runs on old advice",
					len(seen.ari))
			} else {
				var info RenewalInfo
				if err := json.Unmarshal([]byte(seen.ari[0].body), &info); err != nil {
					t.Errorf("the renewalInfo response does not parse (%v): %s", err, seen.ari[0].body)
				} else if !info.SuggestedWindow.Start.Equal(st.ARIWindowStart) || !info.SuggestedWindow.End.Equal(st.ARIWindowEnd) {
					t.Errorf("the renewal pass was given window [%s .. %s] but the clock was set from [%s .. %s]",
						info.SuggestedWindow.Start, info.SuggestedWindow.End, st.ARIWindowStart, st.ARIWindowEnd)
				}
			}
			if len(seen.orders) != 1 {
				t.Errorf("the renewal pass placed %d orders, want exactly 1", len(seen.orders))
			} else {
				if seen.orders[0].profile != config.ProfileTLSServer {
					t.Errorf("the renewal order carried profile %q, not %q", seen.orders[0].profile, config.ProfileTLSServer)
				}
				if seen.orders[0].replaces != before.ARICertID {
					t.Errorf("the renewal order carried replaces=%q instead of the live certificate's ARI certID %q: without it the renewal loses the ARI rate-limit exemption",
						seen.orders[0].replaces, before.ARICertID)
				}
			}

			// Reclamation, which with deploy disabled can only be empty, and the honest
			// assertion is that it is.
			//
			// The reclaim record is written only for a certificate that was actually serving a
			// cloud resource: download computes
			//
			//	retireOld := rebound && oldDeployedID != "" && oldDeployedID != deployedID
			//
			// (manager_done.go:285) and `rebound` is only set when Deploy.Enabled. This suite
			// runs deploy.Noop with deploy disabled, so DeployedCertID is empty for both
			// issuances, oldDeployedID is empty, and nothing is queued. That is not a gap in the
			// case: reclaiming exists to free Tencent Cloud certificate quota, and there is no
			// cloud certificate here -- the outgoing one existed only in state.db, where the
			// renewal overwrites it. So "the old certificate is in the reclaim queue" would be an
			// invented property; what is asserted instead is that no cloud certificate was ever
			// claimed and no phantom reclamation was queued.
			//
			// time.Now() rather than m.now(): RetiredAt is stamped with the wall clock by the
			// store (state.go:1309), while m.now() is this case's advanced clock. The cutoff is
			// in the real future either way, so the list is everything that exists.
			retired, err := store.ListRetiredCertsBefore(time.Now().Add(24 * time.Hour))
			if err != nil {
				t.Fatalf("list the reclaim queue: %v", err)
			}
			if len(retired) != 0 {
				t.Errorf("something was queued for reclamation although no certificate was ever uploaded to a cloud: %+v", retired)
			}
			if after.DeployedCertID != "" || after.DeployConfirmed {
				t.Errorf("a renewal with deploy disabled claims a cloud certificate: deployedCertId=%q deployConfirmed=%v",
					after.DeployedCertID, after.DeployConfirmed)
			}

			if o, _ := store.GetOrder(rcert.Name); o != nil {
				t.Errorf("the renewal left an order in flight: %+v", o)
			}

			// The challenge records this renewal wrote, and cleaned up again.
			//
			// Counted from the provider API's mutation log rather than from the peak value
			// count, because the issuance already wrote these same names: a peak cannot rise
			// twice. And counted per name, because "the renewal wrote a record" and "the zone is
			// clean" are different facts, and a run that only proved the second would pass even
			// if the solver had never run.
			//
			// Whether a given name needs a challenge at all is the CA's choice, not the test's:
			// a CA may answer an order with an authorization it still considers valid
			// (RFC 8555 §7.5.2), and for that name the order is already authorized, so no
			// challenge is accepted and there is nothing to write. pebble rolls that per
			// identifier -- see PEBBLE_AUTHZREUSE in pebble_integration_test.go, which this suite
			// pins to "fresh authorization" so that solving a challenge is the normal path.
			// Both outcomes are correct, so the assertions follow the authorizations the CA
			// actually returned instead of demanding the one shape that was hoped for.
			//
			// Which names the CA considered already authorized when this pass first looked.
			//
			// The first read per identifier is the one that decided whether a challenge had to
			// be solved; the polling loop reads the same authorization again as it turns valid,
			// and that later "valid" says nothing about what this pass had to do.
			firstRead := map[string]string{}
			for _, az := range seen.authzs {
				ident := strings.ToLower(az.identifier)
				if _, ok := firstRead[ident]; !ok {
					firstRead[ident] = az.status
				}
			}
			reused := map[string]bool{}
			for ident, status := range firstRead {
				if status == "valid" {
					reused[ident] = true
				}
			}
			// An order that comes back already authorized makes wecert skip the authorization
			// reads altogether, so "no authorization was read" says the same thing as "every
			// authorization was still valid".
			allReused := len(firstRead) == 0
			isReused := func(d string) bool { return allReused || reused[strings.ToLower(d)] }

			muts := dnsSrv.mutationsSince(dnsMark)
			var added, deleted, reusedCount int
			for _, d := range rdomains {
				name := dns.Fqdn("_acme-challenge." + d)
				var writes, deletes int
				for _, mu := range muts {
					if mu.name != name {
						continue
					}
					if mu.add {
						writes++
					} else {
						deletes++
					}
				}

				if isReused(d) {
					reusedCount++
					if writes != 0 {
						t.Errorf("the CA still had a valid authorization for %s, so this renewal had nothing to solve for it, yet %d record(s) were written at %s",
							d, writes, name)
					}
					continue
				}
				// Not reused: the CA issued a fresh authorization, so this pass had to solve it,
				// and the record had to exist before the CA would look and be gone afterwards.
				if writes == 0 {
					t.Errorf("the renewal accepted a challenge for %s but never wrote its record, so nothing could have validated it", name)
				}
				if deletes == 0 {
					t.Errorf("the renewal never cleaned up %s: the record was written and left in the zone", name)
				}
				added, deleted = added+writes, deleted+deletes
			}
			if want := len(rdomains) - reusedCount; len(seen.accepted) != want {
				t.Errorf("the renewal accepted %d challenges but %d of %d authorizations were fresh (the rest were reused)",
					len(seen.accepted), want, len(rdomains))
			}
			live, _ := dnsSrv.snapshot()
			if len(live) != 0 {
				t.Errorf("challenge records were left behind: %v", live)
			}
			dnsEvidence := fmt.Sprintf("the renewal solved %d of %d names over the test authority (%d record write(s), %d delete(s))",
				len(seen.accepted), len(rdomains), added, deleted)
			if reusedCount > 0 {
				dnsEvidence += fmt.Sprintf("; the other %d already had a valid authorization the CA reused, so nothing had to be written for them", reusedCount)
			}
			if len(live) == 0 {
				dnsEvidence += "; the zone's live record set is empty afterwards"
			}

			// The renewed certificate is bound into the ARI cycle for its own renewal. The
			// previous cycle's bookkeeping -- window, checked-at, retry-after -- was cleared at
			// the same moment (manager_done.go:228-231), which is exactly why the window this
			// case reasons about had to be read before the renewal rather than after it.
			wantARICertID, certIDErr := CertID(afterLeaf)
			if certIDErr != nil {
				t.Errorf("cannot build the renewed certificate's ARI certID: %v", certIDErr)
			} else if after.ARICertID != wantARICertID {
				t.Errorf("the renewed certificate's ARI certID is %q, want %q: its own renewal would look up the wrong certificate",
					after.ARICertID, wantARICertID)
			}

			*ev = append(*ev,
				fmt.Sprintf("issued serial %s, valid %s..%s",
					beforeLeaf.SerialNumber,
					beforeLeaf.NotBefore.UTC().Format(time.RFC3339), before.NotAfter.UTC().Format(time.RFC3339)),
				fmt.Sprintf("the pass inside the validity period recorded the CA's window %s..%s and did not renew",
					st.ARIWindowStart.UTC().Format(time.RFC3339), st.ARIWindowEnd.UTC().Format(time.RFC3339)),
				fmt.Sprintf("clock moved to %s, the deterministic instant inside that window (%.1f days before expiry), while the local fallback for renewBefore=%s was %s",
					renewAt.UTC().Format(time.RFC3339), st.NotAfter.Sub(renewAt).Hours()/24,
					rcert.RenewBeforeDur, fallbackAt.UTC().Format(time.RFC3339)),
				fmt.Sprintf("one Reconcile then renewed it: serial %s -> %s, notAfter %s -> %s, still %d names",
					beforeLeaf.SerialNumber, afterLeaf.SerialNumber,
					before.NotAfter.UTC().Format(time.RFC3339), after.NotAfter.UTC().Format(time.RFC3339), len(rdomains)),
				fmt.Sprintf("that pass read renewalInfo once and placed exactly 1 order, profile %q and replaces=%s",
					config.ProfileTLSServer, before.ARICertID),
				dnsEvidence,
				fmt.Sprintf("the outgoing certificate was not queued for reclamation: deploy is disabled, so no cloud certificate ID exists for it (deployedCertId=%q) and the retire branch cannot run",
					after.DeployedCertID),
				fmt.Sprintf("the renewed certificate's ARI certID %s is recorded for its own next renewal", after.ARICertID))
		})

	// ── case 7: revocation against a real CA ────────────────────────────────────────
	rep.runCase(t, "revocation-and-its-durable-retry",
		"Revoke a real certificate, then revoke it again: an accepted revocation clears the request, and a refused one must stay recorded so every later pass retries it.",
		func(t *testing.T, ev *[]string) {
			m := mkManager(t)
			if err := m.RequestRevocation(context.Background(), "e2e-wildcard", RevocationReasons["superseded"]); err != nil {
				t.Fatalf("the CA refused the first revocation: %v", err)
			}
			if n, err := m.PendingRevocations(); err != nil || n != 0 {
				t.Errorf("an accepted revocation must clear its request: pending=%d err=%v", n, err)
			}
			*ev = append(*ev, "first revocation: recorded in state.db, submitted, accepted, cleared")

			// The second one is the interesting one. RFC 8555 says revoking an already-revoked
			// certificate is an error, and this design's promise is that a refusal is never
			// allowed to make the request disappear -- otherwise the operator's decision is lost
			// with nothing to show for it. Either outcome is acceptable here as long as the two
			// halves agree: accepted and cleared, or refused and still recorded.
			err := m.RequestRevocation(context.Background(), "e2e-wildcard", RevocationReasons["superseded"])
			n, perr := m.PendingRevocations()
			if perr != nil {
				t.Fatal(perr)
			}
			switch {
			case err == nil && n == 0:
				*ev = append(*ev, "second revocation: the CA accepted it again, nothing left pending")
			case err != nil && n == 1:
				*ev = append(*ev, "second revocation: the CA refused it and the request is still "+
					"recorded for the next pass")
			default:
				t.Errorf("inconsistent state after a repeat revocation: err=%v pending=%d. "+
					"A refusal that clears the request loses the operator's decision; an "+
					"acceptance that leaves it pending would revoke forever on every pass", err, n)
			}
		})

	// ── the run's own evidence, for the report ──────────────────────────────────────
	live, peak := dnsSrv.snapshot()
	rep.PeakTXT = peak
	rep.NotRun = []e2eCase{
		{Name: "cloud-deploy-and-rebind", What: "Upload to Tencent Cloud SSL and rebind the CLB listener, then read the binding back from the API.", Verdict: "needs-credentials",
			Evidence: []string{"needs TENCENTCLOUD_SECRET_ID/KEY with the CAM policy in deploy/, plus a CLB and an HTTPS listener: scripts/run-stage-ab.sh"}},
		{Name: "lets-encrypt-staging-issuance", What: "The same lifecycle against Let's Encrypt staging with a real DNSPod or Tencent Cloud DNS zone.", Verdict: "needs-credentials",
			Evidence: []string{"needs a real zone plus DNS API credentials and outbound DNS: cp e2e-config.example.yaml e2e-config.yaml && ./scripts/e2e-test.sh <domain> ./e2e-config.yaml"}},
		{Name: "black-box-probe-of-the-live-endpoint", What: "Dial 443 and compare the certificate served with the one deployed.", Verdict: "needs-credentials",
			Evidence: []string{"needs a deployed certificate behind a CLB: ./bin/wecert-probe -host <name> -min-valid 168h"}},
		{Name: "binary-against-a-local-ca", What: "Run the compiled wecert binary, rather than the Manager in-process, against pebble.", Verdict: "not-possible-on-this-host",
			Evidence: []string{"the binary builds its own ACME HTTP client with no CA override, and on macOS Go ignores SSL_CERT_FILE (verified: GODEBUG=x509usefallbackroots=1 has no effect without SetFallbackRoots, which this program does not call). On Linux, SSL_CERT_FILE is honoured, so the same run works in CI."}},
	}
	if len(live) != 0 {
		rep.NotRun = append(rep.NotRun, e2eCase{
			Name: "zone-left-dirty", What: "Challenge records left in the zone after the run.", Verdict: "fail",
			Evidence: []string{fmt.Sprintf("%v", live)},
		})
	}
	rep.Finished = time.Now()
	rep.DNSQueries = append([]string(nil), func() []string {
		dnsSrv.mu.Lock()
		defer dnsSrv.mu.Unlock()
		return append([]string(nil), dnsSrv.queries...)
	}()...)

	if path := os.Getenv("WECERT_E2E_REPORT"); path != "" {
		body, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			t.Fatalf("marshal the report: %v", err)
		}
		// The test binary's working directory is this package, not the repository root, so a
		// relative path from the caller lands here. Create the directory rather than failing with
		// "no such file or directory", which says nothing about the real cause.
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("create the report directory: %v", err)
			}
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatalf("write the report: %v", err)
		}
		t.Logf("wrote %s", path)
	}

	for _, c := range rep.Cases {
		if c.Verdict != "pass" {
			t.Errorf("case %q did not pass", c.Name)
		}
	}
}
