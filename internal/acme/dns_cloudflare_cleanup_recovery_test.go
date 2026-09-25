package acme

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ---------- a transport that answers the Cloudflare API without a socket ----------
//
// dns_cloudflare_cleanup.go builds every URL from the literal https://api.cloudflare.com/client/v4
// prefix, so a test cannot point the production helpers at an httptest server directly. The seam
// that does exist is the transport: cloudflareZoneID and cloudflareDeleteExactTXT take an
// *http.Client, and newCloudflareTXTRecovery builds its own with a nil Transport, which means
// http.DefaultTransport. Intercepting there keeps URL building, the bearer header, the status check
// and the JSON decoding on the production path instead of testing a re-implementation of them --
// which is the whole point, because a recovery that asks the wrong URL or forgets the token is
// exactly the failure this file has to be able to see.

// recordedCloudflareRequest is one request the stub answered, kept in a form tests can assert on
// after the fact. The target is split into path and query, and the path is the *escaped* path, so a
// test can tell %2F inside an opaque record ID apart from a real extra path segment.
type recordedCloudflareRequest struct {
	method, path, query, auth, body string
}

type cloudflareAPIStub struct {
	// handle answers one request aimed at api.cloudflare.com.
	handle func(*http.Request) (*http.Response, error)
	// fallback serves every other host. The closure test installs the stub as http.DefaultTransport,
	// and a process-wide transport that swallowed unrelated requests would break whatever else the
	// package does while the stub is in place.
	fallback http.RoundTripper

	mu       sync.Mutex
	recorded []recordedCloudflareRequest
}

func newCloudflareAPIStub(handle func(*http.Request) (*http.Response, error)) *cloudflareAPIStub {
	return &cloudflareAPIStub{handle: handle}
}

func (s *cloudflareAPIStub) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "api.cloudflare.com" {
		if s.fallback == nil {
			return nil, fmt.Errorf("cloudflareAPIStub: unexpected request to %s", req.URL)
		}
		return s.fallback.RoundTrip(req)
	}
	var body string
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = string(raw)
	}
	s.mu.Lock()
	s.recorded = append(s.recorded, recordedCloudflareRequest{
		method: req.Method,
		path:   req.URL.EscapedPath(),
		query:  req.URL.RawQuery,
		auth:   req.Header.Get("Authorization"),
		body:   body,
	})
	s.mu.Unlock()
	return s.handle(req)
}

func (s *cloudflareAPIStub) client() *http.Client { return &http.Client{Transport: s} }

func (s *cloudflareAPIStub) requests() []recordedCloudflareRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedCloudflareRequest(nil), s.recorded...)
}

// summary renders the requests seen so far for failure messages: when a test asserts on the third
// request it has to be able to show all three when one of them is wrong.
func (s *cloudflareAPIStub) summary() string {
	var b strings.Builder
	for i, r := range s.requests() {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s %s", r.method, r.path)
		if r.query != "" {
			fmt.Fprintf(&b, "?%s", r.query)
		}
	}
	return b.String()
}

// cloudflareJSONResponse builds the reply a Cloudflare endpoint would send. The body is a
// NopCloser over a string so the production code's defer resp.Body.Close() stays on its normal path.
func cloudflareJSONResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// withCloudflareDefaultTransport routes api.cloudflare.com through the stub for one test.
//
// Only the closure under test needs this: it constructs its own client, so http.DefaultTransport is
// the sole seam a test has. The previous transport becomes the fallback and is restored on cleanup.
// Tests that call this must not call t.Parallel -- the value is process-wide.
func withCloudflareDefaultTransport(t *testing.T, s *cloudflareAPIStub) {
	t.Helper()
	previous := http.DefaultTransport
	s.fallback = previous
	http.DefaultTransport = s
	t.Cleanup(func() { http.DefaultTransport = previous })
}

// cloudflareRecoveryListing is the listing a successful recovery sees: one record that is exactly
// the (name, value) pair the caller asked about.
const cloudflareRecoveryListing = `{"success":true,"result":[{"id":"rec-1","type":"TXT","name":"_acme-challenge.example.com","content":"\"value-1\""}]}`

// cloudflareHappyStub answers the three requests one successful recovery makes: the zone lookup, the
// record listing and the delete.
func cloudflareHappyStub(listing string) *cloudflareAPIStub {
	return newCloudflareAPIStub(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/client/v4/zones/"):
			return cloudflareJSONResponse(http.StatusOK, listing), nil
		case req.Method == http.MethodGet:
			return cloudflareJSONResponse(http.StatusOK, `{"success":true,"result":[{"id":"zone-1"}]}`), nil
		default:
			// A delete body is never parsed, so a plain-text 200 is enough -- and provokes a failure
			// if a future change starts decoding it.
			return cloudflareJSONResponse(http.StatusOK, "deleted"), nil
		}
	})
}

// ---------- cloudflareRequest ----------

// cloudflareRequest is the entire HTTP surface of the recovery helper, so it is asserted against a
// real server: the method and URL the caller passes have to go out unchanged (including the query
// that scopes the call), the token has to travel as the bearer credential Cloudflare scopes on, and
// the reply has to land in the caller's typed envelope.
//
// A delete carries no body and no content type: anything else would be a request Cloudflare did not
// ask for, and a decode of a body that the delete request never asked for is the kind of change
// that turns a successful cleanup into a reported failure.
func TestCloudflareRequestSendsTheCallersMethodAndDecodesTheEnvelope(t *testing.T) {
	type seen struct {
		method, path, query, auth, contentType string
		length                                 int64
	}
	// The handler runs on the server's own goroutine, so the requests it records are handed over
	// under a mutex: the only other ordering between the two goroutines is the socket, which the
	// race detector does not track.
	var (
		mu  sync.Mutex
		got []seen
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, seen{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"),
			r.Header.Get("Content-Type"), r.ContentLength})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"zone-1"}]}`)
	}))
	defer srv.Close()

	query := url.Values{"name": {"example.com"}, "per_page": {"2"}}
	var out cloudflareResponse[[]cloudflareZone]
	if err := cloudflareRequest(context.Background(), srv.Client(), "tok-123", http.MethodGet,
		srv.URL+"/client/v4/zones?"+query.Encode(), &out); err != nil {
		t.Fatalf("cloudflareRequest: %v", err)
	}
	if !out.Success || len(out.Result) != 1 || out.Result[0].ID != "zone-1" {
		t.Errorf("reply = %+v, want the body decoded into the caller's envelope", out)
	}

	if err := cloudflareRequest(context.Background(), srv.Client(), "tok-123", http.MethodDelete,
		srv.URL+"/client/v4/zones/zone-1/dns_records/rec-1", nil); err != nil {
		t.Fatalf("cloudflareRequest with no destination for the reply: %v", err)
	}

	mu.Lock()
	recorded := append([]seen(nil), got...)
	mu.Unlock()
	want := []seen{
		{http.MethodGet, "/client/v4/zones", query.Encode(), "Bearer tok-123", "", 0},
		{http.MethodDelete, "/client/v4/zones/zone-1/dns_records/rec-1", "", "Bearer tok-123", "", 0},
	}
	if len(recorded) != len(want) {
		t.Fatalf("the server saw %d requests, want %d: %+v", len(recorded), len(want), recorded)
	}
	for i := range want {
		if recorded[i] != want[i] {
			t.Errorf("request %d = %+v, want %+v", i, recorded[i], want[i])
		}
	}
}

// cloudflareRequest only looks at the HTTP status; the success/errors half of the envelope is
// decoded for the callers to reason about. A rename on Cloudflare's side, or a typo in the struct
// tags, has to show up here as missing data rather than as a silently empty result that the
// recovery would read as "the record was already deleted".
//
// This asserts the decoding, and deliberately nothing more: no code in this file acts on Success.
// An envelope that reports success:false under an HTTP 200 is therefore an ordinary call as far as
// cloudflareRequest is concerned, and on the delete path an unreadable listing is indistinguishable
// from an empty one. That gap is reported with these tests rather than pinned here as intended.
func TestCloudflareRequestDecodesTheErrorEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":false,"result":[],"errors":[{"message":"Invalid API Token"}]}`)
	}))
	defer srv.Close()

	var out cloudflareResponse[[]cloudflareZone]
	if err := cloudflareRequest(context.Background(), srv.Client(), "tok", http.MethodGet, srv.URL+"/client/v4/zones", &out); err != nil {
		t.Fatalf("cloudflareRequest: %v", err)
	}
	if out.Success {
		t.Errorf("success = true for a body that says false: the field is not reaching the caller")
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "Invalid API Token" {
		t.Errorf("errors = %+v, want the operator-facing message decoded from errors[].message", out.Errors)
	}
}

// Every failure cloudflareRequest can see has to come back as an error. The recovery path decides
// from exactly that value whether the record is gone for good or needs a human, so a swallowed
// failure would be reported as a completed reclaim.
func TestCloudflareRequestReportsTransportStatusAndDecodeFailures(t *testing.T) {
	t.Run("non-2xx status", func(t *testing.T) {
		stub := newCloudflareAPIStub(func(*http.Request) (*http.Response, error) {
			return cloudflareJSONResponse(http.StatusForbidden, `{"success":false,"errors":[{"message":"Invalid API Token"}]}`), nil
		})
		err := cloudflareRequest(context.Background(), stub.client(), "tok", http.MethodGet,
			"https://api.cloudflare.com/client/v4/zones", &cloudflareResponse[[]cloudflareZone]{})
		if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
			t.Fatalf("error = %v, want the status in the message: a 403 is a token that needs replacing, not a missing zone", err)
		}
	})

	t.Run("undecodable body", func(t *testing.T) {
		stub := newCloudflareAPIStub(func(*http.Request) (*http.Response, error) {
			return cloudflareJSONResponse(http.StatusOK, `{"success":true,"result":[`), nil
		})
		err := cloudflareRequest(context.Background(), stub.client(), "tok", http.MethodGet,
			"https://api.cloudflare.com/client/v4/zones", &cloudflareResponse[[]cloudflareZone]{})
		if err == nil {
			t.Fatal("a truncated body must fail the call rather than leave the caller with an empty zone list")
		}
	})

	t.Run("transport error", func(t *testing.T) {
		sentinel := errors.New("dial tcp 198.51.100.7:443: i/o timeout")
		stub := newCloudflareAPIStub(func(*http.Request) (*http.Response, error) { return nil, sentinel })
		err := cloudflareRequest(context.Background(), stub.client(), "tok", http.MethodGet,
			"https://api.cloudflare.com/client/v4/zones", &cloudflareResponse[[]cloudflareZone]{})
		if !errors.Is(err, sentinel) {
			t.Fatalf("error = %v, want the transport's own error: collapsed into a generic message, the operator "+
				"cannot tell a timeout (retry) from a rejected token (replace it)", err)
		}
	})

	t.Run("endpoint that is not a URL", func(t *testing.T) {
		stub := newCloudflareAPIStub(func(*http.Request) (*http.Response, error) {
			t.Error("no request may be sent for an endpoint that does not parse")
			return nil, errors.New("unreachable")
		})
		if err := cloudflareRequest(context.Background(), stub.client(), "tok", http.MethodGet,
			"https://api.cloudflare.com/client/v4/\x7f", nil); err == nil {
			t.Fatal("a malformed endpoint must fail before anything is sent")
		}
		if n := len(stub.requests()); n != 0 {
			t.Fatalf("%d request(s) reached the transport for a malformed endpoint", n)
		}
	})
}

// ---------- cloudflareZoneID ----------

// cloudflareZoneID is what keeps the delete aimed at the right zone. Cloudflare answers a name
// lookup with every zone the token can see that matches, so "the first result" of an ambiguous
// answer could be another account's zone with the same name -- and the delete that follows would
// remove a record there. Only exactly one zone with a non-empty ID may pass, and every refusal has
// to be an error rather than an empty id, which would turn the delete URL into /zones//dns_records.
//
// per_page=2 is part of the contract, not decoration: it is the smallest page that can distinguish
// "one zone" from "more than one", which the guard needs to know.
func TestCloudflareZoneIDRequiresExactlyOneZone(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantID, wantErr string
	}{
		{name: "exactly one", body: `{"success":true,"result":[{"id":"zone-1"}]}`, wantID: "zone-1"},
		{name: "none", body: `{"success":true,"result":[]}`, wantErr: "not found uniquely"},
		{name: "more than one", body: `{"success":true,"result":[{"id":"zone-1"},{"id":"zone-2"}]}`, wantErr: "not found uniquely"},
		{name: "empty id", body: `{"success":true,"result":[{"id":""}]}`, wantErr: "not found uniquely"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newCloudflareAPIStub(func(*http.Request) (*http.Response, error) {
				return cloudflareJSONResponse(http.StatusOK, tc.body), nil
			})
			got, err := cloudflareZoneID(context.Background(), stub.client(), "tok-zone", "example.com")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("cloudflareZoneID: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("zone id %q was accepted where the answer was %s", got, tc.body)
				}
				if !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "example.com") {
					t.Fatalf("error = %v, want %q and the zone name so the operator knows which zone is ambiguous", err, tc.wantErr)
				}
				if got != "" {
					t.Errorf("zone id = %q with an error, want an empty id", got)
				}
			}
			if got != tc.wantID {
				t.Errorf("zone id = %q, want %q", got, tc.wantID)
			}

			reqs := stub.requests()
			if len(reqs) != 1 {
				t.Fatalf("requests = %s, want exactly the one lookup", stub.summary())
			}
			r := reqs[0]
			if r.method != http.MethodGet || r.path != "/client/v4/zones" {
				t.Errorf("lookup = %s %s, want GET /client/v4/zones", r.method, r.path)
			}
			if r.query != "name=example.com&per_page=2" {
				t.Errorf("query = %q, want the name filter and the two-result page", r.query)
			}
			if r.auth != "Bearer tok-zone" {
				t.Errorf("Authorization = %q, want the caller's token", r.auth)
			}
		})
	}

	// A lookup that failed at the HTTP layer must be reported as that failure, not as "the zone is
	// ambiguous": the two need different operator action (fix the token vs. fix the zone name).
	t.Run("api failure", func(t *testing.T) {
		stub := newCloudflareAPIStub(func(*http.Request) (*http.Response, error) {
			return cloudflareJSONResponse(http.StatusInternalServerError, `{"success":false}`), nil
		})
		if _, err := cloudflareZoneID(context.Background(), stub.client(), "tok", "example.com"); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("error = %v, want the HTTP failure", err)
		}
	})
}

// ---------- cloudflareDeleteExactTXT ----------

// The delete is the operation that can destroy another certificate's challenge record, so its
// scoping is the security-relevant part of this file: only a record whose type is TXT, whose name is
// the exact FQDN (a trailing dot on either side is ignored) and whose value is the exact challenge
// value may be removed. Everything else at the same name -- a wildcard's record, the value another
// certificate is proving at this very moment -- has to survive, because deleting it would make that
// other issuance fail its validation.
//
// The listing query is asserted too: type=TXT keeps the answer small, per_page=100 is the page the
// code actually reads (an unread second page would silently look like "no matching record"), and the
// name is the trailing-dot-free form Cloudflare filters on.
func TestCloudflareDeleteExactTXTDeletesOnlyTheMatchingRecord(t *testing.T) {
	const listing = `{"success":true,"result":[
		{"id":"rec-exact","type":"TXT","name":"_acme-challenge.example.com","content":"\"value-1\""},
		{"id":"rec-other-value","type":"TXT","name":"_acme-challenge.example.com.","content":"\"value-2\""},
		{"id":"rec-other-name","type":"TXT","name":"_acme-challenge.other.example.com","content":"value-1"},
		{"id":"rec-other-type","type":"A","name":"_acme-challenge.example.com","content":"value-1"},
		{"id":"rec-unquoted","type":"TXT","name":"_acme-challenge.example.com.","content":"value-1"}
	]}`
	stub := newCloudflareAPIStub(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet {
			return cloudflareJSONResponse(http.StatusOK, listing), nil
		}
		return cloudflareJSONResponse(http.StatusOK, "deleted"), nil
	})

	err := cloudflareDeleteExactTXT(context.Background(), stub.client(), "tok-txt", "zone-1",
		DNSRecord{FQDN: "_acme-challenge.example.com.", Value: "value-1"})
	if err != nil {
		t.Fatalf("cloudflareDeleteExactTXT: %v", err)
	}

	reqs := stub.requests()
	if len(reqs) != 3 {
		t.Fatalf("requests = %s, want one listing and two deletes (the quoted and the unquoted exact match)", stub.summary())
	}
	if reqs[0].method != http.MethodGet || reqs[0].path != "/client/v4/zones/zone-1/dns_records" {
		t.Errorf("listing = %s %s, want GET /client/v4/zones/zone-1/dns_records", reqs[0].method, reqs[0].path)
	}
	if reqs[0].query != "name=_acme-challenge.example.com&per_page=100&type=TXT" {
		t.Errorf("listing query = %q, want the exact name without its trailing dot, TXT only, one page", reqs[0].query)
	}
	for _, wantID := range []string{"rec-exact", "rec-unquoted"} {
		found := false
		for _, r := range reqs[1:] {
			if r.method == http.MethodDelete && r.path == "/client/v4/zones/zone-1/dns_records/"+wantID {
				found = true
				if r.auth != "Bearer tok-txt" {
					t.Errorf("delete %s Authorization = %q, want the caller's token", wantID, r.auth)
				}
			}
		}
		if !found {
			t.Errorf("record %s is the exact (name, value) pair that was asked for and was not deleted: %s", wantID, stub.summary())
		}
	}
	for _, r := range reqs {
		for _, keep := range []string{"rec-other-value", "rec-other-name", "rec-other-type"} {
			if strings.Contains(r.path, keep) {
				t.Errorf("record %s does not match the (name, value) pair this call was asked to remove and must not be touched: %s", keep, stub.summary())
			}
		}
	}
}

// Zone and record IDs are opaque strings Cloudflare hands out. They are escaped into the path so a
// value containing a slash stays inside the segment it was meant for; concatenating them would let
// such an ID address a different endpoint than the caller aimed at, and one of these endpoints
// deletes records. The zone id is the more dangerous of the two: a stray segment there would move
// the whole delete into another zone.
func TestCloudflareDeleteExactTXTKeepsOpaqueIDsInOnePathSegment(t *testing.T) {
	stub := cloudflareHappyStub(`{"success":true,"result":[{"id":"rec/1","type":"TXT","name":"_acme-challenge.example.com","content":"value-1"}]}`)

	err := cloudflareDeleteExactTXT(context.Background(), stub.client(), "tok", "zone/1",
		DNSRecord{FQDN: "_acme-challenge.example.com", Value: "value-1"})
	if err != nil {
		t.Fatalf("cloudflareDeleteExactTXT: %v", err)
	}
	reqs := stub.requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %s, want the listing that found the record and the delete of it", stub.summary())
	}
	if reqs[0].path != "/client/v4/zones/zone%2F1/dns_records" {
		t.Errorf("listing path = %q, want the zone id escaped into one segment", reqs[0].path)
	}
	if reqs[1].method != http.MethodDelete || reqs[1].path != "/client/v4/zones/zone%2F1/dns_records/rec%2F1" {
		t.Errorf("delete = %s %s, want the zone and record ids each escaped into one segment", reqs[1].method, reqs[1].path)
	}
}

// A listing or a delete that failed must be reported, and a listing is not an empty listing: taking
// a 403 for "nothing matched" would report a completed reclaim while the record is still in the zone
// and the certificate's state row would be cleared on no evidence.
//
// A delete that is refused stops the pass there. The remaining candidates are left in place so the
// operator still has the record the error is about, and the caller sees the failure instead of a
// half-done cleanup reported as success.
//
// Nothing matching is the one case that is not a failure: the record being gone is the outcome the
// recovery wanted, and reporting an error for it would send the operator to a console for a record
// that does not exist.
func TestCloudflareDeleteExactTXTReportsFailuresAndToleratesNothingToDo(t *testing.T) {
	t.Run("listing fails", func(t *testing.T) {
		stub := newCloudflareAPIStub(func(*http.Request) (*http.Response, error) {
			return cloudflareJSONResponse(http.StatusForbidden, `{"success":false,"errors":[{"message":"Invalid API Token"}]}`), nil
		})
		err := cloudflareDeleteExactTXT(context.Background(), stub.client(), "tok", "zone-1",
			DNSRecord{FQDN: "_acme-challenge.example.com.", Value: "value-1"})
		if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
			t.Fatalf("error = %v, want the listing failure", err)
		}
		if n := len(stub.requests()); n != 1 {
			t.Fatalf("%d requests were made: a failed listing must not be followed by a delete", n)
		}
	})

	t.Run("delete fails", func(t *testing.T) {
		stub := newCloudflareAPIStub(func(req *http.Request) (*http.Response, error) {
			if req.Method == http.MethodGet {
				return cloudflareJSONResponse(http.StatusOK, `{"success":true,"result":[
					{"id":"rec-first","type":"TXT","name":"_acme-challenge.example.com","content":"value-1"},
					{"id":"rec-second","type":"TXT","name":"_acme-challenge.example.com","content":"value-1"}]}`), nil
			}
			return cloudflareJSONResponse(http.StatusForbidden, `{"success":false}`), nil
		})
		err := cloudflareDeleteExactTXT(context.Background(), stub.client(), "tok", "zone-1",
			DNSRecord{FQDN: "_acme-challenge.example.com", Value: "value-1"})
		if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
			t.Fatalf("error = %v, want the refused delete", err)
		}
		if n := len(stub.requests()); n != 2 {
			t.Fatalf("requests = %s, want the listing and exactly one refused delete", stub.summary())
		}
	})

	t.Run("nothing matches", func(t *testing.T) {
		stub := cloudflareHappyStub(`{"success":true,"result":[
			{"id":"rec-other","type":"TXT","name":"_acme-challenge.example.com","content":"someone-elses-value"}]}`)
		err := cloudflareDeleteExactTXT(context.Background(), stub.client(), "tok", "zone-1",
			DNSRecord{FQDN: "_acme-challenge.example.com", Value: "value-1"})
		if err != nil {
			t.Fatalf("a record that is already gone must not be a failure: %v", err)
		}
		if n := len(stub.requests()); n != 1 {
			t.Fatalf("requests = %s, want the listing only", stub.summary())
		}
	})
}

// ---------- newCloudflareTXTRecovery ----------

// newCloudflareTXTRecovery is what the solver actually calls, and it is the only place that ties the
// three pieces together: the token, the zone id and the exact-record delete.
//
// Two behaviours are load-bearing and are asserted here end to end. The token file is re-read on
// every call, so rotating the credential does not need a restart; and when the file cannot be read
// the last good token is kept, so a transient I/O error does not tear down a working recovery. The
// zone name arrives from lego with a trailing dot, which Cloudflare's name filter does not match --
// a stale dot makes the lookup answer "no such zone" for a zone that exists.
func TestCloudflareTXTRecoveryRecoversTheRecordAndFollowsTokenRotation(t *testing.T) {
	stub := cloudflareHappyStub(cloudflareRecoveryListing)
	withCloudflareDefaultTransport(t, stub)

	tokenFile := filepath.Join(t.TempDir(), "cloudflare.token")
	if err := os.WriteFile(tokenFile, []byte("tok-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recoverTXT := newCloudflareTXTRecovery("", tokenFile)
	rec := DNSRecord{FQDN: "_acme-challenge.example.com.", Value: "value-1"}

	if err := recoverTXT(context.Background(), "example.com.", rec); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	first := stub.requests()
	if len(first) != 3 {
		t.Fatalf("requests = %s, want the zone lookup, the listing and the delete", stub.summary())
	}
	if first[0].query != "name=example.com&per_page=2" {
		t.Errorf("zone lookup query = %q, want the trailing dot lego passes to be trimmed", first[0].query)
	}
	if first[2].method != http.MethodDelete || first[2].path != "/client/v4/zones/zone-1/dns_records/rec-1" {
		t.Errorf("last request = %s %s, want the delete of the recovered record", first[2].method, first[2].path)
	}
	for _, r := range first {
		if r.auth != "Bearer tok-1" {
			t.Fatalf("request %s %s used Authorization %q, want the token read from the file", r.method, r.path, r.auth)
		}
	}

	// Rotation: overwriting the file is all an operator should have to do.
	if err := os.WriteFile(tokenFile, []byte("tok-2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverTXT(context.Background(), "example.com.", rec); err != nil {
		t.Fatalf("recovery after rotation: %v", err)
	}
	rotated := stub.requests()[len(first):]
	if len(rotated) != 3 {
		t.Fatalf("requests after rotation = %s, want a second full pass", stub.summary())
	}
	for _, r := range rotated {
		if r.auth != "Bearer tok-2" {
			t.Fatalf("request %s %s still used %q: the rotated token did not take effect without a restart", r.method, r.path, r.auth)
		}
	}

	// And a file that cannot be read keeps the token the process already has.
	if err := os.Remove(tokenFile); err != nil {
		t.Fatal(err)
	}
	if err := recoverTXT(context.Background(), "example.com.", rec); err != nil {
		t.Fatalf("recovery with the token file removed: %v", err)
	}
	for _, r := range stub.requests()[len(first)+len(rotated):] {
		if r.auth != "Bearer tok-2" {
			t.Fatalf("request %s %s used %q after the file disappeared, want the last good token", r.method, r.path, r.auth)
		}
	}
}

// An empty token must stop the recovery before it touches the API. Cloudflare answers unauthenticated
// requests with 403 and rate-limits the source address, so a missing credential would turn a
// configuration mistake into an outage for every other certificate using the same egress address.
func TestCloudflareTXTRecoveryRefusesAnEmptyToken(t *testing.T) {
	stub := newCloudflareAPIStub(func(*http.Request) (*http.Response, error) {
		t.Error("no request may be sent without a token")
		return cloudflareJSONResponse(http.StatusForbidden, `{"success":false}`), nil
	})
	withCloudflareDefaultTransport(t, stub)

	rec := DNSRecord{FQDN: "_acme-challenge.example.com.", Value: "value-1"}
	missingFile := filepath.Join(t.TempDir(), "not-there.token")
	for _, tc := range []struct {
		name, token, tokenFile string
	}{
		{name: "no token and no file"},
		{name: "token file does not exist", tokenFile: missingFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := newCloudflareTXTRecovery(tc.token, tc.tokenFile)(context.Background(), "example.com.", rec)
			if err == nil || !strings.Contains(err.Error(), "token is empty") {
				t.Fatalf("error = %v, want the empty-token refusal", err)
			}
		})
	}
	if n := len(stub.requests()); n != 0 {
		t.Fatalf("%d request(s) reached the API without a token: %s", n, stub.summary())
	}
}

// A token file that exists but holds only whitespace keeps the token the process already has, the
// same way a missing file does. An operator emptying the file (a truncate-and-rewrite that failed
// halfway, a config management run that blanked it) must not silently turn into "no credential" and
// a burst of 403s.
func TestCloudflareTXTRecoveryKeepsTheLastTokenWhenTheFileIsBlank(t *testing.T) {
	stub := cloudflareHappyStub(cloudflareRecoveryListing)
	withCloudflareDefaultTransport(t, stub)

	tokenFile := filepath.Join(t.TempDir(), "cloudflare.token")
	if err := os.WriteFile(tokenFile, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := newCloudflareTXTRecovery("tok-keep", tokenFile)(context.Background(), "example.com.",
		DNSRecord{FQDN: "_acme-challenge.example.com.", Value: "value-1"})
	if err != nil {
		t.Fatalf("recovery: %v", err)
	}
	reqs := stub.requests()
	if len(reqs) != 3 {
		t.Fatalf("requests = %s, want a full recovery pass", stub.summary())
	}
	for _, r := range reqs {
		if r.auth != "Bearer tok-keep" {
			t.Fatalf("request %s %s used %q, want the in-process token where the file is blank", r.method, r.path, r.auth)
		}
	}
}

// The failures of both halves have to reach the caller unchanged: "the zone is not in this token's
// scope" and "the delete was refused" need different operator action, and the recovery's caller
// reports the record to the console on the strength of that error. A pass that only logged and
// returned nil would clear the certificate's state row while the record is still live.
func TestCloudflareTXTRecoveryReportsLookupAndDeleteFailures(t *testing.T) {
	rec := DNSRecord{FQDN: "_acme-challenge.example.com.", Value: "value-1"}

	t.Run("zone not found", func(t *testing.T) {
		stub := newCloudflareAPIStub(func(*http.Request) (*http.Response, error) {
			return cloudflareJSONResponse(http.StatusOK, `{"success":true,"result":[]}`), nil
		})
		withCloudflareDefaultTransport(t, stub)
		err := newCloudflareTXTRecovery("tok", "")(context.Background(), "example.com.", rec)
		if err == nil || !strings.Contains(err.Error(), "not found uniquely") {
			t.Fatalf("error = %v, want the zone lookup failure", err)
		}
		if n := len(stub.requests()); n != 1 {
			t.Fatalf("%d requests: a zone that cannot be resolved must stop the pass before any record is touched", n)
		}
	})

	t.Run("delete refused", func(t *testing.T) {
		stub := newCloudflareAPIStub(func(req *http.Request) (*http.Response, error) {
			if req.Method == http.MethodDelete {
				return cloudflareJSONResponse(http.StatusForbidden, `{"success":false}`), nil
			}
			if strings.HasPrefix(req.URL.Path, "/client/v4/zones/") {
				return cloudflareJSONResponse(http.StatusOK, cloudflareRecoveryListing), nil
			}
			return cloudflareJSONResponse(http.StatusOK, `{"success":true,"result":[{"id":"zone-1"}]}`), nil
		})
		withCloudflareDefaultTransport(t, stub)
		err := newCloudflareTXTRecovery("tok", "")(context.Background(), "example.com.", rec)
		if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
			t.Fatalf("error = %v, want the refused delete reported to the caller", err)
		}
	})
}
