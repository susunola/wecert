package acme

import (
	"errors"
	"net"
	"net/url"
	"testing"

	legoacme "github.com/go-acme/lego/v4/acme"
)

func TestFailoverAPIUsesStandbyOnlyForDirectoryOutageAndRoutesOrderURLs(t *testing.T) {
	// A transport-level "connection refused" is the only thing that counts as a
	// directory outage: a lost response after the request was sent is NOT (the order
	// may exist on the server).
	primary := &fakeAPI{newOrderErr: &url.Error{Op: "Post", URL: "https://primary.test/new-order", Err: errors.New("dial tcp: connection refused")}}
	standbyOrder := legoacme.ExtendedOrder{Order: legoacme.Order{Status: "pending"}, Location: "https://standby.test/order/1"}
	standby := &fakeAPI{orders: []legoacme.ExtendedOrder{standbyOrder}}
	a, err := NewFailoverAPI(primary, "https://primary.test/directory", []API{standby}, []string{"https://standby.test/directory"})
	if err != nil {
		t.Fatal(err)
	}
	o, err := a.NewOrder([]string{"example.com"}, nil)
	if err != nil {
		t.Fatalf("NewOrder: %v", err)
	}
	if o.Location != standbyOrder.Location {
		t.Fatalf("order = %q, want standby order", o.Location)
	}
	if got := primary.callLog(); len(got) != 1 || got[0] != "NewOrder" {
		t.Fatalf("primary calls = %v", got)
	}
	if got := standby.callLog(); len(got) != 1 || got[0] != "NewOrder" {
		t.Fatalf("standby calls = %v", got)
	}
	if _, err := a.GetOrder(standbyOrder.Location); err != nil {
		t.Fatalf("GetOrder: %v", err)
	}
	if got := standby.callLog(); len(got) != 2 || got[1] != "GetOrder" {
		t.Fatalf("standby URL was not routed to standby: %v", got)
	}
}

func TestFailoverAPIDoesNotTreatAuthorizationFailureAsCAOutage(t *testing.T) {
	primary := &fakeAPI{newOrderErr: errors.New("authorization failed")}
	standby := &fakeAPI{orders: []legoacme.ExtendedOrder{{Location: "https://standby.test/order/1"}}}
	a, err := NewFailoverAPI(primary, "https://primary.test/directory", []API{standby}, []string{"https://standby.test/directory"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.NewOrder([]string{"example.com"}, nil); err == nil {
		t.Fatal("NewOrder unexpectedly succeeded")
	}
	if got := standby.callLog(); len(got) != 0 {
		t.Fatalf("standby must not receive ordinary failure, got %v", got)
	}
}

// directoryUnavailable decides whether a failed directory call is worth a second CA, and being
// wrong is expensive in one direction: a standby attempt spends a second exact-set order. So the
// accepted set is deliberately narrow, and this pins it -- including that the deprecated
// net.Error.Temporary is not what decides it any more.
func TestDirectoryUnavailableAcceptsOnlyTransportAndAccountWideFailures(t *testing.T) {
	transient := []error{
		&net.OpError{Op: "dial", Err: &timeoutError{}},
		errors.New("dial tcp 1.2.3.4:443: connect: connection refused"),
		errors.New("dial tcp: lookup acme.example on 8.8.8.8:53: no such host"),
		errors.New("read tcp 10.0.0.1:443: read: connection reset by peer"),
		errors.New("write tcp 10.0.0.1:443: write: broken pipe"),
		errors.New("dial tcp 10.0.0.1:443: connect: network is unreachable"),
		errors.New("dial tcp 10.0.0.1:443: connect: no route to host"),
		errors.New(`acme: error: 500 :: POST :: https://ca/dir :: urn:ietf:params:acme:error:serverInternal :: server internal error`),
		errors.New("too many new orders recently"),
	}
	for _, err := range transient {
		if !directoryUnavailable(err) {
			t.Errorf("directoryUnavailable(%q) = false, want true: this is a transport or "+
				"account-wide failure a standby CA can survive", err)
		}
	}

	// The failures a second CA cannot fix, and the one that would cost quota for nothing: an order
	// that may already exist on the first CA.
	local := []error{
		errors.New(`acme: error: 400 :: POST :: https://ca/new-order :: urn:ietf:params:acme:error:malformed :: unable to get key identifier`),
		errors.New(`acme: error: 403 :: POST :: https://ca/new-order :: urn:ietf:params:acme:error:unauthorized :: invalid contact`),
		errors.New(`acme: error: 429 :: POST :: https://ca/new-order :: urn:ietf:params:acme:error:rateLimited :: too many certificates already issued for this exact set of domains`),
		errors.New("could not find an SOA for _acme-challenge.example.com."),
		errors.New("authorization failed: incorrect TXT record found"),
	}
	for _, err := range local {
		if directoryUnavailable(err) {
			t.Errorf("directoryUnavailable(%q) = true: a standby CA cannot fix this, and the retry "+
				"spends a second exact-set order", err)
		}
	}
}

type timeoutError struct{}

func (*timeoutError) Error() string   { return "i/o timeout" }
func (*timeoutError) Timeout() bool   { return true }
func (*timeoutError) Temporary() bool { return true }
