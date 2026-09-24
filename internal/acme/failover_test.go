package acme

import (
	"errors"
	"net/url"
	"testing"

	legoacme "github.com/go-acme/lego/v4/acme"
)

func TestFailoverAPIUsesStandbyOnlyForDirectoryOutageAndRoutesOrderURLs(t *testing.T) {
	primary := &fakeAPI{newOrderErr: &url.Error{Op: "Post", URL: "https://primary.test/new-order", Err: errors.New("down")}}
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
