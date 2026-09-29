package deploy

import (
	"context"
	"errors"
	"testing"
	"time"

	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

// fakeCLBAPI is the read-only CLB stub the listener fallback is exercised against.
type fakeCLBAPI struct {
	loadBalancers []*clb.LoadBalancer
	listeners     map[string][]*clb.Listener
	lbErr         error
	listenerErr   error
	calls         *int
}

func (f *fakeCLBAPI) DescribeLoadBalancersWithContext(_ context.Context, _ *clb.DescribeLoadBalancersRequest) (*clb.DescribeLoadBalancersResponse, error) {
	if f.lbErr != nil {
		return nil, f.lbErr
	}
	total := uint64(len(f.loadBalancers))
	return &clb.DescribeLoadBalancersResponse{Response: &clb.DescribeLoadBalancersResponseParams{
		TotalCount:      &total,
		LoadBalancerSet: f.loadBalancers,
	}}, nil
}

func (f *fakeCLBAPI) DescribeListenersWithContext(_ context.Context, req *clb.DescribeListenersRequest) (*clb.DescribeListenersResponse, error) {
	if f.calls != nil {
		*f.calls++
	}
	if f.listenerErr != nil {
		return nil, f.listenerErr
	}
	return &clb.DescribeListenersResponse{Response: &clb.DescribeListenersResponseParams{
		Listeners: f.listeners[derefStr(req.LoadBalancerId)],
	}}, nil
}

func swapCLBClient(fn func(common.CredentialIface, string) (clbAPI, error)) func() {
	orig := newCLBClient
	newCLBClient = fn
	return func() { newCLBClient = orig }
}

// extensionListenerFixture is the shape measured on 2026-09-28: one listener carrying a
// primary certificate plus an SNI extension, and rules serving two names.
func extensionListenerFixture(calls *int) map[string][]*clb.Listener {
	return map[string][]*clb.Listener{
		"lb-hsj1v9eq": {{
			ListenerId: common.StringPtr("lbl-mt59gog6"),
			Protocol:   common.StringPtr("HTTPS"),
			Port:       common.Int64Ptr(8443),
			Certificate: &clb.CertificateOutput{
				CertId:     common.StringPtr("b9Z14O6y"),
				ExtCertIds: []*string{common.StringPtr("b9USe8CP")},
			},
			Rules: []*clb.RuleOutput{
				{
					Domain:      common.StringPtr("algo.joontest.xyz"),
					Certificate: &clb.CertificateOutput{CertId: common.StringPtr("b9Z14O6y")},
				},
				{
					Domain:      common.StringPtr("algo2.joontest.xyz"),
					Certificate: &clb.CertificateOutput{CertId: common.StringPtr("b9USe8CP")},
				},
			},
		}},
	}
}

func clbFixtureFactory(listeners map[string][]*clb.Listener, calls *int) func(common.CredentialIface, string) (clbAPI, error) {
	return func(_ common.CredentialIface, region string) (clbAPI, error) {
		if region != "ap-singapore" {
			return &fakeCLBAPI{lbErr: errors.New("region unavailable")}, nil
		}
		return &fakeCLBAPI{
			loadBalancers: []*clb.LoadBalancer{{LoadBalancerId: common.StringPtr("lb-hsj1v9eq")}},
			listeners:     listeners,
			calls:         calls,
		}, nil
	}
}

// The SSL bind-resource enumeration anchors on a certificate's PRIMARY slot, so a
// certificate bound only as an SNI extension (Listener.Certificate.ExtCertIds) comes back
// as "bound nowhere". Measured on ap-singapore, 2026-09-28: with
// Certificate.CertId=b9Z14O6y and ExtCertIds=["b9USe8CP"] on the same listener the task
// reported clb/ap-singapore=1 for b9Z14O6y and every region zero for b9USe8CP, while
// DescribeListeners returned the extension ID verbatim.
//
// Without the fallback the certificate stays at waiting_manual_bind for its whole lifetime
// (confirmBinding only acts on n > 0) and the inventory page shows it as unbound.
func TestBindingsFallsBackToTheListenerScanForAnExtensionCertificate(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)
	d.regions = []string{"ap-singapore"}
	ForgetBindings("b9USe8CP")
	t.Cleanup(func() { ForgetBindings("b9USe8CP") })

	restore := swapCLBClient(clbFixtureFactory(extensionListenerFixture(nil), nil))
	defer restore()

	fake := &fakeSSLAPI{
		createTaskFn: func(_ context.Context, _ *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
			return &ssl.CreateCertificateBindResourceSyncTaskResponse{
				Response: &ssl.CreateCertificateBindResourceSyncTaskResponseParams{
					CertTaskIds: []*ssl.CertTaskId{{
						CertId: common.StringPtr("b9USe8CP"),
						TaskId: common.StringPtr("task-1"),
					}},
				},
			}, nil
		},
		taskResultFn: func(_ context.Context, _ *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			// A complete zero: one resource type, one region, TotalCount present and 0.
			return &ssl.DescribeCertificateBindResourceTaskResultResponse{
				Response: &ssl.DescribeCertificateBindResourceTaskResultResponseParams{
					SyncTaskBindResourceResult: []*ssl.SyncTaskBindResourceResult{{
						TaskId: common.StringPtr("task-1"),
						Status: common.Uint64Ptr(bindStatusDone),
						BindResourceResult: []*ssl.BindResourceResult{{
							ResourceType: common.StringPtr("clb"),
							BindResourceRegionResult: []*ssl.BindResourceRegionResult{{
								Region:     common.StringPtr("ap-singapore"),
								TotalCount: common.Uint64Ptr(0),
							}},
						}},
					}},
				},
			}, nil
		},
	}

	n, err := d.bindingsWith(context.Background(), fake, "b9USe8CP", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Two rows: the listener's extension list and the algo2 rule. Either one alone is enough
	// to make the certificate "bound", and the count has to reflect both.
	if n.count != 2 || !n.complete {
		t.Fatalf("got %+v, want a complete count of 2: the listener scan found the slots "+
			"the SSL enumeration cannot see", n)
	}

	snap, _, ok := LookupCachedBindings("b9USe8CP")
	if !ok {
		t.Fatal("the listener rows were not cached, so the inventory page would still have nothing to show")
	}
	if len(snap.Items) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(snap.Items), snap.Items)
	}
	var extRow *BindingRow
	for i := range snap.Items {
		if snap.Items[i].Role == "ext" {
			extRow = &snap.Items[i]
		}
	}
	if extRow == nil {
		t.Fatalf("no row carries the extension role: %+v. Calling the extension slot primary "+
			"would send an operator to switch the wrong certificate", snap.Items)
	}
	if extRow.ListenerID != "lbl-mt59gog6" || extRow.Port != 8443 || extRow.LoadBalancerID != "lb-hsj1v9eq" {
		t.Errorf("row = %+v, want the listener the extension is bound to", *extRow)
	}
}

// When the SSL enumeration does find the binding, the fallback must not run: it is an extra
// describe per listener, and the enumeration's own rows are the authoritative ones.
func TestBindingsSkipsTheListenerScanWhenTheEnumerationFoundTheBinding(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)
	d.regions = []string{"ap-singapore"}

	scans := 0
	restore := swapCLBClient(clbFixtureFactory(extensionListenerFixture(&scans), &scans))
	defer restore()

	fake := &fakeSSLAPI{
		createTaskFn: func(_ context.Context, _ *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
			return &ssl.CreateCertificateBindResourceSyncTaskResponse{
				Response: &ssl.CreateCertificateBindResourceSyncTaskResponseParams{
					CertTaskIds: []*ssl.CertTaskId{{
						CertId: common.StringPtr("b9Z14O6y"),
						TaskId: common.StringPtr("task-1"),
					}},
				},
			}, nil
		},
		taskResultFn: func(_ context.Context, _ *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			return &ssl.DescribeCertificateBindResourceTaskResultResponse{
				Response: &ssl.DescribeCertificateBindResourceTaskResultResponseParams{
					SyncTaskBindResourceResult: []*ssl.SyncTaskBindResourceResult{{
						TaskId: common.StringPtr("task-1"),
						Status: common.Uint64Ptr(bindStatusDone),
						BindResourceResult: []*ssl.BindResourceResult{{
							ResourceType: common.StringPtr("clb"),
							BindResourceRegionResult: []*ssl.BindResourceRegionResult{{
								Region:     common.StringPtr("ap-singapore"),
								TotalCount: common.Uint64Ptr(1),
							}},
						}},
					}},
				},
			}, nil
		},
	}

	n, err := d.bindingsWith(context.Background(), fake, "b9Z14O6y", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.count != 1 {
		t.Errorf("count = %d, want 1", n.count)
	}
	if scans != 0 {
		t.Errorf("the listener scan ran %d time(s) although the enumeration already answered: "+
			"the fallback is for the zero case only", scans)
	}
}

// All three slots are independent, and the caller has to be told which one matched:
// a renewal switches exactly one of them while the others must stay untouched.
func TestListenerBindingsReportsPrimaryExtensionAndRuleSlots(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	d := newTestDeployer(clock.now)
	d.regions = []string{"ap-singapore"}

	restore := swapCLBClient(clbFixtureFactory(extensionListenerFixture(nil), nil))
	defer restore()

	t.Run("extension slot", func(t *testing.T) {
		snap, err := d.listenerBindingsForCert(context.Background(), "b9USe8CP")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if snap.Count != 2 || !snap.Complete {
			t.Fatalf("got %+v, want 2 complete rows (listener extension + the algo2 rule)", snap)
		}
		roles := map[string]int{}
		for _, row := range snap.Items {
			roles[row.Role+"/"+row.SNIDomain]++
		}
		// Two places carry it, and they are different slots: the listener's extension list
		// (role ext, no SNI name of its own) and the algo2 rule, where the same certificate is
		// that rule's primary (role rule). Calling the rule row "ext" would hide which name
		// the rule serves.
		if roles["ext/"] != 1 || roles["rule/algo2.joontest.xyz"] != 1 {
			t.Errorf("rows = %v, want the listener-level extension and the rule that serves it", roles)
		}
	})

	t.Run("rule slot", func(t *testing.T) {
		snap, err := d.listenerBindingsForCert(context.Background(), "b9Z14O6y")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// The same certificate is the listener's primary and the algo rule's certificate;
		// both are real places it is bound, so both rows are reported.
		if snap.Count != 2 {
			t.Fatalf("got %+v, want 2 rows for a certificate in both the primary and a rule slot", snap)
		}
		seen := map[string]bool{}
		for _, row := range snap.Items {
			seen[row.Role+"/"+row.SNIDomain] = true
		}
		if !seen["primary/"] || !seen["rule/algo.joontest.xyz"] {
			t.Errorf("rows = %v, want the primary slot and the rule that carries it", seen)
		}
	})

	// A region that cannot be read makes the answer a lower bound, never a zero.
	t.Run("a failed region is incomplete, not empty", func(t *testing.T) {
		d.regions = []string{"ap-singapore", "ap-seoul"}
		snap, err := d.listenerBindingsForCert(context.Background(), "unknown-cert")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if snap.Count != 0 || snap.Complete {
			t.Errorf("got %+v, want an incomplete zero: ap-seoul could not be read, so "+
				"\"bound nowhere\" is not an answer this scan may give", snap)
		}
	})
}
