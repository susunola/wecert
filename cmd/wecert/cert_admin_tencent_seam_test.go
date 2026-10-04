package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"github.com/susunola/wecert/internal/config"
)

// The clb/ssl calls in cert_admin.go used to be reachable only against the real
// cloud. stubCLBAPI and stubSSLAPI implement the seams with a closure per method
// (a nil closure panics: an unexpected cloud call is what a test should catch),
// and withFakeCLB / withFakeSSL swap the factories so every branch of the
// request-building and response-parsing logic is deterministic to test.

type stubCLBAPI struct {
	describeLBFn   func(*clb.DescribeLoadBalancersRequest) (*clb.DescribeLoadBalancersResponse, error)
	describeLisFn  func(*clb.DescribeListenersRequest) (*clb.DescribeListenersResponse, error)
	createLisFn    func(*clb.CreateListenerRequest) (*clb.CreateListenerResponse, error)
	modifyDomainFn func(*clb.ModifyDomainAttributesRequest) (*clb.ModifyDomainAttributesResponse, error)
	createRuleFn   func(*clb.CreateRuleRequest) (*clb.CreateRuleResponse, error)
	modifyLisFn    func(*clb.ModifyListenerRequest) (*clb.ModifyListenerResponse, error)
}

func (f *stubCLBAPI) DescribeLoadBalancers(r *clb.DescribeLoadBalancersRequest) (*clb.DescribeLoadBalancersResponse, error) {
	if f.describeLBFn == nil {
		panic("unexpected DescribeLoadBalancers call")
	}
	return f.describeLBFn(r)
}

func (f *stubCLBAPI) DescribeListeners(r *clb.DescribeListenersRequest) (*clb.DescribeListenersResponse, error) {
	if f.describeLisFn == nil {
		panic("unexpected DescribeListeners call")
	}
	return f.describeLisFn(r)
}

func (f *stubCLBAPI) CreateListener(r *clb.CreateListenerRequest) (*clb.CreateListenerResponse, error) {
	if f.createLisFn == nil {
		panic("unexpected CreateListener call")
	}
	return f.createLisFn(r)
}

func (f *stubCLBAPI) ModifyDomainAttributes(r *clb.ModifyDomainAttributesRequest) (*clb.ModifyDomainAttributesResponse, error) {
	if f.modifyDomainFn == nil {
		panic("unexpected ModifyDomainAttributes call")
	}
	return f.modifyDomainFn(r)
}

func (f *stubCLBAPI) CreateRule(r *clb.CreateRuleRequest) (*clb.CreateRuleResponse, error) {
	if f.createRuleFn == nil {
		panic("unexpected CreateRule call")
	}
	return f.createRuleFn(r)
}

func (f *stubCLBAPI) ModifyListener(r *clb.ModifyListenerRequest) (*clb.ModifyListenerResponse, error) {
	if f.modifyLisFn == nil {
		panic("unexpected ModifyListener call")
	}
	return f.modifyLisFn(r)
}

type stubSSLAPI struct {
	uploadFn func(*ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error)
}

func (f *stubSSLAPI) UploadCertificate(r *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
	if f.uploadFn == nil {
		panic("unexpected UploadCertificate call")
	}
	return f.uploadFn(r)
}

func withFakeSSL(t *testing.T, fake sslAPI) {
	t.Helper()
	orig := newSSLClient
	newSSLClient = func(common.CredentialIface, string, *profile.ClientProfile) (sslAPI, error) { return fake, nil }
	t.Cleanup(func() { newSSLClient = orig })
	t.Setenv("TENCENTCLOUD_SECRET_ID", "id")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "key")
}

func withFakeCLB(t *testing.T, fake clbAPI) {
	t.Helper()
	orig := newCLBClient
	newCLBClient = func(common.CredentialIface, string, *profile.ClientProfile) (clbAPI, error) { return fake, nil }
	t.Cleanup(func() { newCLBClient = orig })
	t.Setenv("TENCENTCLOUD_SECRET_ID", "id")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "key")
}

func uploadResp(certID, repeatID *string) *ssl.UploadCertificateResponse {
	return &ssl.UploadCertificateResponse{
		Response: &ssl.UploadCertificateResponseParams{CertificateId: certID, RepeatCertId: repeatID},
	}
}

// A fresh upload answers with a CertificateId; an already-uploaded one answers
// with a RepeatCertId. Both are a usable cloud certificate id, and neither may be
// dropped -- the latter is what the console needs to bind an existing cert.
func TestTencentUploadCertificatePrefersIDThenRepeat(t *testing.T) {
	cases := []struct {
		name    string
		resp    *ssl.UploadCertificateResponse
		want    string
		wantErr bool
	}{
		{"certificate id", uploadResp(common.StringPtr("ap-fresh"), nil), "ap-fresh", false},
		{"repeat id fallback", uploadResp(nil, common.StringPtr("ap-repeat")), "ap-repeat", false},
		{"neither id", uploadResp(nil, nil), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFakeSSL(t, &stubSSLAPI{uploadFn: func(*ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
				return tc.resp, nil
			}})
			got, err := tencentUploadCertificate("my-cert", []byte("cert"), []byte("key"), "china")
			if tc.wantErr {
				if err == nil {
					t.Fatal("an upload that returns no certificate id must fail")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("id = %q, want %q", got, tc.want)
			}
		})
	}
}

// The request must carry the certificate and key under the documented fields.
func TestTencentUploadCertificateSendsTheChainAndKey(t *testing.T) {
	var got *ssl.UploadCertificateRequest
	withFakeSSL(t, &stubSSLAPI{uploadFn: func(r *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
		got = r
		return uploadResp(common.StringPtr("ap-1"), nil), nil
	}})
	if _, err := tencentUploadCertificate("my-cert", []byte("PEM"), []byte("KEY"), "china"); err != nil {
		t.Fatal(err)
	}
	if got == nil || derefStr(got.CertificatePublicKey) != "PEM" || derefStr(got.CertificatePrivateKey) != "KEY" {
		t.Fatalf("upload request missing the material: %+v", got)
	}
	if derefStr(got.Alias) != "my-cert" {
		t.Errorf("Alias = %q, want my-cert", derefStr(got.Alias))
	}
}

func createListenerResp(ids ...string) *clb.CreateListenerResponse {
	out := &clb.CreateListenerResponse{Response: &clb.CreateListenerResponseParams{}}
	for _, id := range ids {
		out.Response.ListenerIds = append(out.Response.ListenerIds, common.StringPtr(id))
	}
	return out
}

// Without SNI the new listener carries the certificate itself: that is the only
// place CreateListener accepts Certificate.
func TestTencentCreateHTTPSListenerNoSNISetsCertificate(t *testing.T) {
	var got *clb.CreateListenerRequest
	withFakeCLB(t, &stubCLBAPI{createLisFn: func(r *clb.CreateListenerRequest) (*clb.CreateListenerResponse, error) {
		got = r
		return createListenerResp("lbl-1"), nil
	}})
	id, err := tencentCreateHTTPSListener("ap-guangzhou", "lb-1", 443, "name", false, "ap-cert", "china")
	if err != nil {
		t.Fatal(err)
	}
	if id != "lbl-1" {
		t.Errorf("id = %q, want lbl-1", id)
	}
	if got == nil {
		t.Fatal("no request captured")
	}
	if derefInt(got.SniSwitch) != 0 {
		t.Errorf("SniSwitch = %d, want 0", derefInt(got.SniSwitch))
	}
	if got.Certificate == nil || derefStr(got.Certificate.CertId) != "ap-cert" {
		t.Errorf("a non-SNI listener must carry the certificate: %+v", got.Certificate)
	}
}

// With SNI the certificate is attached per-domain later, so CreateListener must
// not carry it.
func TestTencentCreateHTTPSListenerSNIOmitsCertificate(t *testing.T) {
	var got *clb.CreateListenerRequest
	withFakeCLB(t, &stubCLBAPI{createLisFn: func(r *clb.CreateListenerRequest) (*clb.CreateListenerResponse, error) {
		got = r
		return createListenerResp("lbl-2"), nil
	}})
	if _, err := tencentCreateHTTPSListener("ap-guangzhou", "lb-1", 443, "", true, "ap-cert", "china"); err != nil {
		t.Fatal(err)
	}
	if derefInt(got.SniSwitch) != 1 {
		t.Errorf("SniSwitch = %d, want 1", derefInt(got.SniSwitch))
	}
	if got.Certificate != nil {
		t.Errorf("an SNI listener must not carry a default certificate: %+v", got.Certificate)
	}
}

// A CreateListener that returns no usable listener id must be an error, not a
// silent "" that the caller would then bind to.
func TestTencentCreateHTTPSListenerRejectsNoID(t *testing.T) {
	for _, resp := range []*clb.CreateListenerResponse{createListenerResp(), createListenerResp("")} {
		withFakeCLB(t, &stubCLBAPI{createLisFn: func(*clb.CreateListenerRequest) (*clb.CreateListenerResponse, error) {
			return resp, nil
		}})
		if _, err := tencentCreateHTTPSListener("ap-guangzhou", "lb-1", 443, "", true, "ap-cert", "china"); err == nil {
			t.Fatal("no listener id must be reported as an error")
		}
	}
}

// SNI binding prefers the named domain, and only falls back to creating a rule
// when the domain is not already on the listener.
func TestTencentBindListenerSNIUsesModifyDomain(t *testing.T) {
	var ruleCalled bool
	withFakeCLB(t, &stubCLBAPI{
		modifyDomainFn: func(*clb.ModifyDomainAttributesRequest) (*clb.ModifyDomainAttributesResponse, error) {
			return &clb.ModifyDomainAttributesResponse{}, nil
		},
		createRuleFn: func(*clb.CreateRuleRequest) (*clb.CreateRuleResponse, error) {
			ruleCalled = true
			return &clb.CreateRuleResponse{}, nil
		},
	})
	if err := tencentBindListener("ap-guangzhou", "lb-1", "lbl-1", "ap-cert", "www.example.com", "china"); err != nil {
		t.Fatal(err)
	}
	if ruleCalled {
		t.Error("a domain already on the listener must not create a new rule")
	}
}

func TestTencentBindListenerSNIFallsBackToCreateRule(t *testing.T) {
	var got *clb.CreateRuleRequest
	withFakeCLB(t, &stubCLBAPI{
		modifyDomainFn: func(*clb.ModifyDomainAttributesRequest) (*clb.ModifyDomainAttributesResponse, error) {
			return nil, errors.New("domain not found")
		},
		createRuleFn: func(r *clb.CreateRuleRequest) (*clb.CreateRuleResponse, error) {
			got = r
			return &clb.CreateRuleResponse{}, nil
		},
	})
	if err := tencentBindListener("ap-guangzhou", "lb-1", "lbl-1", "ap-cert", "new.example.com", "china"); err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got.Rules) != 1 {
		t.Fatalf("expected one rule to be created, got %+v", got)
	}
	// SSLMode is required even here; omitting it fails the live API.
	if got.Rules[0].Certificate == nil || derefStr(got.Rules[0].Certificate.SSLMode) != "UNIDIRECTIONAL" {
		t.Errorf("CreateRule must carry Certificate.SSLMode: %+v", got.Rules[0].Certificate)
	}
}

func TestTencentBindListenerNonSNIUsesModifyListener(t *testing.T) {
	var domainCalled, listenerCalled bool
	withFakeCLB(t, &stubCLBAPI{
		modifyDomainFn: func(*clb.ModifyDomainAttributesRequest) (*clb.ModifyDomainAttributesResponse, error) {
			domainCalled = true
			return &clb.ModifyDomainAttributesResponse{}, nil
		},
		modifyLisFn: func(*clb.ModifyListenerRequest) (*clb.ModifyListenerResponse, error) {
			listenerCalled = true
			return &clb.ModifyListenerResponse{}, nil
		},
	})
	if err := tencentBindListener("ap-guangzhou", "lb-1", "lbl-1", "ap-cert", "", "china"); err != nil {
		t.Fatal(err)
	}
	if domainCalled || !listenerCalled {
		t.Errorf("a non-SNI bind must ModifyListener only (domain=%v listener=%v)", domainCalled, listenerCalled)
	}
}

// An explicit site never probes; "" probes domestic first, then international,
// and falls back to domestic when both refuse (a wrong site and bad keys look the
// same to the API, so the fallback must not become "unknown").
func TestResolveTencentSite(t *testing.T) {
	orig := newCLBClient
	t.Cleanup(func() { newCLBClient = orig })
	cred := common.NewCredential("id", "key")

	var probed bool
	newCLBClient = func(common.CredentialIface, string, *profile.ClientProfile) (clbAPI, error) {
		probed = true
		return &stubCLBAPI{}, nil
	}
	if got := resolveTencentSite(cred, "ap-guangzhou", "international"); got != "international" {
		t.Errorf("explicit site = %q, want international", got)
	}
	if probed {
		t.Error("an explicit site must not probe")
	}

	// The probe answers per root domain: domestic accepts, international refuses.
	newCLBClient = func(_ common.CredentialIface, _ string, prof *profile.ClientProfile) (clbAPI, error) {
		root := prof.HttpProfile.RootDomain
		return &stubCLBAPI{describeLBFn: func(*clb.DescribeLoadBalancersRequest) (*clb.DescribeLoadBalancersResponse, error) {
			if root == "tencentcloudapi.com" {
				return &clb.DescribeLoadBalancersResponse{Response: &clb.DescribeLoadBalancersResponseParams{}}, nil
			}
			return nil, errors.New("refused")
		}}, nil
	}
	if got := resolveTencentSite(cred, "ap-guangzhou", ""); got != "china" {
		t.Errorf("domestic probe success = %q, want china", got)
	}

	// Only international accepts.
	newCLBClient = func(_ common.CredentialIface, _ string, prof *profile.ClientProfile) (clbAPI, error) {
		root := prof.HttpProfile.RootDomain
		return &stubCLBAPI{describeLBFn: func(*clb.DescribeLoadBalancersRequest) (*clb.DescribeLoadBalancersResponse, error) {
			if root == "intl.tencentcloudapi.com" {
				return &clb.DescribeLoadBalancersResponse{Response: &clb.DescribeLoadBalancersResponseParams{}}, nil
			}
			return nil, errors.New("refused")
		}}, nil
	}
	if got := resolveTencentSite(cred, "ap-guangzhou", ""); got != "international" {
		t.Errorf("international-only probe = %q, want international", got)
	}

	// Both refuse: fall back to domestic, never to an empty/unknown site.
	newCLBClient = func(common.CredentialIface, string, *profile.ClientProfile) (clbAPI, error) {
		return &stubCLBAPI{describeLBFn: func(*clb.DescribeLoadBalancersRequest) (*clb.DescribeLoadBalancersResponse, error) {
			return nil, errors.New("refused")
		}}, nil
	}
	if got := resolveTencentSite(cred, "ap-guangzhou", ""); got != "china" {
		t.Errorf("both refusals = %q, want china", got)
	}
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefInt(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// verifyBindingAccount must refuse an unknown UIN before reaching STS, pass a
// matching account, and refuse both a mismatch and an STS error.
func TestVerifyBindingAccount(t *testing.T) {
	orig := fetchCallerAccountID
	t.Cleanup(func() { fetchCallerAccountID = orig })
	t.Setenv("TENCENTCLOUD_SECRET_ID", "id")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "key")

	called := false
	fetchCallerAccountID = func(common.CredentialIface, string) (string, error) {
		called = true
		return "1000", nil
	}
	if err := verifyBindingAccount("", "ap-guangzhou"); err == nil {
		t.Error("an unknown UIN must be refused")
	}
	if called {
		t.Error("an empty UIN must be refused without calling STS")
	}

	fetchCallerAccountID = func(common.CredentialIface, string) (string, error) { return "1000", nil }
	if err := verifyBindingAccount("1000", "ap-guangzhou"); err != nil {
		t.Errorf("a matching account must pass, got %v", err)
	}

	fetchCallerAccountID = func(common.CredentialIface, string) (string, error) { return "2000", nil }
	if err := verifyBindingAccount("1000", "ap-guangzhou"); err == nil {
		t.Error("a mismatched account must be refused")
	}

	fetchCallerAccountID = func(common.CredentialIface, string) (string, error) {
		return "", errors.New("sts down")
	}
	if err := verifyBindingAccount("1000", "ap-guangzhou"); err == nil {
		t.Error("an STS error must be refused")
	}
}

// Without credentials the check must refuse without touching the cloud.
func TestVerifyBindingAccountWithoutCredentials(t *testing.T) {
	orig := fetchCallerAccountID
	t.Cleanup(func() { fetchCallerAccountID = orig })
	t.Setenv("TENCENTCLOUD_SECRET_ID", "")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "")
	fetchCallerAccountID = func(common.CredentialIface, string) (string, error) {
		t.Error("STS must not be reached without credentials")
		return "", nil
	}
	if err := verifyBindingAccount("1000", "ap-guangzhou"); err == nil {
		t.Error("missing credentials must be refused")
	}
}

// listCloudBindings must enumerate load balancers and their listeners into the
// shape the console's Bind dialog reads.
func TestListCloudBindingsEnumeratesLBsAndListeners(t *testing.T) {
	t.Setenv("TENCENTCLOUD_SECRET_ID", "id")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "key")
	withFakeCLB(t, &stubCLBAPI{
		describeLBFn: func(*clb.DescribeLoadBalancersRequest) (*clb.DescribeLoadBalancersResponse, error) {
			return &clb.DescribeLoadBalancersResponse{Response: &clb.DescribeLoadBalancersResponseParams{
				LoadBalancerSet: []*clb.LoadBalancer{{
					LoadBalancerId:   common.StringPtr("lb-1"),
					LoadBalancerName: common.StringPtr("main"),
				}},
			}}, nil
		},
		describeLisFn: func(*clb.DescribeListenersRequest) (*clb.DescribeListenersResponse, error) {
			return &clb.DescribeListenersResponse{Response: &clb.DescribeListenersResponseParams{
				Listeners: []*clb.Listener{{
					ListenerId: common.StringPtr("lbl-1"),
					Protocol:   common.StringPtr("HTTPS"),
					Port:       common.Int64Ptr(443),
					SniSwitch:  common.Int64Ptr(1),
				}},
			}}, nil
		},
	})
	dir := t.TempDir()
	cfg := &config.Config{
		StatePath: filepath.Join(dir, "state.db"),
		Tencent:   config.Tencent{Regions: []string{"ap-guangzhou"}},
	}
	out, err := listCloudBindings(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Bindings []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Region    string `json:"region"`
			Listeners []struct {
				ID    string `json:"id"`
				Proto string `json:"proto"`
				Port  int    `json:"port"`
				SNI   bool   `json:"sni"`
			} `json:"listeners"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Bindings) != 1 || parsed.Bindings[0].ID != "lb-1" {
		t.Fatalf("bindings = %+v", parsed.Bindings)
	}
	if len(parsed.Bindings[0].Listeners) != 1 {
		t.Fatalf("listeners = %+v", parsed.Bindings[0].Listeners)
	}
	l := parsed.Bindings[0].Listeners[0]
	if l.ID != "lbl-1" || l.Proto != "HTTPS" || l.Port != 443 || !l.SNI {
		t.Errorf("listener = %+v", l)
	}
}

// siteForAccount reads the site recorded with a stored account; an unknown UIN
// must not silently inherit another account's site.
func TestSiteForAccount(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{StatePath: filepath.Join(dir, "state.db")}
	if got := siteForAccount(cfg, ""); got != "" {
		t.Errorf("empty uin = %q, want empty", got)
	}
	accounts := `[{"name":"intl","uin":"1000","cred":"static","cloud":"tencent","site":"international","keyPath":"/x"}]`
	if err := os.WriteFile(filepath.Join(dir, "cloud-accounts.json"), []byte(accounts), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := siteForAccount(cfg, "1000"); got != "international" {
		t.Errorf("site = %q, want international", got)
	}
	if got := siteForAccount(cfg, "9999"); got != "" {
		t.Errorf("unknown uin = %q, want empty", got)
	}
}
