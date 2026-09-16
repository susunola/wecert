package deploy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/susunola/wecert/internal/config"
)

// static credentials come from the config, and the environment is a fallback so the values
// do not have to be written to a file that might be committed or backed up.
func TestCredentialSourceStaticPrefersConfigThenEnv(t *testing.T) {
	cfg := config.Tencent{CredentialMode: config.CredentialStatic, SecretID: "cfg-id", SecretKey: "cfg-key"}
	src, err := NewCredentialSource(cfg)
	if err != nil {
		t.Fatalf("NewCredentialSource: %v", err)
	}
	cred, err := src(context.Background())
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if cred.GetSecretId() != "cfg-id" || cred.GetSecretKey() != "cfg-key" {
		t.Errorf("config credentials must win, got %q / %q", cred.GetSecretId(), cred.GetSecretKey())
	}

	// Nothing in the config: fall back to the SDK's documented variables.
	t.Setenv(EnvSecretID, "env-id")
	t.Setenv(EnvSecretKey, "env-key")
	src, err = NewCredentialSource(config.Tencent{CredentialMode: config.CredentialStatic})
	if err != nil {
		t.Fatalf("NewCredentialSource: %v", err)
	}
	cred, err = src(context.Background())
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if cred.GetSecretId() != "env-id" || cred.GetSecretKey() != "env-key" {
		t.Errorf("environment fallback not used, got %q / %q", cred.GetSecretId(), cred.GetSecretKey())
	}
}

// Half a credential is worse than none: it fails at the first API call with an
// authentication error that says nothing about the real cause.
func TestCredentialSourceStaticRefusesHalfACredential(t *testing.T) {
	for _, tc := range []struct{ id, key string }{
		{"only-id", ""},
		{"", "only-key"},
	} {
		t.Setenv(EnvSecretID, tc.id)
		t.Setenv(EnvSecretKey, tc.key)
		_, err := NewCredentialSource(config.Tencent{CredentialMode: config.CredentialStatic})
		if err == nil {
			t.Errorf("id=%q key=%q must be refused", tc.id, tc.key)
		}
	}
}

// cvm-role needs the role name to build the metadata URL; without it there is no way to
// guess which role was meant.
func TestCredentialSourceCVMRoleRequiresARoleName(t *testing.T) {
	src, err := NewCredentialSource(config.Tencent{CredentialMode: config.CredentialCVMRole})
	if err != nil {
		t.Fatalf("construction must not need the role yet: %v", err)
	}
	if _, err := src(context.Background()); err == nil {
		t.Fatal("a cvm-role credential without roleName must fail")
	}
}

// An unknown mode must be refused at construction, not silently treated as one of the
// known ones -- a typo in credentialMode would otherwise pick a credential source the
// operator did not choose.
func TestCredentialSourceRejectsAnUnknownMode(t *testing.T) {
	if _, err := NewCredentialSource(config.Tencent{CredentialMode: "instance-profile"}); err == nil {
		t.Fatal("an unknown credentialMode must be refused")
	}
}

// The CVM metadata path must be reached only when a credential is actually requested, so a
// process that never deploys never touches the metadata service.
func TestCVMRoleCredentialIsFetchedLazily(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(cvmRoleCredential{
			TmpSecretID: "tmp-id", TmpSecretKey: "tmp-key", Token: "tok", ExpiredTime: 4102444800,
		})
	}))
	defer srv.Close()
	stubMetadataURL(t, srv.URL+"/")

	src, err := NewCredentialSource(config.Tencent{
		CredentialMode: config.CredentialCVMRole, RoleName: "wecert-role",
	})
	if err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatalf("constructing the source must not fetch a credential, got %d request(s)", hits)
	}

	cred, err := src(context.Background())
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if hits != 1 {
		t.Errorf("expected exactly one metadata request, got %d", hits)
	}
	if cred.GetSecretId() != "tmp-id" || cred.GetToken() != "tok" {
		t.Errorf("temporary credential not returned, got id=%q token=%q", cred.GetSecretId(), cred.GetToken())
	}
}

// Every call fetches again: temporary credentials expire, and a deploy happens only once
// every few dozen days, so caching one buys nothing but "it expired right when we finally
// needed it".
func TestCVMRoleCredentialIsNotCached(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(cvmRoleCredential{
			TmpSecretID: "id", TmpSecretKey: "key", Token: "tok",
		})
	}))
	defer srv.Close()
	stubMetadataURL(t, srv.URL+"/")

	src, err := NewCredentialSource(config.Tencent{
		CredentialMode: config.CredentialCVMRole, RoleName: "role",
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := src(context.Background()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if hits != 3 {
		t.Errorf("expected a fresh credential per call, got %d request(s) for 3 calls", hits)
	}
}

// The role name reaches the metadata URL, so an unescaped "../" would let it address other
// metadata paths -- including ones that hand out credentials for a different role.
func TestCVMRoleNameCannotEscapeTheMetadataPath(t *testing.T) {
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.EscapedPath()
		_ = json.NewEncoder(w).Encode(cvmRoleCredential{TmpSecretID: "i", TmpSecretKey: "k"})
	}))
	defer srv.Close()
	stubMetadataURL(t, srv.URL+"/")

	src, err := NewCredentialSource(config.Tencent{
		CredentialMode: config.CredentialCVMRole, RoleName: "../../other-role",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src(context.Background()); err != nil {
		t.Fatalf("credential: %v", err)
	}
	// Escaped, not traversing. %2F is the correct encoding here: the server decodes the
	// path into ONE segment, so the request cannot address a sibling metadata path such as
	// another role's credentials. (The stub replaces the whole base URL, so the fixed
	// /latest/meta-data/cam/security-credentials/ prefix is not part of what we observe --
	// what matters is that the role name itself contributes exactly one segment.)
	if seenPath == "" || strings.HasSuffix(seenPath, "/") {
		t.Fatalf("the role name vanished from the request: %q", seenPath)
	}
	lastSegment := seenPath[strings.LastIndex(seenPath, "/")+1:]
	if strings.Contains(lastSegment, "/") {
		t.Errorf("the role name introduced an extra path segment: %q", seenPath)
	}
	if !strings.Contains(lastSegment, "%2F") && strings.Contains(seenPath, "..") {
		t.Errorf("a traversing role name must be escaped, got %q", seenPath)
	}
}

// A metadata response that names a role but carries no usable credential must fail rather
// than produce a credential with empty fields, which would fail later as an opaque auth error.
func TestCVMRoleCredentialRejectsAnEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Code":"Success"}`))
	}))
	defer srv.Close()
	stubMetadataURL(t, srv.URL+"/")

	src, err := NewCredentialSource(config.Tencent{
		CredentialMode: config.CredentialCVMRole, RoleName: "role",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src(context.Background()); err == nil {
		t.Fatal("a metadata response without credentials must fail")
	}
}

// The metadata error path embeds the body, because on a 404 it is the only thing that says
// "the role is not attached" rather than just "404".
func TestCVMRoleCredentialReportsTheBodyOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("role wecert-role is not attached to this instance"))
	}))
	defer srv.Close()
	stubMetadataURL(t, srv.URL+"/")

	src, err := NewCredentialSource(config.Tencent{
		CredentialMode: config.CredentialCVMRole, RoleName: "wecert-role",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = src(context.Background())
	if err == nil {
		t.Fatal("a 404 must fail")
	}
	if !strings.Contains(err.Error(), "not attached") {
		t.Errorf("the response body is what makes this actionable, got: %v", err)
	}
}
