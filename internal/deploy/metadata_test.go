package deploy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── fetchCVMRoleCredential against a local metadata service ─────────────────
//
// cvmMetadataURL is a package variable precisely so these tests can point the fetch
// at an httptest server instead of the link-local metadata address that only exists
// on a real CVM.

func stubMetadataURL(t *testing.T, url string) {
	t.Helper()
	orig := cvmMetadataURL
	cvmMetadataURL = url
	t.Cleanup(func() { cvmMetadataURL = orig })
}

// A non-200 from the metadata service (typically "the role is not attached to this
// CVM") must surface the status, the role name, and the server's explanation.
func TestFetchCVMRoleCredentialNon200(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		http.Error(w, "role not attached", http.StatusNotFound)
	}))
	defer srv.Close()
	stubMetadataURL(t, srv.URL+"/")

	_, err := fetchCVMRoleCredential(context.Background(), "my-role")
	if err == nil {
		t.Fatal("a 404 from the metadata service must be an error")
	}
	for _, want := range []string{"404", "my-role", "role not attached"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %q", err, want)
		}
	}
	if gotPath != "/my-role" {
		t.Errorf("requested path = %q, want /my-role (metadata URL + role name)", gotPath)
	}
}

// The metadata service only exists on a CVM, so elsewhere the request hangs or
// fails; the error must say so and point at the static credential fallback.
func TestFetchCVMRoleCredentialTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until the client gives up.
		<-r.Context().Done()
	}))
	defer srv.Close()
	stubMetadataURL(t, srv.URL+"/")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := fetchCVMRoleCredential(ctx, "my-role")
	if err == nil || !strings.Contains(err.Error(), "reach the CVM metadata service") {
		t.Fatalf("err = %v, want the metadata-service-unreachable error", err)
	}
	if !strings.Contains(err.Error(), "credentialMode to static") {
		t.Errorf("err = %v, want the static-credential fallback hint", err)
	}
}

// A healthy metadata service returns temporary credentials that must end up in the
// SDK credential, token included.
func TestFetchCVMRoleCredentialSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"TmpSecretId":"tmp-id","TmpSecretKey":"tmp-key","Token":"tmp-token","ExpiredTime":1893456000,"Code":"Success"}`))
	}))
	defer srv.Close()
	stubMetadataURL(t, srv.URL+"/")

	cred, err := fetchCVMRoleCredential(context.Background(), "my-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.GetSecretId() != "tmp-id" || cred.GetSecretKey() != "tmp-key" || cred.GetToken() != "tmp-token" {
		t.Errorf("credential = (%q, %q, %q), want the values returned by the metadata service",
			cred.GetSecretId(), cred.GetSecretKey(), cred.GetToken())
	}
}

// A 200 whose body carries no usable credentials (e.g. an error payload) must not be
// mistaken for success.
func TestFetchCVMRoleCredentialEmptyCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"Code":"AuthFailure"}`))
	}))
	defer srv.Close()
	stubMetadataURL(t, srv.URL+"/")

	_, err := fetchCVMRoleCredential(context.Background(), "my-role")
	if err == nil || !strings.Contains(err.Error(), "no usable credentials") {
		t.Fatalf("err = %v, want the no-usable-credentials error", err)
	}
	if !strings.Contains(err.Error(), `Code="AuthFailure"`) {
		t.Errorf("err = %v, want the server-reported Code in the message", err)
	}
}
