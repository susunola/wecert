package main

import (
	"strings"
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

// The gate in front of `-prune-certs`, and the two helpers that turn the SDK's pointer fields
// into something printable, are small enough that the risk is not their size but their
// direction: a confirmation that reads a non-interactive stdin as "yes" deletes every
// certificate the account holds, and a nil count that prints as 0 makes an unreadable answer
// look like an empty account.
func TestConfirmFromTreatsAnythingButAYesAsNo(t *testing.T) {
	yes := []string{"y\n", "Y\n", "yes\n", "YES\n", "  y  \n", "Yes\n"}
	for _, answer := range yes {
		if !confirmFrom(strings.NewReader(answer)) {
			t.Errorf("confirmFrom(%q) = false, want true: this is the documented yes", answer)
		}
	}
	no := []string{"", "\n", "n\n", "no\n", "yep\n", "yeah\n", "1\n", "true\n"}
	for _, answer := range no {
		if confirmFrom(strings.NewReader(answer)) {
			t.Errorf("confirmFrom(%q) = true, want false: deleting certificates must not pass on "+
				"anything but an explicit yes", answer)
		}
	}
	// A pipe or a cron job that forgot to answer reads as EOF, and EOF is a NO.
	if confirmFrom(strings.NewReader("")) {
		t.Error("an empty stdin must not authorise deleting every certificate wecert ever uploaded")
	}
	// Only the first line counts: an answer followed by a script's remaining output is still
	// that answer.
	if !confirmFrom(strings.NewReader("y\nn\n")) {
		t.Error("the first line is the answer")
	}
}

// certificateCount: an unreadable answer is not zero. "0 certificates" and "could not read the
// count" look the same in a preflight report, and the second one is the one that hides a
// misconfigured credential.
func TestCertificateCountRefusesToReadAnUnreadableAnswerAsZero(t *testing.T) {
	if _, err := certificateCount(nil); err == nil {
		t.Error("a nil response must be an error, not a count of zero")
	}
	if _, err := certificateCount(&ssl.DescribeCertificatesResponse{}); err == nil {
		t.Error("a response without a result must be an error, not a count of zero")
	}
	if _, err := certificateCount(&ssl.DescribeCertificatesResponse{Response: &ssl.DescribeCertificatesResponseParams{}}); err == nil {
		t.Error("a result without a total count must be an error, not a count of zero")
	}

	total := uint64(7)
	got, err := certificateCount(&ssl.DescribeCertificatesResponse{
		Response: &ssl.DescribeCertificatesResponseParams{TotalCount: &total},
	})
	if err != nil {
		t.Fatalf("a complete response must be readable: %v", err)
	}
	if got != 7 {
		t.Errorf("certificateCount = %d, want 7", got)
	}

	// A real zero is a real zero: the account holds none, and that is an answer.
	zero := uint64(0)
	got, err = certificateCount(&ssl.DescribeCertificatesResponse{
		Response: &ssl.DescribeCertificatesResponseParams{TotalCount: &zero},
	})
	if err != nil || got != 0 {
		t.Errorf("an account with no certificates is 0 and no error, got %d, %v", got, err)
	}
}

// deref/derefU64 exist so a nil SDK field prints as something an operator can act on rather
// than panicking the whole preflight run.
func TestDerefRendersAbsentFieldsWithoutPanicking(t *testing.T) {
	if got := deref(nil); got != "<nil>" {
		t.Errorf("deref(nil) = %q, want a printable placeholder", got)
	}
	name := "example.com"
	if got := deref(&name); got != name {
		t.Errorf("deref = %q, want %q", got, name)
	}

	if got := derefU64(nil); got != 0 {
		t.Errorf("derefU64(nil) = %d, want 0", got)
	}
	n := uint64(42)
	if got := derefU64(&n); got != 42 {
		t.Errorf("derefU64 = %d, want 42", got)
	}
}

// dumpBindings needs credentials before it can call the API, and that check comes first: the
// operator's fix is "export the pair", and it has to be said without a network round trip.
func TestDumpBindingsRefusesToStartWithoutCredentials(t *testing.T) {
	t.Setenv("TENCENTCLOUD_SECRET_ID", "")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "")
	err := dumpBindings("cert-id")
	if err == nil {
		t.Fatal("dumpBindings must refuse to run without credentials")
	}
	if !strings.Contains(err.Error(), "TENCENTCLOUD_SECRET_ID") {
		t.Errorf("the error must name the missing variables, got: %v", err)
	}

	// Half a pair is the same answer: it must not build a client from an id with no key.
	t.Setenv("TENCENTCLOUD_SECRET_ID", "id")
	if err := dumpBindings("cert-id"); err == nil ||
		!strings.Contains(err.Error(), "TENCENTCLOUD_SECRET_KEY") {
		t.Errorf("an id with no key must be refused the same way, got: %v", err)
	}
}

// The credential helper is what every path in this command goes through, and its error is the
// one an operator sees when the environment is half-set.
func TestCredsReportsMissingEnvironment(t *testing.T) {
	t.Setenv("TENCENTCLOUD_SECRET_ID", "")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "")
	if _, err := creds(); err == nil {
		t.Error("no credentials in the environment must be an error")
	}

	t.Setenv("TENCENTCLOUD_SECRET_ID", "id")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "key")
	cred, err := creds()
	if err != nil {
		t.Fatalf("a complete static pair must build a credential: %v", err)
	}
	if cred == nil {
		t.Fatal("creds returned a nil credential and no error")
	}
	if _, ok := cred.(*common.Credential); !ok {
		t.Errorf("creds returned %T, want the static credential the SDK calls with", cred)
	}
}
