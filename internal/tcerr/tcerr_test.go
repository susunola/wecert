package tcerr

import (
	"errors"
	"fmt"
	"testing"

	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
)

// The live API's shape for "this domain is not in your account".
//
// The classifier was written against `ResourceNotFound.NoDataOfDomain`, which the round-11
// verification pass could not reproduce on any call it made; what a foreign domain actually answers
// is InvalidParameterValue.DomainNotExists (both DescribeDomainList and DescribeRecordList). With
// only the unobserved code recognised, cmd/preflight's documented answer -- "the domain is not under
// DNSPod in this account" -- was unreachable, and the operator was told to check a permission that
// was fine.
func TestDomainNotExistsIsTreatedAsNoDomain(t *testing.T) {
	t.Parallel()
	err := tcerrors.NewTencentCloudSDKError(CodeDomainNotExists, "Domain not exist.", "req-1")
	if !IsNoDataOfDomain(err) {
		t.Errorf("%s must classify as \"no such domain\": it is what the live API returns", CodeDomainNotExists)
	}
	// The documented-but-unobserved code stays recognised (older API behaviour, other endpoints).
	if !IsNoDataOfDomain(tcerrors.NewTencentCloudSDKError(CodeNoDataOfDomain, "", "req-2")) {
		t.Errorf("%s must stay classified as a defensive case", CodeNoDataOfDomain)
	}
	// And an unrelated error must not be swallowed by the widened check.
	if IsNoDataOfDomain(tcerrors.NewTencentCloudSDKError("UnauthorizedOperation", "", "req-3")) {
		t.Error("a permission error must not be classified as \"no such domain\"")
	}
}

// IsThrottled used to evaluate err.Error() on the right of || whenever Code returned "",
// so a nil error from a polling loop panicked. Every sibling classifier already guarded
// nil; this is the one that did not.
func TestIsThrottledAcceptsNil(t *testing.T) {
	t.Parallel()
	if IsThrottled(nil) {
		t.Error("IsThrottled(nil) must be false, not panic")
	}
	if !IsThrottled(tcerrors.NewTencentCloudSDKError("RequestLimitExceeded", "slow down", "req-1")) {
		t.Error("RequestLimitExceeded must classify as throttled")
	}
	if !IsThrottled(errors.New("api said RequestLimitExceeded.RateExceeded")) {
		t.Error("a plain error carrying the code must classify as throttled")
	}
	if IsThrottled(errors.New("connection reset")) {
		t.Error("an unrelated error must not classify as throttled")
	}
}

func TestIsNoDataOfRecord(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"the typed SDK error", &tcerrors.TencentCloudSDKError{Code: CodeNoDataOfRecord}, true},
		{"the typed error, wrapped", fmt.Errorf("list TXT records: %w", &tcerrors.TencentCloudSDKError{Code: CodeNoDataOfRecord}), true},
		{"a plain error carrying the code", errors.New("dnspod: ResourceNotFound.NoDataOfRecord"), true},
		{"a different SDK error", &tcerrors.TencentCloudSDKError{Code: "AuthFailure.SignatureFailure"}, false},
		{"an unrelated error", errors.New("connection reset"), false},
	}
	for _, tc := range cases {
		if got := IsNoDataOfRecord(tc.err); got != tc.want {
			t.Errorf("%s: IsNoDataOfRecord = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A nil error must be a plain "no" from every predicate -- the polling loop passes whatever the
// last call returned, and Code(nil) is safe while err.Error() on a nil error is not.
func TestPredicatesAcceptNil(t *testing.T) {
	if IsThrottled(nil) {
		t.Error("IsThrottled(nil) = true, want false")
	}
	if IsPermanent(nil) {
		t.Error("IsPermanent(nil) = true, want false")
	}
	if got := Code(nil); got != "" {
		t.Errorf("Code(nil) = %q, want \"\"", got)
	}
}

func TestCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"the typed SDK error", &tcerrors.TencentCloudSDKError{Code: CodeNoDataOfRecord}, CodeNoDataOfRecord},
		{"the typed error, wrapped", fmt.Errorf("list TXT records: %w", &tcerrors.TencentCloudSDKError{Code: CodeNoDataOfRecord}), CodeNoDataOfRecord},
		{"a plain error carries no code", errors.New("dnspod: ResourceNotFound.NoDataOfRecord"), ""},
	}
	for _, tc := range cases {
		if got := Code(tc.err); got != tc.want {
			t.Errorf("%s: Code = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestIsPermanent(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"a bad key", &tcerrors.TencentCloudSDKError{Code: "AuthFailure.SignatureFailure"}, true},
		{"a missing permission", &tcerrors.TencentCloudSDKError{Code: "UnauthorizedOperation"}, true},
		{"a malformed request", &tcerrors.TencentCloudSDKError{Code: "InvalidParameterValue.DomainNotExists"}, true},
		// Throttling must NOT be swallowed as permanent: it is transient and only needs a
		// longer wait (see IsThrottled).
		{"throttling is retryable", &tcerrors.TencentCloudSDKError{Code: "RequestLimitExceeded"}, false},
		// A "not found" is not permanent either: in a polling loop it usually means the
		// resource has not propagated yet.
		{"a missing resource is retryable", &tcerrors.TencentCloudSDKError{Code: CodeNoDataOfRecord}, false},
		{"an unrecognised code is retryable", &tcerrors.TencentCloudSDKError{Code: "InternalError"}, false},
		{"a plain error carrying the code", errors.New("describe: InvalidParameter.Foo"), true},
		{"the typed error, wrapped", fmt.Errorf("describe domain: %w", &tcerrors.TencentCloudSDKError{Code: "AuthFailure.SecretIdNotFound"}), true},
		{"an unrelated error", errors.New("connection reset"), false},
	}
	for _, tc := range cases {
		if got := IsPermanent(tc.err); got != tc.want {
			t.Errorf("%s: IsPermanent = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsThrottled(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"the typed SDK error", &tcerrors.TencentCloudSDKError{Code: "RequestLimitExceeded"}, true},
		{"a plain error carrying the code", errors.New("dnspod: RequestLimitExceeded"), true},
		{"a wrapped error carrying the code", fmt.Errorf("poll order: %w", errors.New("RequestLimitExceeded")), true},
		{"a permanent error is not throttling", &tcerrors.TencentCloudSDKError{Code: "AuthFailure.SignatureFailure"}, false},
		{"an unrelated error", errors.New("connection reset"), false},
	}
	for _, tc := range cases {
		if got := IsThrottled(tc.err); got != tc.want {
			t.Errorf("%s: IsThrottled = %v, want %v", tc.name, got, tc.want)
		}
	}
}
