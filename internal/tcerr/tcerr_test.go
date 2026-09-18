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

func TestIsNoDataOfRecord(t *testing.T) {
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
