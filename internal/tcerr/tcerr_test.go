package tcerr

import (
	"errors"
	"fmt"
	"testing"

	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
)

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
