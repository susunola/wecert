package config

import "testing"

// The remark is the only identity the SSL console shows for an uploaded certificate, and
// the inventory page renders this same string next to the certificate ID. Both are
// asserted here so a change to the prefix is a deliberate, visible one.
func TestUploadAlias(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cert string
		want string
	}{
		{name: "plain", cert: "joontest-xyz", want: "wecert/joontest-xyz"},
		{name: "dashes and digits", cert: "algo-rsa-2", want: "wecert/algo-rsa-2"},
		{name: "empty name has no remark", cert: "", want: ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := UploadAlias(tc.cert); got != tc.want {
				t.Fatalf("UploadAlias(%q) = %q, want %q", tc.cert, got, tc.want)
			}
		})
	}
}
