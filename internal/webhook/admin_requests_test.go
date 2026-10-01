package webhook

import "testing"

// The console offers two backends and "none", and the inventory groups rows by
// what this returns. "clb" must stay target-less on purpose: it means "push this
// wherever the daemon already points", so an operator who reconfigures the
// process for nginx does not find older rows pinned to a backend they left.
func TestResolveDeployMapsTheConsoleChoiceOntoATarget(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		value   string
		enabled bool
		target  string
	}{
		{"clb", true, ""},
		{" clb ", true, ""},
		{"nginx", true, "nginx"},
		{"none", false, ""},
		{"", false, ""},
		{"something-else", false, ""},
	} {
		enabled, target := ResolveDeploy(tc.value)
		if enabled != tc.enabled || target != tc.target {
			t.Errorf("ResolveDeploy(%q) = %v, %q; want %v, %q",
				tc.value, enabled, target, tc.enabled, tc.target)
		}
	}
}
