package onboarding

import "testing"

// joinRecordName turns the relative Name DNSPod returns into a full record name.
//
// This is the cheapest place in the discovery layer to get something wrong, and the most
// expensive when it happens quietly: a wrong join means either a declaration is never
// recognised (so the domains behind it silently lose coverage) or some unrelated TXT record
// is mistaken for a declaration. It is a pure function, so every case below runs without a
// client, a stub or a network.
//
// Two properties are worth stating explicitly, because they are easy to assume wrong:
//
//   - The result has NO trailing dot. Callers compare these names against names built
//     elsewhere, so a stray dot would silently make two identical records look different.
//   - Only the record name is normalised. The zone is passed through untouched, which
//     the last two cases pin down.
func TestJoinRecordName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		zone string
		want string
	}{
		{"plain subdomain", "_acme-challenge", "example.com", "_acme-challenge.example.com"},
		{"plain subdomain, short", "sub", "example.com", "sub.example.com"},
		{"dotted relative name", "_wecert.alpha", "example.com", "_wecert.alpha.example.com"},

		// DNSPod uses "@" for the zone apex itself.
		{"apex as @", "@", "example.com", "example.com"},
		// An empty name is treated the same way; some responses come back blank for apex.
		{"apex as empty", "", "example.com", "example.com"},

		// Surrounding whitespace and case are both normalised, and they can appear together.
		{"whitespace and mixed case", "  _ACME-Challenge  ", "example.com", "_acme-challenge.example.com"},

		// A trailing dot on the name must be stripped, not joined. Naively appending would
		// produce "sub..example.com", which resolves to nothing.
		{"trailing dot on the name", "sub.", "example.com", "sub.example.com"},

		// The zone is NOT normalised. Documented here rather than fixed, because every
		// current caller passes a zone that is already lower-case and dot-free, and
		// normalising inside this function would hide a caller that stops doing so.
		//
		// If a caller ever passes a zone with a trailing dot or upper case, this is what
		// comes out -- and if two callers disagree about the form, the same declaration
		// would be seen as two different records.
		{"zone is passed through untouched", "x", "Example.COM.", "x.Example.COM."},

		// A name that already contains the zone is appended again. DNSPod returns relative
		// names so this is unreachable in practice; it is pinned so nobody assumes the
		// function de-duplicates.
		{"absolute name is appended, not de-duplicated",
			"alpha.example.com", "example.com", "alpha.example.com.example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := joinRecordName(tc.in, tc.zone)
			if got != tc.want {
				t.Errorf("joinRecordName(%q, %q) = %q, want %q", tc.in, tc.zone, got, tc.want)
			}
		})
	}
}

// Whatever else changes, the joined name must never gain a double dot.
//
// "a..b" is not a valid name and resolves to nothing, so a declaration would be dropped
// without any error being reported. Checked across the inputs that could produce it.
func TestJoinRecordNameNeverProducesADoubleDot(t *testing.T) {
	zones := []string{"example.com", "example.com."}
	names := []string{"", "@", "sub", "sub.", "  sub.  ", "_wecert.alpha", "*.wild"}

	for _, zone := range zones {
		for _, name := range names {
			got := joinRecordName(name, zone)
			for i := 0; i+1 < len(got); i++ {
				if got[i] == '.' && got[i+1] == '.' {
					t.Errorf("joinRecordName(%q, %q) = %q contains an empty label", name, zone, got)
					break
				}
			}
		}
	}
}
