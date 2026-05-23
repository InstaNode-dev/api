package handlers

// custom_domain_validate_coverage_test.go — white-box coverage for the pure
// validateHostname helper (custom_domain.go), exercising every rejection arm:
// empty, scheme/path/whitespace, no-dot, port, exact reserved host, reserved
// suffix, plus the trailing-dot trim + happy path.

import "testing"

func TestValidateHostname_Arms(t *testing.T) {
	good := []struct{ in, want string }{
		{"App.Example.com", "app.example.com"}, // lowercased
		{"app.example.com.", "app.example.com"}, // trailing dot trimmed
		{"sub.domain.example.org", "sub.domain.example.org"},
	}
	for _, tc := range good {
		got, err := validateHostname(tc.in)
		if err != nil {
			t.Errorf("validateHostname(%q) unexpected err: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("validateHostname(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}

	bad := []string{
		"",                          // empty
		"https://app.example.com",   // scheme
		"app.example.com/path",      // path
		"app.example.com?q=1",       // query
		"has space.example.com",     // whitespace
		"localhost",                 // no dot
		"app.example.com:8080",      // port
		"instanode.dev",             // exact reserved host
		"instant.dev",               // exact reserved host
		"x.instanode.dev",           // reserved suffix
		"y.deployment.instant.dev",  // reserved suffix
	}
	for _, in := range bad {
		if _, err := validateHostname(in); err == nil {
			t.Errorf("validateHostname(%q) = nil err; want rejection", in)
		}
	}
}
