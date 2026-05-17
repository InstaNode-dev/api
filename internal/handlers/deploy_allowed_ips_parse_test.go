package handlers

// deploy_allowed_ips_parse_test.go — P1-I coverage (bug hunt 2026-05-17 round 2).
//
// splitAllowedIPsField must accept BOTH the CSV form and the JSON-array form.
// The MCP client serialises allowed_ips as a JSON array; before the fix the
// backend only parsed CSV, so every MCP `create_deploy --private` 400'd.
//
// Internal-package test (vs. the external handlers_test in
// deploy_private_test.go) so it can call the unexported parser directly.

import (
	"reflect"
	"testing"
)

func TestSplitAllowedIPsField(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"single CSV", "1.2.3.4", []string{"1.2.3.4"}},
		{"CSV multiple", "1.2.3.4,10.0.0.0/8", []string{"1.2.3.4", "10.0.0.0/8"}},
		{"CSV with spaces", " 1.2.3.4 , 10.0.0.0/8 ", []string{"1.2.3.4", "10.0.0.0/8"}},
		{"CSV trailing comma", "1.2.3.4,", []string{"1.2.3.4"}},
		// P1-I: the JSON-array form the MCP client sends.
		{"JSON array single", `["1.2.3.4"]`, []string{"1.2.3.4"}},
		{"JSON array multiple", `["1.2.3.4","10.0.0.0/8"]`, []string{"1.2.3.4", "10.0.0.0/8"}},
		{"JSON array spaced", `[ "1.2.3.4" , "10.0.0.0/8" ]`, []string{"1.2.3.4", "10.0.0.0/8"}},
		{"JSON array with blank entry", `["1.2.3.4",""]`, []string{"1.2.3.4"}},
		{"JSON empty array", `[]`, nil},
		// A malformed leading-bracket string falls through to CSV rather than
		// hard-failing — defensive, so a stray '[' never bricks the request.
		{"malformed JSON falls back to CSV", "[1.2.3.4", []string{"[1.2.3.4"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitAllowedIPsField(tc.raw)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("splitAllowedIPsField(%q) = %#v, want %#v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestSplitAllowedIPsField_JSONAndCSVAgree is the P1-I regression guard: the
// same set of IPs expressed as JSON or CSV must parse to the identical slice,
// so MCP and curl callers reach byte-identical validation downstream.
func TestSplitAllowedIPsField_JSONAndCSVAgree(t *testing.T) {
	csv := splitAllowedIPsField("1.2.3.4,10.0.0.0/8,2001:db8::/32")
	jsn := splitAllowedIPsField(`["1.2.3.4","10.0.0.0/8","2001:db8::/32"]`)
	if !reflect.DeepEqual(csv, jsn) {
		t.Fatalf("JSON and CSV forms disagree: csv=%#v json=%#v", csv, jsn)
	}
}
