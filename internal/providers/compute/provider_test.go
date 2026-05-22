package compute

import "testing"

// TestTierResources verifies the per-tier resource floor returned by
// TierResources covers every tier and the unknown-tier fallback.
func TestTierResources(t *testing.T) {
	tests := []struct {
		tier                                  string
		wantMemReq, wantMemLimit, wantCPUReq  string
	}{
		{"hobby", "64Mi", "256Mi", "50m"},
		{"anonymous", "64Mi", "256Mi", "50m"},
		{"", "64Mi", "256Mi", "50m"}, // empty tier → default
		{"unknown", "64Mi", "256Mi", "50m"}, // unknown tier → default
		{"pro", "256Mi", "512Mi", "250m"},
		{"team", "512Mi", "2Gi", "500m"},
	}
	for _, tc := range tests {
		t.Run(tc.tier, func(t *testing.T) {
			memReq, memLimit, cpuReq := TierResources(tc.tier)
			if memReq != tc.wantMemReq {
				t.Errorf("memReq = %q; want %q", memReq, tc.wantMemReq)
			}
			if memLimit != tc.wantMemLimit {
				t.Errorf("memLimit = %q; want %q", memLimit, tc.wantMemLimit)
			}
			if cpuReq != tc.wantCPUReq {
				t.Errorf("cpuReq = %q; want %q", cpuReq, tc.wantCPUReq)
			}
		})
	}
}

// TestTierEphemeralStorage verifies non-empty values for known + unknown
// tiers and asserts the explicit floor for each.
func TestTierEphemeralStorage(t *testing.T) {
	tests := []struct {
		tier                  string
		wantReq, wantLimit    string
	}{
		{"hobby", "512Mi", "2Gi"},
		{"anonymous", "512Mi", "2Gi"},
		{"", "512Mi", "2Gi"},
		{"pro", "1Gi", "4Gi"},
		{"team", "2Gi", "8Gi"},
	}
	for _, tc := range tests {
		t.Run(tc.tier, func(t *testing.T) {
			req, limit := TierEphemeralStorage(tc.tier)
			if req != tc.wantReq {
				t.Errorf("request = %q; want %q", req, tc.wantReq)
			}
			if limit != tc.wantLimit {
				t.Errorf("limit = %q; want %q", limit, tc.wantLimit)
			}
		})
	}
}

// TestStackNamespace verifies the deterministic namespace prefix the
// platform relies on for stack teardown.
func TestStackNamespace(t *testing.T) {
	got := StackNamespace("abc123")
	want := "instant-stack-abc123"
	if got != want {
		t.Errorf("StackNamespace = %q; want %q", got, want)
	}
}
