package handlers

// promote_approval_arms_coverage_test.go — white-box coverage for the
// promote-approval HTML helpers + the per-IP rate-limit check
// (checkApproveRateLimit / approvalHTMLRateLimit / approvalHTMLServiceError),
// which the existing promote_approval_test.go leaves at 0% because it wires a
// nil Redis (rate-limit short-circuited) and never renders the rate-limit /
// service-error pages.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// whiteboxTestRedis opens a go-redis client against TEST_REDIS_URL (DB 15,
// matching the rest of the suite). Built inline rather than via testhelpers
// because this is a package-handlers (white-box) file and testhelpers imports
// handlers — importing it here would form a cycle.
func whiteboxTestRedis(t *testing.T) (*redis.Client, func()) {
	t.Helper()
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		url = "redis://localhost:6379/15"
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("parse TEST_REDIS_URL: %v", err)
	}
	rdb := redis.NewClient(opt)
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("test redis unavailable: %v", err)
	}
	return rdb, func() { rdb.Close() }
}

func TestPromoteApproval_HTMLHelpers(t *testing.T) {
	// Each helper must wrap a recognizable phrase in an HTML document.
	cases := map[string]func() string{
		"invalid":       approvalHTMLInvalid,
		"expired":       approvalHTMLExpired,
		"already_used":  approvalHTMLAlreadyUsed,
		"rate_limit":    approvalHTMLRateLimit,
		"service_error": approvalHTMLServiceError,
	}
	for name, fn := range cases {
		html := fn()
		if !strings.Contains(html, "<") || !strings.Contains(strings.ToLower(html), "html") {
			t.Errorf("%s helper did not return an HTML document: %.60s", name, html)
		}
	}
}

func TestPromoteApproval_CheckRateLimit(t *testing.T) {
	rdb, clean := whiteboxTestRedis(t)
	defer clean()
	h := NewPromoteApprovalHandler(nil, rdb)
	ctx := context.Background()

	// Empty IP short-circuits to (false, nil).
	if exceeded, err := h.checkApproveRateLimit(ctx, ""); err != nil || exceeded {
		t.Fatalf("empty IP: exceeded=%v err=%v; want false,nil", exceeded, err)
	}

	// Under the budget: the first call for a FRESH per-run IP must not be
	// limited. Use a uuid-derived IP so a leftover Redis count from a prior
	// run (the bucket key has a 2s TTL) never makes the first call trip.
	freshIP := "rl-fresh-" + uuid.NewString()
	if exceeded, err := h.checkApproveRateLimit(ctx, freshIP); err != nil || exceeded {
		t.Fatalf("first call: exceeded=%v err=%v; want false,nil", exceeded, err)
	}

	// Drive past the per-second budget so the limited branch returns true.
	ip := "rl-burst-" + uuid.NewString()
	var sawLimited bool
	for i := 0; i < promoteApprovalRateLimitPerSec+5; i++ {
		exceeded, err := h.checkApproveRateLimit(ctx, ip)
		if err != nil {
			t.Fatalf("rate-limit call %d: %v", i, err)
		}
		if exceeded {
			sawLimited = true
			break
		}
	}
	if !sawLimited {
		t.Errorf("expected to exceed the per-IP budget within %d calls", promoteApprovalRateLimitPerSec+5)
	}
}
