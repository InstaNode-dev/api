package models_test

// audit_kinds_quota_test.go — pins the exact string values of the two
// storage-quota suspend/unsuspend audit kinds (CHANGE 3, 2026-05-17).
//
// These kinds are a cross-repo CONTRACT: the worker's storage-quota
// enforcement job emits audit_log rows with these literal `kind` strings,
// and the worker's event_email_mapping.go matches on them by exact string
// to build a customer email. A typo on either side silently drops the email
// (the SQL `kind = ANY($1)` filter just never matches the row). This test
// fails if the api-side constant drifts, so the drift is caught in the api
// PR rather than as a missing-email production incident.

import (
	"testing"

	"instant.dev/internal/models"
)

func TestAuditKinds_QuotaSuspendUnsuspend_ExactStrings(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"quota_suspended", models.AuditKindResourceQuotaSuspended, "resource.quota_suspended"},
		{"quota_unsuspended", models.AuditKindResourceQuotaUnsuspended, "resource.quota_unsuspended"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q — the worker emit site + email mapping match on this exact string; a drift drops the customer email",
				c.name, c.got, c.want)
		}
	}
}
