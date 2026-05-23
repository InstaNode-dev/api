package handlers_test

// backup_cursor_coverage_test.go — drives the list-cursor query-param arms of
// the backup/restore list endpoints (parseListCursor / parseIntStrict in
// backup.go) that the existing backup_test.go happy-path coverage doesn't hit:
// bad ?limit, huge ?limit (clamp), bad ?before, valid ?before cursor. DB-only,
// runs under CI's postgres matrix.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBackup_ListCursor_Arms(t *testing.T) {
	f := setupBackupFixture(t, "pro")

	cases := []struct {
		name   string
		suffix string
		code   int
	}{
		{"backups_bad_limit", "/backups?limit=abc", http.StatusBadRequest},
		{"backups_zero_limit", "/backups?limit=0", http.StatusBadRequest},
		{"backups_negative_limit", "/backups?limit=-1", http.StatusBadRequest},
		{"backups_huge_limit_clamps_ok", "/backups?limit=999999", http.StatusOK},
		{"backups_bad_before", "/backups?before=not-a-time", http.StatusBadRequest},
		{"backups_valid_before_rfc3339", "/backups?before=2026-01-02T03:04:05Z", http.StatusOK},
		{"backups_valid_before_nano", "/backups?before=2026-01-02T03:04:05.123456Z", http.StatusOK},
		{"restores_bad_limit", "/restores?limit=xyz", http.StatusBadRequest},
		{"restores_huge_limit_clamps_ok", "/restores?limit=500000", http.StatusOK},
		{"restores_bad_before", "/restores?before=garbage", http.StatusBadRequest},
		{"restores_valid_before", "/restores?before=2026-01-02T03:04:05Z", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doBackupRequest(t, f.app, http.MethodGet, f.jwt, f.resourceToken, tc.suffix, nil)
			assert.Equal(t, tc.code, resp.StatusCode)
			resp.Body.Close()
		})
	}
}
