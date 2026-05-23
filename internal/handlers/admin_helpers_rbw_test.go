package handlers_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/plans"
)

// TestAdminParseTierFilter covers every documented return case.
func TestAdminParseTierFilter(t *testing.T) {
	out, empty := handlers.AdminParseTierFilterForTest("")
	require.Nil(t, out)
	require.False(t, empty)

	out, empty = handlers.AdminParseTierFilterForTest("pro")
	require.Equal(t, []string{"pro"}, out)
	require.False(t, empty)

	out, _ = handlers.AdminParseTierFilterForTest("hobby, ,pro,HOBBY") // dedupe + case + whitespace
	require.Equal(t, []string{"hobby", "pro"}, out)

	out, empty = handlers.AdminParseTierFilterForTest("platinum") // all unknown
	require.Nil(t, out)
	require.True(t, empty)

	out, empty = handlers.AdminParseTierFilterForTest(" , , ") // only whitespace → no filter
	require.Nil(t, out)
	require.False(t, empty)

	out, _ = handlers.AdminParseTierFilterForTest("pro,platinum") // partial unknown
	require.Equal(t, []string{"pro"}, out)
}

// TestAdminParseLimit covers default / clamp-low / clamp-high / valid.
func TestAdminParseLimit(t *testing.T) {
	require.Equal(t, 25, handlers.AdminParseLimitForTest("", 25, 100))
	require.Equal(t, 25, handlers.AdminParseLimitForTest("abc", 25, 100))
	require.Equal(t, 25, handlers.AdminParseLimitForTest("0", 25, 100))
	require.Equal(t, 25, handlers.AdminParseLimitForTest("-3", 25, 100))
	require.Equal(t, 100, handlers.AdminParseLimitForTest("9999", 25, 100))
	require.Equal(t, 42, handlers.AdminParseLimitForTest(" 42 ", 25, 100))
}

// TestAdminParseOffset covers default / negative / valid.
func TestAdminParseOffset(t *testing.T) {
	require.Equal(t, 0, handlers.AdminParseOffsetForTest(""))
	require.Equal(t, 0, handlers.AdminParseOffsetForTest("xyz"))
	require.Equal(t, 0, handlers.AdminParseOffsetForTest("-1"))
	require.Equal(t, 7, handlers.AdminParseOffsetForTest(" 7 "))
}

// TestAdminOrderClause covers all sort keys + the invalid arm.
func TestAdminOrderClause(t *testing.T) {
	for _, sb := range []string{"", "mrr", "last_active", "created_at", "storage_bytes"} {
		clause, err := handlers.AdminOrderClauseForTest(sb)
		require.NoError(t, err, "sort_by=%q", sb)
		require.NotEmpty(t, clause)
	}
	_, err := handlers.AdminOrderClauseForTest("'; DROP TABLE--")
	require.Error(t, err)
}

// TestEscapeLikePattern covers the three metacharacters + backslash.
func TestEscapeLikePattern(t *testing.T) {
	require.Equal(t, `\%\_`, handlers.EscapeLikePatternForTest("%_"))
	require.Equal(t, `\\`, handlers.EscapeLikePatternForTest(`\`))
	require.Equal(t, "plain", handlers.EscapeLikePatternForTest("plain"))
}

// TestComputeMRR covers the nil-plans arm + the priced arm.
func TestComputeMRR(t *testing.T) {
	// nil plans → (0,0)
	hNil := handlers.NewAdminCustomersHandler(nil, nil)
	m, a := handlers.ComputeMRRForTest(hNil, "pro")
	require.Equal(t, 0, m)
	require.Equal(t, 0, a)

	// real registry → monthly>0 for a paid tier, annual = 12×monthly
	h := handlers.NewAdminCustomersHandler(nil, plans.Default())
	m, a = handlers.ComputeMRRForTest(h, "pro")
	require.Greater(t, m, 0)
	require.Equal(t, m*12, a)
}

// TestParsePromoAuditSince covers empty / RFC3339 / date-only / invalid.
func TestParsePromoAuditSince(t *testing.T) {
	tm, err := handlers.ParsePromoAuditSinceForTest("")
	require.NoError(t, err)
	require.True(t, tm.IsZero())

	tm, err = handlers.ParsePromoAuditSinceForTest("2026-05-20T10:00:00Z")
	require.NoError(t, err)
	require.False(t, tm.IsZero())

	tm, err = handlers.ParsePromoAuditSinceForTest("2026-05-20")
	require.NoError(t, err)
	require.Equal(t, 2026, tm.Year())

	_, err = handlers.ParsePromoAuditSinceForTest("not-a-date")
	require.Error(t, err)
}

var _ = errors.Is
var _ = time.Now