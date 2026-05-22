package models

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func auditCols() []string {
	return []string{"id", "team_id", "user_id", "actor", "kind", "resource_type", "resource_id", "summary", "metadata", "created_at"}
}

func TestInsertAuditEvent_Branches(t *testing.T) {
	ctx := context.Background()

	// happy with all optional fields populated (actor default + team + resource)
	db, mock := newMock(t)
	mock.ExpectExec(`INSERT INTO audit_log`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, InsertAuditEvent(ctx, db, AuditEvent{
		TeamID:       uuid.New(),
		ResourceType: ResourceTypePostgres,
		ResourceID:   uuid.NullUUID{UUID: uuid.New(), Valid: true},
		Kind:         AuditKindResourceRead,
		Metadata:     []byte(`{"a":1}`),
	}))

	// happy minimal (nil team, empty actor->agent, empty resource type)
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`INSERT INTO audit_log`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, InsertAuditEvent(ctx, db2, AuditEvent{Kind: AuditKindAuthLogin}))

	// db error
	db3, mock3 := newMock(t)
	mock3.ExpectExec(`INSERT INTO audit_log`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, InsertAuditEvent(ctx, db3, AuditEvent{Kind: "x"}), "boom")
}

func TestSubscriptionChangeAuditExists_Branches(t *testing.T) {
	ctx := context.Background()

	ok, err := SubscriptionChangeAuditExists(ctx, nil, uuid.New(), AuditKindSubscriptionUpgraded, "")
	require.NoError(t, err)
	require.False(t, ok)

	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	ok, err = SubscriptionChangeAuditExists(ctx, db, uuid.New(), AuditKindSubscriptionUpgraded, "sub")
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT EXISTS`).WillReturnError(errors.New("boom"))
	_, err = SubscriptionChangeAuditExists(ctx, db2, uuid.New(), AuditKindSubscriptionUpgraded, "sub")
	require.ErrorContains(t, err, "boom")
}

func TestListAuditEventsForCustomerExport_Branches(t *testing.T) {
	ctx := context.Background()

	// happy with every optional filter set (exercises the dynamic builder)
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM audit_log`).
		WillReturnRows(sqlmock.NewRows(auditCols()).AddRow(uuid.New(), uuid.New(), nil, "agent", "k", "postgres", nil, "s", []byte(`{}`), time.Now()))
	out, err := ListAuditEventsForCustomerExport(ctx, db, AuditCustomerExportQuery{
		TeamID: uuid.New(), Limit: 999, Before: time.Now(), Since: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour), Kind: "k", LookbackS: 3600,
	})
	require.NoError(t, err)
	require.Len(t, out, 1)

	// default limit path + query error
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM audit_log`).WillReturnError(errors.New("qerr"))
	_, err = ListAuditEventsForCustomerExport(ctx, db2, AuditCustomerExportQuery{TeamID: uuid.New()})
	require.ErrorContains(t, err, "qerr")

	// scan error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM audit_log`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListAuditEventsForCustomerExport(ctx, db3, AuditCustomerExportQuery{TeamID: uuid.New()})
	require.Error(t, err)

	// rows.Err()
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM audit_log`).WillReturnRows(
		sqlmock.NewRows(auditCols()).AddRow(uuid.New(), uuid.New(), nil, "agent", "k", "", nil, "s", nil, time.Now()).RowError(0, errors.New("rowerr")))
	_, err = ListAuditEventsForCustomerExport(ctx, db4, AuditCustomerExportQuery{TeamID: uuid.New()})
	require.ErrorContains(t, err, "rowerr")
}

func TestListAuditEventsByTeam_Branches(t *testing.T) {
	ctx := context.Background()

	// no kind filter + default limit
	db, mock := newMock(t)
	mock.ExpectQuery(`WHERE team_id = \$1\s+ORDER BY`).
		WillReturnRows(sqlmock.NewRows(auditCols()).AddRow(uuid.New(), uuid.New(), nil, "agent", "k", "", nil, "s", []byte(`{}`), time.Now()))
	out, err := ListAuditEventsByTeam(ctx, db, uuid.New(), 0, "")
	require.NoError(t, err)
	require.Len(t, out, 1)

	// kind filter + over-max limit
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE team_id = \$1 AND kind = \$2`).
		WillReturnRows(sqlmock.NewRows(auditCols()))
	_, err = ListAuditEventsByTeam(ctx, db2, uuid.New(), 9999, "auth.login")
	require.NoError(t, err)

	// query error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM audit_log`).WillReturnError(errors.New("qerr"))
	_, err = ListAuditEventsByTeam(ctx, db3, uuid.New(), 10, "")
	require.ErrorContains(t, err, "qerr")

	// scan error
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM audit_log`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListAuditEventsByTeam(ctx, db4, uuid.New(), 10, "")
	require.Error(t, err)

	// rows.Err()
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`FROM audit_log`).WillReturnRows(
		sqlmock.NewRows(auditCols()).AddRow(uuid.New(), uuid.New(), nil, "agent", "k", "", nil, "s", nil, time.Now()).RowError(0, errors.New("rowerr")))
	_, err = ListAuditEventsByTeam(ctx, db5, uuid.New(), 10, "")
	require.ErrorContains(t, err, "rowerr")
}
