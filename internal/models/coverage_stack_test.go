package models

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestStackErrorAndHelpers(t *testing.T) {
	require.Contains(t, (&ErrStackNotFound{Slug: "s"}).Error(), "s")

	slug, err := GenerateStackSlug()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(slug, "stk-"))

	require.True(t, IsStackActive("building"))
	require.True(t, IsStackActive("deploying"))
	require.True(t, IsStackActive("healthy"))
	require.False(t, IsStackActive("failed"))
	require.False(t, IsStackActive("stopped"))
}

func TestGetStackBySlug_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM stacks WHERE slug`).WillReturnRows(stackMockRow())
	_, err := GetStackBySlug(ctx, db, "slug")
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM stacks WHERE slug`).WillReturnError(errNoRows())
	var nf *ErrStackNotFound
	_, err = GetStackBySlug(ctx, db2, "slug")
	require.ErrorAs(t, err, &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM stacks WHERE slug`).WillReturnError(errors.New("boom"))
	_, err = GetStackBySlug(ctx, db3, "slug")
	require.ErrorContains(t, err, "boom")
}

func TestGetStackByID_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM stacks WHERE id`).WillReturnRows(stackMockRow())
	_, err := GetStackByID(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM stacks WHERE id`).WillReturnError(errNoRows())
	var nf *ErrStackNotFound
	_, err = GetStackByID(ctx, db2, uuid.New())
	require.ErrorAs(t, err, &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM stacks WHERE id`).WillReturnError(errors.New("boom"))
	_, err = GetStackByID(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestGetStacksByTeam_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM stacks\s+WHERE team_id`).WillReturnRows(stackMockRow())
	out, err := GetStacksByTeam(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM stacks\s+WHERE team_id`).WillReturnError(errors.New("qerr"))
	_, err = GetStacksByTeam(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM stacks\s+WHERE team_id`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = GetStacksByTeam(ctx, db3, uuid.New())
	require.Error(t, err)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM stacks\s+WHERE team_id`).WillReturnRows(stackMockRow().RowError(0, errors.New("rowerr")))
	_, err = GetStacksByTeam(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "rowerr")
}

func TestGetStackFamily_Branches(t *testing.T) {
	ctx := context.Background()
	root := uuid.New()

	// root not found -> nil
	db, mock := newMock(t)
	mock.ExpectQuery(`WITH RECURSIVE chain`).WillReturnError(errNoRows())
	out, err := GetStackFamily(ctx, db, uuid.New(), uuid.New())
	require.NoError(t, err)
	require.Nil(t, out)

	// root walk error
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WITH RECURSIVE chain`).WillReturnError(errors.New("walkerr"))
	_, err = GetStackFamily(ctx, db2, uuid.New(), uuid.New())
	require.ErrorContains(t, err, "walkerr")

	// happy
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WITH RECURSIVE chain`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(root))
	mock3.ExpectQuery(`AND \(id = \$2 OR parent_stack_id = \$2\)`).WillReturnRows(stackMockRow())
	out, err = GetStackFamily(ctx, db3, uuid.New(), uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	// fetch error
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`WITH RECURSIVE chain`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(root))
	mock4.ExpectQuery(`AND \(id = \$2 OR parent_stack_id = \$2\)`).WillReturnError(errors.New("fetcherr"))
	_, err = GetStackFamily(ctx, db4, uuid.New(), uuid.New())
	require.ErrorContains(t, err, "fetcherr")

	// scan error
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`WITH RECURSIVE chain`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(root))
	mock5.ExpectQuery(`AND \(id = \$2 OR parent_stack_id = \$2\)`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = GetStackFamily(ctx, db5, uuid.New(), uuid.New())
	require.Error(t, err)
}

func TestFindStackByEnvInFamily_Branches(t *testing.T) {
	ctx := context.Background()
	root := uuid.New()

	// match
	db, mock := newMock(t)
	mock.ExpectQuery(`WITH RECURSIVE chain`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(root))
	mock.ExpectQuery(`AND \(id = \$2 OR parent_stack_id = \$2\)`).WillReturnRows(stackMockRow()) // env=production
	got, err := FindStackByEnvInFamily(ctx, db, uuid.New(), uuid.New(), "production")
	require.NoError(t, err)
	require.NotNil(t, got)

	// no match
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WITH RECURSIVE chain`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(root))
	mock2.ExpectQuery(`AND \(id = \$2 OR parent_stack_id = \$2\)`).WillReturnRows(stackMockRow())
	got, err = FindStackByEnvInFamily(ctx, db2, uuid.New(), uuid.New(), "staging")
	require.NoError(t, err)
	require.Nil(t, got)

	// family error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WITH RECURSIVE chain`).WillReturnError(errors.New("boom"))
	_, err = FindStackByEnvInFamily(ctx, db3, uuid.New(), uuid.New(), "prod")
	require.ErrorContains(t, err, "boom")
}

func TestUpdateStackStatus_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE stacks\s+SET status`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateStackStatus(ctx, db, uuid.New(), "healthy", ""))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE stacks\s+SET status`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateStackStatus(ctx, db2, uuid.New(), "healthy", ""), "boom")
}

func TestGetExpiredStacks_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`WHERE expires_at IS NOT NULL`).WillReturnRows(stackMockRow())
	out, err := GetExpiredStacks(ctx, db)
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE expires_at IS NOT NULL`).WillReturnError(errors.New("qerr"))
	_, err = GetExpiredStacks(ctx, db2)
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WHERE expires_at IS NOT NULL`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = GetExpiredStacks(ctx, db3)
	require.Error(t, err)
}

func TestElevateStackTiersByTeam_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE stacks`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, ElevateStackTiersByTeam(ctx, db, uuid.New(), "pro"))
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE stacks`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, ElevateStackTiersByTeam(ctx, db2, uuid.New(), "pro"), "boom")
}

func TestDeleteStack_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`DELETE FROM stacks`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, DeleteStack(ctx, db, uuid.New()))
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`DELETE FROM stacks`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, DeleteStack(ctx, db2, uuid.New()), "boom")
}

func TestCreateStackService_Branches(t *testing.T) {
	ctx := context.Background()
	// happy with default port + image ref
	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO stack_services`).WillReturnRows(stackServiceMockRow())
	_, err := CreateStackService(ctx, db, CreateStackServiceParams{StackID: uuid.New(), Name: "svc", ImageRef: "img"})
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO stack_services`).WillReturnError(errors.New("boom"))
	_, err = CreateStackService(ctx, db2, CreateStackServiceParams{StackID: uuid.New(), Name: "svc", Port: 9000})
	require.ErrorContains(t, err, "boom")
}

func TestGetStackServicesByStack_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM stack_services`).WillReturnRows(stackServiceMockRow())
	out, err := GetStackServicesByStack(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM stack_services`).WillReturnError(errors.New("qerr"))
	_, err = GetStackServicesByStack(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM stack_services`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = GetStackServicesByStack(ctx, db3, uuid.New())
	require.Error(t, err)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM stack_services`).WillReturnRows(stackServiceMockRow().RowError(0, errors.New("rowerr")))
	_, err = GetStackServicesByStack(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "rowerr")
}

func TestUpdateStackServiceMutators_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE stack_services\s+SET status`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateStackServiceStatus(ctx, db, uuid.New(), "healthy", "http://x", "")) // appURL set, errMsg empty
	db1b, mock1b := newMock(t)
	mock1b.ExpectExec(`UPDATE stack_services\s+SET status`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateStackServiceStatus(ctx, db1b, uuid.New(), "failed", "", "oops"), "boom")

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE stack_services SET image_tag`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateStackServiceImageTag(ctx, db2, uuid.New(), "tag"))
	db2b, mock2b := newMock(t)
	mock2b.ExpectExec(`UPDATE stack_services SET image_tag`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateStackServiceImageTag(ctx, db2b, uuid.New(), "tag"), "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE stack_services SET image_ref`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateStackServiceImageRef(ctx, db3, uuid.New(), "ref"))
	db3b, mock3b := newMock(t)
	mock3b.ExpectExec(`UPDATE stack_services SET image_ref`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateStackServiceImageRef(ctx, db3b, uuid.New(), "ref"), "boom")
}

func TestGetStackEnvVars_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT COALESCE\(env_vars`).WillReturnRows(sqlmock.NewRows([]string{"env_vars"}).AddRow([]byte(`{"K":"V"}`)))
	out, err := GetStackEnvVars(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Equal(t, "V", out["K"])

	// empty raw -> empty map
	db1b, mock1b := newMock(t)
	mock1b.ExpectQuery(`SELECT COALESCE\(env_vars`).WillReturnRows(sqlmock.NewRows([]string{"env_vars"}).AddRow([]byte{}))
	out, err = GetStackEnvVars(ctx, db1b, uuid.New())
	require.NoError(t, err)
	require.Empty(t, out)

	// not found
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT COALESCE\(env_vars`).WillReturnError(errNoRows())
	var nf *ErrStackNotFound
	_, err = GetStackEnvVars(ctx, db2, uuid.New())
	require.ErrorAs(t, err, &nf)

	// db error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`SELECT COALESCE\(env_vars`).WillReturnError(errors.New("boom"))
	_, err = GetStackEnvVars(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")

	// unmarshal error
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`SELECT COALESCE\(env_vars`).WillReturnRows(sqlmock.NewRows([]string{"env_vars"}).AddRow([]byte(`not json`)))
	_, err = GetStackEnvVars(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "unmarshal")
}

func TestUpdateStackEnvVars_Branches(t *testing.T) {
	ctx := context.Background()

	// nil map -> empty + happy
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE stacks SET env_vars`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateStackEnvVars(ctx, db, uuid.New(), nil))

	// too large
	big := map[string]string{}
	big["k"] = strings.Repeat("x", maxStackEnvVarsBytes+1)
	require.ErrorIs(t, UpdateStackEnvVars(ctx, nil, uuid.New(), big), ErrStackEnvVarsTooLarge)

	// not found (0 rows)
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE stacks SET env_vars`).WillReturnResult(sqlmock.NewResult(0, 0))
	var nf *ErrStackNotFound
	require.ErrorAs(t, UpdateStackEnvVars(ctx, db2, uuid.New(), map[string]string{"a": "b"}), &nf)

	// db error
	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE stacks SET env_vars`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateStackEnvVars(ctx, db3, uuid.New(), map[string]string{"a": "b"}), "boom")
}

// TestMergeStackEnvVars_Branches exercises every error/return arm of the atomic
// PATCH merge with sqlmock: BeginTx error, select→NotFound, select error,
// unmarshal error, over-cap rollback, update error, commit error, and the happy
// path (upsert + present-key delete counting). The real-DB serialization proof
// lives in handlers' TestMergeStackEnvVars_ConcurrentPatchesNoLostUpdate.
func TestMergeStackEnvVars_Branches(t *testing.T) {
	ctx := context.Background()
	id := uuid.New()
	patch := map[string]string{"A": "1"}

	// 1) BeginTx error.
	dbB, mockB := newMock(t)
	mockB.ExpectBegin().WillReturnError(errors.New("begin-boom"))
	_, _, err := MergeStackEnvVars(ctx, dbB, id, patch)
	require.ErrorContains(t, err, "begin-boom")

	// 2) SELECT ... FOR UPDATE → no rows → ErrStackNotFound (rolls back).
	dbNF, mockNF := newMock(t)
	mockNF.ExpectBegin()
	mockNF.ExpectQuery(`SELECT COALESCE\(env_vars.*FOR UPDATE`).WillReturnError(errNoRows())
	mockNF.ExpectRollback()
	var nf *ErrStackNotFound
	_, _, err = MergeStackEnvVars(ctx, dbNF, id, patch)
	require.ErrorAs(t, err, &nf)

	// 3) SELECT error (non-NoRows).
	dbSE, mockSE := newMock(t)
	mockSE.ExpectBegin()
	mockSE.ExpectQuery(`SELECT COALESCE\(env_vars.*FOR UPDATE`).WillReturnError(errors.New("sel-boom"))
	mockSE.ExpectRollback()
	_, _, err = MergeStackEnvVars(ctx, dbSE, id, patch)
	require.ErrorContains(t, err, "sel-boom")

	// 4) unmarshal error (malformed jsonb).
	dbUM, mockUM := newMock(t)
	mockUM.ExpectBegin()
	mockUM.ExpectQuery(`SELECT COALESCE\(env_vars.*FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"env_vars"}).AddRow([]byte(`not json`)))
	mockUM.ExpectRollback()
	_, _, err = MergeStackEnvVars(ctx, dbUM, id, patch)
	require.ErrorContains(t, err, "unmarshal")

	// 5) over-cap → ErrStackEnvVarsTooLarge, checked BEFORE the UPDATE (rolls back).
	dbTL, mockTL := newMock(t)
	mockTL.ExpectBegin()
	mockTL.ExpectQuery(`SELECT COALESCE\(env_vars.*FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"env_vars"}).AddRow([]byte(`{}`)))
	mockTL.ExpectRollback()
	big := map[string]string{"K": strings.Repeat("x", maxStackEnvVarsBytes+1)}
	_, _, err = MergeStackEnvVars(ctx, dbTL, id, big)
	require.ErrorIs(t, err, ErrStackEnvVarsTooLarge)

	// 6) UPDATE error.
	dbUE, mockUE := newMock(t)
	mockUE.ExpectBegin()
	mockUE.ExpectQuery(`SELECT COALESCE\(env_vars.*FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"env_vars"}).AddRow([]byte(`{}`)))
	mockUE.ExpectExec(`UPDATE stacks SET env_vars`).WillReturnError(errors.New("upd-boom"))
	mockUE.ExpectRollback()
	_, _, err = MergeStackEnvVars(ctx, dbUE, id, patch)
	require.ErrorContains(t, err, "upd-boom")

	// 7) Commit error.
	dbCE, mockCE := newMock(t)
	mockCE.ExpectBegin()
	mockCE.ExpectQuery(`SELECT COALESCE\(env_vars.*FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"env_vars"}).AddRow([]byte(`{}`)))
	mockCE.ExpectExec(`UPDATE stacks SET env_vars`).WillReturnResult(sqlmock.NewResult(0, 1))
	mockCE.ExpectCommit().WillReturnError(errors.New("commit-boom"))
	_, _, err = MergeStackEnvVars(ctx, dbCE, id, patch)
	require.ErrorContains(t, err, "commit-boom")

	// 8) Happy path: existing {A:old, B:keep}; patch upserts A, adds C, deletes B
	//    (present → counted) and deletes MISSING (absent → NOT counted).
	dbOK, mockOK := newMock(t)
	mockOK.ExpectBegin()
	mockOK.ExpectQuery(`SELECT COALESCE\(env_vars.*FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"env_vars"}).AddRow([]byte(`{"A":"old","B":"keep"}`)))
	mockOK.ExpectExec(`UPDATE stacks SET env_vars`).WillReturnResult(sqlmock.NewResult(0, 1))
	mockOK.ExpectCommit()
	merged, deletes, err := MergeStackEnvVars(ctx, dbOK, id,
		map[string]string{"A": "new", "C": "3", "B": "", "MISSING": ""})
	require.NoError(t, err)
	require.Equal(t, 1, deletes, "only the present key B counts as a delete")
	require.Equal(t, map[string]string{"A": "new", "C": "3"}, merged)
}
