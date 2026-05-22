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

func TestFamilyLinkError(t *testing.T) {
	require.Equal(t, "detail", (&FamilyLinkError{Detail: "detail"}).Error())
}

func TestGetResourceFamily_Branches(t *testing.T) {
	ctx := context.Background()
	root := uuid.New()

	// root not found
	db, mock := newMock(t)
	mock.ExpectQuery(`WITH RECURSIVE chain`).WillReturnError(errNoRows())
	out, err := GetResourceFamily(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Nil(t, out)

	// root walk error
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WITH RECURSIVE chain`).WillReturnError(errors.New("walkerr"))
	_, err = GetResourceFamily(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "walkerr")

	// happy
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WITH RECURSIVE chain`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(root))
	mock3.ExpectQuery(`FROM resources\s+WHERE \(id = \$1 OR parent_resource_id`).WillReturnRows(resourceMockRow())
	out, err = GetResourceFamily(ctx, db3, uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	// fetch query error
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`WITH RECURSIVE chain`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(root))
	mock4.ExpectQuery(`FROM resources\s+WHERE \(id = \$1 OR parent_resource_id`).WillReturnError(errors.New("fetcherr"))
	_, err = GetResourceFamily(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "fetcherr")

	// scan error
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`WITH RECURSIVE chain`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(root))
	mock5.ExpectQuery(`FROM resources\s+WHERE \(id = \$1 OR parent_resource_id`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = GetResourceFamily(ctx, db5, uuid.New())
	require.Error(t, err)

	// rows.Err()
	db6, mock6 := newMock(t)
	mock6.ExpectQuery(`WITH RECURSIVE chain`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(root))
	mock6.ExpectQuery(`FROM resources\s+WHERE \(id = \$1 OR parent_resource_id`).WillReturnRows(resourceMockRow().RowError(0, errors.New("rowerr")))
	_, err = GetResourceFamily(ctx, db6, uuid.New())
	require.ErrorContains(t, err, "rowerr")
}

func TestFindFamilyMemberByEnv_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`AND env = \$2`).WillReturnRows(resourceMockRow())
	r, err := FindFamilyMemberByEnv(ctx, db, uuid.New(), "prod")
	require.NoError(t, err)
	require.NotNil(t, r)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`AND env = \$2`).WillReturnError(errNoRows())
	r, err = FindFamilyMemberByEnv(ctx, db2, uuid.New(), "prod")
	require.NoError(t, err)
	require.Nil(t, r)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`AND env = \$2`).WillReturnError(errors.New("boom"))
	_, err = FindFamilyMemberByEnv(ctx, db3, uuid.New(), "prod")
	require.ErrorContains(t, err, "boom")
}

func TestListResourceFamiliesByTeam_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`WHERE team_id = \$1 AND status != 'deleted'`).WillReturnRows(resourceMockRow())
	out, err := ListResourceFamiliesByTeam(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE team_id = \$1 AND status != 'deleted'`).WillReturnError(errors.New("qerr"))
	_, err = ListResourceFamiliesByTeam(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WHERE team_id = \$1 AND status != 'deleted'`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListResourceFamiliesByTeam(ctx, db3, uuid.New())
	require.Error(t, err)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`WHERE team_id = \$1 AND status != 'deleted'`).WillReturnRows(resourceMockRow().RowError(0, errors.New("rowerr")))
	_, err = ListResourceFamiliesByTeam(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "rowerr")
}

func TestGetResourceByID_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM resources WHERE id`).WillReturnRows(resourceMockRow())
	_, err := GetResourceByID(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM resources WHERE id`).WillReturnError(errNoRows())
	_, err = GetResourceByID(ctx, db2, uuid.New())
	var nf *ErrResourceNotFound
	require.ErrorAs(t, err, &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM resources WHERE id`).WillReturnError(errors.New("boom"))
	_, err = GetResourceByID(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")
}

// resourceMockRowWith builds a parent-typed/team-typed resource row so the
// ValidateFamilyParent branches (cross-team, cross-type, deleted, twin) are
// reachable.
func resourceMockRowWith(team uuid.UUID, status, resType string, parent *uuid.UUID) *sqlmock.Rows {
	var p interface{}
	if parent != nil {
		p = *parent
	}
	return sqlmock.NewRows(resourceMockCols()).AddRow(
		uuid.New(), team, uuid.New(), resType, nil, nil, nil, "hobby",
		"production", nil, nil, nil, status, nil,
		nil, int64(0), nil, nil, p, nil,
		nil, false, nil, nil, "isolated", time.Now(),
	)
}

func TestValidateFamilyParent_Branches(t *testing.T) {
	ctx := context.Background()
	team := uuid.New()

	// parent not found -> deleted_parent
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM resources WHERE id`).WillReturnError(errNoRows())
	_, err := ValidateFamilyParent(ctx, db, uuid.New(), team, "postgres", "staging")
	var fle *FamilyLinkError
	require.ErrorAs(t, err, &fle)
	require.Equal(t, "deleted_parent", fle.Reason)

	// parent lookup transient error -> bubbled
	db1b, mock1b := newMock(t)
	mock1b.ExpectQuery(`FROM resources WHERE id`).WillReturnError(errors.New("boom"))
	_, err = ValidateFamilyParent(ctx, db1b, uuid.New(), team, "postgres", "staging")
	require.ErrorContains(t, err, "boom")

	// parent deleted status -> deleted_parent
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM resources WHERE id`).WillReturnRows(resourceMockRowWith(team, "deleted", "postgres", nil))
	_, err = ValidateFamilyParent(ctx, db2, uuid.New(), team, "postgres", "staging")
	require.ErrorAs(t, err, &fle)
	require.Equal(t, "deleted_parent", fle.Reason)

	// cross team
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM resources WHERE id`).WillReturnRows(resourceMockRowWith(uuid.New(), "active", "postgres", nil))
	_, err = ValidateFamilyParent(ctx, db3, uuid.New(), team, "postgres", "staging")
	require.ErrorAs(t, err, &fle)
	require.Equal(t, "cross_team", fle.Reason)

	// cross type
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM resources WHERE id`).WillReturnRows(resourceMockRowWith(team, "active", "redis", nil))
	_, err = ValidateFamilyParent(ctx, db4, uuid.New(), team, "postgres", "staging")
	require.ErrorAs(t, err, &fle)
	require.Equal(t, "cross_type", fle.Reason)

	// duplicate twin (FindFamilyMemberByEnv returns a row)
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`FROM resources WHERE id`).WillReturnRows(resourceMockRowWith(team, "active", "postgres", nil))
	mock5.ExpectQuery(`AND env = \$2`).WillReturnRows(resourceMockRow())
	_, err = ValidateFamilyParent(ctx, db5, uuid.New(), team, "postgres", "staging")
	require.ErrorAs(t, err, &fle)
	require.Equal(t, "duplicate_twin", fle.Reason)

	// FindFamilyMemberByEnv error path
	db6, mock6 := newMock(t)
	mock6.ExpectQuery(`FROM resources WHERE id`).WillReturnRows(resourceMockRowWith(team, "active", "postgres", nil))
	mock6.ExpectQuery(`AND env = \$2`).WillReturnError(errors.New("twinerr"))
	_, err = ValidateFamilyParent(ctx, db6, uuid.New(), team, "postgres", "staging")
	require.ErrorContains(t, err, "twinerr")

	// happy with parent having its own parent (root resolution branch)
	grandparent := uuid.New()
	db7, mock7 := newMock(t)
	mock7.ExpectQuery(`FROM resources WHERE id`).WillReturnRows(resourceMockRowWith(team, "active", "postgres", &grandparent))
	mock7.ExpectQuery(`AND env = \$2`).WillReturnError(errNoRows())
	rootID, err := ValidateFamilyParent(ctx, db7, uuid.New(), team, "postgres", "staging")
	require.NoError(t, err)
	require.Equal(t, grandparent, rootID)
}
