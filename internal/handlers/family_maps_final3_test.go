package handlers_test

// family_maps_final3_test.go — FINAL serial pass #3. Exercises the Name.Valid /
// !Valid and ParentResourceID nil/non-nil arms of familyMemberSummaryToMap and
// familyMemberToMap (resource_family.go) directly via the exporters — pure
// rendering helpers, no DB needed.

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
)

func TestFamilyMapsFinal3_SummaryToMap_NameBranches(t *testing.T) {
	withName := handlers.FamilyMemberSummaryToMapForTest(models.FamilyMember{
		ID: uuid.New(), Token: uuid.New(), Env: "production",
		ResourceType: "postgres", Tier: "pro", Status: "active", IsRoot: true,
		Name: sql.NullString{String: "primary-db", Valid: true},
	})
	assert.Equal(t, "primary-db", withName["name"])

	noName := handlers.FamilyMemberSummaryToMapForTest(models.FamilyMember{
		ID: uuid.New(), Token: uuid.New(), Env: "staging",
		ResourceType: "redis", Tier: "pro", Status: "active", IsRoot: false,
		Name: sql.NullString{Valid: false},
	})
	_, has := noName["name"]
	assert.False(t, has, "no name key when Name is NULL")
}

func TestFamilyMapsFinal3_MemberToMap_NameAndParentBranches(t *testing.T) {
	parent := uuid.New()
	withNameAndParent := handlers.FamilyMemberToMapForTest(&models.Resource{
		ID: uuid.New(), Token: uuid.New(), Env: "staging",
		ResourceType: "postgres", Tier: "pro", Status: "active",
		Name:             sql.NullString{String: "twin-db", Valid: true},
		ParentResourceID: &parent,
	})
	assert.Equal(t, "twin-db", withNameAndParent["name"])
	assert.Equal(t, parent.String(), withNameAndParent["parent_resource_id"])

	rootNoName := handlers.FamilyMemberToMapForTest(&models.Resource{
		ID: uuid.New(), Token: uuid.New(), Env: "production",
		ResourceType: "postgres", Tier: "pro", Status: "active",
		Name:             sql.NullString{Valid: false},
		ParentResourceID: nil,
	})
	_, has := rootNoName["name"]
	assert.False(t, has, "no name key when Name is NULL")
	assert.Equal(t, "", rootNoName["parent_resource_id"], "root has empty parent_resource_id")
}
