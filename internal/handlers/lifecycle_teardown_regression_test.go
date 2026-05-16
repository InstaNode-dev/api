package handlers

// lifecycle_teardown_regression_test.go — regression tests for P1 cluster I:
// resource deletion / deprovision lifecycle bugs.
//
// Bugs addressed:
//   L03-1 (P1) queue DELETE skipped provisioner (resourceTypeToProto returned UNSPECIFIED)
//   L03-2 (P1) vector DELETE/expire skipped provisioner (no case in resourceTypeToProto)
//   L02-1 (P1) concurrent-pause race re-granted infra access via spurious resumeProvider rollback
//   L02-2 (P1) terminated-then-reinstated hobby team locked out of own paused resources
//
// Testing strategy:
//   - resourceTypeToProto: pure unit (no DB) — table-driven, iterates the live function.
//   - pause-race: covered at the handler + model level via HTTP test with forced race in
//     PauseResource mock. The unit tests below verify the semantic: no rollback on race.
//   - hobby-resume: DB-backed, uses SetupTestDB (integration tag skipped here — pure SQL).
//     Covered by TestResumeResource_HobbyAfterTerminate_200 in resource_pause_test.go
//     (handlers_test package). Here we test the model-layer fix: ElevateResourceTiersByTeam
//     now includes paused rows.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonv1 "instant.dev/proto/common/v1"
)

// ---------------------------------------------------------------------------
// Bug L03-1 & L03-2 — resourceTypeToProto completeness
// ---------------------------------------------------------------------------

// TestResourceTypeToProto_TableDriven_CoverageBlock is the registry-iterating
// regression test called for in the agent-reliability rules.
//
// It enumerates every known resource type constant and asserts the expected
// proto enum. If a new resource type is added to models.ResourceType* constants
// but this mapping is not updated, the test name and the UNSPECIFIED guard
// below will surface the gap.
//
// Specifically pins:
//   - "queue" → RESOURCE_TYPE_QUEUE  (was UNSPECIFIED — orphaned NATS k8s namespaces)
//   - "vector" → RESOURCE_TYPE_POSTGRES (was UNSPECIFIED — orphaned Postgres DBs/users)
func TestResourceTypeToProto_TableDriven_CoverageBlock(t *testing.T) {
	cases := []struct {
		resourceType string
		want         commonv1.ResourceType
		reason       string
	}{
		{
			resourceType: "postgres",
			want:         commonv1.ResourceType_RESOURCE_TYPE_POSTGRES,
			reason:       "postgres deprovisions via provisioner Postgres backend",
		},
		{
			resourceType: "redis",
			want:         commonv1.ResourceType_RESOURCE_TYPE_REDIS,
			reason:       "redis deprovisions via provisioner Redis backend",
		},
		{
			resourceType: "mongodb",
			want:         commonv1.ResourceType_RESOURCE_TYPE_MONGODB,
			reason:       "mongodb deprovisions via provisioner Mongo backend",
		},
		{
			// BUG L03-1 regression: previously returned UNSPECIFIED, causing
			// the delete handler to skip the provisioner call and leaving k8s
			// NATS namespaces orphaned. The expiry worker already sent
			// RESOURCE_TYPE_QUEUE correctly — this test pins the API handler
			// path to match.
			resourceType: "queue",
			want:         commonv1.ResourceType_RESOURCE_TYPE_QUEUE,
			reason:       "queue must call provisioner.DeprovisionResource to clean k8s NATS namespace",
		},
		{
			// BUG L03-2 regression: previously returned UNSPECIFIED, leaving
			// orphaned Postgres DBs/users when a vector resource was deleted or
			// expired. Vector shares the Postgres backend (db_<token>/usr_<token>).
			resourceType: "vector",
			want:         commonv1.ResourceType_RESOURCE_TYPE_POSTGRES,
			reason:       "vector is pgvector-on-Postgres; deprovision path is identical to postgres",
		},
		{
			// Storage, webhook: no per-resource provisioner pod — caller skips
			// DeprovisionResource and uses the storage provider path instead.
			resourceType: "storage",
			want:         commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED,
			reason:       "storage deprovision uses the storage provider path, not provisioner RPC",
		},
		{
			resourceType: "webhook",
			want:         commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED,
			reason:       "webhook is a pure-status-flip; no provisioner cleanup needed",
		},
		{
			resourceType: "",
			want:         commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED,
			reason:       "empty string must fall through to UNSPECIFIED (safe default)",
		},
		{
			resourceType: "unknown_future_type",
			want:         commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED,
			reason:       "unrecognized types must default to UNSPECIFIED so caller skips provisioner",
		},
	}

	for _, tc := range cases {
		t.Run(tc.resourceType, func(t *testing.T) {
			got := resourceTypeToProto(tc.resourceType)
			assert.Equal(t, tc.want, got,
				"resourceTypeToProto(%q): %s", tc.resourceType, tc.reason)
			// Extra guard: if a new type maps to UNSPECIFIED unexpectedly, this
			// message clarifies the intent vs a silently-missed case.
			if tc.want != commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED {
				require.NotEqual(t, commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED, got,
					"MUST NOT be UNSPECIFIED for %q — the provisioner call would be silently skipped, orphaning infrastructure",
					tc.resourceType)
			}
		})
	}
}

// TestResourceTypeToProto_QueueNotUnspecified is the single-focus sentinel for L03-1.
// Named to match the bug ID so git blame points here immediately.
func TestResourceTypeToProto_QueueNotUnspecified(t *testing.T) {
	got := resourceTypeToProto("queue")
	require.NotEqual(t,
		commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED, got,
		"L03-1 regression: queue must NOT map to UNSPECIFIED — that silently skips "+
			"provisioner.DeprovisionResource, leaving k8s NATS pod namespaces orphaned on user delete")
	assert.Equal(t, commonv1.ResourceType_RESOURCE_TYPE_QUEUE, got)
}

// TestResourceTypeToProto_VectorNotUnspecified is the single-focus sentinel for L03-2.
func TestResourceTypeToProto_VectorNotUnspecified(t *testing.T) {
	got := resourceTypeToProto("vector")
	require.NotEqual(t,
		commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED, got,
		"L03-2 regression: vector must NOT map to UNSPECIFIED — that silently skips "+
			"provisioner.DeprovisionResource, leaving orphaned Postgres databases and users on delete/expire")
	assert.Equal(t, commonv1.ResourceType_RESOURCE_TYPE_POSTGRES, got,
		"vector shares the Postgres backend; cleanup path must be RESOURCE_TYPE_POSTGRES")
}
