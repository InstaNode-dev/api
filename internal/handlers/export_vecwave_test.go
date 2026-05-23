package handlers

// export_vecwave_test.go — test-only exports for the coverage push on
// vector.go / backup.go / github_deploy.go / resource.go (the _vecwave wave).
// Go compiles this only into the test binary (filename suffix _test.go), so
// none of these helpers widen the package's public surface in production
// builds.

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"instant.dev/internal/config"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

// VectorDecryptConnectionURLForTest re-exports VectorHandler.decryptConnectionURL
// so the external handlers_test package can drive its three arms (empty input,
// valid-ciphertext happy path, bad-AES-key fail-closed) directly. The only
// production caller is the anonymous over-cap dedup branch of NewVector, which
// is fingerprint-birthday-collision-flaky to reach end-to-end.
func VectorDecryptConnectionURLForTest(h *VectorHandler, encrypted, requestID string) (string, bool) {
	return h.decryptConnectionURL(encrypted, requestID)
}

// NewResourceHandlerWithBackendsForTest constructs a ResourceHandler with the
// supplied customer-DB / mongo-admin URIs wired so the pause/resume provider
// happy-path arms (revokePostgresConnect / grantPostgresConnect /
// setRedisACLEnabled / revokeMongoRoles / grantMongoRoles) connect to real
// backends. nil rdb is tolerated by the helpers under test (they don't touch
// Redis directly — setRedisACLEnabled opens its own client from the URL).
func NewResourceHandlerWithBackendsForTest(db *sql.DB, cfg *config.Config, reg *plans.Registry) *ResourceHandler {
	return NewResourceHandler(db, nil, cfg, reg, nil, nil)
}

// CallPauseProviderForTest invokes ResourceHandler.pauseProvider against a
// models.Resource built from the supplied fields. Returns the provider error so
// the test can assert the happy (nil) path of each resource-type arm.
func CallPauseProviderForTest(h *ResourceHandler, ctx context.Context, resourceType, token, encryptedConnURL string) error {
	r := buildResourceForProviderTest(resourceType, token, encryptedConnURL)
	return h.pauseProvider(ctx, r)
}

// CallResumeProviderForTest is the inverse — invokes ResourceHandler.resumeProvider.
func CallResumeProviderForTest(h *ResourceHandler, ctx context.Context, resourceType, token, encryptedConnURL string) error {
	r := buildResourceForProviderTest(resourceType, token, encryptedConnURL)
	return h.resumeProvider(ctx, r)
}

func buildResourceForProviderTest(resourceType, token, encryptedConnURL string) *models.Resource {
	r := &models.Resource{
		Token:        uuid.MustParse(token),
		ResourceType: resourceType,
	}
	if encryptedConnURL != "" {
		r.ConnectionURL = sql.NullString{String: encryptedConnURL, Valid: true}
	}
	return r
}
