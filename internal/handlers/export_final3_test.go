package handlers

// export_final3_test.go — test-only seam exporters for the FINAL serial pass #3.
//
// Only symbols NOT already re-exported in another export_*_test.go appear here
// (the existing files were grepped first). These wrap the package-level
// indirection seams added in stack.go / deploy.go / helpers.go so the external
// handlers_test package can force the otherwise-unreachable error/success arms.

import (
	"context"
	"crypto/x509"
	"database/sql"
	"mime/multipart"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/models"
	compute "instant.dev/internal/providers/compute"
	"instant.dev/internal/providers/compute/k8s"
)

// CacheInviteResponseForTest exposes (*TeamMembersHandler).cacheInviteResponse
// so the nil-rdb / dead-rdb store-error arms can be driven directly.
func (h *TeamMembersHandler) CacheInviteResponseForTest(ctx context.Context, teamID uuid.UUID, key string, status int, body fiber.Map) {
	h.cacheInviteResponse(ctx, teamID, key, status, body)
}

// EmitInviteAuditForTest exposes (*TeamMembersHandler).emitInviteAudit so the
// audit-insert-error arm can be driven with a fault DB.
func (h *TeamMembersHandler) EmitInviteAuditForTest(ctx context.Context, teamID, actorID, invID uuid.UUID, inviteEmail, role string) {
	h.emitInviteAudit(ctx, teamID, actorID, invID, inviteEmail, role)
}

// EmitPromoteAuditEventForTest exposes emitPromoteAuditEvent so the
// InsertAuditEvent-error arm can be driven with a fault DB.
func EmitPromoteAuditEventForTest(ctx context.Context, db *sql.DB, row *models.PromoteApproval, kind, summary string, extras map[string]any) {
	emitPromoteAuditEvent(ctx, db, row, kind, summary, extras)
}

// ResolveResourceBindingsForTest exposes resolveResourceBindings so its many
// rejection arms (bad-AES-key, invalid-UUID, family-disabled, family-not-found,
// cross-team, no-env-twin, token-not-found, deleted) can be driven directly
// against a seeded DB without standing up the full /deploy/new multipart path.
// Returns the resolved map and an error string ("" on success).
func ResolveResourceBindingsForTest(ctx context.Context, db *sql.DB, aesKeyHex string, teamID uuid.UUID, env string, bindings map[string]string, familyEnabled bool) (map[string]string, string) {
	out, berr := resolveResourceBindings(ctx, db, aesKeyHex, teamID, env, bindings, familyEnabled)
	if berr != nil {
		return out, string(berr.Kind)
	}
	return out, ""
}

// FamilyMemberSummaryToMapForTest exposes familyMemberSummaryToMap so the
// Name.Valid / !Valid arms can be exercised directly.
func FamilyMemberSummaryToMapForTest(m models.FamilyMember) fiber.Map {
	return familyMemberSummaryToMap(m)
}

// FamilyMemberToMapForTest exposes familyMemberToMap so the Name.Valid and
// ParentResourceID nil/non-nil arms can be exercised directly.
func FamilyMemberToMapForTest(r *models.Resource) fiber.Map {
	return familyMemberToMap(r)
}

// SetOpenMultipartFileForTest overrides the openMultipartFile seam (stack.go)
// and returns a restore func. Lets a test drive the tarball open-error and
// open-but-fail-read arms of stack.New / stack.Redeploy.
func SetOpenMultipartFileForTest(fn func(*multipart.FileHeader) (multipart.File, error)) (restore func()) {
	prev := openMultipartFile
	openMultipartFile = fn
	return func() { openMultipartFile = prev }
}

// SetNewK8sStackProviderForTest overrides the newK8sStackProvider seam so a
// test can exercise the cfg.ComputeProvider=="k8s" success branch of
// NewStackHandler without a live cluster.
func SetNewK8sStackProviderForTest(fn func(string, k8s.BuildContextConfig) (compute.StackProvider, error)) (restore func()) {
	prev := newK8sStackProvider
	newK8sStackProvider = fn
	return func() { newK8sStackProvider = prev }
}

// SetNewK8sComputeProviderForTest overrides the newK8sComputeProvider seam so a
// test can exercise the cfg.ComputeProvider=="k8s" success branch of
// NewDeployHandler without a live cluster.
func SetNewK8sComputeProviderForTest(fn func(string, k8s.BuildContextConfig) (compute.Provider, error)) (restore func()) {
	prev := newK8sComputeProvider
	newK8sComputeProvider = fn
	return func() { newK8sComputeProvider = prev }
}

// InvokeDefaultK8sStackProviderForTest invokes the REAL (default) value of the
// newK8sStackProvider seam so the seam's default closure body is covered. In a
// test env with no kube cluster this may error — the line still executes.
func InvokeDefaultK8sStackProviderForTest() (compute.StackProvider, error) {
	return newK8sStackProvider("instant-apps-test", k8s.BuildContextConfig{})
}

// InvokeDefaultK8sComputeProviderForTest invokes the REAL (default) value of the
// newK8sComputeProvider seam so the seam's default closure body is covered.
func InvokeDefaultK8sComputeProviderForTest() (compute.Provider, error) {
	return newK8sComputeProvider("instant-apps-test", k8s.BuildContextConfig{})
}

// SetRandReadForTest overrides the randRead seam (helpers.go) so a test can
// force the rand.Read error arm of generateAppID / generateOAuthState /
// generateSessionID.
func SetRandReadForTest(fn func([]byte) (int, error)) (restore func()) {
	prev := randRead
	randRead = fn
	return func() { randRead = prev }
}

// GenerateOAuthStateForTest exposes generateOAuthState.
func GenerateOAuthStateForTest() (string, error) { return generateOAuthState() }

// GenerateSessionIDForTest exposes generateSessionID.
func GenerateSessionIDForTest() (string, error) { return generateSessionID() }

// ShouldSetRetryAfterHeaderForTest exposes shouldSetRetryAfterHeader.
func ShouldSetRetryAfterHeaderForTest(status int) bool { return shouldSetRetryAfterHeader(status) }

// RespondProvisionFailedForTest exposes respondProvisionFailed so both arms
// (circuit.ErrOpen → provisioner_unavailable, and the generic provision_failed
// fallback) can be driven through a real *fiber.Ctx.
func RespondProvisionFailedForTest(c *fiber.Ctx, err error, fallbackMessage string) error {
	return respondProvisionFailed(c, err, fallbackMessage)
}

// NewAgentActionDeploymentLimitReachedForTest exposes
// newAgentActionDeploymentLimitReached so the per-tier copy branches
// (hobby/hobby_plus/default) can be exercised directly.
func NewAgentActionDeploymentLimitReachedForTest(tier string, limit int) string {
	return newAgentActionDeploymentLimitReached(tier, limit)
}

// FetchCertViaDefaultForTest constructs a production-shaped snsVerifier, points
// its httpClient at the supplied transport URL, and invokes the REAL
// defaultFetchCert (not an injected stub) so the cert-fetch success + error
// arms run without a live AWS endpoint.
func FetchCertViaDefaultForTest(client *http.Client, certURL string) (*x509.Certificate, error) {
	v := newSNSVerifier()
	if client != nil {
		v.httpClient = client
	}
	return v.defaultFetchCert("sns", certURL)
}

