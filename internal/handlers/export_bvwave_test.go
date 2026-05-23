package handlers

// export_bvwave_test.go — test-only export seams for the bv-wave coverage push
// (billing, vault, twin, custom_domain, deletion_confirm, webhook, storage).
//
// Only the seams NOT already provided by the other export_*_test.go files in
// this package live here (grep confirmed no collisions). Each export is a thin
// pass-through to an unexported symbol so the external handlers_test package can
// drive arms that are otherwise reachable only through a full router wired with
// live infra.

import (
	"context"
	"database/sql"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/email"
	"instant.dev/internal/models"
)

// ── deletion_confirm.go flow-function seams ──────────────────────────────────
//
// The three shared two-step-deletion flow functions are unexported and take an
// unexported requestDeletionDeps struct. These wrappers let the external test
// package construct the deps from exported fields and invoke each flow against
// a real *fiber.Ctx (acquired from a fiber.App) + real test DB.

// BVRequestDeletionDeps mirrors the unexported requestDeletionDeps so the
// external test can populate it without reaching into package internals.
type BVRequestDeletionDeps struct {
	DB               *sql.DB
	Email            email.Mailer
	APIPublicURL     string
	DashboardBaseURL string
	TTLMinutes       int
}

func (d BVRequestDeletionDeps) toInternal() requestDeletionDeps {
	return requestDeletionDeps{
		DB:               d.DB,
		Email:            d.Email,
		APIPublicURL:     d.APIPublicURL,
		DashboardBaseURL: d.DashboardBaseURL,
		TTLMinutes:       d.TTLMinutes,
	}
}

// BVRequestEmailConfirmedDeletion exposes requestEmailConfirmedDeletion.
func BVRequestEmailConfirmedDeletion(c *fiber.Ctx, deps BVRequestDeletionDeps, team *models.Team, resourceID uuid.UUID, resourceType, resourceLabel string) error {
	return requestEmailConfirmedDeletion(c, deps.toInternal(), team, resourceID, resourceType, resourceLabel)
}

// BVResolveEmailConfirmedDeletion exposes resolveEmailConfirmedDeletion.
func BVResolveEmailConfirmedDeletion(c *fiber.Ctx, deps BVRequestDeletionDeps, team *models.Team, token string, deprovisionFn func(ctx context.Context, p *models.PendingDeletion) error) error {
	return resolveEmailConfirmedDeletion(c, deps.toInternal(), team, token, deprovisionFn)
}

// BVCancelEmailConfirmedDeletion exposes cancelEmailConfirmedDeletion.
func BVCancelEmailConfirmedDeletion(c *fiber.Ctx, deps BVRequestDeletionDeps, team *models.Team, resourceID uuid.UUID, resourceType string) error {
	return cancelEmailConfirmedDeletion(c, deps.toInternal(), team, resourceID, resourceType)
}

// ── billing.go portal-factory seam ───────────────────────────────────────────
//
// ListInvoicesAPI / UpdatePaymentMethodAPI / ChangePlanAPI construct a
// razorpaybilling.Portal inline and call methods that hit the Razorpay network.
// SetBillingPortalForTestPortal swaps the factory for a fixed fake so the
// post-subscription network arms are reachable without a live (or rzp_live)
// Razorpay account. Single-goroutine test setup only; returns a restore func.
func SetBillingPortalForTestPortal(p BillingPortal) (restore func()) {
	prev := billingPortalFactory
	billingPortalFactory = func(_ *sql.DB, _ *BillingHandler) BillingPortal { return p }
	return func() { billingPortalFactory = prev }
}
