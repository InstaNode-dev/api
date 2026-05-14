package handlers

// custom_domain.go — Pro+ "bring your own hostname" for stacks.
//
// Routes (registered in router.go inside the auth-required /api/v1 group):
//
//   POST   /api/v1/stacks/:slug/domains              create + return TXT challenge
//   GET    /api/v1/stacks/:slug/domains              list domains for the stack
//   POST   /api/v1/stacks/:slug/domains/:id/verify   re-run verification + ingress + cert
//   DELETE /api/v1/stacks/:slug/domains/:id          remove ingress + DB row
//
// The verification flow advances the row through:
//   pending_verification → verified → ingress_ready → cert_ready (→ live)
//
// Verify is intentionally idempotent — the dashboard polls it once a few
// seconds while DNS propagates and again while Let's Encrypt issues. Each
// call is cheap when there is nothing new to do.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/providers/compute/k8s"
)

// CustomDomainProvider is the slice of K8sStackProvider this handler needs.
// Defined as an interface so tests can stub out k8s without spinning a
// clientset; production wires the real *k8s.K8sStackProvider.
type CustomDomainProvider interface {
	EnsureCustomDomainIngress(ctx context.Context, stackNamespace, hostname, serviceName string, servicePort int) (string, error)
	DeleteCustomDomainIngress(ctx context.Context, stackNamespace, hostname, serviceName string) error
	CertificateReady(ctx context.Context, namespace, certName string) (bool, string, error)
}

// reservedHostSuffixes is the central allowlist of suffixes a customer may
// NOT bind. Keeps anyone from claiming our own subdomains via a hostile DNS
// proof. Order matters only for readability — every entry is checked.
var reservedHostSuffixes = []string{
	".instanode.dev",
	".deployment.instanode.dev",
	".instant.dev",
	".deployment.instant.dev",
}

// reservedHosts is the central allowlist of exact hostnames that may NOT be
// bound. Avoids someone claiming the apex domain itself.
var reservedHosts = []string{
	"instanode.dev",
	"instant.dev",
	"deployment.instanode.dev",
	"deployment.instant.dev",
}

// dnsLookupTimeout caps how long Verify spends on a single TXT lookup. The
// resolver can hang indefinitely if upstream DNS is unhappy; 5s is plenty
// for a TXT query that exists.
const dnsLookupTimeout = 5 * time.Second

// CustomDomainHandler serves /api/v1/stacks/:slug/domains*.
type CustomDomainHandler struct {
	db    *sql.DB
	cfg   *config.Config
	plans *plans.Registry
	k8s   CustomDomainProvider
}

// NewCustomDomainHandler wires the handler. k8sProvider may be nil; in that
// case ingress / cert operations are skipped and the rows stay at "verified".
func NewCustomDomainHandler(db *sql.DB, cfg *config.Config, planRegistry *plans.Registry, k8sProvider CustomDomainProvider) *CustomDomainHandler {
	return &CustomDomainHandler{
		db:    db,
		cfg:   cfg,
		plans: planRegistry,
		k8s:   k8sProvider,
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// validateHostname rejects empty / malformed input and refuses anything that
// would land on our own subdomains. Returns the lowercased canonical form on
// success.
//
// We do not enforce DNS-1123 label-length here; the customer's resolver will
// reject anything truly bizarre. The reserved-suffix guard is the load-bearing
// piece — if it ever returns "ok" for a suffix we own, a customer could bind
// `<anything>.instanode.dev` and steal our certs. Keep the logic centralised
// so future review is easy.
func validateHostname(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(raw))
	if host == "" {
		return "", errors.New("hostname is required")
	}
	// Reject schemes / paths — accept naked hostnames only.
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/?# ") {
		return "", errors.New("hostname must be a bare domain (no scheme, path, or whitespace)")
	}
	// Strip a trailing dot if present (FQDN form).
	host = strings.TrimSuffix(host, ".")
	// At least one dot — the customer's apex `example.com` is fine, but an
	// empty label like just "app" is not.
	if !strings.Contains(host, ".") {
		return "", errors.New("hostname must include a dot (e.g. app.example.com)")
	}
	// Don't allow port numbers.
	if strings.Contains(host, ":") {
		return "", errors.New("hostname must not include a port")
	}
	// Use net/url to catch the truly malformed.
	if _, err := url.Parse("http://" + host); err != nil {
		return "", fmt.Errorf("hostname is not a valid domain: %w", err)
	}
	// Reject our own zones.
	for _, exact := range reservedHosts {
		if host == exact {
			return "", fmt.Errorf("hostname %q is reserved", host)
		}
	}
	for _, suffix := range reservedHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return "", fmt.Errorf("hostname %q falls under reserved suffix %q", host, suffix)
		}
	}
	return host, nil
}

// requireTeam mirrors the helper used by other authenticated handlers. The
// router's RequireAuth middleware guarantees a team_id will be present.
func (h *CustomDomainHandler) requireTeam(c *fiber.Ctx) (*models.Team, error) {
	teamIDStr := middleware.GetTeamID(c)
	if teamIDStr == "" {
		return nil, respondError(c, fiber.StatusUnauthorized, "unauthorized",
			"Authentication required for custom domain operations")
	}
	teamUUID, err := parseTeamID(teamIDStr)
	if err != nil {
		return nil, respondError(c, fiber.StatusBadRequest, "invalid_team",
			"Team ID in token is not a valid UUID")
	}
	team, err := models.GetTeamByID(c.Context(), h.db, teamUUID)
	if err != nil {
		slog.Error("custom_domain.team_lookup_failed",
			"error", err, "team_id", teamIDStr,
			"request_id", middleware.GetRequestID(c))
		return nil, respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed",
			"Failed to look up team")
	}
	return team, nil
}

// requireOwnedStack fetches the stack by slug and verifies the team owns it.
// Returns *models.Stack on success; writes the error response and returns
// (nil, err) on failure so callers can short-circuit.
func (h *CustomDomainHandler) requireOwnedStack(c *fiber.Ctx, team *models.Team, slug string) (*models.Stack, error) {
	stack, err := models.GetStackBySlug(c.Context(), h.db, slug)
	if err != nil {
		var notFound *models.ErrStackNotFound
		if errors.As(err, &notFound) {
			return nil, respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
		}
		slog.Error("custom_domain.stack_lookup_failed",
			"error", err, "slug", slug,
			"request_id", middleware.GetRequestID(c))
		return nil, respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch stack")
	}
	// Anonymous stacks can't carry custom domains — they have no team.
	if stack.TeamID == nil || *stack.TeamID != team.ID {
		return nil, respondError(c, fiber.StatusNotFound, "not_found", "Stack not found")
	}
	return stack, nil
}

// requireOwnedDomain fetches the row by id and asserts (a) it exists and (b)
// the requesting team owns it AND (c) it is bound to the given stack.
// Used by Verify and Delete to defend against teams reading another team's
// rows by guessing UUIDs.
func (h *CustomDomainHandler) requireOwnedDomain(c *fiber.Ctx, team *models.Team, stack *models.Stack, idStr string) (*models.CustomDomain, error) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		return nil, respondError(c, fiber.StatusBadRequest, "invalid_id", "Domain id must be a UUID")
	}
	dom, err := models.GetCustomDomainByID(c.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, models.ErrCustomDomainNotFound) {
			return nil, respondError(c, fiber.StatusNotFound, "not_found", "Custom domain not found")
		}
		slog.Error("custom_domain.lookup_failed",
			"error", err, "id", id,
			"request_id", middleware.GetRequestID(c))
		return nil, respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch custom domain")
	}
	if dom.TeamID != team.ID || dom.StackID != stack.ID {
		// 404 (not 403) so we never confirm "this UUID exists, just not yours".
		return nil, respondError(c, fiber.StatusNotFound, "not_found", "Custom domain not found")
	}
	return dom, nil
}

// expectedTXTValue returns the literal string the customer must include in
// their TXT record at "_instanode.<hostname>".
func expectedTXTValue(token string) string {
	return models.VerificationTokenPrefix + token
}

// txtChallengeRecordName returns "_instanode.<hostname>" — where the customer
// adds their TXT record. We use the same name verbatim in the lookup so the
// payload matches the documentation exactly.
func txtChallengeRecordName(hostname string) string {
	return "_instanode." + hostname
}

// stackCNAMETarget is what the customer should set as a CNAME for their
// hostname. After verification, traffic to the custom hostname has to find
// our ingress controller, which fronts <slug>.deployment.instanode.dev.
func stackCNAMETarget(slug string) string {
	return slug + ".deployment.instanode.dev"
}

// dnsInstructions returns the JSON the API should hand back so the dashboard
// can render the right "next step" panel. We always return BOTH the TXT and
// CNAME instructions but mark which one is currently outstanding via the
// status field — clients can render either one without re-asking.
func dnsInstructions(dom *models.CustomDomain, stackSlug string) fiber.Map {
	return fiber.Map{
		"txt": fiber.Map{
			"record_type":  "TXT",
			"record_name":  txtChallengeRecordName(dom.Hostname),
			"record_value": expectedTXTValue(dom.VerificationToken),
		},
		"cname": fiber.Map{
			"record_type":  "CNAME",
			"record_name":  dom.Hostname,
			"record_value": stackCNAMETarget(stackSlug),
		},
	}
}

// serializeDomain shapes a CustomDomain for the API response, including the
// DNS instructions and a flag mirroring whether the cert is ready (callers
// poll this from the dashboard).
func serializeDomain(dom *models.CustomDomain, stackSlug string) fiber.Map {
	out := fiber.Map{
		"id":                 dom.ID,
		"hostname":           dom.Hostname,
		"status":             dom.Status,
		"created_at":         dom.CreatedAt,
		"verification":       dnsInstructions(dom, stackSlug),
		"verified":           dom.Status != models.CustomDomainStatusPending,
		"certificate_ready":  dom.Status == models.CustomDomainStatusCertReady || dom.Status == models.CustomDomainStatusLive,
	}
	if dom.VerifiedAt.Valid {
		out["verified_at"] = dom.VerifiedAt.Time
	}
	if dom.CertReadyAt.Valid {
		out["cert_ready_at"] = dom.CertReadyAt.Time
	}
	if dom.LastCheckAt.Valid {
		out["last_check_at"] = dom.LastCheckAt.Time
	}
	if dom.LastCheckErr.Valid {
		out["last_check_err"] = dom.LastCheckErr.String
	}
	return out
}

// primaryStackService returns the service we'll route the custom hostname at.
// We pick the first service with expose=true so customers get the same
// service that's already serving traffic on the deployment.instanode.dev URL.
// If no service is exposed, returns ("", err).
func (h *CustomDomainHandler) primaryStackService(ctx context.Context, stack *models.Stack) (*models.StackService, error) {
	svcs, err := models.GetStackServicesByStack(ctx, h.db, stack.ID)
	if err != nil {
		return nil, fmt.Errorf("primaryStackService: %w", err)
	}
	for _, ss := range svcs {
		if ss.Expose {
			return ss, nil
		}
	}
	return nil, errors.New("stack has no service marked expose=true")
}

// ── POST /api/v1/stacks/:slug/domains ─────────────────────────────────────────

type createCustomDomainBody struct {
	Hostname string `json:"hostname"`
}

// Create handles POST /api/v1/stacks/:slug/domains.
func (h *CustomDomainHandler) Create(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	// Tier gate — Hobby Plus and above. Hobby / anonymous / free get a
	// 402-style upgrade hint. W11 (2026-05-13): Hobby Plus is now the
	// cheapest tier with custom_domains: true — the upgrade copy points
	// at Hobby Plus rather than Pro so hobby users see the closer step.
	if !h.plans.CustomDomainsAllowed(team.PlanTier) {
		return respondError(c, fiber.StatusPaymentRequired, "upgrade_required",
			"Custom domains require the Hobby Plus plan or higher. Upgrade at https://instanode.dev/pricing")
	}

	stack, err := h.requireOwnedStack(c, team, c.Params("slug"))
	if err != nil {
		return err
	}

	var body createCustomDomainBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body",
			`Body must be valid JSON: {"hostname":"app.example.com"}`)
	}

	hostname, valErr := validateHostname(body.Hostname)
	if valErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_hostname", valErr.Error())
	}

	dom, err := models.CreateCustomDomain(c.Context(), h.db, team.ID, stack.ID, hostname)
	if err != nil {
		if errors.Is(err, models.ErrCustomDomainTaken) {
			return respondError(c, fiber.StatusConflict, "hostname_taken",
				"This hostname is already bound to another domain. Delete the existing binding first or contact support.")
		}
		slog.Error("custom_domain.create_failed",
			"error", err, "hostname", hostname,
			"team_id", team.ID, "stack_id", stack.ID,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "create_failed",
			"Failed to create custom domain")
	}

	slog.Info("custom_domain.created",
		"id", dom.ID, "hostname", hostname,
		"team_id", team.ID, "stack_slug", stack.Slug,
		"request_id", middleware.GetRequestID(c))

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":     true,
		"domain": serializeDomain(dom, stack.Slug),
	})
}

// ── GET /api/v1/stacks/:slug/domains ──────────────────────────────────────────

// List handles GET /api/v1/stacks/:slug/domains.
func (h *CustomDomainHandler) List(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}
	stack, err := h.requireOwnedStack(c, team, c.Params("slug"))
	if err != nil {
		return err
	}

	doms, err := models.ListCustomDomainsByStack(c.Context(), h.db, stack.ID)
	if err != nil {
		slog.Error("custom_domain.list_failed",
			"error", err, "stack_id", stack.ID,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "list_failed",
			"Failed to list custom domains")
	}
	items := make([]fiber.Map, 0, len(doms))
	for _, d := range doms {
		items = append(items, serializeDomain(d, stack.Slug))
	}
	return c.JSON(fiber.Map{
		"ok":    true,
		"items": items,
		"total": len(items),
	})
}

// ── POST /api/v1/stacks/:slug/domains/:id/verify ──────────────────────────────

// Verify is idempotent. Each call:
//
//  1. If status == pending_verification — re-runs the TXT lookup; advances
//     to "verified" if it matches, otherwise records last_check_err.
//  2. If status >= verified but no Ingress yet — creates the Ingress +
//     Certificate (cert-manager auto-creates the cert once it sees the
//     annotated Ingress + missing TLS Secret) and advances to ingress_ready.
//  3. If status >= ingress_ready — polls the Certificate for Ready=True and
//     advances to cert_ready when the cert lands.
//
// The response always reflects the state AFTER this call's mutations.
func (h *CustomDomainHandler) Verify(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}
	stack, err := h.requireOwnedStack(c, team, c.Params("slug"))
	if err != nil {
		return err
	}
	dom, err := h.requireOwnedDomain(c, team, stack, c.Params("id"))
	if err != nil {
		return err
	}

	// Step 1: TXT lookup if still pending.
	if dom.Status == models.CustomDomainStatusPending {
		ok, lookupErr := h.checkTXT(c.Context(), dom)
		if ok {
			if mkErr := models.MarkCustomDomainVerified(c.Context(), h.db, dom.ID); mkErr != nil {
				slog.Error("custom_domain.mark_verified_failed",
					"error", mkErr, "id", dom.ID)
				return respondError(c, fiber.StatusServiceUnavailable, "verify_failed",
					"Failed to record verification")
			}
			// Reload after mutation so subsequent steps see the new status.
			dom, err = models.GetCustomDomainByID(c.Context(), h.db, dom.ID)
			if err != nil {
				return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed",
					"Failed to refresh domain after verification")
			}
		} else {
			msg := "TXT record missing or wrong value"
			if lookupErr != nil {
				msg = lookupErr.Error()
			}
			_ = models.UpdateCustomDomainStatus(c.Context(), h.db, dom.ID, models.CustomDomainStatusPending, msg)
			dom.LastCheckErr = sql.NullString{String: msg, Valid: true}
			// 200 with current state + the failure reason — clients poll.
			return c.JSON(fiber.Map{
				"ok":     true,
				"domain": serializeDomain(dom, stack.Slug),
			})
		}
	}

	// Step 2: Ensure the Ingress exists once we're at "verified".
	if dom.Status == models.CustomDomainStatusVerified {
		if h.k8s == nil {
			// No k8s wired in this environment (e.g. tests). Treat verification
			// as the terminal state and let the dashboard show "TXT verified — ingress pending."
			return c.JSON(fiber.Map{
				"ok":     true,
				"domain": serializeDomain(dom, stack.Slug),
			})
		}
		svc, svcErr := h.primaryStackService(c.Context(), stack)
		if svcErr != nil {
			_ = models.UpdateCustomDomainStatus(c.Context(), h.db, dom.ID, models.CustomDomainStatusVerified, svcErr.Error())
			dom.LastCheckErr = sql.NullString{String: svcErr.Error(), Valid: true}
			return c.JSON(fiber.Map{
				"ok":     true,
				"domain": serializeDomain(dom, stack.Slug),
			})
		}

		_, ingErr := h.k8s.EnsureCustomDomainIngress(c.Context(), stack.Namespace, dom.Hostname, svc.Name, svc.Port)
		if ingErr != nil {
			slog.Error("custom_domain.ingress_failed",
				"error", ingErr, "id", dom.ID, "hostname", dom.Hostname,
				"namespace", stack.Namespace,
				"request_id", middleware.GetRequestID(c))
			_ = models.UpdateCustomDomainStatus(c.Context(), h.db, dom.ID, models.CustomDomainStatusVerified, ingErr.Error())
			dom.LastCheckErr = sql.NullString{String: ingErr.Error(), Valid: true}
			return c.JSON(fiber.Map{
				"ok":     true,
				"domain": serializeDomain(dom, stack.Slug),
			})
		}
		if mkErr := models.UpdateCustomDomainStatus(c.Context(), h.db, dom.ID, models.CustomDomainStatusIngressReady, ""); mkErr != nil {
			slog.Error("custom_domain.set_ingress_ready_failed",
				"error", mkErr, "id", dom.ID)
		}
		dom.Status = models.CustomDomainStatusIngressReady
	}

	// Step 3: Poll the Certificate for Ready=True.
	if dom.Status == models.CustomDomainStatusIngressReady && h.k8s != nil {
		certName := k8s.CustomDomainTLSSecretName(dom.Hostname)
		ready, certMsg, certErr := h.k8s.CertificateReady(c.Context(), stack.Namespace, certName)
		if certErr != nil {
			slog.Warn("custom_domain.cert_poll_failed",
				"error", certErr, "id", dom.ID, "hostname", dom.Hostname,
				"namespace", stack.Namespace)
			// Soft-fail: leave the row at ingress_ready and surface the message.
			_ = models.UpdateCustomDomainStatus(c.Context(), h.db, dom.ID, models.CustomDomainStatusIngressReady, certErr.Error())
			dom.LastCheckErr = sql.NullString{String: certErr.Error(), Valid: true}
		} else if ready {
			if mkErr := models.MarkCertReady(c.Context(), h.db, dom.ID); mkErr != nil {
				slog.Error("custom_domain.mark_cert_ready_failed",
					"error", mkErr, "id", dom.ID)
			} else {
				dom.Status = models.CustomDomainStatusCertReady
				dom.CertReadyAt = sql.NullTime{Time: time.Now(), Valid: true}
				dom.LastCheckErr = sql.NullString{}
			}
		} else {
			// Still issuing — record the cert-manager message so the dashboard
			// can surface "DNS validation pending" / "ACME order created".
			_ = models.UpdateCustomDomainStatus(c.Context(), h.db, dom.ID, models.CustomDomainStatusIngressReady, certMsg)
			dom.LastCheckErr = sql.NullString{String: certMsg, Valid: certMsg != ""}
		}
	}

	return c.JSON(fiber.Map{
		"ok":     true,
		"domain": serializeDomain(dom, stack.Slug),
	})
}

// checkTXT runs net.LookupTXT against the verification record and reports
// whether the expected payload appears in any returned record.
func (h *CustomDomainHandler) checkTXT(ctx context.Context, dom *models.CustomDomain) (bool, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()
	resolver := net.DefaultResolver
	records, err := resolver.LookupTXT(lookupCtx, txtChallengeRecordName(dom.Hostname))
	if err != nil {
		return false, fmt.Errorf("TXT lookup for %s failed: %w", txtChallengeRecordName(dom.Hostname), err)
	}
	want := expectedTXTValue(dom.VerificationToken)
	for _, r := range records {
		// Some resolvers return the TXT contents wrapped in extra quotes; trim them.
		clean := strings.Trim(r, "\"")
		if clean == want || r == want {
			return true, nil
		}
	}
	return false, nil
}

// ── DELETE /api/v1/stacks/:slug/domains/:id ───────────────────────────────────

// Delete removes the Ingress + Secret (best-effort) and then the DB row.
// We tear down k8s before the DB row so a partial failure leaves the row in
// place and the customer can retry. If k8s already lost the Ingress we
// continue and clear the row anyway.
func (h *CustomDomainHandler) Delete(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}
	stack, err := h.requireOwnedStack(c, team, c.Params("slug"))
	if err != nil {
		return err
	}
	dom, err := h.requireOwnedDomain(c, team, stack, c.Params("id"))
	if err != nil {
		return err
	}

	// Best-effort ingress teardown. We need a service name; fall back to the
	// primary one. If lookup fails (e.g. stack already gone), continue.
	if h.k8s != nil {
		if svc, svcErr := h.primaryStackService(c.Context(), stack); svcErr == nil {
			if delErr := h.k8s.DeleteCustomDomainIngress(c.Context(), stack.Namespace, dom.Hostname, svc.Name); delErr != nil {
				slog.Warn("custom_domain.delete.ingress_teardown_failed",
					"error", delErr, "id", dom.ID, "hostname", dom.Hostname)
			}
		}
	}

	if err := models.DeleteCustomDomain(c.Context(), h.db, dom.ID, team.ID); err != nil {
		if errors.Is(err, models.ErrCustomDomainNotFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Custom domain not found")
		}
		slog.Error("custom_domain.delete_failed",
			"error", err, "id", dom.ID,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "delete_failed",
			"Failed to delete custom domain")
	}

	slog.Info("custom_domain.deleted",
		"id", dom.ID, "hostname", dom.Hostname,
		"team_id", team.ID, "stack_slug", stack.Slug,
		"request_id", middleware.GetRequestID(c))

	return c.JSON(fiber.Map{
		"ok":      true,
		"id":      dom.ID,
		"message": "Custom domain removed",
	})
}
