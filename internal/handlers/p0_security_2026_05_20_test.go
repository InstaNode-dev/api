// Package handlers_test — regression tests for the P0/P1 security fixes
// shipped on 2026-05-20:
//
//   - B5-P0  TestClaim_EmailValidation_Coverage — RFC 5322 email gate
//     on POST /claim. 6 cases: valid, missing @, dotless TLD, empty,
//     leading space, > 254 chars; plus the B5-P1 token-vs-jwt field-name
//     drift sub-cases.
//
//   - B11-P1 TestBilling_UpgradeTeam_RowsAffected — UpgradeTeamAllTiers
//     UPDATE now returns ErrTeamNotFound on 0 rows affected, and the
//     webhook handler maps that to HTTP 404 (was silent 200).
//
//   - B11-P1 TestBilling_PaymentFailed_RecipientResolution — payment.failed
//     resolves the dunning recipient via notes.team_id → team primary
//     user, ignoring payload.email entirely.
package handlers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// ─── B5-P0 ─────────────────────────────────────────────────────────────────
//
// POST /claim accepted ANY string as the email field, minting a users row
// whose `email` value could never receive a magic-link callback. The fix is
// an RFC-5322 gate via mail.ParseAddress + a strict 254-char cap + a dotted-
// domain requirement + a no-inner-whitespace rule.

func TestClaim_EmailValidation_Coverage(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	provisionJWT := func() string {
		fp := testhelpers.UniqueFingerprint(t)
		res := testhelpers.MustProvisionCacheFull(t, app, fp)
		require.NotEmpty(t, res.JWT, "provision must return upgrade_jwt")
		return res.JWT
	}

	type caseDef struct {
		name          string
		email         string
		wantStatus    int
		wantErrorCode string
		expectInvalid bool
	}

	longLocal := strings.Repeat("a", 250)
	overcap := longLocal + "@x.com"
	require.Greater(t, len(overcap), 254)

	cases := []caseDef{
		{
			name:       "valid_address",
			email:      "ok-" + uuid.NewString()[:8] + "@example.com",
			wantStatus: http.StatusCreated,
		},
		{
			name:          "missing_at",
			email:         "not-an-email",
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "invalid_email_format",
			expectInvalid: true,
		},
		{
			name:          "dotless_tld",
			email:         "user@localhost",
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "invalid_email_format",
			expectInvalid: true,
		},
		{
			name:          "empty",
			email:         "",
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "missing_email",
		},
		{
			// B5-P0: NormalizeEmail strips leading/trailing whitespace
			// at the perimeter, so the strict validator never sees them.
			// The remaining whitespace-abuse vector is an INNER space
			// (tab/space/CR/LF between local-part and domain), which
			// some mail.ParseAddress implementations quietly tolerate.
			// We test that path here.
			name:          "leading_space",
			email:         "user @example.com",
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "invalid_email_format",
			expectInvalid: true,
		},
		{
			name:          "over_254_chars",
			email:         overcap,
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "invalid_email_format",
			expectInvalid: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := map[string]any{
				"token": provisionJWT(),
				"email": c.email,
			}
			resp := testhelpers.PostJSON(t, app, "/claim", body)
			defer resp.Body.Close()

			assert.Equal(t, c.wantStatus, resp.StatusCode,
				"case %q: status mismatch", c.name)

			if c.wantStatus == http.StatusCreated {
				return
			}

			var envelope map[string]any
			testhelpers.DecodeJSON(t, resp, &envelope)
			gotCode, _ := envelope["error"].(string)
			if c.wantErrorCode != "" {
				assert.Equal(t, c.wantErrorCode, gotCode,
					"case %q: expected error code %q, got %q (body: %+v)",
					c.name, c.wantErrorCode, gotCode, envelope)
			}
			if c.expectInvalid {
				agentAction, _ := envelope["agent_action"].(string)
				assert.NotEmpty(t, agentAction,
					"case %q: invalid_email_format must carry an agent_action", c.name)
			}
		})
	}

	t.Run("canonical_token_field", func(t *testing.T) {
		email := "tok-canonical-" + uuid.NewString()[:8] + "@example.com"
		resp := testhelpers.PostJSON(t, app, "/claim", map[string]any{
			"token": provisionJWT(),
			"email": email,
		})
		defer resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode,
			"`token` field (B5-P1 canonical) must work on POST /claim")
	})

	t.Run("legacy_jwt_alias_still_works", func(t *testing.T) {
		email := "tok-legacy-" + uuid.NewString()[:8] + "@example.com"
		resp := testhelpers.PostJSON(t, app, "/claim", map[string]any{
			"jwt":   provisionJWT(),
			"email": email,
		})
		defer resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode,
			"`jwt` field (legacy alias) must still work for backward compat")
	})

	t.Run("missing_token_message_says_token_not_jwt", func(t *testing.T) {
		resp := testhelpers.PostJSON(t, app, "/claim", map[string]any{
			"email": "x-" + uuid.NewString()[:8] + "@example.com",
		})
		defer resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var envelope map[string]any
		testhelpers.DecodeJSON(t, resp, &envelope)
		msg, _ := envelope["message"].(string)
		agentAction, _ := envelope["agent_action"].(string)

		assert.Contains(t, strings.ToLower(msg), "token",
			"missing_token message must say `token`, not `jwt`; got %q", msg)
		assert.NotContains(t, strings.ToLower(msg), "jwt field",
			"old message string `jwt field` must NOT appear")
		assert.Contains(t, strings.ToLower(agentAction), "token",
			"missing_token agent_action must reference the onboarding `token` field (not INSTANODE_TOKEN); got %q", agentAction)
	})
}

// ─── B11-P1 (rows-affected gate) ───────────────────────────────────────────

func TestBilling_UpgradeTeam_RowsAffected(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	app, _, cleanup := emailDedupApp(t)
	defer cleanup()

	// Synthesise a subscription.charged event whose notes.team_id
	// points at a UUID that definitely does not exist. The webhook
	// signature is valid; the dedup-claim happy path runs;
	// UpgradeTeamAllTiersWithSubscription's UPDATE matches 0 rows;
	// ErrTeamNotFound bubbles out; the handler must return 404.
	bogusTeamID := uuid.NewString()
	payload := makeChargedPayloadWithPaidCount(t,
		"subscription.charged",
		"evt_b11p1_"+uuid.NewString(),
		bogusTeamID,
		"sub_b11p1_"+uuid.NewString()[:8],
		1,
		false,
	)
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"B11-P1: synthetic webhook for a non-existent team_id MUST return 404 (was silent 200 pre-fix)")

	body, _ := io.ReadAll(resp.Body)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(body, &envelope))
	gotErr, _ := envelope["error"].(string)
	assert.Equal(t, "team_not_found", gotErr,
		"B11-P1: 404 envelope must name the case as `team_not_found`")
}

// ─── B11-P1 (recipient resolution) ─────────────────────────────────────────

func TestBilling_PaymentFailed_RecipientResolution(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	app, sendCount, recipients, cleanup := paymentFailedCapturingApp(t)
	defer cleanup()

	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	teamPrimary := "primary-" + uuid.NewString()[:8] + "@example.com"
	_, err := db.Exec(
		`INSERT INTO users (team_id, email, role, is_primary) VALUES ($1::uuid, $2, 'owner', true)`,
		teamID, teamPrimary,
	)
	require.NoError(t, err)

	// Hostile payload: claims pay.email = attacker, but legitimately
	// names the team via notes.team_id. The fix must IGNORE pay.email
	// and route the dunning email to the team's primary user instead.
	const attacker = "attacker@evil.com"
	payload := makePaymentFailedPayloadWithEventIDAndTeam(t,
		"evt_b11p1_"+uuid.NewString(),
		attacker,
		teamID,
	)
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.Equal(t, int64(1), atomic.LoadInt64(sendCount),
		"B11-P1: payment.failed must send exactly one dunning email; got %d", atomic.LoadInt64(sendCount))

	got := recipients.last()
	assert.Equal(t, strings.ToLower(teamPrimary), strings.ToLower(got),
		"B11-P1: dunning email MUST be sent to the team primary user, not the payload-supplied email; got %q (attacker=%q)",
		got, attacker)
	assert.NotEqual(t, strings.ToLower(attacker), strings.ToLower(got),
		"B11-P1: attacker-controlled payload.email MUST NOT reach the dunning recipient")
}

// ── recipient-capturing variant of emailDedupApp ─────────────────────
//
// emailDedupApp counts sends but discards the to-address. The
// recipient-resolution test needs to assert which address the email
// actually went to, so we wire a capturing httptest.Server that records
// the recipient from the Brevo POST body. The rest of the wiring
// (Brevo provider, URL rewriter, billing handler) mirrors emailDedupApp.

type lastRecipient struct {
	mu  sync.Mutex
	val string
}

func (l *lastRecipient) set(v string) {
	l.mu.Lock()
	l.val = v
	l.mu.Unlock()
}

func (l *lastRecipient) last() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.val
}

func paymentFailedCapturingApp(t *testing.T) (*fiber.App, *int64, *lastRecipient, func()) {
	t.Helper()
	database, cleanup := testhelpers.SetupTestDB(t)

	var sendCount int64
	rec := &lastRecipient{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			To []struct {
				Email string `json:"email"`
			} `json:"to"`
		}
		_ = json.Unmarshal(raw, &body)
		if len(body.To) > 0 {
			rec.set(body.To[0].Email)
		}
		atomic.AddInt64(&sendCount, 1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"messageId":"<stub@example.com>"}`))
	}))
	t.Cleanup(srv.Close)

	rewrite := &urlRewriter{base: srv.URL, inner: http.DefaultTransport}
	emailClient := email.New(email.Config{
		Provider:    "brevo",
		BrevoAPIKey: "xkeysib-test",
		HTTPClient:  &http.Client{Transport: rewrite},
	})

	cfg := &config.Config{
		JWTSecret:             testhelpers.TestJWTSecret,
		RazorpayWebhookSecret: testWebhookSecret,
		RazorpayPlanIDPro:     "plan_test_pro",
	}
	bh := handlers.NewBillingHandler(database, cfg, emailClient)
	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Post("/razorpay/webhook", bh.RazorpayWebhook)

	return app, &sendCount, rec, cleanup
}
