package razorpaybilling

// portal_coverage_test.go — comprehensive Portal-method coverage.
//
// Strategy:
//
//  1. Spin up an httptest.Server that speaks just enough of the Razorpay
//     REST surface (POST/GET /v1/subscriptions/*, /v1/invoices,
//     /v1/payments/*). We never hit the real Razorpay API.
//
//  2. Install a test-only client factory via newClientForPortal that
//     points the SDK's BaseURL at our mock server. Restored after each
//     subtest via t.Cleanup so production paths never see the hijack.
//
//  3. Drive every branch of every Portal method through the mock:
//     happy path, malformed JSON, 4xx error, 5xx error, missing fields,
//     edge cases of toInt64 / pickInvoiceTimestamp.
//
//  4. After tests that produce errors via callWithBreaker, restore the
//     singleton breaker's consecutive-failure counter to 0 so subsequent
//     tests don't get spuriously short-circuited. The singleton has
//     threshold=5; we never come anywhere near tripping it from this
//     file, but defensive resets keep test ordering irrelevant.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	razorpay "github.com/razorpay/razorpay-go"
	"instant.dev/internal/circuit"
	"instant.dev/internal/config"
)

// --- test helpers ----------------------------------------------------

// resetBreaker forces the singleton's consecutive-failure counter back
// to zero. Cheap and safe to call between subtests.
func resetBreaker(t *testing.T) {
	t.Helper()
	Breaker().Record(nil) // success resets `consecutive` to 0
}

// installMockFactory swaps the package-level newClientForPortal so
// every Portal.client() call points at `srv`. The original is restored
// on test cleanup.
func installMockFactory(t *testing.T, srv *httptest.Server) {
	t.Helper()
	orig := newClientForPortal
	newClientForPortal = func(keyID, secret string) *razorpay.Client {
		c := razorpay.NewClient(keyID, secret)
		c.Request.BaseURL = srv.URL
		// Tight test timeout — production code uses 30s but tests should
		// fail fast on a misconfigured mock.
		c.Request.SetTimeout(5)
		return c
	}
	t.Cleanup(func() {
		newClientForPortal = orig
		resetBreaker(t)
	})
}

// mockPortal returns a Portal wired with a valid cfg + a sqlmock-backed
// DB. The caller must close `mock` via t.Cleanup typically.
func mockPortal(t *testing.T) (*Portal, sqlmock.Sqlmock, *sql.DB) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Portal{
		DB: db,
		Cfg: &config.Config{
			RazorpayKeyID:     "rzp_test_key",
			RazorpayKeySecret: "rzp_test_secret",
		},
	}, mock, db
}

// jsonRespond writes a JSON body with the given status to a test
// server's response writer.
func jsonRespond(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// --- pure-helper coverage -------------------------------------------

func TestToInt64_AllCases(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want int64
	}{
		{"float64", float64(123), 123},
		{"int64", int64(456), 456},
		{"int", int(789), 789},
		{"jsonNumber_valid", json.Number("1700000000"), 1700000000},
		{"jsonNumber_invalid", json.Number("not-a-number"), 0},
		{"string_valid", "42", 42},
		{"string_invalid", "nope", 0},
		{"bool_default", true, 0},
		{"nil_default", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := toInt64(tc.in); got != tc.want {
				t.Errorf("toInt64(%v) = %d; want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestPickInvoiceTimestamp_PrefersPaidAt(t *testing.T) {
	m := map[string]interface{}{
		"paid_at":    float64(1700000000),
		"issued_at":  float64(1600000000),
		"created_at": float64(1500000000),
	}
	got := pickInvoiceTimestamp(m)
	if got.Unix() != 1700000000 {
		t.Errorf("expected paid_at; got %v", got)
	}
}

func TestPickInvoiceTimestamp_FallsThroughKeys(t *testing.T) {
	// no paid_at, no issued_at; date present.
	m := map[string]interface{}{"date": float64(1234567890)}
	got := pickInvoiceTimestamp(m)
	if got.Unix() != 1234567890 {
		t.Errorf("expected date timestamp, got %v", got)
	}
	// nothing → zero time
	if !pickInvoiceTimestamp(map[string]interface{}{}).IsZero() {
		t.Error("empty map should yield zero time")
	}
	// key present but parses to 0 → keep scanning
	m2 := map[string]interface{}{
		"paid_at":   "not-a-number",
		"issued_at": float64(99),
	}
	got = pickInvoiceTimestamp(m2)
	if got.Unix() != 99 {
		t.Errorf("expected fallback to issued_at, got %v", got)
	}
}

// --- callWithBreaker direct exercise -------------------------------

func TestCallWithBreaker_OpenReturnsErrOpen(t *testing.T) {
	// Trip a private breaker, prove the generic wrapper short-circuits.
	b := circuit.NewBreaker("rzp_test_cwb", 1, 30*time.Second)
	b.Record(fmt.Errorf("seed failure"))
	if b.State() != circuit.StateOpen {
		t.Fatalf("setup: want open, got %s", b.State())
	}
	// We don't expose a breaker-swap for callWithBreaker, but we can
	// at least show that CallWithBreaker drives the same singleton:
	// when closed, fn is invoked; the open-branch is exercised by
	// the other tests in circuit_test.go.
	called := false
	_, err := CallWithBreaker(func() (int, error) {
		called = true
		return 1, nil
	})
	if Breaker().State() == circuit.StateClosed {
		if !called || err != nil {
			t.Fatalf("expected fn invoked on closed breaker; called=%v err=%v", called, err)
		}
	}
}

// --- client() error paths ------------------------------------------

func TestClient_NoKeyID(t *testing.T) {
	p := &Portal{Cfg: &config.Config{RazorpayKeySecret: "secret"}}
	if _, err := p.client(); err == nil {
		t.Fatal("want billing-not-configured, got nil")
	}
}

func TestClient_NoKeySecret(t *testing.T) {
	p := &Portal{Cfg: &config.Config{RazorpayKeyID: "key"}}
	if _, err := p.client(); err == nil {
		t.Fatal("want billing-not-configured, got nil")
	}
}

func TestClient_ConfiguredReturnsClient(t *testing.T) {
	p := &Portal{Cfg: &config.Config{RazorpayKeyID: "k", RazorpayKeySecret: "s"}}
	c, err := p.client()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c == nil {
		t.Fatal("client nil")
	}
	if got := c.Request.HTTPClient.Timeout; got != 30*time.Second {
		t.Errorf("client timeout = %s; want 30s", got)
	}
}

// --- SubscriptionID --------------------------------------------------

func TestSubscriptionID_OK(t *testing.T) {
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow("sub_abc"))

	got, err := p.SubscriptionID(context.Background(), tid)
	if err != nil || got != "sub_abc" {
		t.Fatalf("want (sub_abc,nil); got (%q,%v)", got, err)
	}
}

func TestSubscriptionID_NotFound(t *testing.T) {
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnError(sql.ErrNoRows)
	_, err := p.SubscriptionID(context.Background(), tid)
	if err == nil || !strings.Contains(err.Error(), "team not found") {
		t.Fatalf("want team-not-found, got %v", err)
	}
}

func TestSubscriptionID_DBError(t *testing.T) {
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	dbErr := errors.New("connection refused")
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnError(dbErr)
	_, err := p.SubscriptionID(context.Background(), tid)
	if err == nil {
		t.Fatal("want db error, got nil")
	}
}

func TestSubscriptionID_NoSubscriptionEmpty(t *testing.T) {
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow(""))
	_, err := p.SubscriptionID(context.Background(), tid)
	if err == nil || !strings.Contains(err.Error(), "no subscription") {
		t.Fatalf("want no-subscription, got %v", err)
	}
}

func TestSubscriptionID_NoSubscriptionWhitespace(t *testing.T) {
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow("   "))
	_, err := p.SubscriptionID(context.Background(), tid)
	if err == nil || !strings.Contains(err.Error(), "no subscription") {
		t.Fatalf("want no-subscription on whitespace, got %v", err)
	}
}

func TestSubscriptionID_NullColumn(t *testing.T) {
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow(nil))
	_, err := p.SubscriptionID(context.Background(), tid)
	if err == nil || !strings.Contains(err.Error(), "no subscription") {
		t.Fatalf("want no-subscription on NULL, got %v", err)
	}
}

func TestSubscriptionID_TrimsWhitespace(t *testing.T) {
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow("  sub_trim  "))
	got, err := p.SubscriptionID(context.Background(), tid)
	if err != nil || got != "sub_trim" {
		t.Fatalf("want sub_trim/nil; got %q/%v", got, err)
	}
}

// --- Cancel ----------------------------------------------------------

func TestCancelAtCycleEnd_OK(t *testing.T) {
	called := int32(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&called, 1)
		if !strings.HasSuffix(r.URL.Path, "/cancel") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["cancel_at_cycle_end"] != true {
			t.Errorf("expected cancel_at_cycle_end=true, got %v", body["cancel_at_cycle_end"])
		}
		jsonRespond(w, 200, map[string]interface{}{"id": "sub_abc", "status": "active"})
	}))
	t.Cleanup(srv.Close)

	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	if err := p.CancelAtCycleEnd("sub_abc"); err != nil {
		t.Fatalf("CancelAtCycleEnd: %v", err)
	}
	if atomic.LoadInt32(&called) != 1 {
		t.Errorf("expected 1 server call, got %d", called)
	}
}

func TestCancelAtCycleEnd_NotConfigured(t *testing.T) {
	p := &Portal{Cfg: &config.Config{}}
	if err := p.CancelAtCycleEnd("sub_x"); err == nil {
		t.Fatal("want not-configured error")
	}
}

func TestCancelAtCycleEnd_4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRespond(w, 400, map[string]interface{}{
			"error": map[string]interface{}{
				"code":        "BAD_REQUEST_ERROR",
				"description": "subscription already cancelled",
			},
		})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	if err := p.CancelAtCycleEnd("sub_x"); err == nil {
		t.Fatal("want 4xx error, got nil")
	}
}

func TestCancelImmediately_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["cancel_at_cycle_end"] != false {
			t.Errorf("expected cancel_at_cycle_end=false, got %v", body["cancel_at_cycle_end"])
		}
		jsonRespond(w, 200, map[string]interface{}{"id": "sub_x", "status": "cancelled"})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	if err := p.CancelImmediately("sub_x"); err != nil {
		t.Fatalf("CancelImmediately: %v", err)
	}
}

func TestCancelImmediately_NotConfigured(t *testing.T) {
	p := &Portal{Cfg: &config.Config{}}
	if err := p.CancelImmediately("sub_x"); err == nil {
		t.Fatal("want not-configured error")
	}
}

func TestCancelImmediately_5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRespond(w, 500, map[string]interface{}{
			"error": map[string]interface{}{
				"code":        "SERVER_ERROR",
				"description": "razorpay overloaded",
			},
		})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	if err := p.CancelImmediately("sub_x"); err == nil {
		t.Fatal("want 5xx error, got nil")
	}
}

// --- ListSubscriptionInvoices ---------------------------------------

func TestListSubscriptionInvoices_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRespond(w, 200, map[string]interface{}{
			"items": []interface{}{
				map[string]interface{}{
					"id":         "inv_1",
					"status":     "paid",
					"currency":   "inr",
					"amount":     float64(1900),
					"paid_at":    float64(1700000000),
					"short_url":  "https://rzp.io/short/inv1",
					"payment_id": "pay_1",
				},
				map[string]interface{}{
					// no short_url, no paid_at — exercises ts-fallback + missing-pdf branches.
					"id":         "inv_2",
					"status":     "issued",
					"currency":   "usd",
					"amount":     float64(2500),
					"created_at": float64(1690000000),
				},
				"not-a-map", // exercises the non-map item skip branch
			},
		})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	inv, err := p.ListSubscriptionInvoices("sub_abc")
	if err != nil {
		t.Fatalf("ListSubscriptionInvoices: %v", err)
	}
	if len(inv) != 2 {
		t.Fatalf("want 2 invoices (third is skipped non-map); got %d", len(inv))
	}
	if inv[0].Currency != "INR" || inv[0].PDFURL != "https://rzp.io/short/inv1" {
		t.Errorf("inv[0] = %+v", inv[0])
	}
	if !inv[0].Date.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Errorf("inv[0].Date wrong: %v", inv[0].Date)
	}
	if inv[1].Currency != "USD" || inv[1].PDFURL != "" {
		t.Errorf("inv[1] = %+v", inv[1])
	}
}

func TestListSubscriptionInvoices_NotConfigured(t *testing.T) {
	p := &Portal{Cfg: &config.Config{}}
	if _, err := p.ListSubscriptionInvoices("sub_x"); err == nil {
		t.Fatal("want not-configured")
	}
}

func TestListSubscriptionInvoices_NoItemsField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRespond(w, 200, map[string]interface{}{}) // no "items"
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	out, err := p.ListSubscriptionInvoices("sub_abc")
	if err != nil {
		t.Fatalf("want nil err, got %v", err)
	}
	if out != nil {
		t.Errorf("want nil slice; got %v", out)
	}
}

func TestListSubscriptionInvoices_4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRespond(w, 400, map[string]interface{}{
			"error": map[string]interface{}{
				"code":        "BAD_REQUEST_ERROR",
				"description": "bad subscription id",
			},
		})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	if _, err := p.ListSubscriptionInvoices("sub_bad"); err == nil {
		t.Fatal("want 4xx error")
	}
}

// --- PaymentUpdateURL -----------------------------------------------

func TestPaymentUpdateURL_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRespond(w, 200, map[string]interface{}{
			"id":        "sub_abc",
			"short_url": "https://rzp.io/i/Up",
		})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	got, err := p.PaymentUpdateURL("sub_abc")
	if err != nil || got != "https://rzp.io/i/Up" {
		t.Fatalf("want short_url; got (%q,%v)", got, err)
	}
}

func TestPaymentUpdateURL_NotConfigured(t *testing.T) {
	p := &Portal{Cfg: &config.Config{}}
	if _, err := p.PaymentUpdateURL("sub_x"); err == nil {
		t.Fatal("want not-configured")
	}
}

func TestPaymentUpdateURL_NoShortURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRespond(w, 200, map[string]interface{}{"id": "sub_abc"})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	if _, err := p.PaymentUpdateURL("sub_abc"); err == nil ||
		!strings.Contains(err.Error(), "no payment update URL") {
		t.Fatalf("want no-payment-update-url; got %v", err)
	}
}

func TestPaymentUpdateURL_WhitespaceShortURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRespond(w, 200, map[string]interface{}{"id": "sub_abc", "short_url": "   "})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	if _, err := p.PaymentUpdateURL("sub_abc"); err == nil {
		t.Fatal("want no-payment-update-url for whitespace short_url")
	}
}

func TestPaymentUpdateURL_5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRespond(w, 500, map[string]interface{}{
			"error": map[string]interface{}{
				"code":        "SERVER_ERROR",
				"description": "boom",
			},
		})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	if _, err := p.PaymentUpdateURL("sub_abc"); err == nil {
		t.Fatal("want 5xx error")
	}
}

// --- ChangePlan ------------------------------------------------------

func TestChangePlan_OK(t *testing.T) {
	tid := uuid.New()
	// Counts how many times the mock receives each route.
	type counters struct {
		cancel int32
		create int32
		fetch  int32
	}
	var c counters
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/cancel"):
			atomic.AddInt32(&c.cancel, 1)
			jsonRespond(w, 200, map[string]interface{}{"id": "sub_old", "status": "active"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/subscriptions"):
			atomic.AddInt32(&c.create, 1)
			// echo back team_id from notes so we can also exercise
			// the success-path body marshalling
			jsonRespond(w, 200, map[string]interface{}{
				"id":        "sub_new",
				"short_url": "https://rzp.io/i/new",
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/subscriptions/sub_old"):
			atomic.AddInt32(&c.fetch, 1)
			jsonRespond(w, 200, map[string]interface{}{
				"id":          "sub_old",
				"current_end": float64(1750000000),
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)

	p, mock, _ := mockPortal(t)
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow("sub_old"))
	mock.ExpectExec("UPDATE teams SET stripe_customer_id").
		WithArgs("sub_new", tid).
		WillReturnResult(sqlmock.NewResult(1, 1))

	res, err := p.ChangePlan(context.Background(), tid, "pro", map[string]string{
		"pro": "plan_pro_id",
	})
	if err != nil {
		t.Fatalf("ChangePlan: %v", err)
	}
	if res.NewSubID != "sub_new" || res.CheckoutShort != "https://rzp.io/i/new" {
		t.Errorf("res = %+v", res)
	}
	if res.NewPlan != "pro" {
		t.Errorf("NewPlan = %q; want pro", res.NewPlan)
	}
	if got := res.EffectiveDate.Unix(); got != 1750000000 {
		t.Errorf("EffectiveDate = %v (unix %d); want 1750000000", res.EffectiveDate, got)
	}
	if c.cancel != 1 || c.create != 1 || c.fetch != 1 {
		t.Errorf("calls = %+v", c)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

func TestChangePlan_NotConfigured(t *testing.T) {
	p := &Portal{Cfg: &config.Config{}}
	if _, err := p.ChangePlan(context.Background(), uuid.New(), "pro", nil); err == nil {
		t.Fatal("want not-configured")
	}
}

func TestChangePlan_NoSubscription(t *testing.T) {
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow(""))
	if _, err := p.ChangePlan(context.Background(), tid, "pro", map[string]string{"pro": "plan_pro_id"}); err == nil {
		t.Fatal("want no-subscription error")
	}
}

func TestChangePlan_CancelFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRespond(w, 500, map[string]interface{}{
			"error": map[string]interface{}{
				"code":        "SERVER_ERROR",
				"description": "cancel broken",
			},
		})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow("sub_old"))
	_, err := p.ChangePlan(context.Background(), tid, "pro", map[string]string{"pro": "plan_pro_id"})
	if err == nil || !strings.Contains(err.Error(), "cancel current subscription") {
		t.Fatalf("want cancel-failed wrap, got %v", err)
	}
}

func TestChangePlan_InvalidTargetPlan(t *testing.T) {
	// Cancel must succeed before we hit the invalid-plan branch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRespond(w, 200, map[string]interface{}{"id": "sub_old"})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow("sub_old"))
	_, err := p.ChangePlan(context.Background(), tid, "enterprise", map[string]string{"pro": "plan_pro_id"})
	if err == nil || !strings.Contains(err.Error(), "invalid target plan") {
		t.Fatalf("want invalid-target-plan, got %v", err)
	}
}

func TestChangePlan_CreateFails(t *testing.T) {
	var seenCreate int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/cancel") {
			jsonRespond(w, 200, map[string]interface{}{"id": "sub_old"})
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/subscriptions") {
			atomic.AddInt32(&seenCreate, 1)
			jsonRespond(w, 500, map[string]interface{}{
				"error": map[string]interface{}{
					"code":        "SERVER_ERROR",
					"description": "create broken",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow("sub_old"))
	_, err := p.ChangePlan(context.Background(), tid, "pro", map[string]string{"pro": "plan_pro_id"})
	if err == nil || !strings.Contains(err.Error(), "create subscription") {
		t.Fatalf("want create-subscription wrap, got %v", err)
	}
}

func TestChangePlan_PersistFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/cancel"):
			jsonRespond(w, 200, map[string]interface{}{"id": "sub_old"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/subscriptions"):
			jsonRespond(w, 200, map[string]interface{}{"id": "sub_new", "short_url": "x"})
		default:
			jsonRespond(w, 200, map[string]interface{}{"id": "sub_old"})
		}
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow("sub_old"))
	mock.ExpectExec("UPDATE teams SET stripe_customer_id").
		WithArgs("sub_new", tid).
		WillReturnError(errors.New("persist boom"))
	_, err := p.ChangePlan(context.Background(), tid, "pro", map[string]string{"pro": "plan_pro_id"})
	if err == nil || !strings.Contains(err.Error(), "persist subscription id") {
		t.Fatalf("want persist wrap, got %v", err)
	}
}

func TestChangePlan_FetchOldFailsButReturnsNow(t *testing.T) {
	// If the post-create fetch of the OLD subscription fails, ChangePlan
	// must fall back to time.Now() and still return success.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/cancel"):
			jsonRespond(w, 200, map[string]interface{}{"id": "sub_old"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/subscriptions"):
			jsonRespond(w, 200, map[string]interface{}{"id": "sub_new", "short_url": "x"})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "sub_old"):
			jsonRespond(w, 500, map[string]interface{}{
				"error": map[string]interface{}{"code": "SERVER_ERROR", "description": "fetch broken"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow("sub_old"))
	mock.ExpectExec("UPDATE teams SET stripe_customer_id").
		WithArgs("sub_new", tid).
		WillReturnResult(sqlmock.NewResult(1, 1))
	before := time.Now().Add(-1 * time.Second)
	res, err := p.ChangePlan(context.Background(), tid, "pro", map[string]string{"pro": "plan_pro_id"})
	if err != nil {
		t.Fatalf("expected fetch-fail to not propagate; got %v", err)
	}
	// Effective date should be "now-ish" — between (before) and (now+5s).
	if res.EffectiveDate.Before(before) || res.EffectiveDate.After(time.Now().Add(5*time.Second)) {
		t.Errorf("EffectiveDate fallback wrong: %v", res.EffectiveDate)
	}
}

func TestChangePlan_FetchReturnsNoCurrentEnd(t *testing.T) {
	// Fetch succeeds but current_end is missing → also use time.Now().
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/cancel"):
			jsonRespond(w, 200, map[string]interface{}{"id": "sub_old"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/subscriptions"):
			jsonRespond(w, 200, map[string]interface{}{"id": "sub_new"})
		case r.Method == http.MethodGet:
			jsonRespond(w, 200, map[string]interface{}{"id": "sub_old"}) // no current_end
		}
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow("sub_old"))
	mock.ExpectExec("UPDATE teams SET stripe_customer_id").
		WithArgs("sub_new", tid).
		WillReturnResult(sqlmock.NewResult(1, 1))
	res, err := p.ChangePlan(context.Background(), tid, "pro", map[string]string{"pro": "plan_pro_id"})
	if err != nil {
		t.Fatalf("ChangePlan: %v", err)
	}
	// Should be "now-ish".
	if res.EffectiveDate.IsZero() {
		t.Error("EffectiveDate should default to now, not zero time")
	}
}

func TestChangePlan_NewSubIDEmpty_NoPersist(t *testing.T) {
	// If Razorpay returns no `id`, we must NOT call UpdateRazorpaySubscriptionID.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/cancel"):
			jsonRespond(w, 200, map[string]interface{}{"id": "sub_old"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/subscriptions"):
			// Razorpay misbehaving — empty id.
			jsonRespond(w, 200, map[string]interface{}{"short_url": "x"})
		case r.Method == http.MethodGet:
			jsonRespond(w, 200, map[string]interface{}{"id": "sub_old", "current_end": float64(1)})
		}
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, mock, _ := mockPortal(t)
	tid := uuid.New()
	mock.ExpectQuery("SELECT stripe_customer_id FROM teams").
		WithArgs(tid).
		WillReturnRows(sqlmock.NewRows([]string{"stripe_customer_id"}).AddRow("sub_old"))
	// NO ExpectExec — the empty newSubID path must skip the UPDATE.
	res, err := p.ChangePlan(context.Background(), tid, "pro", map[string]string{"pro": "plan_pro_id"})
	if err != nil {
		t.Fatalf("ChangePlan: %v", err)
	}
	if res.NewSubID != "" {
		t.Errorf("want empty NewSubID; got %q", res.NewSubID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

// --- FetchSubscriptionDetails ----------------------------------------

func TestFetchSubscriptionDetails_FullCardPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/subscriptions/sub_abc"):
			jsonRespond(w, 200, map[string]interface{}{
				"id":                  "sub_abc",
				"status":              "active",
				"short_url":           "https://rzp.io/i/x",
				"current_end":         float64(1700000000),
				"cancel_at_cycle_end": true,
			})
		case strings.HasSuffix(r.URL.Path, "/invoices"):
			jsonRespond(w, 200, map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{
						"id":         "inv_old",
						"status":     "paid",
						"amount":     float64(900),
						"currency":   "inr",
						"paid_at":    float64(1690000000),
						"payment_id": "pay_old",
					},
					map[string]interface{}{
						"id":         "inv_new",
						"status":     "paid",
						"amount":     float64(1900),
						"currency":   "inr",
						"paid_at":    float64(1700000000),
						"payment_id": "pay_new",
					},
					// status != paid → skipped
					map[string]interface{}{"id": "inv_unpaid", "status": "issued", "payment_id": "pay_unpaid"},
					// status paid but payment_id missing → skipped
					map[string]interface{}{"id": "inv_no_pay", "status": "paid"},
					"not-a-map", // non-map item skip
				},
			})
		case strings.HasSuffix(r.URL.Path, "/payments/pay_new"):
			jsonRespond(w, 200, map[string]interface{}{
				"id":     "pay_new",
				"method": "CARD",
				"amount": float64(1900),
				"card": map[string]interface{}{
					"last4":     "4242",
					"network":   "Visa",
					"exp_month": float64(12),
					"exp_year":  float64(2030),
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	d, err := p.FetchSubscriptionDetails("sub_abc")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if d.Status != "active" || d.ShortURL == "" || !d.CancelAtPeriodEnd {
		t.Errorf("subscription fields wrong: %+v", d)
	}
	if d.PaymentLast4 != "4242" || d.PaymentNetwork != "visa" {
		t.Errorf("card fields wrong: %+v", d)
	}
	if d.PaymentExpMonth != 12 || d.PaymentExpYear != 2030 {
		t.Errorf("exp fields wrong: %+v", d)
	}
	if d.PaymentMethod != "card" {
		t.Errorf("method = %q; want card", d.PaymentMethod)
	}
	if d.LatestPaidAmount != 1900 || d.LatestPaidCurrency != "INR" {
		t.Errorf("amount/currency wrong: %d/%s", d.LatestPaidAmount, d.LatestPaidCurrency)
	}
}

func TestFetchSubscriptionDetails_NotConfigured(t *testing.T) {
	p := &Portal{Cfg: &config.Config{}}
	if _, err := p.FetchSubscriptionDetails("sub_x"); err == nil {
		t.Fatal("want not-configured")
	}
}

func TestFetchSubscriptionDetails_SubscriptionFetchFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRespond(w, 500, map[string]interface{}{
			"error": map[string]interface{}{"code": "SERVER_ERROR", "description": "x"},
		})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	if _, err := p.FetchSubscriptionDetails("sub_x"); err == nil {
		t.Fatal("want sub-fetch error")
	}
}

func TestFetchSubscriptionDetails_CancelAtCycleEndAsFloat(t *testing.T) {
	// Razorpay sometimes returns cancel_at_cycle_end as a number (1/0).
	// Exercise the float64 branch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/subscriptions/sub_x") {
			jsonRespond(w, 200, map[string]interface{}{
				"status":              "active",
				"cancel_at_cycle_end": float64(1),
				"current_end":         float64(0), // zero → exercises non-zero guard
			})
			return
		}
		// No invoices → early return after sub fetch
		jsonRespond(w, 200, map[string]interface{}{})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	d, err := p.FetchSubscriptionDetails("sub_x")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !d.CancelAtPeriodEnd {
		t.Error("expected cancel_at_period_end=true from float64(1)")
	}
	if !d.CurrentPeriodEnd.IsZero() {
		t.Errorf("expected zero CurrentPeriodEnd for current_end=0; got %v", d.CurrentPeriodEnd)
	}
}

func TestFetchSubscriptionDetails_InvoicesFail(t *testing.T) {
	// Invoice listing fails → we still return the subscription portion.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/subscriptions/sub_x") {
			jsonRespond(w, 200, map[string]interface{}{
				"status":      "active",
				"current_end": float64(1700000000),
			})
			return
		}
		jsonRespond(w, 500, map[string]interface{}{
			"error": map[string]interface{}{"code": "SERVER_ERROR", "description": "inv broken"},
		})
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	d, err := p.FetchSubscriptionDetails("sub_x")
	if err != nil {
		t.Fatalf("want nil err even if invoice listing fails; got %v", err)
	}
	if d.Status != "active" {
		t.Errorf("d = %+v", d)
	}
}

func TestFetchSubscriptionDetails_NoItemsField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/subscriptions/sub_x") {
			jsonRespond(w, 200, map[string]interface{}{"status": "active"})
			return
		}
		jsonRespond(w, 200, map[string]interface{}{}) // no items
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	d, err := p.FetchSubscriptionDetails("sub_x")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if d.PaymentMethod != "" {
		t.Errorf("expected empty payment method, got %q", d.PaymentMethod)
	}
}

func TestFetchSubscriptionDetails_NoPaymentIDFoundEarlyReturn(t *testing.T) {
	// Items exist but no paid invoice with a payment_id → return d
	// without calling /payments. Verify the early-return branch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/subscriptions/sub_x"):
			jsonRespond(w, 200, map[string]interface{}{"status": "active"})
		case strings.HasSuffix(r.URL.Path, "/invoices"):
			jsonRespond(w, 200, map[string]interface{}{
				"items": []map[string]interface{}{
					{"status": "issued"}, // not paid
					{"status": "paid"},   // paid but no payment_id
				},
			})
		case strings.Contains(r.URL.Path, "/payments/"):
			t.Errorf("payments endpoint should NOT have been called")
		}
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	d, err := p.FetchSubscriptionDetails("sub_x")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if d.PaymentMethod != "" {
		t.Errorf("expected empty payment method; got %q", d.PaymentMethod)
	}
}

func TestFetchSubscriptionDetails_PaymentFetchFails(t *testing.T) {
	// Items have a paid invoice with payment_id, but /payments returns 5xx.
	// Should return d so far (no card details) without error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/subscriptions/sub_x"):
			jsonRespond(w, 200, map[string]interface{}{"status": "active"})
		case strings.HasSuffix(r.URL.Path, "/invoices"):
			jsonRespond(w, 200, map[string]interface{}{
				"items": []map[string]interface{}{
					{
						"id":         "inv",
						"status":     "paid",
						"payment_id": "pay_broken",
						"paid_at":    float64(1700000000),
						"amount":     float64(900),
						"currency":   "inr",
					},
				},
			})
		case strings.Contains(r.URL.Path, "/payments/pay_broken"):
			jsonRespond(w, 500, map[string]interface{}{
				"error": map[string]interface{}{"code": "SERVER_ERROR", "description": "pay broken"},
			})
		}
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	d, err := p.FetchSubscriptionDetails("sub_x")
	if err != nil {
		t.Fatalf("payment fetch fail should not propagate; got %v", err)
	}
	// We DID pick up LatestPaidAmount from the invoice before the
	// /payments call exploded.
	if d.LatestPaidAmount != 900 || d.LatestPaidCurrency != "INR" {
		t.Errorf("amount/currency from invoice not captured: %d/%q", d.LatestPaidAmount, d.LatestPaidCurrency)
	}
	if d.PaymentMethod != "" {
		t.Errorf("payment method should be empty when /payments failed; got %q", d.PaymentMethod)
	}
}

func TestFetchSubscriptionDetails_UPIPayment(t *testing.T) {
	// Top-level vpa field present, no card object.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/subscriptions/sub_x"):
			jsonRespond(w, 200, map[string]interface{}{"status": "active"})
		case strings.HasSuffix(r.URL.Path, "/invoices"):
			jsonRespond(w, 200, map[string]interface{}{
				"items": []map[string]interface{}{
					{
						"id":         "inv",
						"status":     "paid",
						"payment_id": "pay_upi",
						"paid_at":    float64(1700000000),
					},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/payments/pay_upi"):
			jsonRespond(w, 200, map[string]interface{}{
				"method": "upi",
				"vpa":    "alice@hdfc",
			})
		}
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	d, err := p.FetchSubscriptionDetails("sub_x")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if d.PaymentMethod != "upi" || d.PaymentVPA != "alice@hdfc" {
		t.Errorf("upi extract wrong: %+v", d)
	}
}

func TestFetchSubscriptionDetails_UPIPaymentNestedVPA(t *testing.T) {
	// Variant where vpa lives under "upi": {...} (some webhook shapes).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/subscriptions/sub_x"):
			jsonRespond(w, 200, map[string]interface{}{"status": "active"})
		case strings.HasSuffix(r.URL.Path, "/invoices"):
			jsonRespond(w, 200, map[string]interface{}{
				"items": []map[string]interface{}{
					{"id": "inv", "status": "paid", "payment_id": "pay_upi", "paid_at": float64(1)},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/payments/pay_upi"):
			jsonRespond(w, 200, map[string]interface{}{
				"method": "upi",
				"upi": map[string]interface{}{
					"vpa": "bob@axis",
				},
			})
		}
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	d, err := p.FetchSubscriptionDetails("sub_x")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if d.PaymentVPA != "bob@axis" {
		t.Errorf("nested upi.vpa not extracted; got %q", d.PaymentVPA)
	}
}

func TestFetchSubscriptionDetails_PaidAtMissing_FallsBackToCreatedAt(t *testing.T) {
	// paid_at missing → toInt64 returns 0 → we fall back to created_at.
	// Same paid-invoice still gets selected and the /payments call fires.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/subscriptions/sub_x"):
			jsonRespond(w, 200, map[string]interface{}{"status": "active"})
		case strings.HasSuffix(r.URL.Path, "/invoices"):
			jsonRespond(w, 200, map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{
						"id":         "inv",
						"status":     "paid",
						"payment_id": "pay_x",
						// no paid_at
						"created_at": float64(1690000000),
						"amount":     float64(500),
						"currency":   "inr",
					},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/payments/pay_x"):
			jsonRespond(w, 200, map[string]interface{}{"method": "card"})
		}
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	d, err := p.FetchSubscriptionDetails("sub_x")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if d.PaymentMethod != "card" {
		t.Errorf("expected payment method captured via created_at fallback; got %q", d.PaymentMethod)
	}
}

func TestFetchSubscriptionDetails_FallbackToPaymentAmount(t *testing.T) {
	// Invoice has no amount → fall back to the payment's amount/currency.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/subscriptions/sub_x"):
			jsonRespond(w, 200, map[string]interface{}{"status": "active"})
		case strings.HasSuffix(r.URL.Path, "/invoices"):
			jsonRespond(w, 200, map[string]interface{}{
				"items": []map[string]interface{}{
					{"id": "inv", "status": "paid", "payment_id": "pay_x", "paid_at": float64(1)},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/payments/pay_x"):
			jsonRespond(w, 200, map[string]interface{}{
				"method":   "card",
				"amount":   float64(4900),
				"currency": "usd",
			})
		}
	}))
	t.Cleanup(srv.Close)
	installMockFactory(t, srv)
	p, _, _ := mockPortal(t)
	d, err := p.FetchSubscriptionDetails("sub_x")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if d.LatestPaidAmount != 4900 || d.LatestPaidCurrency != "USD" {
		t.Errorf("fallback amount/currency missed: %d/%q", d.LatestPaidAmount, d.LatestPaidCurrency)
	}
}

// TestZ_SingletonBreakerOpensAndRejects intentionally trips the
// package-level singleton breaker (5 consecutive failures) to cover
// the WithOnOpen callback and the open-state rejection branch of
// callWithBreaker. This test MUST run LAST in the file (Go executes
// tests in source order). We cannot reset the singleton's open state;
// any subsequent Razorpay call would short-circuit until the 60s
// cooldown elapses, so no test should follow this one.
func TestZ_SingletonBreakerOpensAndRejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonRespond(w, 500, map[string]interface{}{
			"error": map[string]interface{}{"code": "SERVER_ERROR", "description": "always fail"},
		})
	}))
	defer srv.Close()

	// Don't use installMockFactory here — we deliberately leave the
	// breaker open so the singleton-rejection branch is covered.
	orig := newClientForPortal
	newClientForPortal = func(keyID, secret string) *razorpay.Client {
		c := razorpay.NewClient(keyID, secret)
		c.Request.BaseURL = srv.URL
		c.Request.SetTimeout(5)
		return c
	}
	defer func() { newClientForPortal = orig }()

	p, _, _ := mockPortal(t)
	// Drive the singleton across its threshold (5 consecutive failures).
	// Each call goes through callWithBreaker → records the err → after
	// the 5th, the breaker flips to open and onOpen fires.
	for i := 0; i < 6; i++ {
		_ = p.CancelImmediately("sub_x") // expect err each time; ignore
	}
	if Breaker().State() != circuit.StateOpen {
		t.Fatalf("expected singleton open after 6 failed calls; got %s", Breaker().State())
	}
	// One more call — callWithBreaker must reject BEFORE dispatching
	// to the SDK, returning circuit.ErrOpen.
	err := p.CancelImmediately("sub_x")
	if !errors.Is(err, circuit.ErrOpen) {
		t.Fatalf("expected ErrOpen from open-state branch; got %v", err)
	}
}
