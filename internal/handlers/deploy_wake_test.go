package handlers

// deploy_wake_test.go — scale-to-zero wake endpoint coverage (Task #54).
//
// The flag-off path is the load-bearing safety property (rule: default OFF,
// inert when off). It must short-circuit with 501 BEFORE any auth lookup, scale
// call, or DB write — so this test constructs the handler with the flag off and
// asserts a 501 with no compute interaction. A panicking compute provider proves
// the handler never reaches the scale layer when the flag is off.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"instant.dev/internal/config"
	"instant.dev/internal/providers/compute"
)

// wakePanicProvider satisfies compute.Provider; Scale panics so a flag-off wake
// that incorrectly reaches the compute layer fails loudly.
type wakePanicProvider struct{}

func (wakePanicProvider) Deploy(context.Context, compute.DeployOptions) (*compute.AppDeployment, error) {
	panic("Deploy: not expected")
}
func (wakePanicProvider) Status(context.Context, string) (*compute.AppDeployment, error) {
	panic("Status: not expected")
}
func (wakePanicProvider) Logs(context.Context, string, bool) (io.ReadCloser, error) {
	panic("Logs: not expected")
}
func (wakePanicProvider) Teardown(context.Context, string) error { panic("Teardown: not expected") }
func (wakePanicProvider) Redeploy(context.Context, string, []byte, map[string]string) (*compute.AppDeployment, error) {
	panic("Redeploy: not expected")
}
func (wakePanicProvider) UpdateAccessControl(context.Context, string, bool, []string) error {
	panic("UpdateAccessControl: not expected")
}
func (wakePanicProvider) Scale(context.Context, string, int32) error {
	panic("Scale: not expected when scale-to-zero flag is OFF")
}

// TestWake_FlagOff_Returns501Inert proves the wake endpoint is fully inert when
// DEPLOY_SCALE_TO_ZERO_ENABLED is off: 501 response, and the (panicking)
// compute provider is never touched.
func TestWake_FlagOff_Returns501Inert(t *testing.T) {
	h := &DeployHandler{
		cfg:     &config.Config{DeployScaleToZeroEnabled: false},
		compute: wakePanicProvider{},
	}
	// Mirror the production fiber ErrorHandler so respondError's
	// ErrResponseWritten sentinel isn't turned into a 500 by the default handler.
	app := fiber.New(fiber.Config{
		ErrorHandler: func(_ *fiber.Ctx, err error) error {
			if err == ErrResponseWritten {
				return nil
			}
			return err
		},
	})
	app.Post("/deploy/:id/wake", h.Wake)

	req := httptest.NewRequest(http.MethodPost, "/deploy/app-123/wake", nil)
	resp, err := app.Test(req, 1000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("flag-off wake status = %d, want 501", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "scale_to_zero_disabled") {
		t.Errorf("flag-off body = %q; want scale_to_zero_disabled error code", string(body))
	}
}
