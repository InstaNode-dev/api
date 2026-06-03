package handlers

// deploy_tarball_cap_test.go — white-box test for the 10 MB deploy upload cap
// (2026-06-03). enforceTarballCap only reads fh.Size, so the 413 path is
// covered without allocating an oversized buffer.

import (
	"mime/multipart"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

func TestEnforceTarballCap_OverCap_413WithAgentAction(t *testing.T) {
	app := fiber.New()
	ctx := app.AcquireCtx(&fasthttp.RequestCtx{})
	defer app.ReleaseCtx(ctx)

	err := enforceTarballCap(ctx, &multipart.FileHeader{Filename: "big.tar.gz", Size: 23 << 20})
	if err == nil {
		t.Fatal("expected an error for an over-cap tarball")
	}
	if got := ctx.Response().StatusCode(); got != fiber.StatusRequestEntityTooLarge {
		t.Fatalf("want 413 Payload Too Large, got %d", got)
	}
	body := string(ctx.Response().Body())
	for _, want := range []string{`"tarball_too_large"`, `"agent_action"`, "10 MB", "23 MB", "prebuilt image"} {
		if !strings.Contains(body, want) {
			t.Errorf("413 body missing %q; got: %s", want, body)
		}
	}
}

func TestEnforceTarballCap_WithinCap_Nil(t *testing.T) {
	app := fiber.New()
	ctx := app.AcquireCtx(&fasthttp.RequestCtx{})
	defer app.ReleaseCtx(ctx)

	if err := enforceTarballCap(ctx, &multipart.FileHeader{Filename: "ok.tar.gz", Size: 5 << 20}); err != nil {
		t.Fatalf("a within-cap tarball must pass, got %v", err)
	}
	// exactly at the cap is allowed (strictly-greater check)
	app2ctx := app.AcquireCtx(&fasthttp.RequestCtx{})
	defer app.ReleaseCtx(app2ctx)
	if err := enforceTarballCap(app2ctx, &multipart.FileHeader{Size: maxTarballBytes}); err != nil {
		t.Fatalf("a tarball exactly at the cap must pass, got %v", err)
	}
}
