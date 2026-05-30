package handlers

import (
	"strings"
	"testing"
)

func TestOpenAPISpecProduction_StripsInternalSetTier(t *testing.T) {
	prod := OpenAPISpecProduction()
	if prod == "" {
		t.Fatal("OpenAPISpecProduction returned empty string")
	}
	if strings.Contains(prod, "/internal/set-tier") {
		t.Errorf("production spec must not advertise /internal/set-tier (dev-only); found it in output")
	}
}

func TestOpenAPISpecProduction_StableAcrossCalls(t *testing.T) {
	a := OpenAPISpecProduction()
	b := OpenAPISpecProduction()
	if a != b {
		t.Errorf("OpenAPISpecProduction must be deterministic; got two different outputs")
	}
}
