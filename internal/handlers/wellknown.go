package handlers

// wellknown.go — agent-auth discovery endpoint.
//
// Implements the MCP Authorization profile resource-server metadata document
// (https://modelcontextprotocol.io/specification/draft/basic/authorization).
//
// MCP-compliant agents fetch this endpoint before calling any protected route
// to discover:
//   - the canonical resource URL (used for RFC 8707 audience checks)
//   - the authorization server(s) that may issue tokens for this resource
//   - which transports for the bearer token are supported
//   - human-readable documentation
//
// The endpoint is unauthenticated by design — discovery must work for any
// caller that has not yet acquired a token.

import (
	"net/url"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// Default canonical resource URL when neither API_PUBLIC_URL nor a request host
// is available. Kept as a const so the spec output is stable in tests.
const defaultCanonicalResourceURL = "https://api.instanode.dev"

// wellKnownDocPath is the public docs URL exposed in the metadata.
const wellKnownDocPath = "/docs/auth"

// CanonicalResourceURL returns the canonical resource URL used for RFC 8707
// audience checks and for `/.well-known/oauth-protected-resource`.
//
// Resolution order:
//  1. API_PUBLIC_URL environment variable (when set and non-empty)
//  2. The X-Forwarded-Proto + Host headers from the live request
//  3. The constant default ("https://api.instanode.dev")
//
// It is a package-level variable (rather than a plain function) so individual
// tests can override it without forcing the rest of the codebase to thread a
// dependency through call sites.
var CanonicalResourceURL = func(c *fiber.Ctx) string {
	if v := strings.TrimRight(os.Getenv("API_PUBLIC_URL"), "/"); v != "" {
		return v
	}
	if c != nil {
		host := c.Get("X-Forwarded-Host")
		if host == "" {
			host = c.Hostname()
		}
		scheme := c.Get("X-Forwarded-Proto")
		if scheme == "" {
			if c.Protocol() != "" {
				scheme = c.Protocol()
			} else {
				scheme = "https"
			}
		}
		if host != "" {
			u := url.URL{Scheme: scheme, Host: host}
			return strings.TrimRight(u.String(), "/")
		}
	}
	return defaultCanonicalResourceURL
}

// ServeOAuthProtectedResourceMetadata serves
// GET /.well-known/oauth-protected-resource per the MCP authorization profile.
//
// Response shape (RFC 9728 / MCP draft):
//
//	{
//	  "resource":                 "https://api.instanode.dev",
//	  "authorization_servers":    ["https://api.instanode.dev"],
//	  "bearer_methods_supported": ["header"],
//	  "resource_documentation":   "https://instanode.dev/docs/auth"
//	}
func ServeOAuthProtectedResourceMetadata(c *fiber.Ctx) error {
	resource := CanonicalResourceURL(c)
	c.Set("Content-Type", "application/json; charset=utf-8")
	c.Set("Cache-Control", "public, max-age=300")
	return c.JSON(fiber.Map{
		"resource":                 resource,
		"authorization_servers":    []string{resource},
		"bearer_methods_supported": []string{"header"},
		"resource_documentation":   "https://instanode.dev" + wellKnownDocPath,
	})
}
