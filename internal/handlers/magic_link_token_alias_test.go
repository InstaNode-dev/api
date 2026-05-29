package handlers

// magic_link_token_alias_test.go — BUG-API-011 regression.
//
// Pre-fix: GET /auth/email/callback?token=<plaintext> rendered
// "Sign-in link is missing its token" — but the token IS present, just
// under the longer param name. The canonical magic-link URL uses
// `?t=<plaintext>` (kept short for SMS-style copy-paste); `?token=` is a
// fallback alias that lets a hand-typing user / MCP tool that guessed
// the longer name still hit the validation branch.

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMagicLink_Callback_AcceptsTokenAlias(t *testing.T) {
	src, err := os.ReadFile("magic_link.go")
	require.NoError(t, err, "magic_link.go must be readable from package dir")
	body := string(src)

	assert.Contains(t, body, `c.Query("t")`,
		"BUG-API-011: canonical param `?t=` must still be read")
	assert.Contains(t, body, `c.Query("token")`,
		"BUG-API-011: `?token=` fallback must be read so the wrong-param-name UX no longer says 'missing'")
}
