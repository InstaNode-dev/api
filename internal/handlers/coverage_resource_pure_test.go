package handlers

// coverage_resource_pure_test.go — pure-function tests for package-internal
// helpers in resource.go / storage_presign.go that don't require a DB / Redis /
// Fiber app. Exercises:
//
//   - validateSQLIdent (positive + negative cases)
//   - urlUsername / extractURLUsername / decryptOrEmpty
//   - resourceTypeToProto (every arm)
//   - isPaidTier (every documented tier)
//   - maskPresignTokenForAudit / maskPresignKeyForAudit
//   - parseTeamID (empty / valid / invalid)
//   - sanitisePresignKey + isSafePresignKey (additional defensive cases)

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonv1 "instant.dev/proto/common/v1"

	"instant.dev/internal/crypto"
)

const pureTestAESKeyHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

// ── validateSQLIdent ───────────────────────────────────────────────────────

func TestResourceHelpers_ValidateSQLIdent(t *testing.T) {
	cases := map[string]bool{
		"":               true,  // expect error
		"db_x":           false, // ok
		"db_with_dash-1": false, // ok (- and _ allowed)
		"abc123":         false,
		"DB_X":           true,  // uppercase rejected
		"db x":           true,  // space rejected
		"db;DROP":        true,
		"db'or'1":        true,
		"db_é":           true, // unicode rejected
	}
	for in, wantErr := range cases {
		err := validateSQLIdent(in)
		if wantErr {
			assert.Errorf(t, err, "validateSQLIdent(%q) should error", in)
		} else {
			assert.NoErrorf(t, err, "validateSQLIdent(%q) should pass", in)
		}
	}
}

// ── urlUsername ────────────────────────────────────────────────────────────

func TestResourceHelpers_URLUsername(t *testing.T) {
	cases := map[string]string{
		"postgres://user:pw@host/db": "user",
		"redis://default:pw@h:6379":  "default",
		"mongodb://admin:p@m":        "admin",
		"redis://h:6379":             "",
		"":                           "",
		"not a url":                  "",
		"://broken":                  "",
	}
	for in, want := range cases {
		assert.Equal(t, want, urlUsername(in), "urlUsername(%q)", in)
	}
}

// ── decryptOrEmpty ─────────────────────────────────────────────────────────

func TestResourceHelpers_DecryptOrEmpty_EmptyInput(t *testing.T) {
	got := decryptOrEmpty("", pureTestAESKeyHex)
	assert.Equal(t, "", got, "empty input → empty output")
}

func TestResourceHelpers_DecryptOrEmpty_BadKey(t *testing.T) {
	// Real ciphertext but wrong key length
	aesKey, err := crypto.ParseAESKey(pureTestAESKeyHex)
	require.NoError(t, err)
	enc, err := crypto.Encrypt(aesKey, "secret")
	require.NoError(t, err)
	got := decryptOrEmpty(enc, "ZZZZ")
	assert.Equal(t, "", got, "bad key parse → empty")
}

func TestResourceHelpers_DecryptOrEmpty_HappyPath(t *testing.T) {
	aesKey, err := crypto.ParseAESKey(pureTestAESKeyHex)
	require.NoError(t, err)
	enc, err := crypto.Encrypt(aesKey, "postgres://u:p@h/db")
	require.NoError(t, err)
	got := decryptOrEmpty(enc, pureTestAESKeyHex)
	assert.Equal(t, "postgres://u:p@h/db", got)
}

func TestResourceHelpers_DecryptOrEmpty_BadCiphertext(t *testing.T) {
	got := decryptOrEmpty("not-real-base64", pureTestAESKeyHex)
	assert.Equal(t, "", got)
}

// ── extractURLUsername ────────────────────────────────────────────────────

func TestResourceHelpers_ExtractURLUsername(t *testing.T) {
	aesKey, err := crypto.ParseAESKey(pureTestAESKeyHex)
	require.NoError(t, err)
	enc, err := crypto.Encrypt(aesKey, "postgres://usr_token:pw@host:5432/db_token")
	require.NoError(t, err)
	got := extractURLUsername(enc, pureTestAESKeyHex)
	assert.Equal(t, "usr_token", got)

	// Empty input
	assert.Equal(t, "", extractURLUsername("", pureTestAESKeyHex))
	// Bad decrypt
	assert.Equal(t, "", extractURLUsername("garbage", pureTestAESKeyHex))
}

// ── resourceTypeToProto ────────────────────────────────────────────────────

func TestResourceTypeToProto(t *testing.T) {
	cases := map[string]commonv1.ResourceType{
		"postgres": commonv1.ResourceType_RESOURCE_TYPE_POSTGRES,
		"redis":    commonv1.ResourceType_RESOURCE_TYPE_REDIS,
		"mongodb":  commonv1.ResourceType_RESOURCE_TYPE_MONGODB,
		"queue":    commonv1.ResourceType_RESOURCE_TYPE_QUEUE,
		"vector":   commonv1.ResourceType_RESOURCE_TYPE_POSTGRES,
		"unknown":  commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED,
		"":        commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED,
	}
	for in, want := range cases {
		assert.Equal(t, want, resourceTypeToProto(in), "resourceTypeToProto(%q)", in)
	}
}

// ── isPaidTier ─────────────────────────────────────────────────────────────

func TestStorageHelpers_IsPaidTier_AllTiers(t *testing.T) {
	paid := []string{"hobby", "hobby_plus", "pro", "growth", "team",
		"hobby_yearly", "hobby_plus_yearly", "pro_yearly", "team_yearly"}
	for _, tier := range paid {
		assert.True(t, isPaidTier(tier), "isPaidTier(%q)", tier)
	}
	notPaid := []string{"anonymous", "free", "", "unknown", "Hobby"}
	for _, tier := range notPaid {
		assert.False(t, isPaidTier(tier), "isPaidTier(%q)", tier)
	}
}

// ── maskPresignTokenForAudit / maskPresignKeyForAudit ─────────────────────

func TestStorageHelpers_MaskPresignTokenForAudit(t *testing.T) {
	assert.Equal(t, "***", maskPresignTokenForAudit("short"))
	assert.Equal(t, "***", maskPresignTokenForAudit(""))
	assert.Equal(t, "abc12345...",
		maskPresignTokenForAudit("abc12345-aaaa-bbbb-cccc-dddddddddddd"))
}

func TestStorageHelpers_MaskPresignKeyForAudit(t *testing.T) {
	assert.Equal(t, "short.txt", maskPresignKeyForAudit("short.txt"))
	long := "this-is-a-very-long-key-that-exceeds-thirty-two-chars.bin"
	got := maskPresignKeyForAudit(long)
	assert.True(t, len(got) <= 35)
	assert.Contains(t, got, "...")
}

// ── parseTeamID ────────────────────────────────────────────────────────────

func TestResourceHelpers_ParseTeamID(t *testing.T) {
	_, err := parseTeamID("")
	assert.Error(t, err, "empty must error")

	_, err = parseTeamID("not-a-uuid")
	assert.Error(t, err, "non-uuid must error")

	id, err := parseTeamID(uuid.NewString())
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, id)
}

// ── isSafePresignKey / sanitisePresignKey defensive cases ────────────────

func TestStorageHelpers_IsSafePresignKey_AdditionalCases(t *testing.T) {
	// already covered in storage_presign_test.go but exercise a few more
	// strange unicode + long-path cases
	cases := map[string]bool{
		"keys/abc.bin":                     true,
		"a/b/c/d/e/f/g/h/i/j/k/file.bin":   true,
		"with_unicode_é/file.bin":          true,
		"with spaces/and tab\tfile.bin":    true,
		"....../a":                         true, // "....." is not "."/".." per check
		"a/...":                            true, // "..." is not "..", treated as a segment
	}
	for in, want := range cases {
		assert.Equalf(t, want, isSafePresignKey(in), "isSafePresignKey(%q)", in)
	}
}

func TestStorageHelpers_SanitisePresignKey_AdditionalCases(t *testing.T) {
	// Already covered; add a couple more for the join-empty edge.
	assert.Equal(t, "", sanitisePresignKey(""))
	assert.Equal(t, "", sanitisePresignKey("./"))
	assert.Equal(t, "", sanitisePresignKey("../"))
	assert.Equal(t, "", sanitisePresignKey("./.."))
	assert.Equal(t, "single", sanitisePresignKey("single"))
}

// ── webhookRedisKey + webhookListKey + webhookMaxStored bounds ───────────

func TestWebhookHelpers_RedisKey(t *testing.T) {
	got := webhookRedisKey("tok", "req")
	assert.Equal(t, "wh:tok:req", got)
}

func TestWebhookHelpers_ListKey(t *testing.T) {
	got := webhookListKey("tok")
	assert.Equal(t, "wh:list:tok", got)
}
