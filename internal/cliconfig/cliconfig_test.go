package cliconfig

// White-box tests: same package so we can set the unexported `path` field
// directly, letting us redirect all file I/O to a t.TempDir() location.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTempConfig returns a Config whose path is set to a file inside t.TempDir().
// The file does NOT yet exist on disk.
func newTempConfig(t *testing.T) *Config {
	t.Helper()
	return &Config{path: filepath.Join(t.TempDir(), "instant-config")}
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

func TestLoad_NonExistentFileReturnsEmptyConfig(t *testing.T) {
	// Point configPath at a path that definitely doesn't exist.
	// We can't override configPath() easily, but Load returns an empty Config
	// when the file is absent — simulate that by calling it with HOME set to a
	// fresh temp dir so ~/.instant-config won't exist.
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Empty(t, cfg.APIKey)
	assert.Empty(t, cfg.Email)
	assert.Empty(t, cfg.Tier)
}

// ---------------------------------------------------------------------------
// IsAuthenticated
// ---------------------------------------------------------------------------

func TestIsAuthenticated_FalseWhenAPIKeyEmpty(t *testing.T) {
	cfg := &Config{}
	assert.False(t, cfg.IsAuthenticated())
}

func TestIsAuthenticated_FalseOnNilConfig(t *testing.T) {
	var cfg *Config
	assert.False(t, cfg.IsAuthenticated())
}

func TestIsAuthenticated_TrueWhenAPIKeySet(t *testing.T) {
	cfg := &Config{APIKey: "inst_live_abc123"}
	assert.True(t, cfg.IsAuthenticated())
}

// ---------------------------------------------------------------------------
// EffectiveTier
// ---------------------------------------------------------------------------

func TestEffectiveTier_ReturnsAnonymousWhenEmpty(t *testing.T) {
	cfg := &Config{}
	assert.Equal(t, "anonymous", cfg.EffectiveTier())
}

func TestEffectiveTier_ReturnsAnonymousOnNilConfig(t *testing.T) {
	var cfg *Config
	assert.Equal(t, "anonymous", cfg.EffectiveTier())
}

func TestEffectiveTier_ReturnsTierWhenSet(t *testing.T) {
	for _, tier := range []string{"hobby", "pro", "team"} {
		cfg := &Config{Tier: tier}
		assert.Equal(t, tier, cfg.EffectiveTier(), "tier=%q", tier)
	}
}

// ---------------------------------------------------------------------------
// Save
// ---------------------------------------------------------------------------

func TestSave_WritesFileWithMode0600(t *testing.T) {
	cfg := newTempConfig(t)
	cfg.APIKey = "inst_live_savetest"
	cfg.Email = "save@example.com"
	cfg.Tier = "pro"

	require.NoError(t, cfg.Save())

	info, err := os.Stat(cfg.path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
		"config file must be mode 0600")
}

func TestSave_FileIsValidJSON(t *testing.T) {
	cfg := newTempConfig(t)
	cfg.APIKey = "inst_live_jsontest"

	require.NoError(t, cfg.Save())

	data, err := os.ReadFile(cfg.path)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"api_key"`)
	assert.Contains(t, string(data), "inst_live_jsontest")
}

func TestSave_UpdatesSavedAt(t *testing.T) {
	cfg := newTempConfig(t)
	before := time.Now().UTC().Add(-time.Second)

	require.NoError(t, cfg.Save())

	assert.True(t, cfg.SavedAt.After(before),
		"SavedAt must be set to approximately now after Save()")
}

// ---------------------------------------------------------------------------
// Clear
// ---------------------------------------------------------------------------

func TestClear_RemovesExistingFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Create the file first via Save.
	path := filepath.Join(dir, ".instant-config")
	cfg := &Config{path: path, APIKey: "inst_live_clear"}
	require.NoError(t, cfg.Save())

	_, err := os.Stat(path)
	require.NoError(t, err, "file must exist before Clear")

	// Clear uses configPath() → HOME/.instant-config, which is our temp path.
	require.NoError(t, Clear())

	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "file must be gone after Clear")
}

func TestClear_NoErrorWhenFileAbsent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// The file was never created; Clear must succeed silently.
	require.NoError(t, Clear())
}

// ---------------------------------------------------------------------------
// Round-trip: Save → Load
// ---------------------------------------------------------------------------

func TestRoundTrip_SaveThenLoadReturnsSameStruct(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	original := &Config{
		APIKey:     "inst_live_roundtrip",
		Email:      "rt@example.com",
		Tier:       "team",
		TeamName:   "Acme",
		APIBaseURL: "https://api.staging.instant.dev",
	}
	// Use the HOME-based path so Load() can find it.
	original.path = filepath.Join(dir, ".instant-config")
	require.NoError(t, original.Save())

	loaded, err := Load()
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, original.APIKey, loaded.APIKey)
	assert.Equal(t, original.Email, loaded.Email)
	assert.Equal(t, original.Tier, loaded.Tier)
	assert.Equal(t, original.TeamName, loaded.TeamName)
	assert.Equal(t, original.APIBaseURL, loaded.APIBaseURL)
	// SavedAt is set by Save(); it should be non-zero after the round-trip.
	assert.False(t, loaded.SavedAt.IsZero(), "SavedAt must survive the round-trip")
}

func TestRoundTrip_IsAuthenticatedAfterLoad(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg := &Config{
		path:   filepath.Join(dir, ".instant-config"),
		APIKey: "inst_live_auth",
	}
	require.NoError(t, cfg.Save())

	loaded, err := Load()
	require.NoError(t, err)
	assert.True(t, loaded.IsAuthenticated())
}

func TestRoundTrip_EffectiveTierAfterLoad(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg := &Config{
		path: filepath.Join(dir, ".instant-config"),
		Tier: "hobby",
	}
	require.NoError(t, cfg.Save())

	loaded, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "hobby", loaded.EffectiveTier())
}
