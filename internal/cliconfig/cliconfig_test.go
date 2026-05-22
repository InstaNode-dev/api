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

// ---------------------------------------------------------------------------
// configPath error branches (UserHomeDir failure)
// ---------------------------------------------------------------------------

// unsetHome removes HOME for the duration of the test so os.UserHomeDir()
// fails. t.Setenv with an empty value still leaves HOME defined, so we must
// Unsetenv and restore manually.
func unsetHome(t *testing.T) {
	t.Helper()
	orig, had := os.LookupEnv("HOME")
	require.NoError(t, os.Unsetenv("HOME"))
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("HOME", orig)
		} else {
			_ = os.Unsetenv("HOME")
		}
	})
}

func TestLoad_ReturnsEmptyConfigWhenHomeUnresolvable(t *testing.T) {
	unsetHome(t)
	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Empty(t, cfg.path, "path stays empty when configPath() errors")
	assert.Empty(t, cfg.APIKey)
}

func TestSave_ErrorsWhenHomeUnresolvable(t *testing.T) {
	unsetHome(t)
	// Empty path forces Save to call configPath(), which fails with no HOME.
	cfg := &Config{APIKey: "inst_live_x"}
	err := cfg.Save()
	require.Error(t, err, "Save must surface the configPath() error")
}

func TestClear_ErrorsWhenHomeUnresolvable(t *testing.T) {
	unsetHome(t)
	err := Clear()
	require.Error(t, err, "Clear must surface the configPath() error")
}

// ---------------------------------------------------------------------------
// Load error branches: malformed JSON + unreadable file
// ---------------------------------------------------------------------------

func TestLoad_ReturnsErrorOnMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	path := filepath.Join(dir, ".instant-config")
	require.NoError(t, os.WriteFile(path, []byte("{not valid json"), 0600))

	cfg, err := Load()
	require.Error(t, err, "malformed JSON must produce a parse error")
	assert.Nil(t, cfg)
}

func TestLoad_ReturnsErrorWhenPathIsADirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	// Create a *directory* at the config path so os.ReadFile returns a
	// non-NotExist error (EISDIR), exercising the generic read-error branch.
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".instant-config"), 0700))

	cfg, err := Load()
	require.Error(t, err, "reading a directory must produce a read error")
	assert.Nil(t, cfg)
}

// ---------------------------------------------------------------------------
// Save error branch: rename target unwritable (temp write fails)
// ---------------------------------------------------------------------------

func TestSave_ErrorsWhenTempWriteFails(t *testing.T) {
	// Point path at a file inside a non-existent directory so the temp-file
	// WriteFile (path + ".tmp") fails with ENOENT.
	cfg := &Config{path: filepath.Join(t.TempDir(), "no-such-dir", "cfg")}
	err := cfg.Save()
	require.Error(t, err, "Save must surface the temp-file write error")
	assert.Contains(t, err.Error(), "writing")
}

// ---------------------------------------------------------------------------
// Save with empty path resolves via configPath() (path == "" branch)
// ---------------------------------------------------------------------------

func TestSave_ResolvesPathViaConfigPathWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg := &Config{APIKey: "inst_live_resolve"} // path intentionally empty
	require.NoError(t, cfg.Save())

	// Save must have resolved and persisted the path.
	assert.Equal(t, filepath.Join(dir, ".instant-config"), cfg.path)
	_, err := os.Stat(cfg.path)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Clear error branch: Remove fails for a non-NotExist reason
// ---------------------------------------------------------------------------

func TestClear_ErrorsWhenTargetIsNonEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	// A non-empty directory at the config path makes os.Remove fail with
	// ENOTEMPTY — a non-NotExist error that Clear must surface.
	cfgDir := filepath.Join(dir, ".instant-config")
	require.NoError(t, os.Mkdir(cfgDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "child"), []byte("x"), 0600))

	err := Clear()
	require.Error(t, err, "Clear must surface a non-NotExist Remove error")
}
