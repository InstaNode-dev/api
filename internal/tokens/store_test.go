package tokens

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withHome redirects the HOME env var to a temp dir for the duration of fn so
// that storePath() resolves to a hermetic location. Returns the temp dir for
// callers that need to assert against it.
func withHome(t *testing.T, fn func(home string)) {
	t.Helper()
	dir := t.TempDir()
	prev, hadPrev := os.LookupEnv("HOME")
	prevUser, hadUser := os.LookupEnv("USERPROFILE") // Windows path resolution
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv("HOME", prev)
		} else {
			_ = os.Unsetenv("HOME")
		}
		if hadUser {
			_ = os.Setenv("USERPROFILE", prevUser)
		} else {
			_ = os.Unsetenv("USERPROFILE")
		}
	})
	fn(dir)
}

func TestLoad_MissingFileReturnsEmptyStore(t *testing.T) {
	withHome(t, func(home string) {
		s, err := Load()
		if err != nil {
			t.Fatalf("expected nil error on missing file, got %v", err)
		}
		if s == nil {
			t.Fatal("expected non-nil store")
		}
		if len(s.Entries) != 0 {
			t.Fatalf("expected 0 entries, got %d", len(s.Entries))
		}
		if s.path != filepath.Join(home, ".instant-tokens") {
			t.Fatalf("unexpected path %q", s.path)
		}
	})
}

func TestLoad_ReadsExistingStore(t *testing.T) {
	withHome(t, func(home string) {
		path := filepath.Join(home, ".instant-tokens")
		entries := &Store{Entries: []Entry{{
			Token:     "tok-1",
			Name:      "monitor-a",
			URL:       "https://example.com/ping",
			Schedule:  "* * * * *",
			Source:    "manual",
			CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		}}}
		data, _ := json.Marshal(entries)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatalf("seed: %v", err)
		}
		s, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(s.Entries) != 1 || s.Entries[0].Token != "tok-1" {
			t.Fatalf("entries not parsed: %+v", s.Entries)
		}
		if s.path != path {
			t.Fatalf("path not restored: %q", s.path)
		}
	})
}

func TestLoad_InvalidJSONReturnsError(t *testing.T) {
	withHome(t, func(home string) {
		path := filepath.Join(home, ".instant-tokens")
		if err := os.WriteFile(path, []byte("not-json"), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := Load()
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

func TestLoad_ReadErrorOtherThanNotExist(t *testing.T) {
	withHome(t, func(home string) {
		// Create the path as a directory so os.ReadFile fails with EISDIR
		// (not IsNotExist), exercising the non-IsNotExist error branch.
		path := filepath.Join(home, ".instant-tokens")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		_, err := Load()
		if err == nil {
			t.Fatal("expected error reading a directory as file")
		}
		// must NOT be a not-exist error — that branch is covered separately
		if errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected non-ErrNotExist, got %v", err)
		}
	})
}

func TestAddAndFindAndSaveRoundTrip(t *testing.T) {
	withHome(t, func(home string) {
		s, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		// Add with empty CreatedAt — Add must stamp it.
		err = s.Add(Entry{Token: "tok-A", Name: "a", Source: "manual"})
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
		if len(s.Entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(s.Entries))
		}
		if s.Entries[0].CreatedAt.IsZero() {
			t.Fatal("Add must auto-stamp CreatedAt when zero")
		}

		// Add with explicit CreatedAt — Add must preserve it.
		fixed := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
		if err := s.Add(Entry{Token: "tok-B", CreatedAt: fixed}); err != nil {
			t.Fatalf("Add B: %v", err)
		}
		if !s.Entries[1].CreatedAt.Equal(fixed) {
			t.Fatalf("expected CreatedAt preserved, got %v", s.Entries[1].CreatedAt)
		}

		// Find — hit + miss
		if got := s.Find("tok-A"); got == nil || got.Token != "tok-A" {
			t.Fatalf("Find(tok-A) miss: %+v", got)
		}
		if got := s.Find("nope"); got != nil {
			t.Fatalf("Find(nope) should return nil, got %+v", got)
		}

		// Save persisted -> Load reads it back.
		s2, err := Load()
		if err != nil {
			t.Fatalf("Load (round-trip): %v", err)
		}
		if len(s2.Entries) != 2 {
			t.Fatalf("expected 2 entries after round-trip, got %d", len(s2.Entries))
		}

		// File perms must be 0600 (token store is sensitive).
		info, err := os.Stat(filepath.Join(home, ".instant-tokens"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("expected 0600 perms, got %v", info.Mode().Perm())
		}
	})
}

func TestSave_WriteErrorPropagates(t *testing.T) {
	// Point the store at an unwritable path by setting path to a directory.
	dir := t.TempDir()
	s := &Store{path: dir} // writing to a directory must fail
	if err := s.Save(); err == nil {
		t.Fatal("expected write error when path is a directory")
	}
}

func TestStorePath_UnsetHome(t *testing.T) {
	// On unix, unsetting HOME triggers UserHomeDir's error path.
	prev, had := os.LookupEnv("HOME")
	prevUser, hadUser := os.LookupEnv("USERPROFILE")
	_ = os.Unsetenv("HOME")
	_ = os.Unsetenv("USERPROFILE")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("HOME", prev)
		}
		if hadUser {
			_ = os.Setenv("USERPROFILE", prevUser)
		}
	})

	p, err := storePath()
	if err != nil {
		// Expected on most CI environments: UserHomeDir returns an error.
		if p != "" {
			t.Fatalf("expected empty path on error, got %q", p)
		}
		return
	}
	// If the runtime still resolved a home (some platforms / runners do),
	// just assert the result ends with the canonical filename so the
	// function contract is exercised either way.
	if filepath.Base(p) != ".instant-tokens" {
		t.Fatalf("unexpected resolved path %q", p)
	}
}

// TestLoad_StorePathError exercises Load's "storePath failed" early-return
// branch by unsetting HOME (and USERPROFILE for Windows-shape runners) so
// os.UserHomeDir returns an error.
func TestLoad_StorePathError(t *testing.T) {
	prev, had := os.LookupEnv("HOME")
	prevUser, hadUser := os.LookupEnv("USERPROFILE")
	_ = os.Unsetenv("HOME")
	_ = os.Unsetenv("USERPROFILE")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("HOME", prev)
		}
		if hadUser {
			_ = os.Setenv("USERPROFILE", prevUser)
		}
	})
	s, err := Load()
	if err == nil {
		// Some runtimes (containers with /etc/passwd seeded) will still
		// resolve a home. In that case, just assert we got a usable store
		// — the storePath error branch is platform-conditional and the
		// other Load tests cover the happy path.
		if s == nil {
			t.Fatal("expected store on resolved home")
		}
		return
	}
	if s != nil {
		t.Fatalf("expected nil store on storePath error, got %+v", s)
	}
}
