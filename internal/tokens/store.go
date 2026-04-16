// Package tokens manages the local ~/.instant-tokens file that persists
// provisioned monitor tokens between CLI invocations.
package tokens

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Entry represents one saved monitor token.
type Entry struct {
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`        // ping URL
	Schedule  string    `json:"schedule"`   // cron expression or "" if manual
	Source    string    `json:"source"`     // "manual" | "discover" | "exec"
	CreatedAt time.Time `json:"created_at"`
}

// Store is the in-memory representation of ~/.instant-tokens.
type Store struct {
	Entries []Entry `json:"entries"`
	path    string
}

// Load reads the store from disk, creating it if absent.
func Load() (*Store, error) {
	path, err := storePath()
	if err != nil {
		return nil, err
	}
	s := &Store{path: path}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	s.path = path
	return s, nil
}

// Save writes the store back to disk.
func (s *Store) Save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

// Add appends a new entry and saves.
func (s *Store) Add(e Entry) error {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	s.Entries = append(s.Entries, e)
	return s.Save()
}

// Find returns the entry for a given token, or nil if not found.
func (s *Store) Find(token string) *Entry {
	for i := range s.Entries {
		if s.Entries[i].Token == token {
			return &s.Entries[i]
		}
	}
	return nil
}

func storePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".instant-tokens"), nil
}
