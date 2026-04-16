// Package cliconfig manages the user's CLI credentials in ~/.instant-config.
// It stores the API key, plan tier, and account email after login.
// Anonymous use requires no config at all — the file is optional.
package cliconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrNotLoggedIn is returned when an action requires authentication
// but no API key is found in the config file.
var ErrNotLoggedIn = errors.New("not logged in — run `instant login` to authenticate")

// Config holds the authenticated user's local credentials.
// The zero value is valid and represents an anonymous (unauthenticated) user.
type Config struct {
	// APIKey is the bearer token sent with every authenticated API request.
	// Format: inst_live_<base64url> (production) or inst_test_<base64url> (sandbox).
	// Empty = anonymous mode.
	APIKey string `json:"api_key,omitempty"`

	// Email is the account email, stored for display in `instant whoami`.
	Email string `json:"email,omitempty"`

	// Tier is the current plan: "anonymous", "hobby", "pro", "team".
	Tier string `json:"tier,omitempty"`

	// TeamName is the team name, if the user belongs to a team.
	TeamName string `json:"team_name,omitempty"`

	// APIBaseURL overrides the default https://instant.dev endpoint.
	// Populated when INSTANT_API_URL env var was set at login time.
	APIBaseURL string `json:"api_base_url,omitempty"`

	// SavedAt is when the config was last written (for staleness checks).
	SavedAt time.Time `json:"saved_at,omitempty"`

	path string // resolved path, not serialised
}

// IsAuthenticated reports whether the config holds valid credentials.
func (c *Config) IsAuthenticated() bool {
	return c != nil && c.APIKey != ""
}

// EffectiveTier returns the tier string, defaulting to "anonymous".
func (c *Config) EffectiveTier() string {
	if c == nil || c.Tier == "" {
		return "anonymous"
	}
	return c.Tier
}

// Load reads ~/.instant-config from disk.
// If the file does not exist, it returns an empty (anonymous) Config.
func Load() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return &Config{path: ""}, nil
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Config{path: path}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	cfg.path = path
	return &cfg, nil
}

// Save writes the config to disk with mode 0600 (owner read/write only).
func (c *Config) Save() error {
	if c.path == "" {
		path, err := configPath()
		if err != nil {
			return err
		}
		c.path = path
	}
	c.SavedAt = time.Now().UTC()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// Write to a temp file then rename for atomicity.
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	return os.Rename(tmp, c.path)
}

// Clear removes the config file (logout).
func Clear() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".instant-config"), nil
}
