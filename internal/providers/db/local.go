package db

// local.go — LocalBackend provisions Postgres databases on the shared postgres-customers pod.
// Connects via POSTGRES_CUSTOMERS_URL (default postgres://postgres:postgres@postgres-customers:5432/postgres).
// Each provisioned token gets its own database (db_{token}) and user (usr_{token}).

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/jackc/pgx/v5"
)

const defaultCustomersURL = "postgres://instant_cust:instant_cust@postgres-customers:5432/instant_customers?sslmode=disable"

// alphanumChars is the charset for generated passwords.
const alphanumChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// LocalBackend provisions databases on the shared postgres-customers instance.
type LocalBackend struct {
	customersURL string // admin connection URL
}

// newLocalBackend creates a LocalBackend using the given admin connection URL.
func newLocalBackend(customersURL string) *LocalBackend {
	if customersURL == "" {
		customersURL = defaultCustomersURL
	}
	return &LocalBackend{customersURL: customersURL}
}

// generatePassword returns a cryptographically random alphanumeric string of length n.
func generatePassword(n int) (string, error) {
	buf := make([]byte, n)
	charsetLen := big.NewInt(int64(len(alphanumChars)))
	for i := range buf {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("generatePassword: %w", err)
		}
		buf[i] = alphanumChars[idx.Int64()]
	}
	return string(buf), nil
}

// Provision creates a Postgres database and user for the given token.
// Equivalent to ProvisionWithExtensions(ctx, token, tier, nil) — kept as a
// convenience wrapper so existing callers don't need to plumb extensions.
func (b *LocalBackend) Provision(ctx context.Context, token, tier string) (*Credentials, error) {
	return b.ProvisionWithExtensions(ctx, token, tier, nil)
}

// ProvisionWithExtensions creates a Postgres database and user for the given
// token, then installs each requested extension (allowlisted in
// backend.AllowedExtensions). Pass nil/empty to provision a vanilla database.
// Currently the only allowed extension is "vector" (pgvector) — see
// backend.ValidateExtensions.
func (b *LocalBackend) ProvisionWithExtensions(ctx context.Context, token, tier string, extensions []string) (*Credentials, error) {
	if err := ValidateExtensions(extensions); err != nil {
		return nil, fmt.Errorf("db.local.Provision: %w", err)
	}

	dbName := "db_" + token
	username := "usr_" + token

	pass, err := generatePassword(16)
	if err != nil {
		return nil, fmt.Errorf("db.local.Provision: %w", err)
	}

	// Connect as admin.
	conn, err := pgx.Connect(ctx, b.customersURL)
	if err != nil {
		return nil, fmt.Errorf("db.local.Provision: connect: %w", err)
	}
	defer func() {
		if discErr := conn.Close(ctx); discErr != nil {
			slog.Error("db.local.Provision: disconnect", "error", discErr)
		}
	}()

	// CREATE DATABASE — identifiers cannot be parameterised.
	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE %q", dbName)); err != nil {
		return nil, fmt.Errorf("db.local.Provision: CREATE DATABASE: %w", err)
	}

	// CREATE USER with password.
	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE USER %q WITH PASSWORD '%s'", username, pass)); err != nil {
		return nil, fmt.Errorf("db.local.Provision: CREATE USER: %w", err)
	}

	// REVOKE CONNECT from PUBLIC so only the provisioned user can connect.
	// PostgreSQL grants CONNECT to PUBLIC by default; without this, any role
	// that knows the password of another user could connect to their database.
	if _, err := conn.Exec(ctx, fmt.Sprintf("REVOKE CONNECT ON DATABASE %q FROM PUBLIC", dbName)); err != nil {
		slog.Error("db.local.Provision: REVOKE CONNECT (non-fatal)", "token", token, "error", err)
	}

	// GRANT ALL PRIVILEGES ON DATABASE to the new user.
	if _, err := conn.Exec(ctx, fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE %q TO %q", dbName, username)); err != nil {
		return nil, fmt.Errorf("db.local.Provision: GRANT DATABASE: %w", err)
	}

	// Connect to the new database to grant schema privileges and install
	// any requested extensions. Extensions must run inside the new DB —
	// CREATE EXTENSION is database-scoped, not cluster-scoped — and must
	// run as a superuser/admin, not the per-token user (which lacks
	// CREATE-on-pg_catalog privileges).
	newDBURL := b.buildDBURL(username, pass, dbName)
	adminNewDB, err := pgx.Connect(ctx, b.buildAdminNewDBURL(dbName))
	if err != nil {
		slog.Error("db.local.Provision: connect new db for schema grant (non-fatal)", "error", err)
		// If extensions were requested and we couldn't connect to the new
		// DB to install them, fail loudly — silently returning a non-
		// vector-enabled database would surprise the caller.
		if len(extensions) > 0 {
			return nil, fmt.Errorf("db.local.Provision: connect new db to install extensions: %w", err)
		}
	} else {
		defer func() {
			if discErr := adminNewDB.Close(ctx); discErr != nil {
				slog.Error("db.local.Provision: disconnect new db", "error", discErr)
			}
		}()
		if _, err := adminNewDB.Exec(ctx, fmt.Sprintf("GRANT ALL ON SCHEMA public TO %q", username)); err != nil {
			slog.Error("db.local.Provision: GRANT SCHEMA (non-fatal)", "token", token, "error", err)
		}
		// Install each allowlisted extension. We've already validated the
		// names against AllowedExtensions, so it's safe to interpolate
		// them into the DDL (Postgres doesn't accept extension names as
		// parameters). Use a quoted identifier to defend against any
		// future allowlist entry that contains uppercase or punctuation.
		for _, ext := range extensions {
			if _, err := adminNewDB.Exec(ctx, fmt.Sprintf("CREATE EXTENSION IF NOT EXISTS %q", ext)); err != nil {
				return nil, fmt.Errorf("db.local.Provision: CREATE EXTENSION %q: %w", ext, err)
			}
		}
	}

	slog.Info("db.local.Provision: provisioned",
		"token", token,
		"db", dbName,
		"user", username,
		"tier", tier,
		"extensions", extensions,
	)

	return &Credentials{
		URL:                newDBURL,
		DatabaseName:       dbName,
		Username:           username,
		ProviderResourceID: "", // empty for local
	}, nil
}

// StorageBytes returns the size of db_{token} in bytes using pg_database_size.
func (b *LocalBackend) StorageBytes(ctx context.Context, token, providerResourceID string) (int64, error) {
	conn, err := pgx.Connect(ctx, b.customersURL)
	if err != nil {
		return 0, fmt.Errorf("db.local.StorageBytes: connect: %w", err)
	}
	defer func() {
		if discErr := conn.Close(ctx); discErr != nil {
			slog.Error("db.local.StorageBytes: disconnect", "error", discErr)
		}
	}()

	dbName := "db_" + token
	var size int64
	if err := conn.QueryRow(ctx, "SELECT pg_database_size($1)", dbName).Scan(&size); err != nil {
		return 0, fmt.Errorf("db.local.StorageBytes: pg_database_size: %w", err)
	}
	return size, nil
}

// Deprovision terminates active connections, drops the database and user for the token.
func (b *LocalBackend) Deprovision(ctx context.Context, token, providerResourceID string) error {
	dbName := "db_" + token
	username := "usr_" + token

	conn, err := pgx.Connect(ctx, b.customersURL)
	if err != nil {
		return fmt.Errorf("db.local.Deprovision: connect: %w", err)
	}
	defer func() {
		if discErr := conn.Close(ctx); discErr != nil {
			slog.Error("db.local.Deprovision: disconnect", "error", discErr)
		}
	}()

	// Terminate active connections before dropping.
	_, err = conn.Exec(ctx,
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()",
		dbName,
	)
	if err != nil {
		slog.Error("db.local.Deprovision: terminate connections (continuing)", "token", token, "error", err)
	}

	// DROP DATABASE IF EXISTS.
	if _, err := conn.Exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %q", dbName)); err != nil {
		return fmt.Errorf("db.local.Deprovision: DROP DATABASE: %w", err)
	}

	// DROP USER IF EXISTS.
	if _, err := conn.Exec(ctx, fmt.Sprintf("DROP USER IF EXISTS %q", username)); err != nil {
		slog.Error("db.local.Deprovision: DROP USER (continuing)", "token", token, "error", err)
	}

	slog.Info("db.local.Deprovision: deprovisioned", "token", token, "db", dbName, "user", username)
	return nil
}

// buildDBURL constructs the user-facing connection URL for the provisioned database.
func (b *LocalBackend) buildDBURL(username, password, dbName string) string {
	// Extract host from admin URL and replace auth + database.
	// Admin URL format: postgres://user:pass@host:port/db
	// We parse it simply by finding the host portion.
	host := extractHost(b.customersURL)
	return fmt.Sprintf("postgres://%s:%s@%s/%s", username, password, host, dbName)
}

// buildAdminNewDBURL builds an admin connection URL targeting a specific database.
func (b *LocalBackend) buildAdminNewDBURL(dbName string) string {
	// Replace the database component at the end of the admin URL.
	// Simple approach: strip trailing /... and append the new dbName.
	base := b.customersURL
	for i := len(base) - 1; i >= 0; i-- {
		if base[i] == '/' {
			return base[:i+1] + dbName
		}
	}
	return base + "/" + dbName
}

// extractHost returns the host:port portion of a postgres:// URL.
func extractHost(rawURL string) string {
	// postgres://user:pass@host:port/db  or  postgres://user:pass@host/db
	// Find "@" then take up to the next "/".
	const prefix = "postgres://"
	s := rawURL
	if len(s) > len(prefix) {
		s = s[len(prefix):]
	}
	// skip user:pass@
	if at := indexOf(s, '@'); at >= 0 {
		s = s[at+1:]
	}
	// take up to first "/"
	if slash := indexOf(s, '/'); slash >= 0 {
		return s[:slash]
	}
	return s
}

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
