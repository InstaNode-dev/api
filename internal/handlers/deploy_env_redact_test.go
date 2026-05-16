package handlers

// deploy_env_redact_test.go — Table-driven unit tests for redactEnvVars.
//
// Tests are in the handlers package (not handlers_test) so they can access
// the unexported helpers (isSecretKey, isCredentialURL, redactEnvVars)
// directly. This keeps the test focused on internal logic without requiring a
// full HTTP test harness.

import (
	"testing"
)

func TestIsSecretKey(t *testing.T) {
	cases := []struct {
		key     string
		want    bool
		comment string
	}{
		// Fragment matches
		{"DATABASE_URL", true, "ends with URL suffix"},
		{"REDIS_URL", true, "ends with URL suffix"},
		{"SECRET_KEY", true, "contains SECRET"},
		{"STRIPE_SECRET_KEY", true, "contains SECRET + ends with _KEY"},
		{"DB_PASSWORD", true, "contains PASSWORD"},
		{"DB_PASSWD", true, "contains PASSWD"},
		{"ADMIN_PWD", true, "contains PWD"},
		{"SESSION_TOKEN", true, "contains TOKEN"},
		{"SIGNING_KEY", true, "contains _KEY (fragment match)"},
		{"APIKEY", true, "contains APIKEY"},
		{"API_KEY", true, "contains _KEY via fragment"},
		{"MY_DSN", true, "ends with DSN suffix"},
		{"MONGO_URI", true, "ends with URI suffix"},

		// Innocuous keys — must NOT be masked
		{"NODE_ENV", false, "plain env name"},
		{"PORT", false, "port number"},
		{"HOST", false, "hostname"},
		{"APP_NAME", false, "app label"},
		{"LOG_LEVEL", false, "log level — LEVEL does not match any fragment"},
		{"MAX_WORKERS", false, "worker count"},
		{"FEATURE_FLAG", false, "feature flag"},
		{"_name", false, "underscore-prefixed internal label"},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			got := isSecretKey(tc.key)
			if got != tc.want {
				t.Errorf("isSecretKey(%q) = %v, want %v (%s)", tc.key, got, tc.want, tc.comment)
			}
		})
	}
}

func TestIsCredentialURL(t *testing.T) {
	cases := []struct {
		value   string
		want    bool
		comment string
	}{
		// Credential-bearing URLs (should be masked)
		{"postgres://user:pass@localhost:5432/mydb", true, "postgres with credentials"},
		{"postgresql://user:pass@localhost:5432/mydb", true, "postgresql alias"},
		{"redis://default:secret@redis.svc:6379", true, "redis with password"},
		{"rediss://default:secret@redis.svc:6379", true, "rediss (TLS) with password"},
		{"mongodb://user:pass@mongo.svc:27017/db", true, "mongodb with credentials"},
		{"mongodb+srv://user:pass@cluster.mongodb.net/db", true, "mongodb+srv with credentials"},
		{"amqp://user:pass@rabbitmq:5672/vhost", true, "amqp with credentials"},
		{"amqps://user:pass@rabbitmq:5672/vhost", true, "amqps TLS with credentials"},
		{"mysql://user:pass@mysql:3306/db", true, "mysql with credentials"},

		// No credentials — must NOT be masked (no @ sign)
		{"redis://localhost:6379", false, "redis without credentials"},
		{"postgres://localhost/mydb", false, "postgres without credentials"},

		// vault refs — never masked by this function
		{"vault://production/DATABASE_URL", false, "vault ref does not match credential URL pattern"},
		{"vault://DATABASE_URL", false, "vault ref short form"},

		// Non-connection-string values
		{"production", false, "plain string"},
		{"8080", false, "port number"},
		{"https://example.com", false, "https URL (scheme not in list)"},
		{"http://localhost:8080", false, "http URL (scheme not in list)"},
	}

	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			got := isCredentialURL(tc.value)
			if got != tc.want {
				t.Errorf("isCredentialURL(%q) = %v, want %v (%s)", tc.value, got, tc.want, tc.comment)
			}
		})
	}
}

func TestRedactEnvVars(t *testing.T) {
	cases := []struct {
		name  string
		input map[string]string
		// For each key in wantMasked, the output value must equal envRedactedMask.
		// For each key in wantPlain, the output value must equal the input value.
		wantMasked []string
		wantPlain  []string
	}{
		{
			name: "credential URL in value is masked regardless of key name",
			input: map[string]string{
				"DB_CONN": "postgres://user:pass@host:5432/db",
				"PORT":    "8080",
			},
			wantMasked: []string{"DB_CONN"},
			wantPlain:  []string{"PORT"},
		},
		{
			name: "secret key name masks value even for non-URL values",
			input: map[string]string{
				"STRIPE_SECRET_KEY": "sk_live_abcdef",
				"APP_NAME":         "myapp",
			},
			wantMasked: []string{"STRIPE_SECRET_KEY"},
			wantPlain:  []string{"APP_NAME"},
		},
		{
			name: "DATABASE_URL with credential is masked",
			input: map[string]string{
				"DATABASE_URL": "postgres://instant_cust:s3cr3t@postgres.svc:5432/db_abc",
				"NODE_ENV":     "production",
			},
			wantMasked: []string{"DATABASE_URL"},
			wantPlain:  []string{"NODE_ENV"},
		},
		{
			name: "vault refs are NEVER masked",
			input: map[string]string{
				"DATABASE_URL": "vault://production/DATABASE_URL",
				"REDIS_URL":    "vault://production/REDIS_URL",
				"NODE_ENV":     "production",
			},
			// vault refs pass through even though DATABASE_URL / REDIS_URL match
			// the key suffix heuristic — vault safety takes priority.
			wantMasked: nil,
			wantPlain:  []string{"DATABASE_URL", "REDIS_URL", "NODE_ENV"},
		},
		{
			name: "mix of vault refs, credential URLs, and plain vars",
			input: map[string]string{
				"DATABASE_URL":  "vault://production/DATABASE_URL",
				"REDIS_URL":     "redis://default:s3cr3t@redis.svc:6379",
				"SESSION_TOKEN": "tok_abcdef",
				"PORT":          "8080",
				"NODE_ENV":      "production",
			},
			wantMasked: []string{"REDIS_URL", "SESSION_TOKEN"},
			wantPlain:  []string{"DATABASE_URL", "PORT", "NODE_ENV"},
		},
		{
			name:       "empty map returns empty map (no panic)",
			input:      map[string]string{},
			wantMasked: nil,
			wantPlain:  nil,
		},
		{
			name: "mongodb+srv credential URL is masked",
			input: map[string]string{
				"MONGO_URL": "mongodb+srv://user:pass@cluster.mongodb.net/mydb",
			},
			wantMasked: []string{"MONGO_URL"},
		},
		{
			name: "redis without credentials is plain",
			input: map[string]string{
				"REDIS_HOST": "redis://localhost:6379",
			},
			// Key contains no secret fragment; value has no @ sign — plain.
			// NOTE: REDIS_HOST does not end in URL/URI/DSN and does not contain
			// SECRET/PASSWORD/TOKEN/_KEY — so it is not masked by key heuristic.
			// The value redis://localhost:6379 has no @ so credential URL check
			// also passes. Result: plain.
			wantPlain: []string{"REDIS_HOST"},
		},
		{
			name: "original map is not mutated",
			input: map[string]string{
				"API_KEY": "sk_live_123",
			},
			wantMasked: []string{"API_KEY"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Capture original values before calling redact.
			originals := make(map[string]string, len(tc.input))
			for k, v := range tc.input {
				originals[k] = v
			}

			got := redactEnvVars(tc.input)

			// Verify original map is NOT mutated.
			for k, origV := range originals {
				if tc.input[k] != origV {
					t.Errorf("redactEnvVars mutated original map: key %q was %q, now %q", k, origV, tc.input[k])
				}
			}

			for _, k := range tc.wantMasked {
				if got[k] != envRedactedMask {
					t.Errorf("key %q: expected masked value %q, got %q", k, envRedactedMask, got[k])
				}
			}

			for _, k := range tc.wantPlain {
				if got[k] != originals[k] {
					t.Errorf("key %q: expected plain value %q, got %q", k, originals[k], got[k])
				}
			}
		})
	}
}
