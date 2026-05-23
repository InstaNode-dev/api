package handlers_test

// decrypt_url_provarms_test.go — drives the two fail-closed error branches of
// every provisioning handler's decryptConnectionURL / decryptStorageURL:
//   - AES key parse error  → ("", false)   (bad AES_KEY hex in cfg)
//   - ciphertext decrypt error → ("", false) (garbage stored value)
// plus the empty-input ("", true) early return. These can't be reached via the
// HTTP dedup path (it requires a real, decryptable row first), so we call the
// handler methods directly with crafted inputs and a nil DB (decrypt touches
// only cfg.AESKey).

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func goodAESConfig() *config.Config {
	return &config.Config{AESKey: testhelpers.TestAESKeyHex, EnabledServices: "postgres,redis,mongodb,queue,storage"}
}
func badAESConfig() *config.Config {
	return &config.Config{AESKey: "not-valid-hex", EnabledServices: "postgres,redis,mongodb,queue,storage"}
}

// decryptFn is the common (enc, requestID) → (plain, ok) shape every handler
// exposes via its *ForTest re-export.
type decryptFn func(enc, rid string) (string, bool)

func TestDecryptConnectionURL_AllHandlers_ErrorAndEmptyBranches(t *testing.T) {
	reg := plans.Default()

	// Build one handler of each type with a GOOD key (for the empty + decrypt-
	// error branches) and a BAD key (for the parse-error branch). nil db/rdb is
	// safe — none of these constructors dial at build time and decrypt only
	// reads cfg.AESKey.
	good := goodAESConfig()
	bad := badAESConfig()

	dbGood := handlers.NewDBHandler(nil, nil, good, nil, reg)
	dbBad := handlers.NewDBHandler(nil, nil, bad, nil, reg)
	cacheGood := handlers.NewCacheHandler(nil, nil, good, nil, reg)
	cacheBad := handlers.NewCacheHandler(nil, nil, bad, nil, reg)
	nosqlGood := handlers.NewNoSQLHandler(nil, nil, good, nil, reg)
	nosqlBad := handlers.NewNoSQLHandler(nil, nil, bad, nil, reg)
	queueGood := handlers.NewQueueHandler(nil, nil, good, nil, reg)
	queueBad := handlers.NewQueueHandler(nil, nil, bad, nil, reg)
	storageGood := handlers.NewStorageHandler(nil, nil, good, nil, reg)
	storageBad := handlers.NewStorageHandler(nil, nil, bad, nil, reg)

	goodFns := map[string]decryptFn{
		"db":      dbGood.DecryptConnectionURLForTest,
		"cache":   cacheGood.DecryptConnectionURLForTest,
		"nosql":   nosqlGood.DecryptConnectionURLForTest,
		"queue":   queueGood.DecryptConnectionURLForTest,
		"storage": storageGood.DecryptStorageURLForTest,
	}
	badFns := map[string]decryptFn{
		"db":      dbBad.DecryptConnectionURLForTest,
		"cache":   cacheBad.DecryptConnectionURLForTest,
		"nosql":   nosqlBad.DecryptConnectionURLForTest,
		"queue":   queueBad.DecryptConnectionURLForTest,
		"storage": storageBad.DecryptStorageURLForTest,
	}

	for name, fn := range goodFns {
		// Empty input → ("", true): nothing to decrypt.
		plain, ok := fn("", "req-empty")
		assert.True(t, ok, "%s: empty input must report ok=true", name)
		assert.Empty(t, plain, "%s: empty input returns empty", name)

		// Garbage ciphertext under a valid key → decrypt error → ("", false).
		plain, ok = fn("this-is-not-valid-ciphertext", "req-garbage")
		assert.False(t, ok, "%s: undecryptable input must fail closed (ok=false)", name)
		assert.Empty(t, plain, "%s: must NOT return ciphertext as a connection_url", name)
	}

	for name, fn := range badFns {
		// Non-empty input under an unparseable AES key → parse error → ("", false).
		plain, ok := fn("anything-nonempty", "req-badkey")
		assert.False(t, ok, "%s: bad AES key must fail closed (ok=false)", name)
		assert.Empty(t, plain, "%s: bad key returns no plaintext", name)
	}
}
