package nosql

// mongo_seam_test.go drives the MongoDB defensive branches that cannot be
// triggered deterministically against a healthy mongod: the crypto/rand
// failure and the client.Disconnect defer-error logs. Both go through the
// package seams (randRead + mongoDisconnect). The disconnect-error tests need
// a live mongod (TEST_MONGO_URI) so the happy path runs up to the deferred
// close; they skip cleanly when it is unset.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TestStorageSizeToInt64 covers every arm of the storageSize numeric
// normalisation deterministically, independent of which BSON type a given
// mongod returns.
func TestStorageSizeToInt64(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want int64
	}{
		{"int32", int32(123), 123},
		{"int64", int64(456), 456},
		{"float64", float64(789.9), 789},
		{"nil", nil, 0},
		{"string-unknown", "not-a-number", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := storageSizeToInt64(c.in); got != c.want {
				t.Fatalf("storageSizeToInt64(%v) = %d; want %d", c.in, got, c.want)
			}
		})
	}
}

func seamMongoURI(t *testing.T) string {
	t.Helper()
	uri := os.Getenv("TEST_MONGO_URI")
	if uri == "" {
		t.Skip("TEST_MONGO_URI not set — skipping MongoDB seam tests")
	}
	return uri
}

func seamHost(uri string) string {
	after := strings.TrimPrefix(uri, "mongodb://")
	if i := strings.Index(after, "@"); i != -1 {
		after = after[i+1:]
	}
	if i := strings.Index(after, "/"); i != -1 {
		after = after[:i]
	}
	if after == "" {
		return "localhost:27017"
	}
	return after
}

func seamCleanup(t *testing.T, uri, token string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return
	}
	defer client.Disconnect(ctx)
	client.Database("admin").RunCommand(ctx, bson.D{{Key: "dropUser", Value: "usr_" + token}})
	client.Database("db_" + token).Drop(ctx)
}

// TestStorageBytes_DBStatsError_FailOpen covers the dbStats RunCommand error
// branch deterministically: a token containing '.' makes db_<token> an invalid
// MongoDB database name, which the driver rejects client-side, so dbStats
// errors and StorageBytes fails open with (0, nil).
func TestStorageBytes_DBStatsError_FailOpen(t *testing.T) {
	uri := seamMongoURI(t)
	p := New(uri, seamHost(uri), "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if n, err := p.StorageBytes(ctx, "bad.name"); err != nil || n != 0 {
		t.Fatalf("dbStats error must fail open; got (%d,%v)", n, err)
	}
}

// TestDeprovision_DropDatabaseError covers the fatal DROP DATABASE error return
// deterministically: a token containing '.' makes db_<token> an invalid
// MongoDB database name, which the driver rejects when Drop is called.
func TestDeprovision_DropDatabaseError(t *testing.T) {
	uri := seamMongoURI(t)
	p := New(uri, seamHost(uri), "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := p.Deprovision(ctx, "bad.name")
	if err == nil || !strings.Contains(err.Error(), "drop database") {
		t.Fatalf("invalid db name must surface a drop database error; got %v", err)
	}
}

// TestProvision_RandReadFailure covers the crypto/rand failure branch in
// Provision via the randRead seam. It needs a connectable mongod so the flow
// reaches the password step (the connect happens before the RNG call).
func TestProvision_RandReadFailure(t *testing.T) {
	uri := seamMongoURI(t)
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("entropy depleted") }
	t.Cleanup(func() { randRead = orig })

	p := New(uri, seamHost(uri), "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := p.Provision(ctx, "randfail", "anonymous")
	if err == nil || !strings.Contains(err.Error(), "generate password") {
		t.Fatalf("randRead failure must surface as generate-password error; got %v", err)
	}
}

// TestProvision_DisconnectError covers the Provision disconnect defer-error log.
// The provision succeeds; mongoDisconnect is forced to error so the deferred
// close hits the error branch.
func TestProvision_DisconnectError(t *testing.T) {
	uri := seamMongoURI(t)
	token := "discprov1"
	defer seamCleanup(t, uri, token)

	orig := mongoDisconnect
	mongoDisconnect = func(c *mongo.Client, ctx context.Context) error {
		_ = c.Disconnect(ctx) // still really close so we don't leak
		return errors.New("forced disconnect error")
	}
	t.Cleanup(func() { mongoDisconnect = orig })

	p := New(uri, seamHost(uri), "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	creds, err := p.Provision(ctx, token, "anonymous")
	if err != nil {
		t.Fatalf("Provision must succeed despite a disconnect error: %v", err)
	}
	if creds.DatabaseName != "db_"+token {
		t.Fatalf("DatabaseName = %q", creds.DatabaseName)
	}
}

// TestStorageBytes_DisconnectError covers the StorageBytes disconnect defer-error
// log. The dbStats call fails open; the forced disconnect error is logged.
func TestStorageBytes_DisconnectError(t *testing.T) {
	uri := seamMongoURI(t)

	orig := mongoDisconnect
	mongoDisconnect = func(c *mongo.Client, ctx context.Context) error {
		_ = c.Disconnect(ctx)
		return errors.New("forced disconnect error")
	}
	t.Cleanup(func() { mongoDisconnect = orig })

	p := New(uri, seamHost(uri), "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if n, err := p.StorageBytes(ctx, "ghost-token-xyz"); err != nil || n != 0 {
		t.Fatalf("StorageBytes must fail open; got (%d,%v)", n, err)
	}
}

// TestDeprovision_DisconnectError covers the Deprovision disconnect defer-error
// log. Deprovision of a non-existent token drops nothing fatal; the forced
// disconnect error is logged. The Drop of a missing DB is a no-op (returns nil).
func TestDeprovision_DisconnectError(t *testing.T) {
	uri := seamMongoURI(t)

	orig := mongoDisconnect
	mongoDisconnect = func(c *mongo.Client, ctx context.Context) error {
		_ = c.Disconnect(ctx)
		return errors.New("forced disconnect error")
	}
	t.Cleanup(func() { mongoDisconnect = orig })

	p := New(uri, seamHost(uri), "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Dropping a never-created DB is a no-op in MongoDB and returns nil, so
	// Deprovision succeeds while still running the deferred (erroring) close.
	if err := p.Deprovision(ctx, "neverexisted-token"); err != nil {
		t.Fatalf("Deprovision of missing token must succeed: %v", err)
	}
}
