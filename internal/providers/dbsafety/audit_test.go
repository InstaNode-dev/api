package dbsafety

import (
	"context"
	"sync"
	"testing"
)

// recordingSink is a test AuditSink capturing every emitted record.
type recordingSink struct {
	mu   sync.Mutex
	recs []AuditRecord
}

func newRecordingSink() *recordingSink { return &recordingSink{} }

func (r *recordingSink) Emit(_ context.Context, rec AuditRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, rec)
}

func (r *recordingSink) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.recs)
}

func (r *recordingSink) last() AuditRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.recs[len(r.recs)-1]
}

// TestSetAuditSink_NilResetsToDefault asserts that passing nil restores the
// structured-slog default (so a later emit doesn't panic on a nil sink).
func TestSetAuditSink_NilResetsToDefault(t *testing.T) {
	t.Cleanup(func() { SetAuditSink(nil) })

	// Install a recording sink, confirm it's used, then reset to default.
	rec := newRecordingSink()
	SetAuditSink(rec)
	emitAudit(context.Background(), DropParams{
		Provider: "db.local", Token: "t", DatabaseName: "db_t", UserName: "usr_t",
		DSNHost: "postgres://u:p@localhost:5432/d",
	})
	if rec.count() != 1 {
		t.Fatalf("recording sink should capture one; got %d", rec.count())
	}

	// nil resets to the slog default — emit must not panic and must NOT reach
	// the recording sink.
	SetAuditSink(nil)
	emitAudit(context.Background(), DropParams{
		Provider: "db.local", Token: "t2", DatabaseName: "db_t2",
		DSNHost: "postgres://u:p@localhost:5432/d",
	})
	if rec.count() != 1 {
		t.Fatalf("after reset, the old sink must not receive emits; got %d", rec.count())
	}
}

// TestSlogSink_EmitDoesNotPanic exercises the default slogSink.Emit directly so
// its structured-log path is covered (it has no observable return; the test
// asserts only that it runs without panicking).
func TestSlogSink_EmitDoesNotPanic(t *testing.T) {
	slogSink{}.Emit(context.Background(), AuditRecord{
		Kind:         AuditKindCustomerDBDirectDrop,
		Provider:     "nosql.mongo",
		Token:        "tok",
		DatabaseName: "db_tok",
		UserName:     "usr_tok",
		DSNHost:      "mongodb",
	})
}
