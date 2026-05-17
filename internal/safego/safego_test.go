package safego

import (
	"sync"
	"testing"
	"time"
)

// TestGo_RecoversPanic verifies a panicking fire-and-forget goroutine does not
// crash the process — the deferred Recover() swallows it and the test goroutine
// (and therefore the process) survives.
func TestGo_RecoversPanic(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	Go("test.panic", func() {
		defer wg.Done()
		panic("boom")
	})

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		// Reaching here means the panic was recovered — if it had
		// propagated, the whole test binary would have crashed.
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine never completed — panic likely propagated")
	}
}

// TestGo_NoPanic verifies the happy path runs fn to completion.
func TestGo_NoPanic(t *testing.T) {
	ran := make(chan struct{})
	Go("test.clean", func() { close(ran) })

	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("fn never ran")
	}
}

// TestRun_RecoversPanicSynchronously verifies Run swallows a panic in-line.
// If Run did not recover, this test goroutine would crash the binary.
func TestRun_RecoversPanicSynchronously(t *testing.T) {
	Run("test.run", func() { panic("sync boom") })
	// Reaching here means the panic was recovered.
}

// TestRecover_NoPanicIsNoop verifies a bare deferred Recover() with no panic
// in flight does not misbehave.
func TestRecover_NoPanicIsNoop(t *testing.T) {
	func() {
		defer Recover("test.noop")
	}()
}
