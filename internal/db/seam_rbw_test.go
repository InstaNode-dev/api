// Package db: coverage for the genuinely-unreachable error branches in the
// migration runner + ConnectPostgres, driven through the package-var seams
// (readMigrationDir / readMigrationFile / sqlOpen). These paths can't be
// reached with the real embedded FS (compiled in, always readable) or the
// lib/pq driver (sql.Open is lazy and never errors on a DSN), so the seams
// let a test inject the failure deterministically.
//
// Rule-17 coverage block:
//   Symptom:       postgres.go 34-36 / 40-42 / 72-74 / 177-178 uncovered (94.1%)
//   Enumeration:   grep 'postgres.go' cover.out | awk '$NF==0'
//   Sites found:   4 zero-count blocks
//   Sites touched: 4 (this file)
//   Coverage test: TestRunMigrations_FilenameListError, _FileReadError,
//                  TestEmbeddedMigrationFilenames_ReadDirError,
//                  TestConnectPostgres_PanicsOnOpenError,
//                  TestStartPoolStatsExporter_CtxDoneAfterFirstTick
package db

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"
)

// withSeams swaps the package-var seams for the duration of a test and
// restores them after. Centralises the save/restore so a forgotten restore
// can't leak into the next test in the serialized (-p 1) run.
func withSeams(t *testing.T, dir func() ([]fs.DirEntry, error), file func(string) ([]byte, error), open func(string, string) (*sql.DB, error)) {
	t.Helper()
	origDir, origFile, origOpen := readMigrationDir, readMigrationFile, sqlOpen
	if dir != nil {
		readMigrationDir = dir
	}
	if file != nil {
		readMigrationFile = file
	}
	if open != nil {
		sqlOpen = open
	}
	t.Cleanup(func() {
		readMigrationDir = origDir
		readMigrationFile = origFile
		sqlOpen = origOpen
	})
}

// TestEmbeddedMigrationFilenames_ReadDirError covers postgres.go:72-74 — the
// fs.ReadDir failure path inside embeddedMigrationFilenames.
func TestEmbeddedMigrationFilenames_ReadDirError(t *testing.T) {
	sentinel := errors.New("boom: embed dir unreadable")
	withSeams(t, func() ([]fs.DirEntry, error) { return nil, sentinel }, nil, nil)

	names, err := embeddedMigrationFilenames()
	if err == nil {
		t.Fatal("embeddedMigrationFilenames: want error, got nil")
	}
	if names != nil {
		t.Errorf("names should be nil on error, got %v", names)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error should wrap sentinel: %v", err)
	}
	if !strings.Contains(err.Error(), "read dir") {
		t.Errorf("error wrapping lost 'read dir': %v", err)
	}
}

// TestRunMigrations_FilenameListError covers postgres.go:34-36 — RunMigrations
// returns early when embeddedMigrationFilenames (via the dir seam) errors.
func TestRunMigrations_FilenameListError(t *testing.T) {
	sentinel := errors.New("boom: cannot list migrations")
	withSeams(t, func() ([]fs.DirEntry, error) { return nil, sentinel }, nil, nil)

	err := RunMigrations(nil) // db never touched — list fails first
	if err == nil {
		t.Fatal("RunMigrations: want error from filename list, got nil")
	}
	if !strings.Contains(err.Error(), "db.RunMigrations") {
		t.Errorf("error wrapping lost prefix: %v", err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error should wrap sentinel: %v", err)
	}
}

// TestRunMigrations_FileReadError covers postgres.go:40-42 — RunMigrations
// returns when reading a listed migration file fails. The dir seam yields a
// non-empty name list so the loop body runs, and the file seam fails the read.
func TestRunMigrations_FileReadError(t *testing.T) {
	sentinel := errors.New("boom: file vanished")
	withSeams(t,
		func() ([]fs.DirEntry, error) { return []fs.DirEntry{fakeDirEntry{name: "001_x.sql"}}, nil },
		func(string) ([]byte, error) { return nil, sentinel },
		nil,
	)

	err := RunMigrations(nil) // db never reached — read fails before Exec
	if err == nil {
		t.Fatal("RunMigrations: want error from file read, got nil")
	}
	if !strings.Contains(err.Error(), "read 001_x.sql") {
		t.Errorf("error should name the failing file: %v", err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error should wrap sentinel: %v", err)
	}
}

// fakeDirEntry is a minimal fs.DirEntry so the dir seam can return a
// synthetic non-empty file list without touching a real FS.
type fakeDirEntry struct{ name string }

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                 { return false }
func (f fakeDirEntry) Type() fs.FileMode           { return 0 }
func (f fakeDirEntry) Info() (fs.FileInfo, error)  { return nil, nil }

// TestConnectPostgres_PanicsOnOpenError covers postgres.go:177-178 — the
// sql.Open failure panic. lib/pq's Open is lazy and never errors on a DSN,
// so this branch is only reachable via the sqlOpen seam.
func TestConnectPostgres_PanicsOnOpenError(t *testing.T) {
	sentinel := errors.New("boom: driver open failed")
	withSeams(t, nil, nil, func(string, string) (*sql.DB, error) { return nil, sentinel })

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("ConnectPostgres: expected panic on open error")
		}
		e, ok := r.(*ErrDBConnect)
		if !ok {
			t.Fatalf("panic value: want *ErrDBConnect, got %T (%v)", r, r)
		}
		if !errors.Is(e.Cause, sentinel) {
			t.Errorf("ErrDBConnect.Cause should wrap sentinel, got %v", e.Cause)
		}
	}()
	ConnectPostgres("postgres://whatever")
}

// TestRunExporterLoop_CtxDoneArm drives the ctx.Done() branch
// (pool_metrics.go ctx.Done case) SYNCHRONOUSLY on the test goroutine, so the
// atomic coverage counter is recorded deterministically. A pre-cancelled
// context + an empty (never-firing) tick channel forces the ctx.Done() arm.
func TestRunExporterLoop_CtxDoneArm(t *testing.T) {
	dsn := testDSN()
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("postgres open: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done before the loop is entered
	tick := make(chan time.Time)

	// runs on this goroutine and returns immediately via the ctx.Done() arm.
	runExporterLoop(ctx, pool, "rbw-ctxdone", tick)
}

// TestRunExporterLoop_TickArm drives the ticker arm synchronously: a pre-fed
// tick channel publishes one sample, then ctx cancellation exits the loop.
func TestRunExporterLoop_TickArm(t *testing.T) {
	dsn := testDSN()
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("postgres open: %v", err)
	}
	defer pool.Close()

	tick := make(chan time.Time, 1)
	tick <- time.Now() // one sample will publish

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel shortly after the single tick is consumed so the loop takes the
	// tick arm at least once, then exits via ctx.Done().
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	runExporterLoop(ctx, pool, "rbw-tick", tick)
}

// TestStartPoolStatsExporter_CtxDoneAfterFirstTick exercises the public entry
// end-to-end (immediate publish + loop) and asserts clean shutdown on cancel.
func TestStartPoolStatsExporter_CtxDoneAfterFirstTick(t *testing.T) {
	dsn := testDSN()
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("postgres open: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		StartPoolStatsExporter(ctx, pool, "rbw-ctxdone-e2e")
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartPoolStatsExporter did not return after ctx cancel")
	}
}
