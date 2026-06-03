package handlers

// deploy_git_installation_token_test.go — coverage for P4.2b: minting a GitHub
// App installation token for a source=git clone (applyInstallationAuth +
// installationCloneToken). Driven with sqlmock + a fake minter so every branch
// (non-git / PAT-present / app-disabled / no-connection / no-installation-id /
// installation-missing / suspended / team-mismatch / mint-error / minted) runs
// synchronously without a real DB. The end-to-end source=git runDeploy path
// (with a real DB) is exercised by TestDeployNew_SourceGit_FlagOn_Accepted.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"instant.dev/internal/config"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/providers/compute"
)

// fakeTokenMinter is an installationTokenMinter double.
type fakeTokenMinter struct {
	token string
	err   error
	calls int
}

func (f *fakeTokenMinter) InstallationToken(_ context.Context, _ int64) (string, error) {
	f.calls++
	return f.token, f.err
}

// connRow builds an app_github_connections row for sqlmock. installID < 0 → NULL.
func connRow(appID, team uuid.UUID, installID int64) *sqlmock.Rows {
	r := sqlmock.NewRows([]string{
		"id", "app_id", "team_id", "github_repo", "branch", "webhook_secret",
		"installation_id", "created_at", "last_deploy_at", "last_commit_sha",
	})
	var iid interface{}
	if installID >= 0 {
		iid = installID
	}
	return r.AddRow(uuid.New(), appID, team, "owner/repo", "main", "sec", iid, time.Now(), nil, nil)
}

func instRow(team uuid.UUID, suspended bool) *sqlmock.Rows {
	var susp interface{}
	if suspended {
		susp = time.Now()
	}
	return sqlmock.NewRows([]string{
		"installation_id", "team_id", "account_login", "suspended_at", "created_at", "updated_at",
	}).AddRow(int64(42), team, "acme", susp, time.Now(), time.Now())
}

// runApply builds a DeployHandler over a sqlmock DB + fake minter, runs
// applyInstallationAuth on a git deploy, and returns the resolved GitAuth.
func runApply(t *testing.T, setup func(sqlmock.Sqlmock), minter installationTokenMinter, opts *compute.DeployOptions, team uuid.UUID) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if setup != nil {
		setup(mock)
	}
	h := &DeployHandler{db: db}
	if minter != nil {
		h.SetGitHubApp(minter) // exercise the setter (not a struct-literal field write)
	}
	d := &models.Deployment{ID: uuid.New(), TeamID: team, AppID: "gitdep"}
	h.applyInstallationAuth(context.Background(), opts, d)
}

func TestApplyInstallationAuth_Minted(t *testing.T) {
	team := uuid.New()
	m := &fakeTokenMinter{token: "ghs_minted"}
	opts := &compute.DeployOptions{Source: "git"}
	runApply(t, func(mk sqlmock.Sqlmock) {
		mk.ExpectQuery(`FROM app_github_connections WHERE app_id`).WillReturnRows(connRow(uuid.New(), team, 42))
		mk.ExpectQuery(`FROM github_installations WHERE installation_id`).WillReturnRows(instRow(team, false))
	}, m, opts, team)
	if opts.GitAuth != "ghs_minted" || m.calls != 1 {
		t.Errorf("want minted token + 1 call, got GitAuth=%q calls=%d", opts.GitAuth, m.calls)
	}
}

func TestApplyInstallationAuth_EarlyReturns(t *testing.T) {
	team := uuid.New()
	m := &fakeTokenMinter{token: "ghs"}
	// non-git source → no-op, no queries.
	o1 := &compute.DeployOptions{Source: "image"}
	runApply(t, nil, m, o1, team)
	// PAT already present → no-op.
	o2 := &compute.DeployOptions{Source: "git", GitAuth: "ghp_pat"}
	runApply(t, nil, m, o2, team)
	// app disabled (nil minter) → no-op.
	o3 := &compute.DeployOptions{Source: "git"}
	runApply(t, nil, nil, o3, team)
	if o1.GitAuth != "" || o2.GitAuth != "ghp_pat" || o3.GitAuth != "" || m.calls != 0 {
		t.Errorf("early-returns must not mint: %q %q %q calls=%d", o1.GitAuth, o2.GitAuth, o3.GitAuth, m.calls)
	}
}

func TestInstallationCloneToken_Misses(t *testing.T) {
	team := uuid.New()
	cases := map[string]func(sqlmock.Sqlmock){
		"no connection": func(mk sqlmock.Sqlmock) {
			mk.ExpectQuery(`FROM app_github_connections WHERE app_id`).WillReturnError(errors.New("nope"))
		},
		"connection without installation_id": func(mk sqlmock.Sqlmock) {
			mk.ExpectQuery(`FROM app_github_connections WHERE app_id`).WillReturnRows(connRow(uuid.New(), team, -1))
		},
		"installation missing": func(mk sqlmock.Sqlmock) {
			mk.ExpectQuery(`FROM app_github_connections WHERE app_id`).WillReturnRows(connRow(uuid.New(), team, 42))
			mk.ExpectQuery(`FROM github_installations WHERE installation_id`).WillReturnError(errors.New("gone"))
		},
		"installation suspended": func(mk sqlmock.Sqlmock) {
			mk.ExpectQuery(`FROM app_github_connections WHERE app_id`).WillReturnRows(connRow(uuid.New(), team, 42))
			mk.ExpectQuery(`FROM github_installations WHERE installation_id`).WillReturnRows(instRow(team, true))
		},
		"team mismatch": func(mk sqlmock.Sqlmock) {
			mk.ExpectQuery(`FROM app_github_connections WHERE app_id`).WillReturnRows(connRow(uuid.New(), team, 42))
			mk.ExpectQuery(`FROM github_installations WHERE installation_id`).WillReturnRows(instRow(uuid.New(), false)) // different team
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			opts := &compute.DeployOptions{Source: "git"}
			m := &fakeTokenMinter{token: "ghs"}
			runApply(t, setup, m, opts, team)
			if opts.GitAuth != "" {
				t.Errorf("%s: must not mint, got %q", name, opts.GitAuth)
			}
			if m.calls != 0 {
				t.Errorf("%s: minter must not be called, calls=%d", name, m.calls)
			}
		})
	}
}

func TestInstallationCloneToken_MintError(t *testing.T) {
	team := uuid.New()
	m := &fakeTokenMinter{err: context.DeadlineExceeded}
	opts := &compute.DeployOptions{Source: "git"}
	runApply(t, func(mk sqlmock.Sqlmock) {
		mk.ExpectQuery(`FROM app_github_connections WHERE app_id`).WillReturnRows(connRow(uuid.New(), team, 42))
		mk.ExpectQuery(`FROM github_installations WHERE installation_id`).WillReturnRows(instRow(team, false))
	}, m, opts, team)
	if opts.GitAuth != "" || m.calls != 1 {
		t.Errorf("mint error must fail-soft: GitAuth=%q calls=%d", opts.GitAuth, m.calls)
	}
}

// testRSAPEM returns a throwaway PKCS#1 RSA private key PEM (what GitHub issues).
func testRSAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

// NewDeployHandler wires the GitHub App minter when enabled + key valid, leaves
// it nil on a bad key (logged), and nil when disabled (P4.2b).
func TestNewDeployHandler_GitHubAppWiring(t *testing.T) {
	valid := NewDeployHandler(nil, nil, &config.Config{
		GitHubAppEnabled: true, GitHubAppID: "12345", GitHubAppPrivateKey: testRSAPEM(t),
	}, plans.Default())
	if valid.githubApp == nil {
		t.Error("enabled + valid key must wire the minter")
	}

	badKey := NewDeployHandler(nil, nil, &config.Config{
		GitHubAppEnabled: true, GitHubAppID: "12345", GitHubAppPrivateKey: "not-a-pem",
	}, plans.Default())
	if badKey.githubApp != nil {
		t.Error("a malformed key must leave the minter nil (logged), not panic")
	}

	disabled := NewDeployHandler(nil, nil, &config.Config{GitHubAppEnabled: false}, plans.Default())
	if disabled.githubApp != nil {
		t.Error("disabled must leave the minter nil")
	}
}
