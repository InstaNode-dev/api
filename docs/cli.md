# instant CLI — Internal Engineering Reference

Internal reference for the `instant` CLI binary. For user-facing docs, see the main website documentation.

---

## Architecture

### Binary entry point

`cmd/instant/` is a standard Go binary. `main.go` at the repo root delegates to the server; the CLI lives at `cmd/instant/cmd/` and is built separately.

```
cmd/instant/
  cmd/
    root.go       — Cobra root, authTransport, HTTPClient, initConfig
    exec.go       — exec subcommand (wraps child processes)
    discover.go   — discover subcommand (crontab / job discovery)
    login.go      — login + logout + upgrade subcommands
    monitor.go    — monitor-related subcommands (if present)
    whoami.go     — whoami + logout subcommands
internal/
  cliconfig/      — ~/.instant-config load/save/clear
  tokens/         — ~/.instant-tokens load/save/add (local token store)
  crontab/        — crontab parse, job extraction, rewrite
```

### `authTransport`

Defined in `root.go`. Implements `http.RoundTripper`. On every request it clones the request and injects `Authorization: Bearer <apiKey>` when the user is authenticated.

### Config files

| File | Package | Purpose |
|---|---|---|
| `~/.instant-config` | `internal/cliconfig` | API key, email, tier, team name, API base URL. Written at login; absent = anonymous. Mode 0600. |
| `~/.instant-tokens` | `internal/tokens` | Locally stored resource tokens / metadata from discovery or manual commands. Mode 0600. |

Both files are JSON. Both are written atomically (temp file + rename).

### API base URL resolution

Priority (highest first):

1. `INSTANT_API_URL` environment variable  
2. `api_base_url` field in `~/.instant-config`  
3. Hardcoded default: `https://instant.dev`

Resolved in `initConfig()` in `root.go`.

---

## Command internals (summary)

### `login` / `logout` / `upgrade` (`login.go`)

Device-flow login against the agent API (`POST /auth/cli`, poll `GET /auth/cli/:id`), then persist `~/.instant-config`. Logout clears config. Upgrade flow may open billing or onboarding URLs depending on auth state.

### `whoami` (`whoami.go`)

Reads `~/.instant-config`. No network call.

### `exec` / `discover` / `monitor`

These commands orchestrate local jobs and token storage. **HTTP paths and payloads are defined in source** (`cmd/instant/cmd/*.go`) and must track the current agent API (`POST /db/new`, `/cache/new`, etc.) — do not assume legacy heartbeat URLs in documentation here.

---

## Adding a new command

1. Create `cmd/instant/cmd/<name>.go` in package `cmd`.
2. Declare `var <name>Cmd = &cobra.Command{...}`.
3. Register in `init()`: `rootCmd.AddCommand(<name>Cmd)`.
4. Use `HTTPClient` and `APIBaseURL` for all calls.

---

## Build

```sh
go build -o bin/instant ./cmd/instant/
```

---

## Testing

```sh
go test ./internal/cliconfig/...
go test ./internal/tokens/...
go test ./internal/crontab/...
go vet ./cmd/instant/...
```

Integration tests for the CLI should shell out to the binary against `httptest` or a local stack with `INSTANT_API_URL` set.

---

## Config file schemas

### `~/.instant-config` (JSON, 0600)

```json
{
  "api_key":      "inst_live_<base64url>",
  "email":        "user@example.com",
  "tier":         "anonymous|hobby|pro|team",
  "team_name":    "optional team name",
  "api_base_url": "https://instant.dev",
  "saved_at":     "2025-03-01T12:00:00Z"
}
```

### `~/.instant-tokens` (JSON, 0600)

```json
{
  "entries": [
    {
      "token":      "uuid...",
      "name":       "job-label",
      "schedule":   "0 2 * * *",
      "source":     "manual|discover",
      "created_at": "2025-03-01T02:00:00Z"
    }
  ]
}
```
