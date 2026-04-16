# instant-api — Claude Code Project Config

## Available Skills

### `/instant-ship`
Full deploy pipeline: unit tests → docker build → k8s rollout → E2E verification.

### `/instant-review`
Code review against project conventions.

### `/instant-add-service`
Scaffolds a new provisioning service end-to-end.

### `/instant-e2e`
Runs the E2E test suite with auto-detection of k8s vs docker-compose target.

## Quick reference

- `make run` — start local server
- `make test` — unit + integration tests
- `make test-e2e` — E2E against k8s
- `make test-e2e-full` — E2E with JWT from k8s secret
- `make docker-build` — build Docker image
