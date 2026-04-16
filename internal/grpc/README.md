# Agent API — Planned gRPC Server

The agent API (`api/`) will expose a gRPC server on port **50052**.
This interface is planned but **not yet implemented**.

## Purpose

The `dashboard-api` service calls the agent API over gRPC to perform resource operations
on behalf of authenticated dashboard users. The agent API is the single source of truth
for all provisioned resources (Postgres, Redis, MongoDB, etc.).

The dashboard-api never talks to the provisioner directly — all resource operations
go through the agent API.

## Planned Operations

| RPC | Request | Response | Notes |
|---|---|---|---|
| `ListResourcesByTeam` | `team_id string` | `[]Resource` | Returns all active resources for a team |
| `GetResourceByToken` | `token string` | `Resource` | Look up a single resource |
| `DeleteResource` | `token string` | `ok bool` | Deprovision via provisioner |
| `RotateCredentials` | `token string` | `new_connection_url string` | Rotate DB password / Redis auth |
| `GetTeamUsage` | `team_id string` | `UsageSummary` | Aggregate usage stats for billing |

## Implementation Plan

1. Add proto definition to `proto/common/agent.proto` (or a new `proto/dashboard/v1/`)
2. Run `make proto` to generate Go stubs
3. Implement `internal/grpc/server.go` that wires the gRPC server to existing handler/model logic
4. Start gRPC listener in `main.go` on `:50052` alongside the existing HTTP server on `:8080`
5. Update `dashboard-api/internal/grpc/agent_client.go` to use the generated client

## Authentication

The gRPC server will use a shared secret (metadata header `x-internal-secret`) for
service-to-service auth. This secret is injected via Kubernetes secrets and must NOT
be exposed outside the cluster.

## Port allocation

| Service | HTTP | gRPC |
|---|---|---|
| `api` (agent API) | 8080 | 50052 (planned) |
| `dashboard-api` | 8081 | — |
| `provisioner` | — | 50051 |
