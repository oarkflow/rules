# Capability Inventory

This inventory maps the platform's documented surfaces to their implementation and current evidence. It is intended to keep feature claims tied to executable behavior and to make remaining work visible. File and SQLite coverage is in the core and contrib modules; PostgreSQL coverage is integration-dependent.

| Capability | Implementation | Existing evidence | Follow-up |
|---|---|---|---|
| Decision evaluation, validation, simulation, compare, canary, mutation testing | `service.go`, BCL compiler/runtime | `service_test.go`, `production_features_test.go`, `benchmark_test.go` | Keep the acceptance matrix current as DSL behavior evolves. |
| Policy packages, action catalogs, output contracts, threat models | `contracts.go`, `governance.go`, `threat_model.go` | `service_test.go` contract and governance cases | Add cases when a new public DSL block is introduced. |
| Routes, overlays, lifecycle phases, request/response facts | `lifecycle.go`, `analytics.go`, `pkg/routing` | lifecycle, routing, and server tests | Expand malformed-envelope and route-precedence cases as use cases emerge. |
| Stateful chains, idempotent events, entity locking, quotas | `chain.go`, `service.go`, storage adapters | duplicate-ID, concurrent-update, tenant, and quota tests | Add process-restart idempotency cases for durable adapters. |
| Lifecycle evaluation, idempotency, action delivery, incidents | `lifecycle.go`, `service.go` | replay, persistence-failure, pre-dispatch durability, retry, and concurrency tests | Add deployment-level fault injection for external action handlers. |
| Workflows, nested conditions, SLA ticking | `workflow.go`, `service.go` | workflow tests in `service_test.go` | Add workflow restart and timeout-worker integration cases. |
| Audit chain and signed policy bundles | `pkg/audit`, `signing.go` | audit and production feature tests | Preserve fail-closed behavior and exercise verification after restart. |
| Tenant isolation, quotas, readiness, retention | `context.go`, `service.go`, storage adapters | service tests; memory/file/SQLite conformance; optional PostgreSQL integration test | Run PostgreSQL conformance with `RULES_POSTGRES_TEST_DSN` in integration CI. |
| HTTP API, CLI, reload, authz, runtime limits | `pkg/server`, `cmd/rules`, `pkg/reload` | server, CLI, and reload tests | Keep API compatibility checks and verify cancellation/timeouts end to end. |
| Performance baselines | `benchmark_test.go`, `pkg/routing/routing_test.go`, contrib storage tests | Publish/evaluate/routing/chain/lifecycle/memory/SQLite benchmarks | Add PostgreSQL workload benchmarks when a stable integration environment exists. |

## Cross-cutting acceptance requirements

- Every documented capability has a positive case and a representative rejection or failure case.
- Stateful behavior is checked for tenant separation, duplicate requests, concurrency, and restart persistence where the adapter supports persistence.
- External side effects remain allowlisted; audit or persistence failures are surfaced to callers rather than silently treated as success.
- Performance changes include comparable benchmark inputs and report latency and allocation changes; numeric service targets are set only after workload baselines exist.
- Public Go, HTTP, storage, and BCL behavior remains backward compatible unless an explicitly versioned migration is documented.

## Known limits of current evidence

Unit tests and examples demonstrate behavior but do not replace production-adapter integration tests, workload-specific SLOs, or operational validation in a deployed environment. PostgreSQL tests require a configured database and should be run in the integration pipeline. Benchmark numbers are hardware- and workload-dependent and should be treated as comparisons, not universal targets.
