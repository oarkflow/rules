# Added Feature Example Coverage

Every recently added production capability has an example in this directory. `main.go` and `additional.go` are executable; `decision.bcl` contains the valid DSL examples; `invalid-workflow-target.bcl` is an intentionally invalid validation example.

| Feature | Example |
| --- | --- |
| Deep `all` / `any` / `not` workflow conditions and nested fact paths | `decision.bcl`, workflow `signal_review` |
| Transition priority, competing matches, explicit fallback, low-risk branch | `main.go`, output beginning with `workflow` |
| SLA deadlines and timeout ticking | `main.go`, `TickWorkflows` result |
| Invalid workflow target diagnostics | `invalid-workflow-target.bcl` and the validation command below |
| Signed bundles and stored verification | `main.go`, `SignBundle` and `VerifyBundle` |
| Tampered bundle rejection | `main.go`, output beginning with `signed_bundle` |
| Lifecycle idempotency | `main.go`, repeated `evaluation_id` |
| Chain idempotency | `main.go`, repeated `event_id` and one persisted occurrence |
| Cross-worker entity locking | `additional.go`, two file-store-backed services and twelve concurrent events |
| Durable action result records | `main.go`, `ListActionDeliveries` |
| Retry backoff, rescheduling, and dead-lettering | `decision.bcl` action `always_fail` and `main.go` retry passes |
| Tenant/environment action allowlists | `main.go`, `RuntimePolicy.ActionAllowlists` |
| Tenant event quotas | `additional.go`, `demonstrateTenantQuota` |
| Incident grouping, acknowledgement, and resolution | `main.go`, incident update flow |
| Approval-gated activation and governance review age | `additional.go`, `demonstrateApprovalGate` |
| Typed semantic policy IR and dependency edges | `main.go`, `PolicyIR` |
| Route-specific coverage | `main.go`, `RouteCoverage` |
| OpenAPI import, export, and BCL catalog generation | `openapi.yaml` and `main.go` |
| Stateful lifecycle scenarios and time travel | `decision.bcl`, `lifecycle_test "stateful signal sequence"` |
| Mutation testing | `main.go`, `MutationTest` |
| Decision/chain/action latency histograms | `main.go`, `GetLatencyHistograms` |
| Readiness, failed-action, incident, and state counts | `main.go`, `ProductionReadiness` |
| SQLite and PostgreSQL entity locking | Same `Service` API as the file example; substitute the stores from `contrib/storage` |
| CLI and HTTP API parity | Commands in `README.md` |

Run the valid example and the negative validation example:

```sh
go run ./examples/production-features
go run ./cmd/rules validate --name invalid-workflow ./examples/production-features/invalid-workflow-target.bcl
```

The second command is expected to report `valid: false` and `publishable: false` because `missing_stage` is not declared.
