# Production Features Example

This runnable example ties together all recent production additions in one flow. See [FEATURES.md](FEATURES.md) for the feature-by-feature coverage matrix.

- Ed25519-signed policy publishing and activation-time verification
- typed semantic `PolicyIR` generation and dependency diagnostics
- lifecycle and chain idempotency IDs
- stateful, clock-controlled multi-step `lifecycle_test` scenarios
- durable failed-action retry processing with backoff
- retry rescheduling and terminal dead-letter delivery
- tenant quotas, incident acknowledgement/resolution, readiness reporting, and approval-gated activation
- cross-worker file-store locking with concurrent evaluators
- deeply nested `all`/`any`/`not` workflow conditions, priority-based branches, explicit fallback support, SLA deadlines, and timeout ticking
- route coverage and OpenAPI route import/export

Run it from the repository root:

```sh
go run ./examples/production-features
```

The example intentionally makes the first notification delivery fail. It then advances the injected clock and processes the durable retry successfully. It also evaluates the same lifecycle request twice with one `evaluation_id`, demonstrating that the second evaluation returns the stored result without creating another set of side effects.

The `signal_review` workflow demonstrates a three-level condition tree over `case.risk`, `case.context.region`, `case.context.score`, and `case.flags.suppressed`. If several branches match, the highest priority wins; equal-priority matches are rejected as ambiguous. `default true` can be used for an explicit fallback branch.

The BCL policy is in `decision.bcl`; `openapi.yaml` demonstrates route discovery input.

## CLI Examples

After publishing to the default file store, the added operational features can be exercised directly:

```sh
go run ./cmd/rules publish --name production-features --version 1 ./examples/production-features/decision.bcl
go run ./cmd/rules chain-evaluate --event notify --event-id evt-001 --entity cli-user --input ./examples/production-features/chain-input.json production-features signal_history
go run ./cmd/rules lifecycle-evaluate --input ./examples/production-features/lifecycle-request.json production-features api_request
go run ./cmd/rules workflow-start --input ./examples/production-features/workflow-high-risk.json production-features signal_review
go run ./cmd/rules workflow-advance --input ./examples/production-features/workflow-high-risk.json WORKFLOW_RUN_ID
go run ./cmd/rules tick-workflows
go run ./cmd/rules retry-actions
go run ./cmd/rules route-coverage production-features
go run ./cmd/rules ir production-features
go run ./cmd/rules mutation-test production-features
go run ./cmd/rules verify-bundle production-features
go run ./cmd/rules routes-import --input ./examples/production-features/openapi.yaml --catalog api
go run ./cmd/rules blast-radius --candidate ./examples/production-features/decision.bcl production-features
go run ./cmd/rules incident-update --status acknowledged --actor operator --reason investigating INCIDENT_ID
go run ./cmd/rules compact --before 2026-07-15T00:00:00Z production-features
go run ./cmd/rules approve --actor release-manager --reason reviewed production-features 1
```

`verify-bundle` requires publishing with `--signed-bundle`. The runnable Go example generates an ephemeral Ed25519 key and demonstrates that complete flow without committing a private key.

## HTTP API Examples

With the production server running, the same operations are available over HTTP:

```sh
curl -H 'X-Roles: condition-admin' -H 'Content-Type: application/json' \
  --data @examples/production-features/lifecycle-request.json \
  http://localhost:8080/v1/definitions/production-features/lifecycles/api_request/evaluate

curl -H 'X-Roles: condition-admin' -H 'Content-Type: application/json' \
  --data @examples/production-features/workflow-high-risk.json \
  http://localhost:8080/v1/definitions/production-features/workflows/signal_review/start

curl -H 'X-Roles: condition-admin' -H 'Content-Type: application/json' \
  --data '{"limit":100}' http://localhost:8080/v1/actions/retry

curl -H 'X-Roles: condition-admin' -H 'Content-Type: application/json' \
  --data '{"limit":100}' http://localhost:8080/v1/workflows/tick

curl -H 'X-Roles: condition-auditor' \
  http://localhost:8080/v1/definitions/production-features/ir
curl -H 'X-Roles: condition-auditor' \
  http://localhost:8080/v1/metrics/histograms
```

The remaining matching operations are `/chains/{chain}/evaluate`, `/route-coverage`, `/mutation-test`, `/verify-bundle`, `/v1/incidents/{id}`, `/v1/state/compact`, and `/v1/readiness`.
