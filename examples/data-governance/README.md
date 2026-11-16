# Data Governance Policy Example

This example demonstrates a BCL-based governance layer for warehouse access and data operations:

- Access decisions for purpose, user clearance, PII, legal hold, and residency.
- Masking and privacy review for analytics or exported PII.
- Bulk, external, and cross-region export controls.
- Retention disposition with legal-hold precedence and minimum-retention enforcement.
- A priority-based privacy workflow for legal, security, and data-owner review with SLA timeouts.
- Stateful detection of repeated sensitive export reviews.
- BCL package metadata, standard facts, action catalog, output contract, reason codes, schemas, and seven acceptance tests.

The complete policy and tests are in [`decision.bcl`](decision.bcl). The Go runner only maps trusted identity, dataset, residency, and query facts into the BCL request, calls the engine, and demonstrates the returned host action. Residency comparisons, masking requirements, approval thresholds, and retention decisions are all expressed in BCL. The sample never executes generated SQL or performs deletion; integrate those operations with your own warehouse, authorization, masking, and retention systems after checking the policy result.

Run from the repository root:

```sh
cd examples && go run ./data-governance
```

Validate and run all BCL tests:

```sh
go run ./cmd/rules validate --store memory --name data-governance --tests ./examples/data-governance/decision.bcl
```

The demo covers allowed casework access, masked analytics review, legal-hold denial, residency denial, bulk export review, retention disposition, workflow routing, and repeated export anomaly events.
