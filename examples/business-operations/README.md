# Business Operations Policy Example

This BCL-first example demonstrates common procurement and finance controls in one runnable application:

- Purchase approval using delegated limits, available budget, vendor status, sanctions, security rating, and data sensitivity.
- Expense reimbursement controls for prohibited categories, missing receipts, and higher-value claims.
- Vendor onboarding based on sanctions, tax documentation, contract status, and security review.
- A priority-based purchase approval workflow with manager, finance, security, and timeout stages.
- Stateful vendor compliance escalation over a rolling window, with event IDs for reliable event ingestion.
- BCL reason codes, decision schemas, output contract, action catalog, policy package, and executable policy tests.

The policy is in [`decision.bcl`](decision.bcl). Go constructs trusted business facts, calls BCL decisions/workflows/chains, and performs the resulting business operation. Keep budget, vendor, sanctions, and security facts sourced from trusted systems; never accept them directly from a requester.

Run from the repository root:

```sh
cd examples && go run ./business-operations
```

Validate the policy and run its BCL tests:

```sh
go run ./cmd/rules validate --store memory --name business-operations --tests ./examples/business-operations/decision.bcl
```

The demo prints an auto-approved requisition, a high-value purchase routed for approval, a prohibited vendor denial, an expense review, a vendor onboarding result, workflow advancement, and repeated vendor compliance events that escalate through the stateful chain.
