# Condition Examples

These examples are intentionally self-contained. Each directory is a small domain application, not a shared runner with renamed inputs. Each one has:

* `main.go` with typed Go domain objects, use-case-specific enrichment/scoring/planning logic, Condition service setup, and business follow-up behavior.
* `decision.bcl` with the policy, tests, reason codes, and decision table for that use case.

## Start With the Comprehensive Examples

For a complete BCL-driven application, start with [`complete-platform`](complete-platform/README.md). It combines modular decision tables, route catalogs, action and output contracts, policy overlays, lifecycle phases, stateful chains, response classification, BCL scenarios, and a runnable Fiber host. The policy lives in `.bcl`; the Go app supplies facts and applies the returned enforcement response.

Run it from the repository root:

```sh
cd examples && go run ./complete-platform
```

For operations and governance features such as signed publishing, durable retries, idempotency, workflow SLAs, mutation testing, and route import/export, continue with [`production-features`](production-features/README.md).

Run any example from the repository root:

```sh
cd examples && go run ./access-control
cd examples && go run ./payment-risk
cd examples && go run ./kyc-onboarding
cd examples && go run ./ai-safety
cd examples && go run ./logistics-routing
cd examples && go run ./healthcare-prior-auth
cd examples && go run ./dynamic-pricing
cd examples && go run ./procurement-approval
cd examples && go run ./support-routing
cd examples && go run ./api-traffic-control
cd examples && go run ./http-auth-guard
cd examples && go run ./request-lifecycle
cd examples && go run ./complete-platform
cd examples && go run ./anomaly-detection
cd examples && go run ./manufacturing-iot
cd examples && go run ./hr-leave-approval
cd examples && go run ./education-scholarship
cd examples && go run ./data-governance
cd examples && go run ./content-moderation
cd examples && go run ./loan-eligibility
cd examples && go run ./cybersecurity-session-risk
cd examples && go run ./government-benefits
cd examples && go run ./marketplace-escrow
cd examples && go run ./devops-deployment-gate
cd examples && go run ./telecom-notification-routing
cd examples && go run ./aml-transaction-monitoring
cd examples && go run ./insurance-claims
cd examples && go run ./subscription-entitlements
cd examples && go run ./crm-churn-upsell
cd examples && go run ./investment-trade-compliance
cd examples && go run ./smart-city-traffic
cd examples && go run ./supply-chain-replenishment
cd examples && go run ./temporal-behavior-risk
cd examples && go run ./fraud-ring-graph
cd examples && go run ./geo-territory-assignment
cd examples && go run ./event-correlation
cd examples && go run ./product-recommendation
cd examples && go run ./autonomous-remediation
```

Production server configuration examples live in `production-server`. They are not Go use-case runners; they show BCL-native runtime config for file storage, strict validation/evaluation, fail-closed audit behavior, HTTP timeouts, trusted proxies, TLS, rate limits, and route-scoped authz.

`production-features` is the end-to-end reference for signed publishing and tamper rejection, lifecycle and chain idempotency, durable retry/dead-letter handling, cross-worker locks, quotas, approval governance, incident acknowledgement/resolution, typed semantic IR, mutation testing, readiness and latency metrics, deeply nested conditional workflows, SLA timeout ticking, stateful time-travel scenarios, route coverage, and OpenAPI route import/export. Its `FEATURES.md` maps every added feature to executable code or DSL.

## Use Case Coverage

* `access-control`: RBAC/ABAC, session risk, conditional MFA, and break-glass access.
* `payment-risk`: payment authorization, fraud blocking, and step-up authentication.
* `kyc-onboarding`: identity verification, document confidence, biometrics, and sanctions screening.
* `ai-safety`: prompt intent governance, safe routing, refusal, and manual safety review.
* `logistics-routing`: carrier eligibility, hazmat controls, capacity review, and shipment booking.
* `healthcare-prior-auth`: treatment eligibility, clinical safety, documentation, and prior authorization routing.
* `dynamic-pricing`: margin floors, surge review, inventory signals, and loyalty discount approval.
* `procurement-approval`: vendor risk, budget policy, purchase order automation, and approval chains.
* `support-routing`: SLA handling, security escalation, enterprise support, and self-service routing.
* `api-traffic-control`: bot blocking, tenant quotas, throttling, and gateway routing.
* `http-auth-guard`: global HTTP middleware, authentication guardrails, and RBAC/ABAC/ACL endpoint authorization.
* `request-lifecycle`: native route catalogs, pre/post lifecycle evaluation, request/response envelopes, 5xx escalation, expected 400/401/403 handling, route coverage, action history, and incident history.
* `complete-platform`: GoFiber reference app covering package metadata, contracts, action catalogs, overlays, routes, lifecycle phases, chains, analytics watches, response classification, lifecycle scenarios, curlable use cases, action history, incidents, readiness, and route coverage.
* `anomaly-detection`: GoFiber anomaly platform covering session hijacking, geo/country policy, business-rule abuse, commerce risk, data exfiltration, API health escalation, threat model output, state, events, actions, incidents, readiness, and route coverage.
* `manufacturing-iot`: sensor thresholds, machine shutdown, maintenance review, and production continuity.
* `hr-leave-approval`: leave balances, staffing coverage, blackout periods, and manager review.
* `education-scholarship`: student eligibility, committee review, and merit/need scholarship awards.
* `business-operations`: procurement approvals, expense reimbursement, vendor onboarding, approval workflows, and stateful vendor-risk escalation.
* `data-governance`: purpose-based warehouse access, PII masking, residency, exports, legal holds, retention, privacy workflows, and stateful export-anomaly escalation.
* `content-moderation`: classifier scores, copyright matches, creator reputation, and publish/remove routing.
* `loan-eligibility`: credit policy, underwriting review, collateral checks, and loan approval.
* `cybersecurity-session-risk`: impossible travel, device trust, Tor signals, MFA step-up, and session termination.
* `government-benefits`: residency, income thresholds, missing documents, and public benefits eligibility.
* `marketplace-escrow`: dispute handling, seller trust, chargebacks, and payout release decisions.
* `devops-deployment-gate`: tests, security scans, canary health, freeze windows, and production promotion.
* `telecom-notification-routing`: consent, blocked countries, provider quality, fallback routing, and SMS sends.
* `aml-transaction-monitoring`: wire velocity, structuring, sanctions hits, country risk, and EDD/SAR routing.
* `insurance-claims`: claim estimation, duplicate checks, missing evidence, provider risk, and SIU/settlement routing.
* `subscription-entitlements`: plan catalogs, feature flags, quota math, entitlement tokens, and upgrade walls.
* `crm-churn-upsell`: product health, NPS, seat utilization, churn scoring, retention and expansion motions.
* `investment-trade-compliance`: pre-trade restricted lists, suitability, concentration limits, and supervision review.
* `smart-city-traffic`: sensor-derived congestion, emergency preemption, crowd events, and signal plan changes.
* `supply-chain-replenishment`: demand forecasting, days-to-stockout, vendor scorecards, auto-POs, and planner review.
* `temporal-behavior-risk`: rolling-window failed logins, reset/new-payee sequences, spend baselines, and velocity review.
* `fraud-ring-graph`: shared devices, payout instruments, known-bad neighbors, chargeback clusters, and seller payout release.
* `geo-territory-assignment`: geofencing, territory capacity, licensed coverage, data residency, and sales assignment.
* `event-correlation`: login/reset/address-change/purchase sequence detection, order holds, and account locks.
* `product-recommendation`: ranked next-best offers, eligibility gates, inventory, margin policy, and compliance review.
* `autonomous-remediation`: SRE runbook guardrails, blast-radius checks, confidence thresholds, and human-in-the-loop approval.

The examples duplicate their small amount of Condition service bootstrapping on purpose so each one can be copied into a real application without also copying a demo runner. The domain logic is deliberately different across examples: KYC builds evidence packages, support computes queue/SLA routing, payments enrich authorizations, logistics scores carrier lanes, data governance rewrites query access, temporal risk computes rolling windows, graph risk links related entities, recommendations rank offers before applying policy, and autonomous remediation turns observability signals into guarded runbooks.

`http-auth-guard` can also run as a curlable server:

```sh
cd examples && go run ./http-auth-guard --serve --addr :8080
```
