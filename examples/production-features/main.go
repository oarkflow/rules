package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/oarkflow/rules"
	"github.com/oarkflow/rules/pkg/routing"
	"github.com/oarkflow/rules/pkg/storage"
)

//go:embed decision.bcl
var policySource string

//go:embed openapi.yaml
var openAPISource []byte

func main() {
	ctx := context.Background()
	current := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	publicPEM, privatePEM := signingKeys()
	signer, err := rules.NewBundleSigner(privatePEM, "production-example")
	if err != nil {
		log.Fatal(err)
	}
	payload := rules.SignedPolicyPayload{Source: policySource, Name: "production-features", Version: "1"}
	signed, err := signer.SignBundle(payload)
	if err != nil {
		log.Fatal(err)
	}

	deliveryAttempts := 0
	store := storage.NewMemoryStore()
	service := rules.NewService(store, rules.Config{
		Environment: "example",
		Clock:       func() time.Time { return current },
		SignaturePolicy: rules.SignatureVerificationPolicy{
			Required:       true,
			AllowedSigners: []string{"production-example"},
			MinimumAlgo:    "Ed25519",
		},
		TrustedPublicKeys: map[string]string{"production-example": string(publicPEM)},
		Runtime: rules.RuntimePolicy{ActionAllowlists: []rules.ActionAllowlist{{
			TenantID: "default", Environment: "example", Actions: []string{"notify", "always_fail"}, Sinks: []string{"webhook"},
		}}},
		ActionHandlers: map[string]rules.ActionHandler{
			"notify": func(context.Context, rules.LifecycleAction) (rules.ActionResult, error) {
				deliveryAttempts++
				if deliveryAttempts == 1 {
					return rules.ActionResult{}, errors.New("simulated provider outage")
				}
				return rules.ActionResult{Handled: true, Status: "delivered"}, nil
			},
			"always_fail": func(context.Context, rules.LifecycleAction) (rules.ActionResult, error) {
				return rules.ActionResult{}, errors.New("simulated permanent provider outage")
			},
		},
	})

	published, err := service.Publish(ctx, rules.PublishRequest{Name: "production-features", Version: "1", SignedBundle: signed})
	if err != nil {
		log.Fatal(err)
	}
	validSignature, err := service.VerifyBundle(ctx, "production-features")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("published version=%s signature_valid=%v\n", published.Definition.Version, validSignature)
	tampered := *signed
	tampered.Payload = append([]byte(nil), signed.Payload...)
	tampered.Payload[0] ^= 1
	_, tamperErr := service.PublishVersion(ctx, rules.PublishRequest{Name: "production-features", Version: "1", SignedBundle: &tampered})
	fmt.Printf("signed_bundle tamper_rejected=%v\n", tamperErr != nil)

	tests, err := service.Test(ctx, "production-features", "")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("stateful_scenarios_passed=%v scenarios=%d\n", tests.Passed, len(tests.LifecycleScenarios))

	request := rules.LifecycleEvaluateRequest{
		EvaluationID: "signal-request-001",
		Phase:        "post", Method: "POST", Path: "/signals", Event: "notify",
		Input: map[string]any{"request": map[string]any{"actor_key": "alice", "signal": true}},
	}
	first, err := service.EvaluateLifecycle(ctx, "production-features", "api_request", request)
	if err != nil {
		log.Fatal(err)
	}
	duplicate, err := service.EvaluateLifecycle(ctx, "production-features", "api_request", request)
	if err != nil {
		log.Fatal(err)
	}
	deliveries, _ := service.ListActionDeliveries(ctx, storage.ActionDeliveryQuery{Definition: "production-features"})
	fmt.Printf("lifecycle action=%s duplicate_action=%s durable_deliveries=%d\n", first.Evaluation.FinalAction, duplicate.Evaluation.FinalAction, len(deliveries))

	for _, delivery := range deliveries {
		if delivery.NextAttempt != nil {
			current = delivery.NextAttempt.Add(time.Second)
			break
		}
	}
	retried, err := service.RetryActions(ctx, rules.ActionRetryRequest{Now: current})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("retry delivered=%d rescheduled=%d dead_letter=%d\n", retried.Delivered, retried.Rescheduled, retried.DeadLetter)

	chainRequest := rules.ChainEvaluateRequest{
		EventID: "chain-event-001", Event: "notify", EntityKey: "chain-user",
		Input: map[string]any{"request": map[string]any{"actor_key": "chain-user", "signal": false}},
	}
	if _, err := service.EvaluateChain(ctx, "production-features", "signal_history", chainRequest); err != nil {
		log.Fatal(err)
	}
	chainDuplicate, err := service.EvaluateChain(ctx, "production-features", "signal_history", chainRequest)
	if err != nil {
		log.Fatal(err)
	}
	chainEvents, _ := store.QueryChainEvents(ctx, storage.ChainEventQuery{Definition: "production-features", Chain: "signal_history", EntityKey: "chain-user", IncludeExpired: true})
	eventOccurrences := 0
	for _, event := range chainEvents {
		if event.ID == chainRequest.EventID {
			eventOccurrences++
		}
	}
	fmt.Printf("chain_idempotency duplicate_diagnostics=%d persisted_event_occurrences=%d\n", len(chainDuplicate.Evaluation.Diagnostics), eventOccurrences)

	_, err = service.EvaluateLifecycle(ctx, "production-features", "api_request", rules.LifecycleEvaluateRequest{
		EvaluationID: "dead-letter-request-001", Phase: "post", Method: "POST", Path: "/signals",
		Input: map[string]any{"request": map[string]any{"actor_key": "dead-letter-user", "deadletter": true}},
	})
	if err != nil {
		log.Fatal(err)
	}
	failing, _ := service.ListActionDeliveries(ctx, storage.ActionDeliveryQuery{Definition: "production-features", Action: "always_fail"})
	for _, delivery := range failing {
		if delivery.NextAttempt != nil && delivery.NextAttempt.After(current) {
			current = delivery.NextAttempt.Add(time.Second)
		}
	}
	rescheduled, err := service.RetryActions(ctx, rules.ActionRetryRequest{Now: current})
	if err != nil {
		log.Fatal(err)
	}
	failing, _ = service.ListActionDeliveries(ctx, storage.ActionDeliveryQuery{Definition: "production-features", Action: "always_fail"})
	for _, delivery := range failing {
		if delivery.NextAttempt != nil && delivery.NextAttempt.After(current) {
			current = delivery.NextAttempt.Add(time.Second)
		}
	}
	deadLettered, err := service.RetryActions(ctx, rules.ActionRetryRequest{Now: current})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("retry_failure rescheduled=%d dead_letter=%d\n", rescheduled.Rescheduled, deadLettered.DeadLetter)

	highRisk, err := service.StartWorkflow(ctx, "production-features", "signal_review", map[string]any{"case": map[string]any{"risk": "high", "context": map[string]any{"region": "restricted", "score": 40}, "flags": map[string]any{"suppressed": false}}})
	if err != nil {
		log.Fatal(err)
	}
	highRisk, err = service.AdvanceWorkflow(ctx, highRisk.ID, nil)
	if err != nil {
		log.Fatal(err)
	}
	lowRisk, err := service.StartWorkflow(ctx, "production-features", "signal_review", map[string]any{"case": map[string]any{"risk": "low"}})
	if err != nil {
		log.Fatal(err)
	}
	lowRisk, err = service.AdvanceWorkflow(ctx, lowRisk.ID, nil)
	if err != nil {
		log.Fatal(err)
	}
	fallback, err := service.StartWorkflow(ctx, "production-features", "signal_review", map[string]any{"case": map[string]any{"risk": "unknown"}})
	if err != nil {
		log.Fatal(err)
	}
	fallback, err = service.AdvanceWorkflow(ctx, fallback.ID, nil)
	if err != nil {
		log.Fatal(err)
	}
	timeoutRun, err := service.StartWorkflow(ctx, "production-features", "signal_review", map[string]any{"case": map[string]any{"risk": "pending"}})
	if err != nil {
		log.Fatal(err)
	}
	current = current.Add(2 * time.Minute)
	ticked, err := service.TickWorkflows(ctx, rules.WorkflowTickRequest{Now: current})
	if err != nil {
		log.Fatal(err)
	}
	timeoutRun, _ = service.GetWorkflowRun(ctx, timeoutRun.ID)
	fmt.Printf("workflow priority_stage=%s low_stage=%s fallback_stage=%s timed_out=%d timeout_stage=%s\n", highRisk.Stage, lowRisk.Stage, fallback.Stage, ticked.TimedOut, timeoutRun.Stage)

	ir, err := service.PolicyIR(ctx, "production-features")
	if err != nil {
		log.Fatal(err)
	}
	coverage, err := service.RouteCoverage(ctx, "production-features")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("semantic_ir decisions=%d chains=%d dependencies=%d coverage=%v\n", len(ir.Decisions), len(ir.Chains), len(ir.Dependencies), coverage.Passed)
	mutations, err := service.MutationTest(ctx, "production-features")
	if err != nil {
		log.Fatal(err)
	}
	histograms := service.GetLatencyHistograms(ctx)
	fmt.Printf("mutation score=%.0f%% killed=%d/%d latency_histograms=%d\n", mutations.Score, mutations.Killed, mutations.Total, len(histograms))
	incidents, err := service.ListIncidents(ctx, storage.IncidentQuery{Definition: "production-features", Status: "open"})
	if err != nil {
		log.Fatal(err)
	}
	if len(incidents) > 0 {
		acknowledged, err := service.UpdateIncident(ctx, incidents[0].ID, rules.IncidentUpdateRequest{Status: "acknowledged", Actor: "example-operator", Reason: "demonstration triage"})
		if err != nil {
			log.Fatal(err)
		}
		resolved, err := service.UpdateIncident(ctx, acknowledged.ID, rules.IncidentUpdateRequest{Status: "resolved", Actor: "example-operator", Reason: "provider restored"})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("incident id=%s acknowledged=true final_status=%s count=%d\n", resolved.ID, resolved.Status, resolved.Count)
	}
	remainingIncidents, _ := service.ListIncidents(ctx, storage.IncidentQuery{Definition: "production-features", Status: "open"})
	for _, incident := range remainingIncidents {
		if _, err := service.UpdateIncident(ctx, incident.ID, rules.IncidentUpdateRequest{Status: "resolved", Actor: "example-operator", Reason: "demonstration cleanup"}); err != nil {
			log.Fatal(err)
		}
	}
	readiness := service.ProductionReadiness(ctx)
	fmt.Printf("readiness ready=%v dead_letters=%d open_incidents=%d\n", readiness.Ready, readiness.Counts["dead_letter_actions"], readiness.Counts["open_incidents"])

	routes, diagnostics, err := routing.ImportOpenAPI(openAPISource)
	if err != nil {
		log.Fatal(err)
	}
	exported, err := routing.ExportOpenAPI("Production Features API", "1.0.0", routes)
	if err != nil {
		log.Fatal(err)
	}
	catalog := routing.FormatBCLRouteCatalog("api", routes)
	fmt.Printf("openapi routes=%d diagnostics=%d exported_bytes=%d bcl_catalog_bytes=%d\n", len(routes), len(diagnostics), len(exported), len(catalog))

	demonstrateApprovalGate(ctx, policySource, current)
	demonstrateTenantQuota(ctx)
	demonstrateCrossWorkerLocking(ctx)
}

func signingKeys() ([]byte, []byte) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
}
