package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"examples/internal/examplebase"

	"github.com/oarkflow/rules"
	"github.com/oarkflow/rules/pkg/storage"
)

//go:embed decision.bcl
var policySource string

const definition = "business-operations"

type Requisition struct {
	ID                  string
	AmountUSD           int
	Category            string
	SensitiveData       bool
	RequesterID         string
	BudgetRemainingUSD  int
	VendorID            string
	VendorApproved      bool
	VendorSanctioned    bool
	VendorActive        bool
	VendorSecurityScore int
}

func main() {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	service := rules.NewService(store, rules.Config{Environment: "example", RequireTests: true})
	if _, err := service.Publish(ctx, rules.PublishRequest{
		Name: definition, Version: "1", Source: policySource, BaseDir: examplebase.Dir(), RunTests: true,
	}); err != nil {
		log.Fatal(err)
	}

	showPurchase(ctx, service, Requisition{
		ID: "req-1001", AmountUSD: 3200, Category: "office", RequesterID: "employee-17", BudgetRemainingUSD: 12000,
		VendorID: "vendor-42", VendorApproved: true, VendorActive: true, VendorSecurityScore: 91,
	})
	showPurchase(ctx, service, Requisition{
		ID: "req-1002", AmountUSD: 72000, Category: "security_software", SensitiveData: true,
		RequesterID: "employee-23", BudgetRemainingUSD: 90000, VendorID: "vendor-88", VendorApproved: true,
		VendorActive: true, VendorSecurityScore: 95,
	})
	showPurchase(ctx, service, Requisition{
		ID: "req-1003", AmountUSD: 1800, Category: "consulting", RequesterID: "employee-39",
		BudgetRemainingUSD: 6000, VendorID: "vendor-99", VendorSanctioned: true,
		VendorActive: true, VendorSecurityScore: 82,
	})

	expense, err := service.Evaluate(ctx, definition, rules.EvaluateRequest{
		Decision: "expense_compliance",
		Input:    map[string]any{"expense": map[string]any{"id": "exp-5001", "category": "travel", "amount_usd": 85, "receipt_present": false, "policy_exception": false}},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nexpense exp-5001: effect=%s action=%v reason=%s\n", expense.Report.Decision.Effect, expense.Report.Decision.Attributes["action"], expense.Report.Decision.ReasonCode)

	vendor, err := service.Evaluate(ctx, definition, rules.EvaluateRequest{
		Decision: "vendor_onboarding",
		Input:    map[string]any{"vendor": map[string]any{"sanctioned": false, "tax_form_received": true, "security_review_complete": true, "contract_signed": true, "security_rating": 92}},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("vendor vendor-123 onboarding: effect=%s action=%v reason=%s\n", vendor.Report.Decision.Effect, vendor.Report.Decision.Attributes["action"], vendor.Report.Decision.ReasonCode)

	workflow, err := service.StartWorkflow(ctx, definition, "purchase_approval", map[string]any{
		"case": map[string]any{"id": "req-1002", "amount_usd": 72000, "sensitive_data": true, "vendor_id": "vendor-88"},
	})
	if err != nil {
		log.Fatal(err)
	}
	workflow, err = service.AdvanceWorkflow(ctx, workflow.ID, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("workflow %s: stage=%s status=%s events=%v\n", workflow.ID, workflow.Stage, workflow.Status, workflow.Events)

	for i := 1; i <= 4; i++ {
		result, err := service.EvaluateChain(ctx, definition, "vendor_risk_watch", rules.ChainEvaluateRequest{
			Event: "vendor_compliance_failure", EventID: fmt.Sprintf("vendor-42-failure-%d", i), EntityKey: "vendor-42",
			Input: map[string]any{"vendor": map[string]any{"id": "vendor-42"}},
		})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("vendor risk event %d: action=%s severity=%s\n", i, result.Evaluation.FinalAction, result.Evaluation.FinalSeverity)
	}
}

func showPurchase(ctx context.Context, service *rules.Service, requisition Requisition) {
	response, err := service.Evaluate(ctx, definition, rules.EvaluateRequest{
		Decision: "purchase_approval",
		Input: map[string]any{
			"purchase":  map[string]any{"id": requisition.ID, "amount_usd": requisition.AmountUSD, "category": requisition.Category, "sensitive_data": requisition.SensitiveData},
			"requester": map[string]any{"id": requisition.RequesterID, "budget_remaining_usd": requisition.BudgetRemainingUSD},
			"vendor":    map[string]any{"id": requisition.VendorID, "approved": requisition.VendorApproved, "sanctioned": requisition.VendorSanctioned, "active": requisition.VendorActive, "security_rating": requisition.VendorSecurityScore},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	decision := response.Report.Decision
	fmt.Printf("\npurchase %s ($%d %s): effect=%s action=%v route=%v reason=%s\n",
		requisition.ID, requisition.AmountUSD, requisition.Category, decision.Effect,
		decision.Attributes["action"], decision.Attributes["route"], decision.ReasonCode)
	switch decision.Effect {
	case "allow":
		fmt.Printf("  host action: reserve budget and issue purchase order for %s\n", requisition.VendorID)
	case "require_review":
		fmt.Printf("  host action: start the BCL approval workflow for %s\n", requisition.ID)
	default:
		fmt.Printf("  host action: reject requisition and retain vendor evidence for audit\n")
	}
}
