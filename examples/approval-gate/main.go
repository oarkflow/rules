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

type DeployCase struct {
	Name        string
	Environment string
}

func main() {
	ctx := context.Background()

	svc := rules.NewService(storage.NewMemoryStore(), rules.Config{
		Environment:               "example",
		RequireActivationApproval: true,
	})

	fmt.Println("=== Approval Gate: Deploy Policy with Activation Approval ===\n")

	fmt.Println("Step 1: Publish policy version 1 (not yet active)")
	pub, err := svc.Publish(ctx, rules.PublishRequest{
		Name: "approval-gate", Version: "1", Source: policySource,
		BaseDir: examplebase.Dir(),
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  version=%s activation_pending=%v\n\n", pub.Definition.Version, pub.Definition.Metadata["activation_pending"])

	fmt.Println("Step 2: Try to evaluate (should fail — no active version)")
	if _, err := svc.Evaluate(ctx, "approval-gate", rules.EvaluateRequest{
		Decision: "deploy_gate",
		Input:    map[string]any{"deploy": map[string]any{"environment": "staging", "risk_score": 10, "bypass_approval": false}},
	}); err != nil {
		fmt.Printf("  Expected error: %v\n\n", err)
	}

	fmt.Println("Step 3: Try to activate without approval (should fail)")
	if _, err := svc.Activate(ctx, "approval-gate", "1", "example"); err != nil {
		fmt.Printf("  Expected error: %v\n\n", err)
	}

	fmt.Println("Step 4: Approve version 1 for activation")
	approval, err := svc.Approve(ctx, "approval-gate", "1", rules.ApprovalRequest{
		ApprovedBy: "deploy-manager",
		Reason:     "risk review completed",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  approved_by=%s approved_at=%v\n\n",
		approval.Definition.Metadata["approved_by"],
		approval.Definition.Metadata["approved_at"])

	fmt.Println("Step 5: Activate (now succeeds)")
	activated, err := svc.Activate(ctx, "approval-gate", "1", "example")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  active version=%s name=%s\n\n", activated.Definition.Version, activated.Definition.Name)

	fmt.Println("Step 6: Evaluate deployment decisions")
	cases := []DeployCase{
		{Name: "staging deploy", Environment: "staging"},
		{Name: "production deploy", Environment: "production"},
	}
	for _, c := range cases {
		resp, err := svc.Evaluate(ctx, "approval-gate", rules.EvaluateRequest{
			Decision: "deploy_gate",
			Input:    map[string]any{"deploy": map[string]any{"env": c.Environment}},
		})
		if err != nil {
			log.Fatal(err)
		}
		dec := resp.Report.Decision
		action := ""
		switch dec.Effect {
		case "allow":
			action = "Deploy pipeline proceeds"
		case "deny":
			action = "Deploy pipeline blocked"
		case "require_review":
			action = "Risk review paged"
		}
		fmt.Printf("  %s: effect=%s → %s\n", c.Name, dec.Effect, action)
	}

	fmt.Println("\nStep 7: Check audit trail")
	audits, err := svc.QueryAudits(ctx, storage.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  %d audit events:\n", len(audits))
	for _, a := range audits {
		meta := ""
		if a.Metadata != nil {
			if v, ok := a.Metadata["published"]; ok {
				meta = fmt.Sprintf("published=%v", v)
			} else if v, ok := a.Metadata["approved"]; ok {
				meta = fmt.Sprintf("approved=%v", v)
			} else if v, ok := a.Metadata["active"]; ok {
				meta = fmt.Sprintf("active=%v", v)
			}
		}
		fmt.Printf("    [%s] %s %s\n", a.Operation, a.Definition, meta)
	}
}
