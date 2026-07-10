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

//go:embed candidate.bcl
var candidateSource string

func main() {
	ctx := context.Background()
	svc := rules.NewService(storage.NewMemoryStore(), rules.Config{
		Environment:  "example",
		RequireTests: true,
	})

	if _, err := svc.Publish(ctx, rules.PublishRequest{
		Name: "blast-radius", Version: "1", Source: policySource,
		BaseDir: examplebase.Dir(),
	}); err != nil {
		log.Fatal(err)
	}

	fmt.Println("=== Blast Radius: Policy Change Impact Analysis ===\n")

	fmt.Println("--- Version 1 (base) evaluation ---")
	evalDemo(ctx, svc)

	fmt.Println("\n--- Blast radius analysis: Version 1 → Version 2 ---")
	report, err := svc.BlastRadius(ctx, "blast-radius", rules.SimulationRequest{
		CandidateSource: candidateSource, Decision: "candidate",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Base: %s → Candidate: %s\n\n", report.BaseVersion, report.CandidateVersion)

	printDiff("Decisions", report.Decisions)
	printDiff("Chains", report.Chains)
	printDiff("Routes", report.Routes)
	printDiff("Lifecycles", report.Lifecycles)
	printDiff("Actions", report.Actions)

	if len(report.Steps.Added)+len(report.Steps.Removed)+len(report.Steps.Changed) > 0 {
		fmt.Println("\nSteps:")
		for _, s := range report.Steps.Added {
			fmt.Printf("  + %s\n", s)
		}
		for _, s := range report.Steps.Removed {
			fmt.Printf("  - %s\n", s)
		}
		for _, s := range report.Steps.Changed {
			fmt.Printf("  ~ %s\n", s)
		}
	}

	fmt.Println("\nDependency Graph:")
	for _, n := range report.DependencyGraph.Nodes {
		mark := " "
		if n.Removed {
			mark = "-"
		}
		if n.New {
			mark = "+"
		}
		fmt.Printf("  %s %s (%s)\n", mark, n.ID, n.Kind)
	}
	for _, e := range report.DependencyGraph.Edges {
		fmt.Printf("    %s → %s (weight=%d)\n", e.From, e.To, e.Weight)
	}

	fmt.Println("\nImpact Summary:")
	for _, s := range report.ImpactSummary {
		fmt.Printf("  • %s\n", s)
	}
}

func printDiff(label string, diff rules.RadiusDiff) {
	affected := len(diff.Added) + len(diff.Removed)
	if affected == 0 {
		return
	}
	fmt.Printf("%s: +%d -%d unchanged=%d (%.0f%% affected)\n",
		label, len(diff.Added), len(diff.Removed), len(diff.Unchanged), diff.AffectedPct)
	for _, s := range diff.Added {
		fmt.Printf("  + %s\n", s)
	}
	for _, s := range diff.Removed {
		fmt.Printf("  - %s\n", s)
	}
}

func evalDemo(ctx context.Context, svc *rules.Service) {
	resp, err := svc.Evaluate(ctx, "blast-radius", rules.EvaluateRequest{
		Decision: "rate_limit",
		Input:    map[string]any{"request": map[string]any{"rate": 10, "country": "US", "user_id": "u-1"}},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  rate_limit (rate=10): effect=%s reason=%s\n",
		resp.Report.Decision.Effect, resp.Report.Decision.ReasonCode)
}
