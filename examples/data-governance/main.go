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

const definition = "data-governance"

type Dataset struct {
	ID             string
	Region         string
	Classification string
	LegalHold      bool
	ContainsPII    bool
}

type DataUser struct {
	ID        string
	Clearance string
	Region    string
	Purpose   string
}

type QueryRequest struct {
	ID      string
	Columns []string
	Export  bool
}

type AccessCase struct {
	Name    string
	Dataset Dataset
	User    DataUser
	Query   QueryRequest
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

	customers := Dataset{ID: "customers", Region: "US", Classification: "restricted", ContainsPII: true}
	claims := Dataset{ID: "claims", Region: "US", Classification: "confidential", LegalHold: true, ContainsPII: true}
	cases := []AccessCase{
		{Name: "restricted caseworker", Dataset: customers, User: DataUser{ID: "user-1", Clearance: "restricted", Region: "US", Purpose: "casework"}, Query: QueryRequest{ID: "query-1", Columns: []string{"email", "status"}}},
		{Name: "analytics PII access", Dataset: customers, User: DataUser{ID: "user-2", Clearance: "standard", Region: "US", Purpose: "analytics"}, Query: QueryRequest{ID: "query-2", Columns: []string{"email", "phone"}, Export: true}},
		{Name: "legal hold dataset", Dataset: claims, User: DataUser{ID: "user-3", Clearance: "restricted", Region: "US", Purpose: "casework"}, Query: QueryRequest{ID: "query-3", Columns: []string{"ssn"}}},
		{Name: "wrong region", Dataset: customers, User: DataUser{ID: "user-4", Clearance: "restricted", Region: "EU", Purpose: "casework"}, Query: QueryRequest{ID: "query-4", Columns: []string{"status"}}},
	}

	for _, accessCase := range cases {
		response, err := service.Evaluate(ctx, definition, rules.EvaluateRequest{Decision: "data_access", Input: accessFacts(accessCase)})
		if err != nil {
			log.Fatal(err)
		}
		decision := response.Report.Decision
		fmt.Printf("\naccess %s (%s/%s): effect=%s action=%v transform=%v reason=%s\n",
			accessCase.Query.ID, accessCase.Name, accessCase.Dataset.ID,
			decision.Effect, decision.Attributes["action"], decision.Attributes["transform"], decision.ReasonCode)
		fmt.Printf("  requested columns=%v region=%s purpose=%s\n", accessCase.Query.Columns, accessCase.User.Region, accessCase.User.Purpose)
		applyAccessOutcome(accessCase, decision.Effect, decision.Attributes["transform"])
	}

	export, err := service.Evaluate(ctx, definition, rules.EvaluateRequest{
		Decision: "data_export",
		Input: map[string]any{
			"dataset": map[string]any{"contains_pii": true, "legal_hold": false, "classification": "restricted", "region": "US"},
			"user":    map[string]any{"clearance": "restricted"},
			"export":  map[string]any{"destination_region": "US", "row_count": 25000, "external": true},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nexport review: effect=%s action=%v route=%v reason=%s\n", export.Report.Decision.Effect, export.Report.Decision.Attributes["action"], export.Report.Decision.Attributes["route"], export.Report.Decision.ReasonCode)

	retention, err := service.Evaluate(ctx, definition, rules.EvaluateRequest{
		Decision: "retention_disposition",
		Input: map[string]any{
			"dataset":   map[string]any{"id": "claims", "legal_hold": false},
			"retention": map[string]any{"age_days": 900, "minimum_days": 365, "deletion_approved": true},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("retention review: effect=%s action=%v transform=%v reason=%s\n", retention.Report.Decision.Effect, retention.Report.Decision.Attributes["action"], retention.Report.Decision.Attributes["transform"], retention.Report.Decision.ReasonCode)

	workflow, err := service.StartWorkflow(ctx, definition, "data_access_review", map[string]any{
		"case": map[string]any{"id": "query-2", "classification": "restricted", "contains_pii": true, "external": true, "legal_hold": false},
	})
	if err != nil {
		log.Fatal(err)
	}
	workflow, err = service.AdvanceWorkflow(ctx, workflow.ID, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("workflow %s: stage=%s status=%s events=%v\n", workflow.ID, workflow.Stage, workflow.Status, workflow.Events)

	for i := 1; i <= 3; i++ {
		result, err := service.EvaluateChain(ctx, definition, "export_anomaly_watch", rules.ChainEvaluateRequest{
			Event: "sensitive_export_review", EventID: fmt.Sprintf("export-review-%d", i), EntityKey: "user-2",
			Input: map[string]any{"user": map[string]any{"id": "user-2"}},
		})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("export review event %d: action=%s severity=%s\n", i, result.Evaluation.FinalAction, result.Evaluation.FinalSeverity)
	}
}

func accessFacts(c AccessCase) map[string]any {
	return map[string]any{
		"dataset": map[string]any{"id": c.Dataset.ID, "region": c.Dataset.Region, "classification": c.Dataset.Classification, "contains_pii": c.Dataset.ContainsPII, "legal_hold": c.Dataset.LegalHold},
		"user":    map[string]any{"id": c.User.ID, "clearance": c.User.Clearance, "region": c.User.Region},
		"query":   map[string]any{"id": c.Query.ID, "purpose": c.User.Purpose, "export": c.Query.Export},
	}
}

func applyAccessOutcome(c AccessCase, effect string, transform any) {
	switch effect {
	case "allow":
		fmt.Printf("  host action: issue scoped warehouse credentials for purpose=%s\n", c.User.Purpose)
	case "require_review":
		fmt.Printf("  host action: route to privacy review; requested transform=%v\n", transform)
	default:
		fmt.Printf("  host action: reject query and append denial facts to the audit record\n")
	}
}
