package rules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/oarkflow/bcl"
	"github.com/oarkflow/rules/pkg/storage"
)

type lifecycleScenario struct {
	Name      string
	Lifecycle string
	Phase     string
	Method    string
	Path      string
	Request   map[string]any
	Input     map[string]any
	Response  map[string]any
	Event     string
	EntityKey string
	Expect    map[string]any
	Clock     string
	Steps     []lifecycleScenarioStep
}

type lifecycleScenarioStep struct {
	Name      string
	After     string
	Phase     string
	Method    string
	Path      string
	Request   map[string]any
	Input     map[string]any
	Response  map[string]any
	Event     string
	EntityKey string
	Expect    map[string]any
}

func lifecycleScenarios(program *bcl.DecisionProgram) ([]lifecycleScenario, []bcl.Diagnostic) {
	var blocks []map[string]any
	if program != nil && program.Governance["_condition_lifecycle_tests"] != nil {
		collectBlocks(program.Governance["_condition_lifecycle_tests"], "lifecycle_test", &blocks)
	} else if program != nil && program.Normalized != nil {
		collectBlocks(program.Normalized.Body, "lifecycle_test", &blocks)
	}
	var out []lifecycleScenario
	var diags []bcl.Diagnostic
	for _, block := range blocks {
		body := bodyMap(block["body"])
		scenario := lifecycleScenario{
			Name:      strings.TrimSpace(stringAny(block["id"])),
			Lifecycle: first(stringAny(body["lifecycle"]), stringAny(body["lifecycle_id"])),
			Phase:     stringAny(body["phase"]),
			Method:    stringAny(body["method"]),
			Path:      stringAny(body["path"]),
			Event:     stringAny(body["event"]),
			EntityKey: stringAny(body["entity_key"]),
			Clock:     stringAny(body["clock"]),
		}
		for _, child := range childBlocks(block["body"], "input") {
			scenario.Input = lifecycleObjectMap(child["body"])
		}
		for _, child := range childBlocks(block["body"], "request") {
			scenario.Request = lifecycleObjectMap(child["body"])
		}
		for _, child := range childBlocks(block["body"], "response") {
			scenario.Response = lifecycleObjectMap(child["body"])
		}
		for _, child := range childBlocks(block["body"], "expect") {
			scenario.Expect = lifecycleObjectMap(child["body"])
		}
		for _, child := range childBlocks(block["body"], "step") {
			stepBody := bodyMap(child["body"])
			step := lifecycleScenarioStep{Name: stringAny(child["id"]), After: stringAny(stepBody["after"]), Phase: stringAny(stepBody["phase"]), Method: stringAny(stepBody["method"]), Path: stringAny(stepBody["path"]), Event: stringAny(stepBody["event"]), EntityKey: stringAny(stepBody["entity_key"])}
			for _, nested := range childBlocks(child["body"], "input") {
				step.Input = lifecycleObjectMap(nested["body"])
			}
			for _, nested := range childBlocks(child["body"], "request") {
				step.Request = lifecycleObjectMap(nested["body"])
			}
			for _, nested := range childBlocks(child["body"], "response") {
				step.Response = lifecycleObjectMap(nested["body"])
			}
			for _, nested := range childBlocks(child["body"], "expect") {
				step.Expect = lifecycleObjectMap(nested["body"])
			}
			scenario.Steps = append(scenario.Steps, step)
		}
		if scenario.Name == "" {
			diags = append(diags, bcl.Diagnostic{Severity: "error", Message: "lifecycle_test is missing id"})
			continue
		}
		if scenario.Lifecycle == "" {
			diags = append(diags, bcl.Diagnostic{Severity: "error", Message: fmt.Sprintf("lifecycle_test %q is missing lifecycle", scenario.Name)})
			continue
		}
		if scenario.Phase == "" {
			diags = append(diags, bcl.Diagnostic{Severity: "error", Message: fmt.Sprintf("lifecycle_test %q is missing phase", scenario.Name)})
			continue
		}
		out = append(out, scenario)
	}
	return out, diags
}

func (s *Service) runLifecycleScenarios(program *bcl.DecisionProgram, definition, version, environment string) []LifecycleScenarioResult {
	scenarios, diags := lifecycleScenarios(program)
	var results []LifecycleScenarioResult
	for _, diag := range diags {
		results = append(results, LifecycleScenarioResult{Passed: false, Diagnostics: []bcl.Diagnostic{diag}})
	}
	if len(scenarios) == 0 {
		return results
	}
	for _, scenario := range scenarios {
		store := storage.NewMemoryStore()
		record := storage.DefinitionRecord{TenantID: s.cfg.DefaultTenant, Name: first(definition, "lifecycle-test"), Version: first(version, "test"), Environment: first(environment, s.cfg.Environment), Program: program, PublishedAt: s.now()}
		if err := store.SaveDefinitionVersion(context.Background(), record); err != nil {
			results = append(results, LifecycleScenarioResult{Passed: false, Diagnostics: []bcl.Diagnostic{{Severity: "error", Message: err.Error()}}})
			continue
		}
		if err := store.ActivateDefinition(context.Background(), record.Name, record.Version, record.Environment); err != nil {
			results = append(results, LifecycleScenarioResult{Passed: false, Diagnostics: []bcl.Diagnostic{{Severity: "error", Message: err.Error()}}})
			continue
		}
		runner := NewService(store, s.cfg)
		current := s.now()
		if scenario.Clock != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, scenario.Clock); err == nil {
				current = parsed.UTC()
			}
		}
		runner.cfg.Clock = func() time.Time { return current }
		result := LifecycleScenarioResult{Name: scenario.Name, Lifecycle: scenario.Lifecycle, Phase: scenario.Phase, Passed: true, Expected: scenario.Expect}
		steps := scenario.Steps
		if len(steps) == 0 {
			steps = []lifecycleScenarioStep{{Phase: scenario.Phase, Method: scenario.Method, Path: scenario.Path, Request: scenario.Request, Input: scenario.Input, Response: scenario.Response, Event: scenario.Event, EntityKey: scenario.EntityKey, Expect: scenario.Expect}}
		}
		var resp *LifecycleEvaluateResponse
		var err error
		for _, step := range steps {
			if step.After != "" {
				if duration, parseErr := time.ParseDuration(step.After); parseErr != nil {
					err = parseErr
					break
				} else {
					current = current.Add(duration)
				}
			}
			resp, err = runner.EvaluateLifecycle(context.Background(), record.Name, scenario.Lifecycle, LifecycleEvaluateRequest{Phase: first(step.Phase, scenario.Phase), Method: first(step.Method, scenario.Method), Path: first(step.Path, scenario.Path), Request: mergeMaps(scenario.Request, step.Request), Input: mergeMaps(scenario.Input, step.Input), Response: mergeMaps(scenario.Response, step.Response), Event: first(step.Event, scenario.Event), EntityKey: first(step.EntityKey, scenario.EntityKey), DryRun: true})
			if err != nil {
				break
			}
			actual := lifecycleScenarioActual(resp)
			for key, want := range step.Expect {
				if got := fmt.Sprint(lookupInputPath(actual, key)); got != fmt.Sprint(want) {
					result.Passed = false
					result.Diagnostics = append(result.Diagnostics, bcl.Diagnostic{Severity: "error", Message: fmt.Sprintf("step %s expected %s=%v got %v", step.Name, key, want, got)})
				}
			}
		}
		if err != nil {
			result.Passed = false
			result.Diagnostics = append(result.Diagnostics, bcl.Diagnostic{Severity: "error", Message: err.Error()})
			results = append(results, result)
			continue
		}
		result.Actual = lifecycleScenarioActual(resp)
		for key, want := range scenario.Expect {
			if got := fmt.Sprint(lookupInputPath(result.Actual, key)); got != fmt.Sprint(want) {
				result.Passed = false
				result.Diagnostics = append(result.Diagnostics, bcl.Diagnostic{Severity: "error", Message: fmt.Sprintf("expected %s=%v got %v", key, want, got)})
			}
		}
		results = append(results, result)
	}
	return results
}

func lifecycleScenarioActual(resp *LifecycleEvaluateResponse) map[string]any {
	if resp == nil {
		return nil
	}
	actual := map[string]any{"final_action": resp.Evaluation.FinalAction, "final_effect": resp.Evaluation.FinalEffect, "final_reason": resp.Evaluation.FinalReason, "route": resp.Evaluation.Route.ID, "state": map[string]any{}}
	states := actual["state"].(map[string]any)
	for _, chain := range resp.Evaluation.Chains {
		for _, state := range chain.StateAfter {
			states[state.Watch] = map[string]any{"count": state.Counters[firstNonEmptyMapKey(state.Counters)], "counters": state.Counters, "step": state.Step, "action": state.Action, "severity": state.Severity, "attributes": state.Attributes, "metadata": state.Metadata}
		}
	}
	return actual
}

func firstNonEmptyMapKey(values map[string]int) string {
	for key := range values {
		if key != "" {
			return key
		}
	}
	return ""
}

func lifecycleObjectMap(v any) map[string]any {
	out := map[string]any{}
	for _, item := range blockList(v) {
		name := stringAny(item["name"])
		if name != "" {
			setPathValue(out, name, literalValue(item["value"]))
			continue
		}
		typ := stringAny(item["type"])
		if typ == "" || typ == "assignment" {
			continue
		}
		child := lifecycleObjectMap(item["body"])
		if id := strings.TrimSpace(stringAny(item["id"])); id != "" {
			child["id"] = id
		}
		setPathValue(out, typ, child)
	}
	if len(out) > 0 {
		return out
	}
	return metadataMap(v)
}
