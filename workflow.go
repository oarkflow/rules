package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/oarkflow/bcl"
	"github.com/oarkflow/rules/pkg/storage"
)

func workflowDefinition(program *bcl.DecisionProgram, workflowID string) (*WorkflowDefinition, error) {
	if program == nil {
		return nil, fmt.Errorf("nil decision program")
	}
	var workflows []map[string]any
	if raw := program.Governance["_condition_workflows"]; raw != nil {
		collectBlocks(raw, "workflow", &workflows)
	}
	if len(workflows) == 0 && program.Normalized != nil {
		collectBlocks(program.Normalized.Body, "workflow", &workflows)
	}
	if len(workflows) == 0 {
		return nil, fmt.Errorf("definition has no workflows")
	}
	for _, block := range workflows {
		id := stringAny(block["id"])
		if workflowID != "" && id != workflowID {
			continue
		}
		body := bodyMap(block["body"])
		def := &WorkflowDefinition{ID: id, Start: first(stringAny(body["start"]), stringAny(body["start_at"]))}
		for _, stage := range childBlocks(block["body"], "stage") {
			stageBody := bodyMap(stage["body"])
			ws := WorkflowStage{ID: stringAny(stage["id"]), SLA: stringAny(stageBody["sla"]), OnTimeout: stringAny(stageBody["on_timeout"])}
			ws.Assign = assignmentFromStage(stageBody)
			for _, rule := range childBlocks(stage["body"], "rule") {
				ruleBody := bodyMap(rule["body"])
				whenExpr := workflowConditionExpression(ruleBody["when"])
				if whenBlocks := childBlocks(rule["body"], "when"); whenExpr == "" && len(whenBlocks) > 0 {
					whenExpr = workflowConditionExpression(whenBlocks[0]["body"])
				}
				ws.Transitions = append(ws.Transitions, WorkflowTransition{
					ID:        stringAny(rule["id"]),
					NextStage: stringAny(ruleBody["next_stage"]),
					WhenExpr:  whenExpr,
					Events:    stringListAny(ruleBody["event"]),
					Priority:  intAny(ruleBody["priority"]),
					Default:   boolAny(ruleBody["default"]),
				})
			}
			def.Stages = append(def.Stages, ws)
		}
		if err := validateWorkflowDefinition(def); err != nil {
			return nil, err
		}
		return def, nil
	}
	return nil, fmt.Errorf("unknown workflow %q", workflowID)
}

func validateWorkflows(program *bcl.DecisionProgram) []bcl.Diagnostic {
	if program == nil {
		return nil
	}
	var blocks []map[string]any
	if raw := program.Governance["_condition_workflows"]; raw != nil {
		collectBlocks(raw, "workflow", &blocks)
	}
	if len(blocks) == 0 && program.Normalized != nil {
		collectBlocks(program.Normalized.Body, "workflow", &blocks)
	}
	var diagnostics []bcl.Diagnostic
	seen := map[string]bool{}
	for _, block := range blocks {
		id := strings.TrimSpace(stringAny(block["id"]))
		if id == "" {
			diagnostics = append(diagnostics, bcl.Diagnostic{Severity: "error", Message: "workflow is missing id"})
			continue
		}
		if seen[id] {
			diagnostics = append(diagnostics, bcl.Diagnostic{Severity: "error", Message: fmt.Sprintf("duplicate workflow %q", id)})
			continue
		}
		seen[id] = true
		if _, err := workflowDefinition(program, id); err != nil {
			diagnostics = append(diagnostics, bcl.Diagnostic{Severity: "error", Message: err.Error()})
		}
	}
	return diagnostics
}

func bodyMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	out := map[string]any{}
	for _, item := range blockList(v) {
		if name := stringAny(item["name"]); name != "" {
			out[name] = literalValue(item["value"])
			continue
		}
		switch stringAny(item["type"]) {
		case "assignment":
			name := stringAny(item["name"])
			if name != "" {
				out[name] = literalValue(item["value"])
			}
		default:
			typ := stringAny(item["type"])
			if typ != "" {
				out[typ] = append(blockList(out[typ]), item)
			}
		}
	}
	return out
}

func childBlocks(v any, typ string) []map[string]any {
	var out []map[string]any
	for _, item := range blockList(v) {
		if stringAny(item["type"]) == typ {
			out = append(out, item)
		}
	}
	return out
}

func literalValue(v any) any {
	if m, ok := v.(map[string]any); ok {
		if data, exists := m["data"]; exists {
			return data
		}
	}
	return v
}

func applyWorkflowStage(run *WorkflowRun, workflow *WorkflowDefinition, input map[string]any, now time.Time) {
	stage := findStage(workflow, run.Stage)
	if stage == nil {
		run.Status = "completed"
		return
	}
	run.Assignment = stage.Assign
	if stage.SLA != "" {
		if run.Assignment == nil {
			run.Assignment = map[string]any{}
		}
		run.Assignment["sla"] = stage.SLA
		if duration, err := time.ParseDuration(stage.SLA); err == nil {
			run.Assignment["deadline"] = now.Add(duration).UTC().Format(time.RFC3339Nano)
		}
	}
	if stage.OnTimeout != "" {
		if run.Assignment == nil {
			run.Assignment = map[string]any{}
		}
		run.Assignment["on_timeout"] = stage.OnTimeout
	}
	_ = input
}

func advanceWorkflowStage(run *WorkflowRun, workflow *WorkflowDefinition, input map[string]any, now time.Time) error {
	stage := findStage(workflow, run.Stage)
	if stage == nil || len(stage.Transitions) == 0 {
		run.Status = "completed"
		return nil
	}
	var matched []WorkflowTransition
	var defaults []WorkflowTransition
	for _, transition := range stage.Transitions {
		if transition.Default || strings.TrimSpace(transition.WhenExpr) == "" {
			defaults = append(defaults, transition)
			continue
		}
		ok, err := workflowTransitionMatches(transition, input, now)
		if err != nil {
			return fmt.Errorf("workflow transition %q: %w", transition.ID, err)
		}
		if !ok {
			continue
		}
		matched = append(matched, transition)
	}
	if len(matched) == 0 {
		matched = defaults
	}
	if len(matched) > 0 {
		sort.SliceStable(matched, func(i, j int) bool { return matched[i].Priority > matched[j].Priority })
		if len(matched) > 1 && matched[0].Priority == matched[1].Priority {
			return fmt.Errorf("workflow stage %q has ambiguous transitions %q and %q at priority %d", stage.ID, matched[0].ID, matched[1].ID, matched[0].Priority)
		}
		transition := matched[0]
		run.Events = append(run.Events, transition.Events...)
		if transition.NextStage != "" {
			run.Stage = transition.NextStage
			applyWorkflowStage(run, workflow, input, now)
			return nil
		}
	}
	if len(matched) == 0 {
		return nil
	}
	run.Status = "completed"
	return nil
}

func workflowExpression(v any) string {
	if raw := expressionText(v); raw != "" {
		return raw
	}
	if m, ok := v.(map[string]any); ok {
		for _, key := range []string{"$expr", "raw", "expr"} {
			if raw, ok := m[key].(string); ok {
				return strings.TrimSpace(raw)
			}
		}
	}
	return strings.TrimSpace(stringAny(v))
}

func workflowConditionExpression(v any) string {
	if v == nil {
		return ""
	}
	switch value := v.(type) {
	case []any:
		var expressions []string
		for _, item := range value {
			if expression := workflowConditionExpression(item); expression != "" {
				expressions = append(expressions, expression)
			}
		}
		return strings.Join(expressions, " && ")
	case map[string]any:
		op := strings.ToLower(strings.TrimSpace(stringAny(value["op"])))
		if op == "expr" {
			return workflowExpression(value["expr"])
		}
		if raw := workflowExpression(value); raw != "" && op == "" {
			return raw
		}
		children := value["children"]
		if children == nil {
			children = value["body"]
		}
		var parts []string
		for _, child := range blockList(children) {
			if expression := workflowConditionExpression(child); expression != "" {
				parts = append(parts, expression)
			}
		}
		if len(parts) == 0 {
			if expression := expressionText(value); expression != "" {
				return expression
			}
			return ""
		}
		switch op {
		case "any", "or":
			return "(" + strings.Join(parts, " || ") + ")"
		case "not":
			return "!(" + strings.Join(parts, " && ") + ")"
		default:
			return "(" + strings.Join(parts, " && ") + ")"
		}
	default:
		return workflowExpression(v)
	}
}

func validateWorkflowDefinition(workflow *WorkflowDefinition) error {
	if workflow == nil {
		return fmt.Errorf("nil workflow")
	}
	stages := map[string]bool{}
	for _, stage := range workflow.Stages {
		if stage.ID == "" {
			return fmt.Errorf("workflow %q has a stage without id", workflow.ID)
		}
		if stages[stage.ID] {
			return fmt.Errorf("workflow %q has duplicate stage %q", workflow.ID, stage.ID)
		}
		stages[stage.ID] = true
	}
	if workflow.Start != "" && !stages[workflow.Start] {
		return fmt.Errorf("workflow %q references unknown start stage %q", workflow.ID, workflow.Start)
	}
	for _, stage := range workflow.Stages {
		if stage.OnTimeout != "" && !stages[stage.OnTimeout] {
			return fmt.Errorf("workflow %q stage %q references unknown timeout stage %q", workflow.ID, stage.ID, stage.OnTimeout)
		}
		seen := map[string]bool{}
		for _, transition := range stage.Transitions {
			if transition.ID == "" {
				return fmt.Errorf("workflow %q stage %q has a transition without id", workflow.ID, stage.ID)
			}
			if seen[transition.ID] {
				return fmt.Errorf("workflow %q stage %q has duplicate transition %q", workflow.ID, stage.ID, transition.ID)
			}
			seen[transition.ID] = true
			if transition.NextStage != "" && !stages[transition.NextStage] {
				return fmt.Errorf("workflow %q transition %q references unknown stage %q", workflow.ID, transition.ID, transition.NextStage)
			}
			if transition.WhenExpr != "" {
				if _, err := bcl.CompileExpression(transition.WhenExpr); err != nil {
					return fmt.Errorf("workflow %q transition %q has invalid condition: %w", workflow.ID, transition.ID, err)
				}
			}
		}
	}
	return nil
}

func workflowTransitionMatches(transition WorkflowTransition, input map[string]any, now time.Time) (bool, error) {
	raw := strings.TrimSpace(transition.WhenExpr)
	if raw == "" {
		return true, nil
	}
	value, err := bcl.EvalExpr(raw, &bcl.EvalOptions{Variables: input, Now: func() time.Time { return now }})
	if err != nil {
		return false, err
	}
	return boolAny(value), nil
}

func workflowRunRecord(run WorkflowRun) storage.WorkflowRunRecord {
	return storage.WorkflowRunRecord{
		ID: run.ID, TenantID: run.TenantID, Definition: run.Definition, Version: run.Version, Environment: run.Environment, WorkflowID: run.WorkflowID,
		Stage: run.Stage, Status: run.Status, Input: run.Input, Assignment: run.Assignment, Events: run.Events, CreatedAt: run.CreatedAt, UpdatedAt: run.UpdatedAt,
	}
}

func workflowRunFromRecord(record storage.WorkflowRunRecord) WorkflowRun {
	return WorkflowRun{
		ID: record.ID, TenantID: record.TenantID, Definition: record.Definition, Version: record.Version, Environment: record.Environment, WorkflowID: record.WorkflowID,
		Stage: record.Stage, Status: record.Status, Input: record.Input, Assignment: record.Assignment, Events: record.Events, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
}

func firstWorkflowStage(workflow *WorkflowDefinition) string {
	if workflow != nil && len(workflow.Stages) > 0 {
		return workflow.Stages[0].ID
	}
	return ""
}

func findStage(workflow *WorkflowDefinition, id string) *WorkflowStage {
	if workflow == nil {
		return nil
	}
	for i := range workflow.Stages {
		if workflow.Stages[i].ID == id {
			return &workflow.Stages[i]
		}
	}
	return nil
}

func collectBlocks(v any, want string, out *[]map[string]any) {
	switch x := v.(type) {
	case map[string]any:
		if stringAny(x["type"]) == want {
			*out = append(*out, x)
		}
		for _, child := range x {
			collectBlocks(child, want, out)
		}
	case []any:
		for _, child := range x {
			collectBlocks(child, want, out)
		}
	case []map[string]any:
		for _, child := range x {
			collectBlocks(child, want, out)
		}
	}
}

func blockList(v any) []map[string]any {
	switch x := v.(type) {
	case []any:
		out := make([]map[string]any, 0, len(x))
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{x}
	case []map[string]any:
		return x
	default:
		return nil
	}
}

func assignmentFromStage(body map[string]any) map[string]any {
	assign := map[string]any{}
	for _, block := range blockList(body["assign"]) {
		if typ := stringAny(block["type"]); typ != "" {
			assign[typ] = block["value"]
		}
		if id := stringAny(block["id"]); id != "" {
			assign["target"] = id
		}
		if b, ok := block["body"].(map[string]any); ok {
			for k, v := range b {
				assign[k] = v
			}
		}
	}
	for _, key := range []string{"queue", "role", "user"} {
		if value := body[key]; value != nil {
			assign[key] = value
		}
	}
	if len(assign) == 0 {
		return nil
	}
	return assign
}

func stringAny(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		if v == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func stringListAny(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, item := range x {
			if s := stringAny(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func initWorkflowRunDefaults(run *WorkflowRun) {
	now := time.Now()
	if run.CreatedAt.IsZero() {
		run.CreatedAt = now
	}
	if run.UpdatedAt.IsZero() {
		run.UpdatedAt = now
	}
}
