package rules

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/oarkflow/bcl"
	"github.com/oarkflow/rules/pkg/routing"
)

// Symbol is a resolved policy identifier. Keeping it distinct from string
// prevents runtime plans from accidentally treating user text as a reference.
type Symbol string

type ValueType string

const (
	TypeAny    ValueType = "any"
	TypeBool   ValueType = "bool"
	TypeNumber ValueType = "number"
	TypeString ValueType = "string"
	TypeObject ValueType = "object"
	TypeList   ValueType = "list"
)

type SemanticExpr struct {
	Kind       string    `json:"kind"`
	Raw        string    `json:"raw,omitempty"`
	ResultType ValueType `json:"result_type"`
	FactRefs   []FactRef `json:"fact_refs,omitempty"`
	Span       bcl.Span  `json:"span,omitempty"`
}

type FactRef struct {
	Root   string   `json:"root"`
	Fields []string `json:"fields,omitempty"`
	Path   string   `json:"path"`
}

type RuleIR struct {
	ID         Symbol       `json:"id"`
	Priority   int64        `json:"priority,omitempty"`
	Effect     string       `json:"effect,omitempty"`
	Condition  SemanticExpr `json:"condition"`
	ReasonCode string       `json:"reason_code,omitempty"`
	Span       bcl.Span     `json:"span,omitempty"`
}

type DecisionIR struct {
	ID       Symbol   `json:"id"`
	Default  string   `json:"default,omitempty"`
	Strategy string   `json:"strategy,omitempty"`
	Rules    []RuleIR `json:"rules,omitempty"`
	Span     bcl.Span `json:"span,omitempty"`
}

type PolicyDependency struct {
	From Symbol `json:"from"`
	To   Symbol `json:"to"`
	Kind string `json:"kind"`
}

// PolicyIR is the typed semantic layer between BCL's syntax/normalized AST and
// runtime evaluation. It is also suitable for LSP, graph, diff and docs tools.
type PolicyIR struct {
	Packages     map[Symbol]PolicyPackageManifest `json:"packages,omitempty"`
	Decisions    map[Symbol]DecisionIR            `json:"decisions,omitempty"`
	Chains       map[Symbol]ChainDefinition       `json:"chains,omitempty"`
	Routes       map[Symbol][]routing.Route       `json:"routes,omitempty"`
	Lifecycles   map[Symbol]LifecycleDefinition   `json:"lifecycles,omitempty"`
	Actions      map[Symbol]ActionDefinition      `json:"actions,omitempty"`
	FactSchemas  map[string]string                `json:"fact_schemas,omitempty"`
	Dependencies []PolicyDependency               `json:"dependencies,omitempty"`
	Diagnostics  []bcl.Diagnostic                 `json:"diagnostics,omitempty"`
}

var factReferencePattern = regexp.MustCompile(`\b(request|response|principal|route|tenant|resource|risk|state|context|session)(?:\.[A-Za-z_][A-Za-z0-9_]*)+`)

func CompilePolicyIR(program *bcl.DecisionProgram) *PolicyIR {
	ir := &PolicyIR{
		Packages:    map[Symbol]PolicyPackageManifest{},
		Decisions:   map[Symbol]DecisionIR{},
		Chains:      map[Symbol]ChainDefinition{},
		Routes:      map[Symbol][]routing.Route{},
		Lifecycles:  map[Symbol]LifecycleDefinition{},
		Actions:     map[Symbol]ActionDefinition{},
		FactSchemas: map[string]string{},
	}
	if program == nil {
		ir.Diagnostics = append(ir.Diagnostics, bcl.Diagnostic{Severity: "error", Message: "cannot compile semantic IR from nil program"})
		return ir
	}
	packages, diags := policyPackageManifests(program)
	ir.Diagnostics = append(ir.Diagnostics, diags...)
	for _, item := range packages {
		ir.Packages[Symbol(item.ID)] = item
	}
	_, actions, diags := actionCatalogs(program)
	ir.Diagnostics = append(ir.Diagnostics, diags...)
	for id, item := range actions {
		ir.Actions[Symbol(id)] = item
	}
	contracts, diags := standardFactContracts(program)
	ir.Diagnostics = append(ir.Diagnostics, diags...)
	for _, contract := range contracts {
		for root, schema := range contract.Facts {
			if old := ir.FactSchemas[root]; old != "" && schema != "" && old != schema {
				ir.Diagnostics = append(ir.Diagnostics, bcl.Diagnostic{Severity: "error", Message: fmt.Sprintf("fact %q has conflicting schemas %q and %q", root, old, schema)})
			}
			ir.FactSchemas[root] = schema
			if contract.Strict && schema != "" {
				if _, ok := program.Schemas[schema]; !ok {
					ir.Diagnostics = append(ir.Diagnostics, bcl.Diagnostic{Severity: "error", Message: fmt.Sprintf("fact %q references unknown schema %q", root, schema)})
				}
			}
		}
	}
	for id, decision := range program.Decisions {
		item := DecisionIR{ID: Symbol(id), Default: decision.Default, Strategy: decision.Strategy, Span: decision.Span}
		for _, rule := range decision.Rules {
			raw := expressionText(rule.Condition)
			item.Rules = append(item.Rules, RuleIR{ID: Symbol(rule.ID), Priority: rule.Priority, Effect: rule.Effect, ReasonCode: rule.ReasonCode, Span: rule.Span, Condition: SemanticExpr{Kind: "condition", Raw: raw, ResultType: TypeBool, FactRefs: factRefs(raw), Span: rule.Span}})
			for _, action := range actionNamesFromAny(rule.Then) {
				ir.Dependencies = append(ir.Dependencies, PolicyDependency{From: Symbol(id), To: Symbol(action), Kind: "decision_action"})
			}
		}
		ir.Decisions[Symbol(id)] = item
	}
	for _, contract := range contracts {
		if !contract.Strict {
			continue
		}
		for _, decision := range ir.Decisions {
			for _, rule := range decision.Rules {
				for _, ref := range rule.Condition.FactRefs {
					if isStandardFactRoot(ref.Root) {
						if _, declared := contract.Facts[ref.Root]; !declared {
							ir.Diagnostics = append(ir.Diagnostics, bcl.Diagnostic{Severity: "error", Message: fmt.Sprintf("decision %q rule %q references undeclared standard fact %q in contract %q", decision.ID, rule.ID, ref.Root, contract.ID)})
						}
					}
				}
			}
		}
	}
	chains, diags := chainDefinitions(program)
	ir.Diagnostics = append(ir.Diagnostics, diags...)
	for _, chain := range chains {
		ir.Chains[Symbol(chain.ID)] = chain
		for _, decision := range chain.Decisions {
			ir.Dependencies = append(ir.Dependencies, PolicyDependency{From: Symbol(chain.ID), To: Symbol(decision), Kind: "chain_decision"})
			if _, ok := program.Decisions[decision]; !ok {
				ir.Diagnostics = append(ir.Diagnostics, bcl.Diagnostic{Severity: "error", Message: fmt.Sprintf("chain %q references unknown decision %q", chain.ID, decision)})
			}
		}
		for _, watch := range chain.Watches {
			for _, step := range watch.Steps {
				ir.Dependencies = append(ir.Dependencies, PolicyDependency{From: Symbol(chain.ID), To: Symbol(step.Action), Kind: "chain_action"})
				if _, ok := ir.Actions[Symbol(step.Action)]; len(ir.Actions) > 0 && !ok {
					ir.Diagnostics = append(ir.Diagnostics, bcl.Diagnostic{Severity: "error", Message: fmt.Sprintf("chain %q watch %q step %q references unknown action %q", chain.ID, watch.ID, step.ID, step.Action)})
				}
			}
		}
	}
	routes, diags := routeCatalogs(program)
	ir.Diagnostics = append(ir.Diagnostics, diags...)
	for id, catalog := range routes {
		ir.Routes[Symbol(id)] = catalog
	}
	lifecycles, diags := lifecycleDefinitions(program)
	ir.Diagnostics = append(ir.Diagnostics, diags...)
	for _, lifecycle := range lifecycles {
		ir.Lifecycles[Symbol(lifecycle.ID)] = lifecycle
		if _, ok := routes[lifecycle.Routes]; lifecycle.Routes != "" && !ok {
			ir.Diagnostics = append(ir.Diagnostics, bcl.Diagnostic{Severity: "error", Message: fmt.Sprintf("lifecycle %q references unknown route catalog %q", lifecycle.ID, lifecycle.Routes)})
		}
		for _, route := range routes[lifecycle.Routes] {
			ir.Dependencies = append(ir.Dependencies, PolicyDependency{From: Symbol(lifecycle.Routes + "." + route.ID), To: Symbol(lifecycle.ID), Kind: "route_lifecycle"})
		}
		for _, phase := range lifecycle.Phases {
			for _, decision := range phase.Decisions {
				ir.Dependencies = append(ir.Dependencies, PolicyDependency{From: Symbol(lifecycle.ID), To: Symbol(decision), Kind: "lifecycle_decision"})
				if _, ok := program.Decisions[decision]; !ok {
					ir.Diagnostics = append(ir.Diagnostics, bcl.Diagnostic{Severity: "error", Message: fmt.Sprintf("lifecycle %q phase %q references unknown decision %q", lifecycle.ID, phase.ID, decision)})
				}
			}
			for _, chain := range phase.Chains {
				ir.Dependencies = append(ir.Dependencies, PolicyDependency{From: Symbol(lifecycle.ID), To: Symbol(chain), Kind: "lifecycle_chain"})
				if _, ok := ir.Chains[Symbol(chain)]; !ok {
					ir.Diagnostics = append(ir.Diagnostics, bcl.Diagnostic{Severity: "error", Message: fmt.Sprintf("lifecycle %q phase %q references unknown chain %q", lifecycle.ID, phase.ID, chain)})
				}
			}
		}
	}
	sort.Slice(ir.Dependencies, func(i, j int) bool {
		if ir.Dependencies[i].From == ir.Dependencies[j].From {
			return ir.Dependencies[i].To < ir.Dependencies[j].To
		}
		return ir.Dependencies[i].From < ir.Dependencies[j].From
	})
	return ir
}

func isStandardFactRoot(root string) bool {
	switch root {
	case "request", "response", "principal", "route", "tenant", "resource", "risk", "state":
		return true
	default:
		return false
	}
}

func (s *Service) PolicyIR(ctx context.Context, definition string) (*PolicyIR, error) {
	ctx = s.requestContext(ctx, "")
	record, err := s.store.GetActiveDefinition(ctx, definition, s.cfg.Environment)
	if err != nil {
		return nil, err
	}
	return CompilePolicyIR(record.Program), nil
}

func expressionText(value any) string {
	var parts []string
	var walk func(any)
	walk = func(current any) {
		switch item := current.(type) {
		case string:
			parts = append(parts, item)
		case map[string]any:
			for _, key := range []string{"$expr", "raw"} {
				if raw, ok := item[key].(string); ok && strings.TrimSpace(raw) != "" {
					parts = append(parts, raw)
					return
				}
			}
			for _, key := range []string{"expr", "children", "condition", "conditions", "body"} {
				if value, ok := item[key]; ok {
					walk(value)
				}
			}
		case []any:
			for _, value := range item {
				walk(value)
			}
		}
	}
	walk(value)
	return strings.Join(parts, " ")
}

func factRefs(raw string) []FactRef {
	seen := map[string]bool{}
	var refs []FactRef
	for _, path := range factReferencePattern.FindAllString(raw, -1) {
		if seen[path] {
			continue
		}
		seen[path] = true
		parts := strings.Split(path, ".")
		refs = append(refs, FactRef{Root: parts[0], Fields: parts[1:], Path: path})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Path < refs[j].Path })
	return refs
}
