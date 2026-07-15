package rules

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/oarkflow/bcl"
	"github.com/oarkflow/rules/pkg/storage"
)

func (s *Service) RouteCoverage(ctx context.Context, definition string) (*RouteCoverageReport, error) {
	ctx = s.requestContext(ctx, "")
	start := time.Now()
	record, err := s.store.GetActiveDefinition(ctx, definition, s.cfg.Environment)
	if err != nil {
		return nil, err
	}
	catalogs, routeDiags := routeCatalogs(record.Program)
	lifecycles, lifecycleDiags := lifecycleDefinitions(record.Program)
	report := RouteCoverageReport{Definition: definition, Passed: true}
	if len(routeDiags) > 0 || len(lifecycleDiags) > 0 {
		report.Passed = false
	}
	type coverageRef struct {
		lifecycle string
		phase     string
	}
	coverage := map[string][]coverageRef{}
	for _, lifecycle := range lifecycles {
		if lifecycle.Routes == "" {
			continue
		}
		for _, phase := range lifecycle.Phases {
			if len(phase.Decisions) == 0 && len(phase.Chains) == 0 {
				continue
			}
			refs, routeSpecific := phaseRouteReferences(record.Program, phase)
			if !routeSpecific {
				for _, route := range catalogs[lifecycle.Routes] {
					coverage[lifecycle.Routes+"."+route.ID] = append(coverage[lifecycle.Routes+"."+route.ID], coverageRef{lifecycle: lifecycle.ID, phase: phase.ID})
				}
				continue
			}
			for routeID := range refs {
				coverage[lifecycle.Routes+"."+routeID] = append(coverage[lifecycle.Routes+"."+routeID], coverageRef{lifecycle: lifecycle.ID, phase: phase.ID})
			}
		}
	}
	for catalogID, routes := range catalogs {
		for _, route := range routes {
			refs := coverage[catalogID+"."+route.ID]
			item := RouteCoverageItem{Catalog: catalogID, RouteID: route.ID, Method: route.Method, Pattern: route.Pattern, Covered: len(refs) > 0}
			seenLifecycle := map[string]bool{}
			seenPhase := map[string]bool{}
			for _, ref := range refs {
				if !seenLifecycle[ref.lifecycle] {
					item.Lifecycles = append(item.Lifecycles, ref.lifecycle)
					seenLifecycle[ref.lifecycle] = true
				}
				key := ref.lifecycle + "." + ref.phase
				if !seenPhase[key] {
					item.Phases = append(item.Phases, key)
					seenPhase[key] = true
				}
			}
			sort.Strings(item.Lifecycles)
			sort.Strings(item.Phases)
			if !item.Covered {
				report.Passed = false
				report.Uncovered = append(report.Uncovered, fmt.Sprintf("%s.%s", catalogID, route.ID))
			}
			report.Routes = append(report.Routes, item)
		}
	}
	sort.Slice(report.Routes, func(i, j int) bool {
		if report.Routes[i].Catalog == report.Routes[j].Catalog {
			return report.Routes[i].RouteID < report.Routes[j].RouteID
		}
		return report.Routes[i].Catalog < report.Routes[j].Catalog
	})
	sort.Strings(report.Uncovered)
	envelope, err := s.audit(ctx, "route_coverage", definition, record.Version, record.Environment, record.Digest, map[string]any{"definition": definition}, report, start, nil)
	if err != nil {
		return nil, err
	}
	report.Audit = envelope
	if err := s.store.SaveReport(ctx, storage.ReportRecord{ID: envelope.ID, Kind: "route_coverage", Definition: definition, CreatedAt: s.now(), Payload: map[string]any{"report": report}}); err != nil {
		return nil, err
	}
	return &report, nil
}

func phaseRouteReferences(program *bcl.DecisionProgram, phase LifecyclePhaseDefinition) (map[string]bool, bool) {
	refs := map[string]bool{}
	routeSpecific := false
	inspectDecision := func(id string) {
		decision := program.Decisions[id]
		if decision == nil {
			return
		}
		for _, rule := range decision.Rules {
			raw := expressionText(rule.Condition)
			if !strings.Contains(raw, "route.id") {
				continue
			}
			routeSpecific = true
			for _, token := range strings.FieldsFunc(raw, func(r rune) bool {
				return !(r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
			}) {
				refs[token] = true
			}
		}
	}
	for _, decision := range phase.Decisions {
		inspectDecision(decision)
	}
	for _, chainID := range phase.Chains {
		if chain, err := chainDefinition(program, chainID); err == nil {
			for _, decision := range chain.Decisions {
				inspectDecision(decision)
			}
		}
	}
	return refs, routeSpecific
}
