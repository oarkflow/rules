package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/oarkflow/bcl"
)

func BlastRadiusCheck(base, candidate *bcl.DecisionProgram, baseVersion, candidateVersion string) BlastRadiusReport {
	report := BlastRadiusReport{
		BaseVersion:      baseVersion,
		CandidateVersion: candidateVersion,
		Decisions:        radiusDiff(decisionIDs(base), decisionIDs(candidate)),
		Chains:           radiusDiff(chainIDs(base), chainIDs(candidate)),
		Routes:           radiusDiff(routeIDsReachable(base), routeIDsReachable(candidate)),
		Lifecycles:       radiusDiff(lifecycleIDs(base), lifecycleIDs(candidate)),
		Actions:          radiusDiff(declaredActionNames(base), declaredActionNames(candidate)),
		Steps:            buildStepDiff(base, candidate),
	}
	report.DependencyGraph = buildDependencyGraph(base, candidate)
	report.ImpactSummary = buildImpactSummary(report)
	if base != nil {
		report.Definition = firstModule(base)
	}
	return report
}

func radiusDiff(base, candidate []string) RadiusDiff {
	baseSet := make(map[string]bool, len(base))
	for _, v := range base {
		baseSet[v] = true
	}
	candSet := make(map[string]bool, len(candidate))
	for _, v := range candidate {
		candSet[v] = true
	}
	diff := RadiusDiff{}
	total := len(base) + len(candidate)
	for _, v := range base {
		if candSet[v] {
			diff.Unchanged = append(diff.Unchanged, v)
		} else {
			diff.Removed = append(diff.Removed, v)
		}
	}
	for _, v := range candidate {
		if !baseSet[v] {
			diff.Added = append(diff.Added, v)
		}
	}
	diff.Total = total
	affected := len(diff.Added) + len(diff.Removed)
	if total > 0 {
		diff.AffectedPct = float64(affected) / float64(total) * 100
	}
	sort.Strings(diff.Added)
	sort.Strings(diff.Removed)
	sort.Strings(diff.Unchanged)
	return diff
}

func routeIDsReachable(program *bcl.DecisionProgram) []string {
	if program == nil {
		return nil
	}
	set := map[string]bool{}
	catalogs, _ := routeCatalogs(program)
	for catalogID, routes := range catalogs {
		for _, route := range routes {
			set[catalogID+"."+route.ID] = true
		}
	}
	return sortedKeys(set)
}

func buildStepDiff(base, candidate *bcl.DecisionProgram) RadiusStepDiff {
	diff := RadiusStepDiff{}
	baseSteps := collectSteps(base)
	candSteps := collectSteps(candidate)
	for id := range candSteps {
		if _, ok := baseSteps[id]; !ok {
			diff.Added = append(diff.Added, id)
		} else if baseSteps[id] != candSteps[id] {
			diff.Changed = append(diff.Changed, id)
		}
	}
	for id := range baseSteps {
		if _, ok := candSteps[id]; !ok {
			diff.Removed = append(diff.Removed, id)
		}
	}
	sort.Strings(diff.Added)
	sort.Strings(diff.Removed)
	sort.Strings(diff.Changed)
	return diff
}

func collectSteps(program *bcl.DecisionProgram) map[string]string {
	if program == nil {
		return nil
	}
	out := map[string]string{}
	chains, _ := chainDefinitions(program)
	for _, chain := range chains {
		for _, watch := range chain.Watches {
			for _, step := range watch.Steps {
				key := chain.ID + "." + watch.ID + "." + step.ID
				out[key] = fmt.Sprintf("%s:%d:%s", step.Action, step.Threshold, step.Severity)
			}
		}
	}
	return out
}

func buildDependencyGraph(base, candidate *bcl.DecisionProgram) DependencyGraph {
	var g DependencyGraph
	nodeSet := map[string]bool{}

	addNode := func(id, kind string, added, removed bool) {
		if nodeSet[id] {
			return
		}
		nodeSet[id] = true
		g.Nodes = append(g.Nodes, DepNode{ID: id, Kind: kind, New: added, Removed: removed})
	}

	baseDecisions := decisionIDs(base)
	candDecisions := decisionIDs(candidate)
	baseChains := chainIDs(base)
	candChains := chainIDs(candidate)
	baseLifecycles := lifecycleIDs(base)
	candLifecycles := lifecycleIDs(candidate)

	baseDecSet := setOf(baseDecisions)
	candDecSet := setOf(candDecisions)
	baseChainSet := setOf(baseChains)
	candChainSet := setOf(candChains)
	baseLifecycleSet := setOf(baseLifecycles)

	for _, v := range candDecisions {
		addNode(v, "decision", !baseDecSet[v], false)
	}
	for _, v := range baseDecisions {
		if !candDecSet[v] {
			addNode(v, "decision", false, true)
		}
	}
	for _, v := range candChains {
		addNode(v, "chain", !baseChainSet[v], false)
	}
	for _, v := range baseChains {
		if !candChainSet[v] {
			addNode(v, "chain", false, true)
		}
	}
	for _, v := range candLifecycles {
		addNode(v, "lifecycle", !baseLifecycleSet[v], false)
	}
	for _, v := range baseLifecycles {
		if !setOf(candLifecycles)[v] {
			addNode(v, "lifecycle", false, true)
		}
	}

	for _, lifecycleID := range candLifecycles {
		lc := findLifecycle(candidate, lifecycleID)
		if lc == nil {
			continue
		}
		for _, phase := range lc.Phases {
			for _, decisionID := range phase.Decisions {
				g.Edges = append(g.Edges, DepEdge{From: lifecycleID, To: decisionID, Weight: 1})
			}
			for _, chainID := range phase.Chains {
				g.Edges = append(g.Edges, DepEdge{From: lifecycleID, To: chainID, Weight: 1})
			}
		}
	}
	for _, chainID := range candChains {
		ch := findChain(candidate, chainID)
		if ch == nil {
			continue
		}
		for _, decisionID := range ch.Decisions {
			g.Edges = append(g.Edges, DepEdge{From: chainID, To: decisionID, Weight: 1})
		}
	}

	return g
}

func setOf(items []string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, v := range items {
		out[v] = true
	}
	return out
}

func findLifecycle(program *bcl.DecisionProgram, id string) *LifecycleDefinition {
	lifecycles, _ := lifecycleDefinitions(program)
	for _, lc := range lifecycles {
		if lc.ID == id {
			return &lc
		}
	}
	return nil
}

func findChain(program *bcl.DecisionProgram, id string) *ChainDefinition {
	chains, _ := chainDefinitions(program)
	for _, ch := range chains {
		if ch.ID == id {
			return &ch
		}
	}
	return nil
}

func buildImpactSummary(report BlastRadiusReport) []string {
	var summary []string
	sections := []struct {
		label string
		diff  RadiusDiff
	}{
		{"decisions", report.Decisions},
		{"chains", report.Chains},
		{"routes", report.Routes},
		{"lifecycles", report.Lifecycles},
		{"actions", report.Actions},
	}
	for _, s := range sections {
		totalAffected := len(s.diff.Added) + len(s.diff.Removed)
		if totalAffected == 0 {
			continue
		}
		summary = append(summary, fmt.Sprintf("%s: %d added, %d removed, %d unchanged (%.0f%% affected)", s.label, len(s.diff.Added), len(s.diff.Removed), len(s.diff.Unchanged), s.diff.AffectedPct))
	}
	if len(report.Steps.Added) > 0 {
		summary = append(summary, fmt.Sprintf("steps: %d added", len(report.Steps.Added)))
	}
	if len(report.Steps.Removed) > 0 {
		summary = append(summary, fmt.Sprintf("steps: %d removed", len(report.Steps.Removed)))
	}
	if len(report.Steps.Changed) > 0 {
		summary = append(summary, fmt.Sprintf("steps: %d changed", len(report.Steps.Changed)))
	}
	if len(report.DependencyGraph.Edges) > 0 {
		summary = append(summary, fmt.Sprintf("dependency graph: %d nodes, %d edges", len(report.DependencyGraph.Nodes), len(report.DependencyGraph.Edges)))
	}
	return summary
}

var _ = strings.TrimSpace
