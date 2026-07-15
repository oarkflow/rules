package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/oarkflow/bcl"
	"github.com/oarkflow/rules/pkg/storage"
)

func policyGovernanceMetadata(program *bcl.DecisionProgram, metadata map[string]any) map[string]any {
	metadata = copyMetadata(metadata)
	packages, _ := policyPackageManifests(program)
	if len(packages) > 0 {
		manifest := packages[0]
		if metadata["owner"] == nil {
			metadata["owner"] = manifest.Owner
		}
		if metadata["domain"] == nil {
			metadata["domain"] = manifest.Domain
		}
		metadata["package"] = manifest.ID
		metadata["package_version"] = manifest.Version
		metadata["capabilities"] = manifest.Capabilities
		for key, value := range manifest.Metadata {
			if metadata[key] == nil {
				metadata[key] = value
			}
		}
	}
	maxSeverity := "low"
	_, actions, _ := actionCatalogs(program)
	for _, action := range actions {
		if severityRank(action.Severity) > severityRank(maxSeverity) {
			maxSeverity = action.Severity
		}
	}
	chains, _ := chainDefinitions(program)
	for _, chain := range chains {
		for _, watch := range chain.Watches {
			for _, step := range watch.Steps {
				if severityRank(step.Severity) > severityRank(maxSeverity) {
					maxSeverity = step.Severity
				}
			}
		}
	}
	if metadata["severity"] == nil {
		metadata["severity"] = maxSeverity
	}
	return metadata
}

func validateGovernanceActivation(record storage.DefinitionRecord, now time.Time) error {
	if record.Metadata == nil || !metadataBool(record.Metadata, "review_required") {
		return nil
	}
	lastReviewed := stringAny(record.Metadata["last_reviewed"])
	if lastReviewed == "" {
		return fmt.Errorf("definition %q requires governance review before activation", record.Name)
	}
	reviewedAt, err := time.Parse(time.RFC3339Nano, lastReviewed)
	if err != nil {
		return fmt.Errorf("definition %q has invalid last_reviewed timestamp", record.Name)
	}
	intervalText := stringAny(record.Metadata["review_interval"])
	if intervalText == "" {
		return nil
	}
	interval, err := time.ParseDuration(intervalText)
	if err != nil {
		return fmt.Errorf("definition %q has invalid review_interval %q", record.Name, intervalText)
	}
	if reviewedAt.Add(interval).Before(now) {
		return fmt.Errorf("definition %q governance review expired at %s", record.Name, reviewedAt.Add(interval).UTC().Format(time.RFC3339))
	}
	return nil
}

func (s *Service) enforceTenantQuota(ctx context.Context, kind string) error {
	if s == nil || len(s.cfg.Runtime.TenantQuotas) == 0 {
		return nil
	}
	tenant := TenantFromContext(ctx)
	for _, quota := range s.cfg.Runtime.TenantQuotas {
		if !matchRuntimeScope(quota.TenantID, tenant) || !matchRuntimeScope(quota.Environment, s.cfg.Environment) {
			continue
		}
		stats, err := s.store.Stats(ctx)
		if err != nil {
			return err
		}
		limit, count := 0, 0
		switch kind {
		case "event":
			limit, count = quota.MaxEvents, stats.ChainEvents
		case "state":
			limit, count = quota.MaxStates, stats.ChainStates
		case "action":
			limit, count = quota.MaxActionDeliveries, stats.ActionDeliveries
		case "incident":
			limit, count = quota.MaxIncidents, stats.Incidents
		}
		if limit > 0 && count >= limit {
			return fmt.Errorf("tenant %q %s quota exceeded: %d/%d", tenant, kind, count, limit)
		}
	}
	return nil
}

func (s *Service) UpdateIncident(ctx context.Context, id string, req IncidentUpdateRequest) (storage.IncidentRecord, error) {
	ctx = s.requestContext(ctx, req.TenantID)
	status := strings.ToLower(strings.TrimSpace(req.Status))
	switch status {
	case "open", "acknowledged", "resolved":
	default:
		return storage.IncidentRecord{}, fmt.Errorf("unsupported incident status %q", req.Status)
	}
	records, err := s.store.ListIncidents(ctx, storage.IncidentQuery{})
	if err != nil {
		return storage.IncidentRecord{}, err
	}
	for _, record := range records {
		if record.ID != id {
			continue
		}
		record.Status = status
		record.Metadata = cloneMap(record.Metadata)
		if record.Metadata == nil {
			record.Metadata = map[string]any{}
		}
		record.Metadata["resolution_reason"] = req.Reason
		record.Metadata["resolution_actor"] = first(req.Actor, SubjectFromContext(ctx), "system")
		record.Metadata["status_changed_at"] = s.now().Format(time.RFC3339Nano)
		if err := s.store.UpsertIncident(ctx, record); err != nil {
			return storage.IncidentRecord{}, err
		}
		_, auditErr := s.audit(ctx, "incident_"+status, record.Definition, "", record.Environment, "", req, record, s.now(), nil)
		return record, auditErr
	}
	return storage.IncidentRecord{}, fmt.Errorf("unknown incident %q", id)
}

// MutationTest removes each decision rule in isolation and reruns the policy's
// BCL and lifecycle scenarios. A mutation is killed when the tests fail.
func (s *Service) MutationTest(ctx context.Context, definition string) (*MutationReport, error) {
	ctx = s.requestContext(ctx, "")
	record, err := s.store.GetActiveDefinition(ctx, definition, s.cfg.Environment)
	if err != nil {
		return nil, err
	}
	report := &MutationReport{Definition: definition}
	for decisionID, decision := range record.Program.Decisions {
		for index, rule := range decision.Rules {
			payload, marshalErr := json.Marshal(record.Program)
			if marshalErr != nil {
				return nil, marshalErr
			}
			var mutant bcl.DecisionProgram
			if err := json.Unmarshal(payload, &mutant); err != nil {
				return nil, err
			}
			mutated := mutant.Decisions[decisionID]
			mutated.Rules = append(mutated.Rules[:index], mutated.Rules[index+1:]...)
			tests := s.runTests(&mutant, decisionID, "", false, definition, record.Version, record.Environment)
			result := MutationResult{ID: decisionID + ".remove." + rule.ID, Kind: "remove_rule", Target: decisionID + "." + rule.ID, Killed: !tests.Passed}
			report.Total++
			if result.Killed {
				report.Killed++
			} else {
				report.Survived = append(report.Survived, result)
			}
			report.Results = append(report.Results, result)
		}
	}
	if report.Total > 0 {
		report.Score = float64(report.Killed) / float64(report.Total) * 100
	}
	return report, nil
}
