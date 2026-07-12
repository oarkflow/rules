package storage

import (
	"context"
	"strings"
	"time"

	core "github.com/oarkflow/rules/pkg/storage"
)

type DefinitionRecord = core.DefinitionRecord
type ActiveDefinition = core.ActiveDefinition
type ReportRecord = core.ReportRecord
type ListOptions = core.ListOptions
type WorkflowRunRecord = core.WorkflowRunRecord
type ChainEventRecord = core.ChainEventRecord
type ChainStateRecord = core.ChainStateRecord
type ActionDeliveryRecord = core.ActionDeliveryRecord
type IncidentRecord = core.IncidentRecord
type ChainEventQuery = core.ChainEventQuery
type ChainStateQuery = core.ChainStateQuery
type ActionDeliveryQuery = core.ActionDeliveryQuery
type IncidentQuery = core.IncidentQuery
type RetentionRequest = core.RetentionRequest
type RetentionResult = core.RetentionResult
type StatsRecord = core.StatsRecord
type Store = core.Store

func ContextWithTenant(ctx context.Context, tenant string) context.Context {
	return core.ContextWithTenant(ctx, tenant)
}

func TenantFromContext(ctx context.Context) string { return core.TenantFromContext(ctx) }

func ApplyListOptions[T any](items []T, opts ListOptions, include func(T) bool) []T {
	return core.ApplyListOptions(items, opts, include)
}

func firstEnv(environment string) string {
	if strings.TrimSpace(environment) == "" {
		return "development"
	}
	return strings.TrimSpace(environment)
}

func firstTenant(tenant string) string {
	if strings.TrimSpace(tenant) == "" {
		return "default"
	}
	return strings.TrimSpace(tenant)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func nowUTC() time.Time { return time.Now().UTC() }

func inRange(t time.Time, opts ListOptions) bool {
	if opts.Since != nil && t.Before(*opts.Since) {
		return false
	}
	if opts.Until != nil && t.After(*opts.Until) {
		return false
	}
	return true
}
