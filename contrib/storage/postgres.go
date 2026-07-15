package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/oarkflow/rules/pkg/audit"
	"github.com/oarkflow/squealx"
	"github.com/oarkflow/squealx/drivers/postgres"
)

type PostgresStore struct {
	db *squealx.DB
}

func NewPostgresStore(connString string) (*PostgresStore, error) {
	db, err := postgres.Open(connString, "rules-storage")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	s := &PostgresStore{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *PostgresStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *PostgresStore) LockEntity(ctx context.Context, key string) (func() error, error) {
	conn, err := s.db.Connx(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, key); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return func() error {
		_, unlockErr := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key)
		closeErr := conn.Close()
		if unlockErr != nil {
			return unlockErr
		}
		return closeErr
	}, nil
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS condition_definition_versions (
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'development',
    source TEXT,
    source_path TEXT,
    digest TEXT NOT NULL,
    program_json JSONB NOT NULL,
    published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata_json JSONB DEFAULT '{}',
    PRIMARY KEY (tenant_id, name, version, environment)
);
CREATE TABLE IF NOT EXISTS condition_active_definitions (
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'development',
    version TEXT NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, name, environment)
);
CREATE TABLE IF NOT EXISTS condition_audits (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    hash TEXT NOT NULL,
    previous_hash TEXT,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload_json JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS condition_reports (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    kind TEXT NOT NULL,
    definition TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload_json JSONB DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS condition_workflow_runs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    definition TEXT,
    version TEXT,
    environment TEXT DEFAULT 'development',
    workflow_id TEXT,
    stage TEXT,
    status TEXT,
    input_json JSONB DEFAULT '{}',
    assignment_json JSONB DEFAULT '{}',
    events_json JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS condition_chain_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    definition TEXT,
    version TEXT,
    environment TEXT DEFAULT 'development',
    chain TEXT NOT NULL,
    watch TEXT,
    entity_key TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_decision TEXT,
    reason_code TEXT,
    severity TEXT,
    attributes_json JSONB DEFAULT '{}',
    metadata_json JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS condition_chain_states (
    tenant_id TEXT NOT NULL DEFAULT 'default',
    chain TEXT NOT NULL,
    watch TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    definition TEXT,
    version TEXT,
    environment TEXT DEFAULT 'development',
    counters_json JSONB DEFAULT '{}',
    step TEXT,
    action TEXT,
    severity TEXT,
    attributes_json JSONB DEFAULT '{}',
    metadata_json JSONB DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, chain, watch, entity_key)
);
CREATE TABLE IF NOT EXISTS condition_action_deliveries (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    definition TEXT,
    version TEXT,
    environment TEXT DEFAULT 'development',
    lifecycle TEXT,
    entity_key TEXT,
    action TEXT NOT NULL,
    sink TEXT,
    status TEXT,
    handled BOOLEAN DEFAULT FALSE,
    attempts INTEGER DEFAULT 1,
    max_attempts INTEGER DEFAULT 1,
    next_attempt TIMESTAMPTZ,
    error TEXT,
    reason_code TEXT,
    severity TEXT,
    attributes_json JSONB DEFAULT '{}',
    metadata_json JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS condition_incidents (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    definition TEXT,
    environment TEXT DEFAULT 'development',
    group_key TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    action TEXT,
    severity TEXT,
    reason_code TEXT,
    count INTEGER DEFAULT 1,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata_json JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audits_tenant_completed ON condition_audits(tenant_id, completed_at);
CREATE INDEX IF NOT EXISTS idx_chain_events_tenant_entity ON condition_chain_events(tenant_id, chain, entity_key, created_at);
CREATE INDEX IF NOT EXISTS idx_chain_states_tenant ON condition_chain_states(tenant_id, chain, entity_key);
CREATE INDEX IF NOT EXISTS idx_action_deliveries_tenant ON condition_action_deliveries(tenant_id, definition, status);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant ON condition_incidents(tenant_id, definition, status);
CREATE INDEX IF NOT EXISTS idx_reports_tenant ON condition_reports(tenant_id, kind, created_at);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_tenant ON condition_workflow_runs(tenant_id, definition);
`)
	return err
}

func (s *PostgresStore) SaveDefinition(ctx context.Context, record DefinitionRecord) error {
	if err := s.SaveDefinitionVersion(ctx, record); err != nil {
		return err
	}
	return s.ActivateDefinition(ctx, record.Name, record.Version, record.Environment)
}

func (s *PostgresStore) SaveDefinitionVersion(ctx context.Context, record DefinitionRecord) error {
	payload, err := json.Marshal(record.Program)
	if err != nil {
		return err
	}
	if record.Environment == "" {
		record.Environment = "development"
	}
	record.TenantID = firstTenant(firstNonEmpty(record.TenantID, TenantFromContext(ctx)))
	metadata, _ := json.Marshal(record.Metadata)
	_, err = s.db.ExecContext(ctx, `INSERT INTO condition_definition_versions
(tenant_id, name, version, environment, source, source_path, digest, program_json, published_at, metadata_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (tenant_id, name, version, environment) DO UPDATE SET
source=EXCLUDED.source, source_path=EXCLUDED.source_path, digest=EXCLUDED.digest,
program_json=EXCLUDED.program_json, published_at=EXCLUDED.published_at, metadata_json=EXCLUDED.metadata_json`,
		record.TenantID, record.Name, record.Version, record.Environment, record.Source, record.SourcePath, record.Digest, string(payload), record.PublishedAt, string(metadata))
	return err
}

func (s *PostgresStore) GetDefinition(ctx context.Context, name string) (DefinitionRecord, error) {
	return s.GetActiveDefinition(ctx, name, "")
}

func (s *PostgresStore) GetDefinitionVersion(ctx context.Context, name, version, environment string) (DefinitionRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT tenant_id, name, version, environment, source, source_path, digest, program_json, published_at, metadata_json
FROM condition_definition_versions WHERE tenant_id = $1 AND name = $2 AND version = $3 AND environment = $4`,
		TenantFromContext(ctx), name, version, firstEnv(environment))
	record, err := scanDefinition(row)
	if err == sql.ErrNoRows {
		return DefinitionRecord{}, fmt.Errorf("unknown definition %q version %q", name, version)
	}
	return record, err
}

func (s *PostgresStore) ListDefinitions(ctx context.Context) ([]DefinitionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT v.tenant_id, v.name, v.version, v.environment, v.source, v.source_path, v.digest, v.program_json, v.published_at, v.metadata_json
FROM condition_active_definitions a
JOIN condition_definition_versions v ON v.tenant_id = a.tenant_id AND v.name = a.name AND v.version = a.version AND v.environment = a.environment
WHERE a.tenant_id = $1
ORDER BY v.name`, TenantFromContext(ctx))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DefinitionRecord
	for rows.Next() {
		record, err := scanDefinition(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListDefinitionVersions(ctx context.Context, name, environment string) ([]DefinitionRecord, error) {
	query := `SELECT tenant_id, name, version, environment, source, source_path, digest, program_json, published_at, metadata_json FROM condition_definition_versions WHERE tenant_id = $1 AND name = $2`
	args := []any{TenantFromContext(ctx), name}
	if environment != "" {
		query += ` AND environment = $3`
		args = append(args, firstEnv(environment))
	}
	query += ` ORDER BY published_at`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DefinitionRecord
	for rows.Next() {
		record, err := scanDefinition(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ActivateDefinition(ctx context.Context, name, version, environment string) error {
	if _, err := s.GetDefinitionVersion(ctx, name, version, environment); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO condition_active_definitions (tenant_id, name, environment, version, activated_at)
VALUES ($1, $2, $3, $4, NOW())
ON CONFLICT (tenant_id, name, environment) DO UPDATE SET version=EXCLUDED.version, activated_at=NOW()`,
		TenantFromContext(ctx), name, firstEnv(environment), version)
	return err
}

func (s *PostgresStore) GetActiveDefinition(ctx context.Context, name, environment string) (DefinitionRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT v.tenant_id, v.name, v.version, v.environment, v.source, v.source_path, v.digest, v.program_json, v.published_at, v.metadata_json
FROM condition_active_definitions a
JOIN condition_definition_versions v ON v.tenant_id = a.tenant_id AND v.name = a.name AND v.version = a.version AND v.environment = a.environment
WHERE a.tenant_id = $1 AND a.name = $2 AND a.environment = $3`, TenantFromContext(ctx), name, firstEnv(environment))
	record, err := scanDefinition(row)
	if err == sql.ErrNoRows {
		return DefinitionRecord{}, fmt.Errorf("unknown definition %q", name)
	}
	return record, err
}

func (s *PostgresStore) SaveReport(ctx context.Context, report ReportRecord) error {
	payload, _ := json.Marshal(report.Payload)
	report.TenantID = firstTenant(firstNonEmpty(report.TenantID, TenantFromContext(ctx)))
	_, err := s.db.ExecContext(ctx, `INSERT INTO condition_reports (id, tenant_id, kind, definition, created_at, payload_json) VALUES ($1, $2, $3, $4, $5, $6)`,
		report.ID, report.TenantID, report.Kind, report.Definition, report.CreatedAt, string(payload))
	return err
}

func (s *PostgresStore) ListReports(ctx context.Context, kind string) ([]ReportRecord, error) {
	return s.ListReportsQuery(ctx, ListOptions{Kind: kind})
}

func (s *PostgresStore) ListReportsQuery(ctx context.Context, opts ListOptions) ([]ReportRecord, error) {
	query := `SELECT id, tenant_id, kind, definition, created_at, payload_json FROM condition_reports`
	args := []any{}
	var where []string
	where = append(where, fmt.Sprintf(`tenant_id = $%d`, len(args)+1))
	args = append(args, firstTenant(firstNonEmpty(opts.TenantID, TenantFromContext(ctx))))
	if opts.Kind != "" {
		where = append(where, fmt.Sprintf(`kind = $%d`, len(args)+1))
		args = append(args, opts.Kind)
	}
	if opts.Definition != "" {
		where = append(where, fmt.Sprintf(`definition = $%d`, len(args)+1))
		args = append(args, opts.Definition)
	}
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, ` AND `)
	}
	query += ` ORDER BY created_at`
	if opts.Limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, opts.Limit)
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(` OFFSET %d`, opts.Offset)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportRecord
	for rows.Next() {
		var report ReportRecord
		var payload string
		if err := rows.Scan(&report.ID, &report.TenantID, &report.Kind, &report.Definition, &report.CreatedAt, &payload); err != nil {
			return nil, err
		}
		if !inRange(report.CreatedAt, opts) {
			continue
		}
		_ = json.Unmarshal([]byte(payload), &report.Payload)
		out = append(out, report)
	}
	return out, rows.Err()
}

func (s *PostgresStore) AppendAudit(ctx context.Context, envelope audit.Envelope) error {
	payload, _ := json.Marshal(envelope)
	envelope.TenantID = firstTenant(firstNonEmpty(envelope.TenantID, TenantFromContext(ctx)))
	payload, _ = json.Marshal(envelope)
	_, err := s.db.ExecContext(ctx, `INSERT INTO condition_audits (id, tenant_id, hash, previous_hash, completed_at, payload_json) VALUES ($1, $2, $3, $4, $5, $6)`,
		envelope.ID, envelope.TenantID, envelope.Hash, envelope.PreviousHash, envelope.CompletedAt, string(payload))
	return err
}

func (s *PostgresStore) LastAuditHash(ctx context.Context) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT hash FROM condition_audits WHERE tenant_id = $1 ORDER BY completed_at DESC LIMIT 1`, TenantFromContext(ctx)).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return hash, err
}

func (s *PostgresStore) ListAudits(ctx context.Context) ([]audit.Envelope, error) {
	return s.ListAuditsQuery(ctx, ListOptions{})
}

func (s *PostgresStore) ListAuditsQuery(ctx context.Context, opts ListOptions) ([]audit.Envelope, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT payload_json FROM condition_audits WHERE tenant_id = $1 ORDER BY completed_at`, firstTenant(firstNonEmpty(opts.TenantID, TenantFromContext(ctx))))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []audit.Envelope
	for rows.Next() {
		var payload string
		var envelope audit.Envelope
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(payload), &envelope); err != nil {
			return nil, err
		}
		if (opts.Operation == "" || envelope.Operation == opts.Operation) &&
			(opts.Definition == "" || envelope.Definition == opts.Definition) &&
			(opts.Subject == "" || envelope.Subject == opts.Subject) &&
			inRange(envelope.CompletedAt, opts) {
			out = append(out, envelope)
		}
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return ApplyListOptions(out, opts, nil), nil
}

func (s *PostgresStore) GetAudit(ctx context.Context, id string) (audit.Envelope, error) {
	var payload string
	err := s.db.QueryRowContext(ctx, `SELECT payload_json FROM condition_audits WHERE tenant_id = $1 AND id = $2`, TenantFromContext(ctx), id).Scan(&payload)
	if err == sql.ErrNoRows {
		return audit.Envelope{}, fmt.Errorf("unknown audit %q", id)
	}
	if err != nil {
		return audit.Envelope{}, err
	}
	var envelope audit.Envelope
	return envelope, json.Unmarshal([]byte(payload), &envelope)
}

func (s *PostgresStore) SaveWorkflowRun(ctx context.Context, run WorkflowRunRecord) error {
	input, _ := json.Marshal(run.Input)
	assignment, _ := json.Marshal(run.Assignment)
	events, _ := json.Marshal(run.Events)
	run.TenantID = firstTenant(firstNonEmpty(run.TenantID, TenantFromContext(ctx)))
	_, err := s.db.ExecContext(ctx, `INSERT INTO condition_workflow_runs
(id, tenant_id, definition, version, environment, workflow_id, stage, status, input_json, assignment_json, events_json, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT(id) DO UPDATE SET stage=EXCLUDED.stage, status=EXCLUDED.status, input_json=EXCLUDED.input_json,
assignment_json=EXCLUDED.assignment_json, events_json=EXCLUDED.events_json, updated_at=EXCLUDED.updated_at`,
		run.ID, run.TenantID, run.Definition, run.Version, run.Environment, run.WorkflowID, run.Stage, run.Status, string(input), string(assignment), string(events), run.CreatedAt, run.UpdatedAt)
	return err
}

func (s *PostgresStore) GetWorkflowRun(ctx context.Context, id string) (WorkflowRunRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, tenant_id, definition, version, environment, workflow_id, stage, status, input_json, assignment_json, events_json, created_at, updated_at FROM condition_workflow_runs WHERE tenant_id = $1 AND id = $2`, TenantFromContext(ctx), id)
	run, err := scanWorkflowRun(row)
	if err == sql.ErrNoRows {
		return WorkflowRunRecord{}, fmt.Errorf("unknown workflow run %q", id)
	}
	return run, err
}

func (s *PostgresStore) ListWorkflowRuns(ctx context.Context, opts ListOptions) ([]WorkflowRunRecord, error) {
	query := `SELECT id, tenant_id, definition, version, environment, workflow_id, stage, status, input_json, assignment_json, events_json, created_at, updated_at FROM condition_workflow_runs`
	var where []string
	var args []any
	where = append(where, fmt.Sprintf(`tenant_id = $%d`, len(args)+1))
	args = append(args, firstTenant(firstNonEmpty(opts.TenantID, TenantFromContext(ctx))))
	if opts.Definition != "" {
		where = append(where, fmt.Sprintf(`definition = $%d`, len(args)+1))
		args = append(args, opts.Definition)
	}
	if opts.Environment != "" {
		where = append(where, fmt.Sprintf(`environment = $%d`, len(args)+1))
		args = append(args, opts.Environment)
	}
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, ` AND `)
	}
	query += ` ORDER BY created_at`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WorkflowRunRecord
	for rows.Next() {
		run, err := scanWorkflowRun(rows)
		if err != nil {
			return nil, err
		}
		if inRange(run.UpdatedAt, opts) {
			out = append(out, run)
		}
	}
	return ApplyListOptions(out, opts, nil), rows.Err()
}

func (s *PostgresStore) AppendChainEvent(ctx context.Context, event ChainEventRecord) error {
	event.TenantID = firstTenant(firstNonEmpty(event.TenantID, TenantFromContext(ctx)))
	if event.CreatedAt.IsZero() {
		event.CreatedAt = nowUTC()
	}
	attributes, _ := json.Marshal(event.Attributes)
	metadata, _ := json.Marshal(event.Metadata)
	_, err := s.db.ExecContext(ctx, `INSERT INTO condition_chain_events
(id, tenant_id, definition, version, environment, chain, watch, entity_key, event_type, source_decision, reason_code, severity, attributes_json, metadata_json, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		event.ID, event.TenantID, event.Definition, event.Version, event.Environment, event.Chain, event.Watch, event.EntityKey, event.EventType, event.SourceDecision, event.ReasonCode, event.Severity, string(attributes), string(metadata), event.CreatedAt, event.ExpiresAt)
	return err
}

func (s *PostgresStore) QueryChainEvents(ctx context.Context, query ChainEventQuery) ([]ChainEventRecord, error) {
	sqlQuery := `SELECT id, tenant_id, definition, version, environment, chain, watch, entity_key, event_type, source_decision, reason_code, severity, attributes_json, metadata_json, created_at, expires_at FROM condition_chain_events`
	var where []string
	var args []any
	where = append(where, fmt.Sprintf(`tenant_id = $%d`, len(args)+1))
	args = append(args, firstTenant(firstNonEmpty(query.TenantID, TenantFromContext(ctx))))
	if query.Definition != "" {
		where = append(where, fmt.Sprintf(`definition = $%d`, len(args)+1))
		args = append(args, query.Definition)
	}
	if query.Environment != "" {
		where = append(where, fmt.Sprintf(`environment = $%d`, len(args)+1))
		args = append(args, query.Environment)
	}
	if query.Chain != "" {
		where = append(where, fmt.Sprintf(`chain = $%d`, len(args)+1))
		args = append(args, query.Chain)
	}
	if query.Watch != "" {
		where = append(where, fmt.Sprintf(`watch = $%d`, len(args)+1))
		args = append(args, query.Watch)
	}
	if query.EntityKey != "" {
		where = append(where, fmt.Sprintf(`entity_key = $%d`, len(args)+1))
		args = append(args, query.EntityKey)
	}
	if query.EventType != "" {
		where = append(where, fmt.Sprintf(`event_type = $%d`, len(args)+1))
		args = append(args, query.EventType)
	}
	if len(where) > 0 {
		sqlQuery += ` WHERE ` + strings.Join(where, ` AND `)
	}
	sqlQuery += ` ORDER BY created_at`
	rows, err := s.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := nowUTC()
	var out []ChainEventRecord
	for rows.Next() {
		event, err := scanChainEvent(rows)
		if err != nil {
			return nil, err
		}
		if (query.Since != nil && event.CreatedAt.Before(*query.Since)) ||
			(query.Until != nil && event.CreatedAt.After(*query.Until)) ||
			(!query.IncludeExpired && event.ExpiresAt != nil && !event.ExpiresAt.After(now)) {
			continue
		}
		out = append(out, event)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	if query.Limit > 0 && len(out) > query.Limit {
		out = out[len(out)-query.Limit:]
	}
	return out, nil
}

func (s *PostgresStore) GetChainState(ctx context.Context, chain, watch, entityKey string) (ChainStateRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT tenant_id, definition, version, environment, chain, watch, entity_key, counters_json, step, action, severity, attributes_json, metadata_json, updated_at, expires_at
FROM condition_chain_states WHERE tenant_id = $1 AND chain = $2 AND watch = $3 AND entity_key = $4`, TenantFromContext(ctx), chain, watch, entityKey)
	state, err := scanChainState(row)
	if err == sql.ErrNoRows {
		return ChainStateRecord{}, fmt.Errorf("unknown watch state %q/%q/%q", chain, watch, entityKey)
	}
	if err != nil {
		return ChainStateRecord{}, err
	}
	if state.ExpiresAt != nil && !state.ExpiresAt.After(nowUTC()) {
		return ChainStateRecord{}, fmt.Errorf("unknown watch state %q/%q/%q", chain, watch, entityKey)
	}
	return state, nil
}

func (s *PostgresStore) ListChainStates(ctx context.Context, query ChainStateQuery) ([]ChainStateRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tenant_id, definition, version, environment, chain, watch, entity_key, counters_json, step, action, severity, attributes_json, metadata_json, updated_at, expires_at
FROM condition_chain_states WHERE tenant_id = $1 ORDER BY updated_at ASC`, firstTenant(firstNonEmpty(query.TenantID, TenantFromContext(ctx))))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := nowUTC()
	var out []ChainStateRecord
	for rows.Next() {
		state, err := scanChainState(rows)
		if err != nil {
			return nil, err
		}
		if (query.Definition != "" && state.Definition != query.Definition) ||
			(query.Environment != "" && state.Environment != query.Environment) ||
			(query.Chain != "" && state.Chain != query.Chain) ||
			(query.Watch != "" && state.Watch != query.Watch) ||
			(query.EntityKey != "" && state.EntityKey != query.EntityKey) ||
			(!query.IncludeExpired && state.ExpiresAt != nil && !state.ExpiresAt.After(now)) {
			continue
		}
		out = append(out, state)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	if query.Limit > 0 && len(out) > query.Limit {
		out = out[len(out)-query.Limit:]
	}
	return out, nil
}

func (s *PostgresStore) UpsertChainState(ctx context.Context, state ChainStateRecord) error {
	state.TenantID = firstTenant(firstNonEmpty(state.TenantID, TenantFromContext(ctx)))
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = nowUTC()
	}
	counters, _ := json.Marshal(state.Counters)
	attributes, _ := json.Marshal(state.Attributes)
	metadata, _ := json.Marshal(state.Metadata)
	_, err := s.db.ExecContext(ctx, `INSERT INTO condition_chain_states
(tenant_id, definition, version, environment, chain, watch, entity_key, counters_json, step, action, severity, attributes_json, metadata_json, updated_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT(tenant_id, chain, watch, entity_key) DO UPDATE SET definition=EXCLUDED.definition, version=EXCLUDED.version,
environment=EXCLUDED.environment, counters_json=EXCLUDED.counters_json, step=EXCLUDED.step, action=EXCLUDED.action,
severity=EXCLUDED.severity, attributes_json=EXCLUDED.attributes_json, metadata_json=EXCLUDED.metadata_json, updated_at=EXCLUDED.updated_at, expires_at=EXCLUDED.expires_at`,
		state.TenantID, state.Definition, state.Version, state.Environment, state.Chain, state.Watch, state.EntityKey, string(counters), state.Step, state.Action, state.Severity, string(attributes), string(metadata), state.UpdatedAt, state.ExpiresAt)
	return err
}

func (s *PostgresStore) DeleteExpiredChainStates(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM condition_chain_states WHERE tenant_id = $1 AND expires_at IS NOT NULL AND expires_at <= $2`, TenantFromContext(ctx), now)
	return err
}

func (s *PostgresStore) SaveActionDelivery(ctx context.Context, record ActionDeliveryRecord) error {
	record.TenantID = firstTenant(firstNonEmpty(record.TenantID, TenantFromContext(ctx)))
	if record.CreatedAt.IsZero() {
		record.CreatedAt = nowUTC()
	}
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = record.CreatedAt
	}
	attributes, _ := json.Marshal(record.Attributes)
	metadata, _ := json.Marshal(record.Metadata)
	_, err := s.db.ExecContext(ctx, `INSERT INTO condition_action_deliveries
(id, tenant_id, definition, version, environment, lifecycle, entity_key, action, sink, status, handled, attempts, max_attempts, next_attempt, error, reason_code, severity, attributes_json, metadata_json, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status, handled=EXCLUDED.handled, attempts=EXCLUDED.attempts, max_attempts=EXCLUDED.max_attempts, next_attempt=EXCLUDED.next_attempt, error=EXCLUDED.error, updated_at=EXCLUDED.updated_at`,
		record.ID, record.TenantID, record.Definition, record.Version, record.Environment, record.Lifecycle, record.EntityKey, record.Action, record.Sink, record.Status, record.Handled, record.Attempts, record.MaxAttempts, record.NextAttempt, record.Error, record.ReasonCode, record.Severity, string(attributes), string(metadata), record.CreatedAt, record.UpdatedAt)
	return err
}

func (s *PostgresStore) ListActionDeliveries(ctx context.Context, query ActionDeliveryQuery) ([]ActionDeliveryRecord, error) {
	sqlQuery := `SELECT id, tenant_id, definition, version, environment, lifecycle, entity_key, action, sink, status, handled, attempts, max_attempts, next_attempt, error, reason_code, severity, attributes_json, metadata_json, created_at, updated_at FROM condition_action_deliveries`
	var where []string
	var args []any
	where = append(where, fmt.Sprintf("tenant_id = $%d", len(args)+1))
	args = append(args, firstTenant(firstNonEmpty(query.TenantID, TenantFromContext(ctx))))
	if query.Definition != "" {
		where = append(where, fmt.Sprintf("definition = $%d", len(args)+1))
		args = append(args, query.Definition)
	}
	if query.Environment != "" {
		where = append(where, fmt.Sprintf("environment = $%d", len(args)+1))
		args = append(args, query.Environment)
	}
	if query.Action != "" {
		where = append(where, fmt.Sprintf("action = $%d", len(args)+1))
		args = append(args, query.Action)
	}
	if query.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", len(args)+1))
		args = append(args, query.Status)
	}
	sqlQuery += " WHERE " + strings.Join(where, " AND ") + " ORDER BY created_at"
	rows, err := s.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActionDeliveryRecord
	for rows.Next() {
		record, err := scanActionDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	if query.Limit > 0 && len(out) > query.Limit {
		out = out[len(out)-query.Limit:]
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpsertIncident(ctx context.Context, record IncidentRecord) error {
	record.TenantID = firstTenant(firstNonEmpty(record.TenantID, TenantFromContext(ctx)))
	if record.Status == "" {
		record.Status = "open"
	}
	if record.FirstSeen.IsZero() {
		record.FirstSeen = nowUTC()
	}
	if record.LastSeen.IsZero() {
		record.LastSeen = record.FirstSeen
	}
	if record.Count == 0 {
		record.Count = 1
	}
	metadata, _ := json.Marshal(record.Metadata)
	_, err := s.db.ExecContext(ctx, `INSERT INTO condition_incidents
(id, tenant_id, definition, environment, group_key, status, action, severity, reason_code, count, first_seen, last_seen, metadata_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status, count=EXCLUDED.count, last_seen=EXCLUDED.last_seen, metadata_json=EXCLUDED.metadata_json`,
		record.ID, record.TenantID, record.Definition, record.Environment, record.GroupKey, record.Status, record.Action, record.Severity, record.ReasonCode, record.Count, record.FirstSeen, record.LastSeen, string(metadata))
	return err
}

func (s *PostgresStore) ListIncidents(ctx context.Context, query IncidentQuery) ([]IncidentRecord, error) {
	sqlQuery := `SELECT id, tenant_id, definition, environment, group_key, status, action, severity, reason_code, count, first_seen, last_seen, metadata_json FROM condition_incidents`
	var where []string
	var args []any
	where = append(where, fmt.Sprintf("tenant_id = $%d", len(args)+1))
	args = append(args, firstTenant(firstNonEmpty(query.TenantID, TenantFromContext(ctx))))
	if query.Definition != "" {
		where = append(where, fmt.Sprintf("definition = $%d", len(args)+1))
		args = append(args, query.Definition)
	}
	if query.Environment != "" {
		where = append(where, fmt.Sprintf("environment = $%d", len(args)+1))
		args = append(args, query.Environment)
	}
	if query.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", len(args)+1))
		args = append(args, query.Status)
	}
	if query.Action != "" {
		where = append(where, fmt.Sprintf("action = $%d", len(args)+1))
		args = append(args, query.Action)
	}
	sqlQuery += " WHERE " + strings.Join(where, " AND ") + " ORDER BY last_seen"
	rows, err := s.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IncidentRecord
	for rows.Next() {
		record, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	if query.Limit > 0 && len(out) > query.Limit {
		out = out[len(out)-query.Limit:]
	}
	return out, rows.Err()
}

func (s *PostgresStore) Compact(ctx context.Context, req RetentionRequest) (RetentionResult, error) {
	result := RetentionResult{}
	tenant := firstTenant(firstNonEmpty(req.TenantID, TenantFromContext(ctx)))
	before := req.Before.UTC()
	if stateCount, err := pgDelete(s.db, ctx, "condition_chain_states",
		`tenant_id = $1 AND expires_at IS NOT NULL AND expires_at <= $2`, tenant, before); err != nil {
		return result, err
	} else {
		result.ChainStates = stateCount
	}
	if eventCount, err := pgDelete(s.db, ctx, "condition_chain_events", `tenant_id = $1 AND created_at <= $2`, tenant, before); err != nil {
		return result, err
	} else {
		result.ChainEvents = eventCount
	}
	actionWhere := fmt.Sprintf(`tenant_id = $1 AND created_at <= $2`)
	if !req.DeleteActiveDeliveries {
		actionWhere += ` AND status NOT IN ('retry_scheduled', 'pending')`
	}
	if actionCount, err := pgDelete(s.db, ctx, "condition_action_deliveries", actionWhere, tenant, before); err != nil {
		return result, err
	} else {
		result.ActionDeliveries = actionCount
	}
	incidentWhere := fmt.Sprintf(`tenant_id = $1 AND last_seen <= $2`)
	if !req.DeleteOpenIncidents {
		incidentWhere += ` AND status != 'open'`
	}
	if incidentCount, err := pgDelete(s.db, ctx, "condition_incidents", incidentWhere, tenant, before); err != nil {
		return result, err
	} else {
		result.Incidents = incidentCount
	}
	return result, nil
}

func pgDelete(db interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, ctx context.Context, table, where string, args ...any) (int, error) {
	res, err := db.ExecContext(ctx, "DELETE FROM "+table+" WHERE "+where, args...)
	if err != nil {
		return 0, err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (s *PostgresStore) Stats(ctx context.Context) (StatsRecord, error) {
	tenant := TenantFromContext(ctx)
	stats := StatsRecord{}
	counts := []struct {
		table string
		dst   *int
	}{
		{"condition_definition_versions", &stats.Definitions},
		{"condition_chain_events", &stats.ChainEvents},
		{"condition_chain_states", &stats.ChainStates},
		{"condition_action_deliveries", &stats.ActionDeliveries},
		{"condition_incidents", &stats.Incidents},
	}
	for _, item := range counts {
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+item.table+" WHERE tenant_id = $1", tenant).Scan(item.dst); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

var _ Store = (*PostgresStore)(nil)
