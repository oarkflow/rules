package rules

import (
	"context"
	"time"

	"github.com/oarkflow/bcl"
	"github.com/oarkflow/rules/pkg/audit"
	"github.com/oarkflow/rules/pkg/routing"
	"github.com/oarkflow/rules/pkg/storage"
)

type Config struct {
	Environment               string                      `json:"environment,omitempty"`
	DefaultTenant             string                      `json:"default_tenant,omitempty"`
	RequestTimeout            time.Duration               `json:"request_timeout,omitempty"`
	MaxRequestBytes           int64                       `json:"max_request_bytes,omitempty"`
	StrictValidation          bool                        `json:"strict_validation,omitempty"`
	StrictEvaluation          bool                        `json:"strict_evaluation,omitempty"`
	RequireActivationApproval bool                        `json:"require_activation_approval,omitempty"`
	RequireTests              bool                        `json:"require_tests,omitempty"`
	Runtime                   RuntimePolicy               `json:"runtime,omitempty"`
	Routes                    []routing.Route             `json:"routes,omitempty"`
	ActionHandlers            map[string]ActionHandler    `json:"-"`
	Clock                     func() time.Time            `json:"-"`
	OnDecision                func(durationMs float64)    `json:"-"`
	OnChain                   func(durationMs float64)    `json:"-"`
	OnAction                  func(durationMs float64)    `json:"-"`
	ApprovalPolicies          []ApprovalPolicyRule        `json:"approval_policies,omitempty"`
	ApprovalSinks             []ApprovalSink              `json:"approval_sinks,omitempty"`
	RedactConfig              *PIIRedactionConfig         `json:"redact_config,omitempty"`
	SignaturePolicy           SignatureVerificationPolicy `json:"signature_policy,omitempty"`
	TrustedPublicKeys         map[string]string           `json:"trusted_public_keys,omitempty"`
}

type RuntimePolicy struct {
	AllowTime              bool              `json:"allow_time,omitempty"`
	FixedTime              string            `json:"fixed_time,omitempty"`
	AllowEnv               bool              `json:"allow_env,omitempty"`
	AllowedDatasetAdapters []string          `json:"allowed_dataset_adapters,omitempty"`
	AllowedHTTPHosts       []string          `json:"allowed_http_hosts,omitempty"`
	AllowedHTTPMethods     []string          `json:"allowed_http_methods,omitempty"`
	AllowedActionSinks     []string          `json:"allowed_action_sinks,omitempty"`
	AllowedWebhookHosts    []string          `json:"allowed_webhook_hosts,omitempty"`
	AllowedWebhookMethods  []string          `json:"allowed_webhook_methods,omitempty"`
	ActionAllowlists       []ActionAllowlist `json:"action_allowlists,omitempty"`
	WebhookTimeout         time.Duration     `json:"webhook_timeout,omitempty"`
	ExternalTimeout        time.Duration     `json:"external_timeout,omitempty"`
	MaxStateRecords        int               `json:"max_state_records,omitempty"`
	TenantQuotas           []TenantQuota     `json:"tenant_quotas,omitempty"`
	Metadata               map[string]any    `json:"metadata,omitempty"`
}

type TenantQuota struct {
	TenantID            string `json:"tenant_id,omitempty"`
	Environment         string `json:"environment,omitempty"`
	MaxEvents           int    `json:"max_events,omitempty"`
	MaxStates           int    `json:"max_states,omitempty"`
	MaxActionDeliveries int    `json:"max_action_deliveries,omitempty"`
	MaxIncidents        int    `json:"max_incidents,omitempty"`
}

type ActionAllowlist struct {
	TenantID    string   `json:"tenant_id,omitempty"`
	Environment string   `json:"environment,omitempty"`
	Actions     []string `json:"actions,omitempty"`
	Sinks       []string `json:"sinks,omitempty"`
}

type PublishRequest struct {
	TenantID     string         `json:"tenant_id,omitempty"`
	Name         string         `json:"name,omitempty"`
	Version      string         `json:"version,omitempty"`
	Environment  string         `json:"environment,omitempty"`
	Path         string         `json:"path,omitempty"`
	Source       string         `json:"source,omitempty"`
	BaseDir      string         `json:"base_dir,omitempty"`
	RunTests     bool           `json:"run_tests,omitempty"`
	Strict       bool           `json:"strict,omitempty"`
	RequireTests bool           `json:"require_tests,omitempty"`
	Bundle       string         `json:"bundle,omitempty"`
	SignedBundle *SignedBundle  `json:"signed_bundle,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

type PublishResponse struct {
	Definition storage.DefinitionRecord `json:"definition"`
	Tests      *TestReport              `json:"tests,omitempty"`
	Gates      *bcl.DecisionGateReport  `json:"gates,omitempty"`
	Audit      audit.Envelope           `json:"audit"`
}

type EvaluateRequest struct {
	TenantID               string         `json:"tenant_id,omitempty"`
	Decision               string         `json:"decision"`
	Input                  map[string]any `json:"input,omitempty"`
	Bundle                 string         `json:"bundle,omitempty"`
	IncludeGates           bool           `json:"include_gates,omitempty"`
	Counterfactuals        bool           `json:"counterfactuals,omitempty"`
	IncludeFeatures        bool           `json:"include_features,omitempty"`
	IncludeExplain         bool           `json:"include_explain,omitempty"`
	Strict                 bool           `json:"strict,omitempty"`
	Environment            string         `json:"environment,omitempty"`
	ShadowCandidateSource  string         `json:"shadow_candidate_source,omitempty"`
	ShadowCandidatePath    string         `json:"shadow_candidate_path,omitempty"`
	ShadowCandidateBaseDir string         `json:"shadow_candidate_base_dir,omitempty"`
}

type EvaluateResponse struct {
	Report   *bcl.DecisionPlatformReport `json:"report"`
	Shadow   *bcl.DecisionCompareReport  `json:"shadow,omitempty"`
	Workflow *WorkflowResult             `json:"workflow,omitempty"`
	Audit    audit.Envelope              `json:"audit"`
}

type ChainEvaluateRequest struct {
	TenantID       string         `json:"tenant_id,omitempty"`
	Input          map[string]any `json:"input,omitempty"`
	Event          string         `json:"event,omitempty"`
	EventID        string         `json:"event_id,omitempty"`
	EntityKey      string         `json:"entity_key,omitempty"`
	Strict         bool           `json:"strict,omitempty"`
	IncludeExplain bool           `json:"include_explain,omitempty"`
}

type ChainEvaluateResponse struct {
	Evaluation ChainEvaluation `json:"evaluation"`
	Audit      audit.Envelope  `json:"audit"`
}

type ChainEvaluation struct {
	Chain         string                     `json:"chain"`
	EntityKey     string                     `json:"entity_key"`
	Decisions     []ChainDecisionResult      `json:"decisions,omitempty"`
	StateBefore   []storage.ChainStateRecord `json:"state_before,omitempty"`
	StateAfter    []storage.ChainStateRecord `json:"state_after,omitempty"`
	Events        []storage.ChainEventRecord `json:"events,omitempty"`
	FinalAction   string                     `json:"final_action,omitempty"`
	FinalEffect   string                     `json:"final_effect,omitempty"`
	FinalReason   string                     `json:"final_reason,omitempty"`
	FinalSeverity string                     `json:"final_severity,omitempty"`
	FinalDecision *bcl.DecisionResult        `json:"final_decision,omitempty"`
	Diagnostics   []bcl.Diagnostic           `json:"diagnostics,omitempty"`
}

type ChainDecisionResult struct {
	Decision string                      `json:"decision"`
	Report   *bcl.DecisionPlatformReport `json:"report,omitempty"`
}

type LifecycleEvaluateRequest struct {
	TenantID       string         `json:"tenant_id,omitempty"`
	EvaluationID   string         `json:"evaluation_id,omitempty"`
	Phase          string         `json:"phase"`
	Method         string         `json:"method,omitempty"`
	Path           string         `json:"path,omitempty"`
	Request        map[string]any `json:"request,omitempty"`
	Input          map[string]any `json:"input,omitempty"`
	Response       map[string]any `json:"response,omitempty"`
	Event          string         `json:"event,omitempty"`
	EntityKey      string         `json:"entity_key,omitempty"`
	Strict         bool           `json:"strict,omitempty"`
	IncludeExplain bool           `json:"include_explain,omitempty"`
	DryRun         bool           `json:"dry_run,omitempty"`
}

type ActionRetryRequest struct {
	TenantID string    `json:"tenant_id,omitempty"`
	Limit    int       `json:"limit,omitempty"`
	Now      time.Time `json:"now,omitempty"`
}

type ActionRetryResult struct {
	Scanned     int      `json:"scanned"`
	Delivered   int      `json:"delivered"`
	Rescheduled int      `json:"rescheduled"`
	DeadLetter  int      `json:"dead_letter"`
	DeliveryIDs []string `json:"delivery_ids,omitempty"`
}

type IncidentUpdateRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Actor    string `json:"actor,omitempty"`
}

type MutationResult struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Killed bool   `json:"killed"`
}

type MutationReport struct {
	Definition string           `json:"definition"`
	Total      int              `json:"total"`
	Killed     int              `json:"killed"`
	Score      float64          `json:"score"`
	Survived   []MutationResult `json:"survived,omitempty"`
	Results    []MutationResult `json:"results,omitempty"`
}

type LifecycleEvaluateResponse struct {
	Evaluation LifecycleEvaluation `json:"evaluation"`
	Audit      audit.Envelope      `json:"audit"`
}

type LifecycleEvaluation struct {
	Lifecycle   string                `json:"lifecycle"`
	Phase       string                `json:"phase"`
	TraceID     string                `json:"trace_id,omitempty"`
	AuditID     string                `json:"audit_id,omitempty"`
	EntityKey   string                `json:"entity_key,omitempty"`
	Route       routing.Match         `json:"route,omitempty"`
	Decisions   []ChainDecisionResult `json:"decisions,omitempty"`
	Chains      []ChainEvaluation     `json:"chains,omitempty"`
	Actions     []LifecycleAction     `json:"actions,omitempty"`
	Enforcement *EnforcementEnvelope  `json:"enforcement,omitempty"`
	FinalAction string                `json:"final_action,omitempty"`
	FinalEffect string                `json:"final_effect,omitempty"`
	FinalReason string                `json:"final_reason,omitempty"`
	Diagnostics []bcl.Diagnostic      `json:"diagnostics,omitempty"`
}

type EnforcementEnvelope struct {
	Action            string            `json:"action,omitempty"`
	Effect            string            `json:"effect,omitempty"`
	Reason            string            `json:"reason,omitempty"`
	ReasonCode        string            `json:"reason_code,omitempty"`
	Severity          string            `json:"severity,omitempty"`
	Status            int               `json:"status,omitempty"`
	Blocking          bool              `json:"blocking,omitempty"`
	RetryAfterSeconds int               `json:"retry_after_seconds,omitempty"`
	ExpiresAt         *time.Time        `json:"expires_at,omitempty"`
	Chain             string            `json:"chain,omitempty"`
	Watch             string            `json:"watch,omitempty"`
	Step              string            `json:"step,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	Body              map[string]any    `json:"body,omitempty"`
	Attributes        map[string]any    `json:"attributes,omitempty"`
	Metadata          map[string]any    `json:"metadata,omitempty"`
}

type LifecycleAction struct {
	Name       string         `json:"name"`
	Sink       string         `json:"sink,omitempty"`
	Handled    bool           `json:"handled,omitempty"`
	DeliveryID string         `json:"delivery_id,omitempty"`
	IncidentID string         `json:"incident_id,omitempty"`
	Result     *ActionResult  `json:"result,omitempty"`
	ReasonCode string         `json:"reason_code,omitempty"`
	Severity   string         `json:"severity,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type ActionHandler func(context.Context, LifecycleAction) (ActionResult, error)

type ActionResult struct {
	Handled  bool           `json:"handled"`
	Status   string         `json:"status,omitempty"`
	Error    string         `json:"error,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type LifecycleDefinition struct {
	ID            string                     `json:"id"`
	EntityKeyPath string                     `json:"entity_key_path,omitempty"`
	Routes        string                     `json:"routes,omitempty"`
	Phases        []LifecyclePhaseDefinition `json:"phases,omitempty"`
}

type LifecyclePhaseDefinition struct {
	ID        string   `json:"id"`
	Decisions []string `json:"decisions,omitempty"`
	Chains    []string `json:"chains,omitempty"`
}

type ChainDefinition struct {
	ID            string                 `json:"id"`
	EntityKeyPath string                 `json:"entity_key_path,omitempty"`
	Decisions     []string               `json:"decisions,omitempty"`
	Watches       []ChainWatchDefinition `json:"watches,omitempty"`
}

type ChainWatchDefinition struct {
	ID              string         `json:"id"`
	Event           string         `json:"event"`
	Events          []string       `json:"events,omitempty"`
	Window          string         `json:"window,omitempty"`
	GroupBy         string         `json:"group_by,omitempty"`
	BaselineWindow  string         `json:"baseline_window,omitempty"`
	Compare         string         `json:"compare,omitempty"`
	Ratio           map[string]any `json:"ratio,omitempty"`
	Consecutive     bool           `json:"consecutive,omitempty"`
	SuccessStatuses []string       `json:"success_statuses,omitempty"`
	FailureStatuses []string       `json:"failure_statuses,omitempty"`
	Distinct        string         `json:"distinct,omitempty"`
	Field           string         `json:"field,omitempty"`
	Metrics         []string       `json:"metrics,omitempty"`
	Suppress        bool           `json:"suppress,omitempty"`
	Decay           string         `json:"decay,omitempty"`
	Cooldown        string         `json:"cooldown,omitempty"`
	Reset           string         `json:"reset,omitempty"`
	Steps           []ChainStep    `json:"steps,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

type ChainStep struct {
	ID         string         `json:"id"`
	ResultID   string         `json:"result_id,omitempty"`
	Threshold  int            `json:"threshold"`
	Metric     string         `json:"metric,omitempty"`
	Operator   string         `json:"op,omitempty"`
	Value      float64        `json:"value,omitempty"`
	Compare    string         `json:"compare,omitempty"`
	Action     string         `json:"action"`
	Severity   string         `json:"severity,omitempty"`
	TTL        string         `json:"ttl,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type PolicyPackageManifest struct {
	ID           string         `json:"id"`
	Owner        string         `json:"owner,omitempty"`
	Domain       string         `json:"domain,omitempty"`
	Version      string         `json:"version,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	Routes       []string       `json:"routes,omitempty"`
	Actions      []string       `json:"actions,omitempty"`
	State        bool           `json:"state,omitempty"`
	External     bool           `json:"external,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

type ActionCatalogDefinition struct {
	ID      string             `json:"id"`
	Actions []ActionDefinition `json:"actions,omitempty"`
}

type ActionDefinition struct {
	ID       string         `json:"id"`
	Sinks    []string       `json:"sinks,omitempty"`
	Severity string         `json:"severity,omitempty"`
	Retries  int            `json:"retries,omitempty"`
	Approval string         `json:"approval,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type OutputContractDefinition struct {
	ID         string   `json:"id"`
	Actions    []string `json:"actions,omitempty"`
	Severities []string `json:"severities,omitempty"`
}

type StandardFactContract struct {
	ID       string            `json:"id"`
	Facts    map[string]string `json:"facts,omitempty"`
	Strict   bool              `json:"strict,omitempty"`
	Metadata map[string]any    `json:"metadata,omitempty"`
}

type PolicyOverlayDefinition struct {
	ID          string         `json:"id"`
	Layer       string         `json:"layer"`
	TenantID    string         `json:"tenant_id,omitempty"`
	Environment string         `json:"environment,omitempty"`
	RouteID     string         `json:"route_id,omitempty"`
	Endpoint    string         `json:"endpoint,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type ResponseClassifierDefinition struct {
	ID                     string `json:"id"`
	HealthyStatuses        []int  `json:"healthy_statuses,omitempty"`
	UnhealthyStatuses      []int  `json:"unhealthy_statuses,omitempty"`
	ExpectedClientStatuses []int  `json:"expected_client_statuses,omitempty"`
	HealthyBelow           int    `json:"healthy_below,omitempty"`
	UnhealthyAtOrAbove     int    `json:"unhealthy_at_or_above,omitempty"`
}

type PackageExplainRequest struct {
	TenantID         string `json:"tenant_id,omitempty"`
	CandidateSource  string `json:"candidate_source,omitempty"`
	CandidatePath    string `json:"candidate_path,omitempty"`
	CandidateBaseDir string `json:"candidate_base_dir,omitempty"`
}

type PackageExplainResponse struct {
	Report PackageExplainReport `json:"report"`
	Audit  audit.Envelope       `json:"audit"`
}

type PackageExplainReport struct {
	Definition  string              `json:"definition"`
	BaseVersion string              `json:"base_version,omitempty"`
	Summary     []string            `json:"summary,omitempty"`
	Decisions   PackageDiff[string] `json:"decisions"`
	Chains      PackageDiff[string] `json:"chains"`
	Routes      PackageDiff[string] `json:"routes"`
	Lifecycles  PackageDiff[string] `json:"lifecycles"`
	Actions     PackageDiff[string] `json:"actions"`
	Diagnostics []bcl.Diagnostic    `json:"diagnostics,omitempty"`
}

type PackageDiff[T comparable] struct {
	Added   []T `json:"added,omitempty"`
	Removed []T `json:"removed,omitempty"`
	Common  []T `json:"common,omitempty"`
}

type RouteCoverageReport struct {
	Definition string              `json:"definition"`
	Passed     bool                `json:"passed"`
	Routes     []RouteCoverageItem `json:"routes,omitempty"`
	Uncovered  []string            `json:"uncovered,omitempty"`
	Audit      audit.Envelope      `json:"audit,omitempty"`
}

type RouteCoverageItem struct {
	Catalog    string   `json:"catalog"`
	RouteID    string   `json:"route_id"`
	Method     string   `json:"method,omitempty"`
	Pattern    string   `json:"pattern,omitempty"`
	Covered    bool     `json:"covered"`
	Lifecycles []string `json:"lifecycles,omitempty"`
	Phases     []string `json:"phases,omitempty"`
}

type TestReport struct {
	Passed             bool                         `json:"passed"`
	Scenarios          []bcl.DecisionScenarioResult `json:"scenarios,omitempty"`
	LifecycleScenarios []LifecycleScenarioResult    `json:"lifecycle_scenarios,omitempty"`
	Gates              *bcl.DecisionGateReport      `json:"gates,omitempty"`
	Diagnostics        []bcl.Diagnostic             `json:"diagnostics,omitempty"`
	Audit              *audit.Envelope              `json:"audit,omitempty"`
}

type LifecycleScenarioResult struct {
	Name        string           `json:"name"`
	Lifecycle   string           `json:"lifecycle"`
	Phase       string           `json:"phase"`
	Passed      bool             `json:"passed"`
	Expected    map[string]any   `json:"expected,omitempty"`
	Actual      map[string]any   `json:"actual,omitempty"`
	Diagnostics []bcl.Diagnostic `json:"diagnostics,omitempty"`
}

type ValidationRequest struct {
	TenantID     string `json:"tenant_id,omitempty"`
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	Environment  string `json:"environment,omitempty"`
	Path         string `json:"path,omitempty"`
	Source       string `json:"source,omitempty"`
	BaseDir      string `json:"base_dir,omitempty"`
	RunTests     bool   `json:"run_tests,omitempty"`
	Strict       bool   `json:"strict,omitempty"`
	RequireTests bool   `json:"require_tests,omitempty"`
	Bundle       string `json:"bundle,omitempty"`
}

type ValidationReport struct {
	Valid         bool                         `json:"valid"`
	Publishable   bool                         `json:"publishable"`
	Strict        bool                         `json:"strict,omitempty"`
	TestsRequired bool                         `json:"tests_required,omitempty"`
	Name          string                       `json:"name,omitempty"`
	Version       string                       `json:"version,omitempty"`
	Environment   string                       `json:"environment,omitempty"`
	Digest        string                       `json:"digest,omitempty"`
	Decisions     []string                     `json:"decisions,omitempty"`
	Tests         *TestReport                  `json:"tests,omitempty"`
	Gates         *bcl.DecisionGateReport      `json:"gates,omitempty"`
	Features      bcl.DecisionPlatformFeatures `json:"features,omitempty"`
	Diagnostics   []bcl.Diagnostic             `json:"diagnostics,omitempty"`
}

type ActivationResponse struct {
	Definition storage.DefinitionRecord `json:"definition"`
	Audit      audit.Envelope           `json:"audit"`
}

type ApprovalRequest struct {
	TenantID    string `json:"tenant_id,omitempty"`
	Environment string `json:"environment,omitempty"`
	ApprovedBy  string `json:"approved_by,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type LifecycleResponse struct {
	Definition storage.DefinitionRecord `json:"definition"`
	Audit      audit.Envelope           `json:"audit"`
}

type ProductionReadinessReport struct {
	Ready       bool            `json:"ready"`
	Environment string          `json:"environment,omitempty"`
	Checks      map[string]bool `json:"checks,omitempty"`
	Counts      map[string]int  `json:"counts,omitempty"`
	Missing     []string        `json:"missing,omitempty"`
}

type DisableRequest struct {
	TenantID    string `json:"tenant_id,omitempty"`
	Version     string `json:"version,omitempty"`
	Environment string `json:"environment,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type SimulationRequest struct {
	TenantID         string                  `json:"tenant_id,omitempty"`
	CandidateSource  string                  `json:"candidate_source,omitempty"`
	CandidatePath    string                  `json:"candidate_path,omitempty"`
	CandidateBaseDir string                  `json:"candidate_base_dir,omitempty"`
	Decision         string                  `json:"decision"`
	Dataset          string                  `json:"dataset,omitempty"`
	Cases            []bcl.DecisionBatchCase `json:"cases,omitempty"`
}

type SimulationResponse struct {
	Compare *bcl.DecisionCompareReport `json:"compare"`
	Audit   audit.Envelope             `json:"audit"`
}

type CanaryRequest struct {
	SimulationRequest
	MaxChangedCases int            `json:"max_changed_cases,omitempty"`
	RequireNoErrors bool           `json:"require_no_errors,omitempty"`
	Promote         bool           `json:"promote,omitempty"`
	PromoteVersion  string         `json:"promote_version,omitempty"`
	PromoteMetadata map[string]any `json:"promote_metadata,omitempty"`
}

type CanaryResponse struct {
	Passed       bool                       `json:"passed"`
	ChangedCases int                        `json:"changed_cases"`
	Compare      *bcl.DecisionCompareReport `json:"compare,omitempty"`
	Promotion    *PublishResponse           `json:"promotion,omitempty"`
	Audit        audit.Envelope             `json:"audit"`
}

type ReloadRequest struct {
	TenantID       string `json:"tenant_id,omitempty"`
	Name           string `json:"name"`
	Path           string `json:"path,omitempty"`
	RunTests       bool   `json:"run_tests,omitempty"`
	DebounceMillis int    `json:"debounce_millis,omitempty"`
	IncludeImports *bool  `json:"include_imports,omitempty"`
}

type ReloadResponse struct {
	Reloaded       bool             `json:"reloaded"`
	KeptLast       bool             `json:"kept_last_known_good"`
	ChangedPath    string           `json:"changed_path,omitempty"`
	DependencyPath string           `json:"dependency_path,omitempty"`
	Publish        *PublishResponse `json:"publish,omitempty"`
	Audit          audit.Envelope   `json:"audit"`
}

type WorkflowResult struct {
	Stage      string         `json:"stage,omitempty"`
	Assignment map[string]any `json:"assignment,omitempty"`
	Events     []string       `json:"events,omitempty"`
}

type WorkflowDefinition struct {
	ID     string          `json:"id"`
	Start  string          `json:"start,omitempty"`
	Stages []WorkflowStage `json:"stages,omitempty"`
}

type WorkflowStage struct {
	ID          string               `json:"id"`
	Assign      map[string]any       `json:"assign,omitempty"`
	SLA         string               `json:"sla,omitempty"`
	OnTimeout   string               `json:"on_timeout,omitempty"`
	Transitions []WorkflowTransition `json:"transitions,omitempty"`
}

type WorkflowTransition struct {
	ID        string         `json:"id,omitempty"`
	NextStage string         `json:"next_stage,omitempty"`
	When      map[string]any `json:"when,omitempty"`
	WhenExpr  string         `json:"when_expr,omitempty"`
	Events    []string       `json:"events,omitempty"`
	Priority  int            `json:"priority,omitempty"`
	Default   bool           `json:"default,omitempty"`
}

type WorkflowRun struct {
	ID          string          `json:"id"`
	TenantID    string          `json:"tenant_id,omitempty"`
	Definition  string          `json:"definition"`
	Version     string          `json:"version,omitempty"`
	Environment string          `json:"environment,omitempty"`
	WorkflowID  string          `json:"workflow_id"`
	Stage       string          `json:"stage,omitempty"`
	Status      string          `json:"status,omitempty"`
	Input       map[string]any  `json:"input,omitempty"`
	Assignment  map[string]any  `json:"assignment,omitempty"`
	Events      []string        `json:"events,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Audit       *audit.Envelope `json:"audit,omitempty"`
}

type WorkflowRequest struct {
	TenantID    string         `json:"tenant_id,omitempty"`
	Input       map[string]any `json:"input,omitempty"`
	Environment string         `json:"environment,omitempty"`
}

type WorkflowTickRequest struct {
	TenantID string    `json:"tenant_id,omitempty"`
	Now      time.Time `json:"now,omitempty"`
	Limit    int       `json:"limit,omitempty"`
}

type WorkflowTickResult struct {
	Scanned  int      `json:"scanned"`
	TimedOut int      `json:"timed_out"`
	RunIDs   []string `json:"run_ids,omitempty"`
}

type ApprovalPolicyRule struct {
	ID           string         `json:"id,omitempty"`
	MinSeverity  string         `json:"min_severity,omitempty"`
	Definitions  []string       `json:"definitions,omitempty"`
	Environments []string       `json:"environments,omitempty"`
	Sinks        []ApprovalSink `json:"sinks,omitempty"`
	RequireOwner bool           `json:"require_owner,omitempty"`
	MaxAge       string         `json:"max_age,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

type BlastRadiusReport struct {
	Definition       string          `json:"definition"`
	BaseVersion      string          `json:"base_version,omitempty"`
	CandidateVersion string          `json:"candidate_version,omitempty"`
	Decisions        RadiusDiff      `json:"decisions"`
	Chains           RadiusDiff      `json:"chains"`
	Routes           RadiusDiff      `json:"routes"`
	Lifecycles       RadiusDiff      `json:"lifecycles"`
	Actions          RadiusDiff      `json:"actions"`
	Steps            RadiusStepDiff  `json:"steps,omitempty"`
	DependencyGraph  DependencyGraph `json:"dependency_graph,omitempty"`
	ImpactSummary    []string        `json:"impact_summary,omitempty"`
}

type RadiusDiff struct {
	Total       int      `json:"total"`
	Added       []string `json:"added,omitempty"`
	Removed     []string `json:"removed,omitempty"`
	Unchanged   []string `json:"unchanged,omitempty"`
	AffectedPct float64  `json:"affected_pct,omitempty"`
}

type RadiusStepDiff struct {
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	Changed []string `json:"changed,omitempty"`
}

type DependencyGraph struct {
	Nodes []DepNode `json:"nodes,omitempty"`
	Edges []DepEdge `json:"edges,omitempty"`
}

type DepNode struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	New      bool   `json:"new,omitempty"`
	Removed  bool   `json:"removed,omitempty"`
	Affected bool   `json:"affected,omitempty"`
}

type DepEdge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Weight int    `json:"weight,omitempty"`
}

type GovernanceMetadata struct {
	Owner                string   `json:"owner,omitempty"`
	Domain               string   `json:"domain,omitempty"`
	Tags                 []string `json:"tags,omitempty"`
	ComplianceFrameworks []string `json:"compliance_frameworks,omitempty"`
	DataClassification   string   `json:"data_classification,omitempty"`
	ReviewRequired       bool     `json:"review_required,omitempty"`
	ReviewInterval       string   `json:"review_interval,omitempty"`
	LastReviewed         string   `json:"last_reviewed,omitempty"`
}

type OwnershipRecord struct {
	Definition string `json:"definition"`
	Owner      string `json:"owner"`
	Team       string `json:"team,omitempty"`
	Contact    string `json:"contact,omitempty"`
	Slack      string `json:"slack,omitempty"`
	ReviewedAt string `json:"reviewed_at,omitempty"`
}

type LatencyHistogram struct {
	Label   string   `json:"label"`
	Buckets []Bucket `json:"buckets,omitempty"`
	P50     float64  `json:"p50,omitempty"`
	P90     float64  `json:"p90,omitempty"`
	P99     float64  `json:"p99,omitempty"`
	Count   int64    `json:"count"`
	Total   float64  `json:"total_ms"`
}

type Bucket struct {
	Le    float64 `json:"le"`
	Count int64   `json:"count"`
}
