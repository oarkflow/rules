package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oarkflow/rules/pkg/storage"
)

type ApprovalSinkType string

const (
	ApprovalSinkWebhook ApprovalSinkType = "webhook"
	ApprovalSinkSlack   ApprovalSinkType = "slack"
	ApprovalSinkEmail   ApprovalSinkType = "email"
)

type ApprovalSink struct {
	Type   ApprovalSinkType `json:"type"`
	URL    string           `json:"url,omitempty"`
	Token  string           `json:"token,omitempty"`
	Config map[string]any   `json:"config,omitempty"`
}

type ApprovalRequestRecord struct {
	Definition  string     `json:"definition"`
	Version     string     `json:"version"`
	Environment string     `json:"environment,omitempty"`
	Severity    string     `json:"severity"`
	RequestedBy string     `json:"requested_by,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	Status      string     `json:"status"`
	ApprovedBy  string     `json:"approved_by,omitempty"`
	ApprovedAt  *time.Time `json:"approved_at,omitempty"`
	Resolution  string     `json:"resolution,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (s *Service) CheckApproval(ctx context.Context, definition, version, environment string) (bool, *ApprovalPolicyRule, error) {
	env := first(environment, s.cfg.Environment)
	if len(s.cfg.ApprovalPolicies) == 0 {
		return true, nil, nil
	}
	for _, policy := range s.cfg.ApprovalPolicies {
		if !policyApplies(policy, definition, env) {
			continue
		}
		record, err := s.store.GetDefinitionVersion(ctx, definition, version, env)
		if err != nil {
			return false, &policy, err
		}
		severity := first(stringAny(record.Metadata["severity"]), "low")
		if !severityMeetsThreshold(severity, policy.MinSeverity) {
			continue
		}
		approved := metadataBool(record.Metadata, "approved")
		if !approved {
			return false, &policy, nil
		}
		return true, &policy, nil
	}
	return true, nil, nil
}

func (s *Service) ResolveApproval(ctx context.Context, definition, version, environment string, approved bool, approvedBy, reason string) (*LifecycleResponse, error) {
	env := first(environment, s.cfg.Environment)
	record, err := s.store.GetDefinitionVersion(ctx, definition, version, env)
	if err != nil {
		return nil, err
	}
	record.Metadata = copyMetadata(record.Metadata)
	record.Metadata["approved"] = approved
	if approved {
		record.Metadata["approved_by"] = first(approvedBy, SubjectFromContext(ctx), "system")
		record.Metadata["approval_reason"] = reason
		record.Metadata["approved_at"] = s.now().Format(time.RFC3339Nano)
		record.Metadata["approval_status"] = "approved"
	} else {
		record.Metadata["rejected_by"] = first(approvedBy, SubjectFromContext(ctx), "system")
		record.Metadata["rejection_reason"] = reason
		record.Metadata["approval_status"] = "rejected"
	}
	if err := s.store.SaveDefinitionVersion(ctx, record); err != nil {
		return nil, err
	}
	operation := "approve"
	if !approved {
		operation = "reject"
	}
	envelope, err := s.audit(ctx, operation, definition, version, env, record.Digest,
		map[string]any{"approved": approved, "approved_by": approvedBy, "reason": reason},
		map[string]any{"approval_status": record.Metadata["approval_status"]}, s.now(), nil)
	if err != nil {
		return nil, err
	}
	return &LifecycleResponse{Definition: record, Audit: envelope}, nil
}

func (s *Service) NotifyApprovalSink(ctx context.Context, req ApprovalRequestRecord, sink ApprovalSink) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	switch sink.Type {
	case ApprovalSinkWebhook:
		return s.notifyApprovalWebhook(ctx, sink.URL, sink.Token, payload)
	case ApprovalSinkSlack:
		return s.notifySlack(ctx, sink, req)
	case ApprovalSinkEmail:
		return s.notifyEmail(ctx, sink, req)
	default:
		return fmt.Errorf("unsupported approval sink type %q", sink.Type)
	}
}

func policyApplies(policy ApprovalPolicyRule, definition, environment string) bool {
	if len(policy.Definitions) > 0 {
		found := false
		for _, d := range policy.Definitions {
			if d == definition || d == "*" {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(policy.Environments) > 0 {
		found := false
		for _, e := range policy.Environments {
			if e == environment || e == "*" {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func severityMeetsThreshold(severity, minSeverity string) bool {
	rank := map[string]int{
		"low":      0,
		"medium":   1,
		"high":     2,
		"critical": 3,
	}
	sRank := rank[strings.ToLower(strings.TrimSpace(severity))]
	mRank := rank[strings.ToLower(strings.TrimSpace(minSeverity))]
	return sRank >= mRank
}

func (s *Service) notifyApprovalWebhook(ctx context.Context, rawURL, token string, payload []byte) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("invalid approval webhook URL")
	}
	hosts := s.cfg.Runtime.AllowedWebhookHosts
	if len(hosts) == 0 {
		hosts = s.cfg.Runtime.AllowedHTTPHosts
	}
	if !stringAllowed(hosts, parsed.Hostname()) {
		return fmt.Errorf("approval webhook host %q is not allowlisted", parsed.Hostname())
	}
	methods := s.cfg.Runtime.AllowedWebhookMethods
	if len(methods) == 0 {
		methods = s.cfg.Runtime.AllowedHTTPMethods
	}
	if !stringAllowed(methods, http.MethodPost) {
		return fmt.Errorf("approval webhook method POST is not allowlisted")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	timeout := s.cfg.Runtime.WebhookTimeout
	if timeout <= 0 {
		timeout = s.cfg.Runtime.ExternalTimeout
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

func (s *Service) notifySlack(ctx context.Context, sink ApprovalSink, req ApprovalRequestRecord) error {
	channel := "approvals"
	if ch, ok := sink.Config["channel"].(string); ok {
		channel = ch
	}
	msg := fmt.Sprintf("Approval required: %s %s (severity: %s) requested by %s", req.Definition, req.Version, req.Severity, req.RequestedBy)
	payload, _ := json.Marshal(map[string]any{
		"channel": channel,
		"text":    msg,
		"attachments": []map[string]any{{
			"fallback": msg,
			"fields": []map[string]any{
				{"title": "Definition", "value": req.Definition, "short": true},
				{"title": "Version", "value": req.Version, "short": true},
				{"title": "Severity", "value": req.Severity, "short": true},
				{"title": "Requested By", "value": req.RequestedBy, "short": true},
			},
		}},
	})
	return s.notifyApprovalWebhook(ctx, sink.URL, sink.Token, payload)
}

func (s *Service) notifyEmail(ctx context.Context, sink ApprovalSink, req ApprovalRequestRecord) error {
	to := "approver@example.com"
	if t, ok := sink.Config["to"].(string); ok {
		to = t
	}
	subject := fmt.Sprintf("Approval Required: %s %s", req.Definition, req.Version)
	body := fmt.Sprintf("Definition: %s\nVersion: %s\nSeverity: %s\nRequested By: %s\nReason: %s",
		req.Definition, req.Version, req.Severity, req.RequestedBy, req.Reason)
	payload, _ := json.Marshal(map[string]any{
		"to":      to,
		"subject": subject,
		"body":    body,
	})
	return s.notifyApprovalWebhook(ctx, sink.URL, sink.Token, payload)
}

func (s *Service) requestApprovalIfNeeded(ctx context.Context, record storage.DefinitionRecord) error {
	if len(s.cfg.ApprovalPolicies) == 0 {
		return nil
	}
	env := record.Environment
	severity := first(stringAny(record.Metadata["severity"]), "low")
	for _, policy := range s.cfg.ApprovalPolicies {
		if !policyApplies(policy, record.Name, env) {
			continue
		}
		if !severityMeetsThreshold(severity, policy.MinSeverity) {
			continue
		}
		if metadataBool(record.Metadata, "approved") {
			continue
		}
		if s.cfg.RequireActivationApproval {
			record.Metadata = copyMetadata(record.Metadata)
			record.Metadata["activation_pending"] = true
		}
		req := ApprovalRequestRecord{
			Definition:  record.Name,
			Version:     record.Version,
			Environment: env,
			Severity:    severity,
			RequestedBy: SubjectFromContext(ctx),
			Reason:      stringAny(record.Metadata["approval_reason"]),
			Status:      "pending",
			CreatedAt:   s.now(),
		}
		for _, sink := range policy.Sinks {
			if err := s.NotifyApprovalSink(ctx, req, sink); err != nil {
				return fmt.Errorf("approval notification failed: %w", err)
			}
		}
		return fmt.Errorf("definition %q version %q requires approval (severity %s meets policy %q threshold %s)",
			record.Name, record.Version, severity, policy.ID, policy.MinSeverity)
	}
	return nil
}
