package rules

import (
	"encoding/json"
	"regexp"
	"strings"
)

var piiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
	regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`),
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	regexp.MustCompile(`\b(?:\d{3}[.-]?\d{2}[.-]?\d{4})\b`),
	regexp.MustCompile(`\b(?:\+\d{1,3}[-\s]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}\b`),
	regexp.MustCompile(`\b[A-Z]{2}\d{6}[A-Z0-9]{1,10}\b`),
}

type PIIRedactionConfig struct {
	Enabled      bool     `json:"enabled,omitempty"`
	Mask         string   `json:"mask,omitempty"`
	Fields       []string `json:"fields,omitempty"`
	MaxFieldDepth int     `json:"max_field_depth,omitempty"`
	ExcludePaths []string `json:"exclude_paths,omitempty"`
}

var defaultRedactConfig = PIIRedactionConfig{
	Enabled:       false,
	Mask:          "***",
	Fields:        []string{"email", "ssn", "password", "secret", "token", "credit_card", "phone", "passport", "pan", "aadhaar"},
	MaxFieldDepth: 5,
}

type RedactionRule struct {
	FieldPattern string `json:"field_pattern,omitempty"`
	MatchPattern string `json:"match_pattern,omitempty"`
	Mask         string `json:"mask,omitempty"`
}

type RedactionPolicy []RedactionRule

func RedactPayload(v any, cfg ...*PIIRedactionConfig) any {
	config := &defaultRedactConfig
	if len(cfg) > 0 && cfg[0] != nil {
		if !cfg[0].Enabled {
			return v
		}
		config = cfg[0]
	}
	return redactValue(v, config, 0)
}

func redactValue(v any, cfg *PIIRedactionConfig, depth int) any {
	if depth > cfg.MaxFieldDepth {
		return v
	}
	switch val := v.(type) {
	case string:
		return redactString(val, cfg)
	case map[string]any:
		out := make(map[string]any, len(val))
		for key, value := range val {
			if isSensitiveField(key, cfg) {
				out[key] = cfg.Mask
			} else {
				out[key] = redactValue(value, cfg, depth+1)
			}
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = redactValue(item, cfg, depth+1)
		}
		return out
	default:
		return v
	}
}

func redactString(s string, cfg *PIIRedactionConfig) string {
	if !cfg.Enabled {
		return s
	}
	for _, pattern := range piiPatterns {
		s = pattern.ReplaceAllString(s, cfg.Mask)
	}
	return s
}

func isSensitiveField(key string, cfg *PIIRedactionConfig) bool {
	lower := strings.ToLower(key)
	for _, field := range cfg.Fields {
		if strings.EqualFold(lower, field) {
			return true
		}
		if strings.Contains(lower, field) {
			return true
		}
	}
	return false
}

func AddRedactionToAudit(envelope map[string]any, cfg *PIIRedactionConfig) map[string]any {
	if envelope == nil || !cfg.Enabled {
		return envelope
	}
	out := make(map[string]any, len(envelope))
	for key, value := range envelope {
		if key == "request_hash" || key == "result_hash" || key == "hash" || key == "previous_hash" {
			out[key] = value
			continue
		}
		out[key] = redactValue(value, cfg, 0)
	}
	return out
}

func RedactAuditPayloadJSON(data []byte, cfg *PIIRedactionConfig) ([]byte, error) {
	if !cfg.Enabled {
		return data, nil
	}
	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return data, nil
	}
	redacted := redactValue(parsed, cfg, 0)
	return json.Marshal(redacted)
}

func MergeRedactConfig(base *PIIRedactionConfig, overlay *PIIRedactionConfig) *PIIRedactionConfig {
	if overlay == nil {
		return base
	}
	if base == nil {
		return overlay
	}
	merged := *base
	if overlay.Enabled {
		merged.Enabled = true
	}
	if overlay.Mask != "" {
		merged.Mask = overlay.Mask
	}
	if len(overlay.Fields) > 0 {
		merged.Fields = append(merged.Fields, overlay.Fields...)
	}
	if overlay.MaxFieldDepth > 0 {
		merged.MaxFieldDepth = overlay.MaxFieldDepth
	}
	return &merged
}
