package condition

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oarkflow/rules/pkg/storage"
)

func BenchmarkServicePublishStrict(b *testing.B) {
	ctx := context.Background()
	baseDir := benchmarkModuleDir(b)
	for i := 0; i < b.N; i++ {
		svc := NewService(storage.NewMemoryStore(), Config{StrictValidation: true, RequireTests: true})
		if _, err := svc.PublishVersion(ctx, PublishRequest{Name: "demo", Version: "1", Source: strictDemoSource(), BaseDir: baseDir, RunTests: true}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServiceEvaluateStrict(b *testing.B) {
	ctx := context.Background()
	baseDir := benchmarkModuleDir(b)
	svc := NewService(storage.NewMemoryStore(), Config{StrictValidation: true, StrictEvaluation: true, RequireTests: true})
	if _, err := svc.PublishVersion(ctx, PublishRequest{Name: "demo", Version: "1", Source: strictDemoSource(), BaseDir: baseDir, RunTests: true}); err != nil {
		b.Fatal(err)
	}
	if _, err := svc.Approve(ctx, "demo", "1", ApprovalRequest{ApprovedBy: "bench"}); err != nil {
		b.Fatal(err)
	}
	if _, err := svc.Activate(ctx, "demo", "1", "development"); err != nil {
		b.Fatal(err)
	}
	input := map[string]any{"request": map[string]any{"ok": true}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.Evaluate(ctx, "demo", EvaluateRequest{Decision: "access", Input: input}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServiceEvaluateWithShadow(b *testing.B) {
	ctx := context.Background()
	svc := NewService(storage.NewMemoryStore(), Config{})
	if _, err := svc.Publish(ctx, PublishRequest{Name: "demo", Source: demoSource}); err != nil {
		b.Fatal(err)
	}
	candidate := `module "demo" {
  decision_table "access" {
    default deny
    hit_policy first
    row "deny-ok" { when { request.ok == true } then { decision deny reason "shadow" } reason "shadow" reason_code "SHADOW" }
  }
}`
	input := map[string]any{"request": map[string]any{"ok": true}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.Evaluate(ctx, "demo", EvaluateRequest{Decision: "access", Input: input, ShadowCandidateSource: candidate}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServiceEvaluateStrictConcurrent(b *testing.B) {
	ctx := context.Background()
	baseDir := benchmarkModuleDir(b)
	svc := NewService(storage.NewMemoryStore(), Config{StrictValidation: true, StrictEvaluation: true, RequireTests: true})
	if _, err := svc.Publish(ctx, PublishRequest{Name: "demo", Version: "1", Source: strictDemoSource(), BaseDir: baseDir, RunTests: true}); err != nil {
		b.Fatal(err)
	}
	input := map[string]any{"request": map[string]any{"ok": true}}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := svc.Evaluate(ctx, "demo", EvaluateRequest{Decision: "access", Input: input}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkServiceExternalDatasetDenied(b *testing.B) {
	ctx := context.Background()
	svc := NewService(storage.NewMemoryStore(), Config{})
	source := `module "external" {
  decision_table "access" { default deny hit_policy first }
  dataset "batch" { source { adapter file path "./batch.jsonl" format jsonl } }
}`
	if _, err := svc.Publish(ctx, PublishRequest{Name: "external", Source: source}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.Evaluate(ctx, "external", EvaluateRequest{Decision: "access"})
	}
}

func BenchmarkServiceTenantPartitionedEvaluate(b *testing.B) {
	svc := NewService(storage.NewMemoryStore(), Config{})
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if _, err := svc.Publish(ContextWithTenant(context.Background(), tenant), PublishRequest{Name: "demo", Source: demoSource}); err != nil {
			b.Fatal(err)
		}
	}
	ctx := ContextWithTenant(context.Background(), "tenant-b")
	input := map[string]any{"request": map[string]any{"ok": true}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.Evaluate(ctx, "demo", EvaluateRequest{Decision: "access", Input: input}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServiceLargeDecisionTable(b *testing.B) {
	ctx := context.Background()
	svc := NewService(storage.NewMemoryStore(), Config{})
	var rows strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&rows, `row "r-%d" { when { request.code == "%d" } then { decision allow reason "hit" } reason "hit" reason_code "HIT_%d" }`, i, i, i)
		rows.WriteByte('\n')
	}
	source := `module "large" { decision_table "access" { default deny hit_policy first ` + rows.String() + ` } }`
	if _, err := svc.Publish(ctx, PublishRequest{Name: "large", Source: source}); err != nil {
		b.Fatal(err)
	}
	input := map[string]any{"request": map[string]any{"code": "499"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.Evaluate(ctx, "large", EvaluateRequest{Decision: "access", Input: input}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoutingMultiRouteMatch(b *testing.B) {
	ctx := context.Background()
	var routes strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&routes, `route "r-%d" { method "GET" pattern "/api/resource/%d" decisions ["access"] chains ["ch"] }`, i, i)
		routes.WriteByte('\n')
	}
	source := fmt.Sprintf(`module "routing" {
  decision_schema "access" { effects [allow, deny] default allow strategy first_match }
  decision_table "access" { default allow }
  chain "ch" { entity "request.id" watch "w" { event "e" window "1m" step "s" { threshold 1 action "log" severity "low" } } }
  routes "http" { %s }
}`, routes.String())
	if _, err := NewService(storage.NewMemoryStore(), Config{}).Publish(ctx, PublishRequest{Name: "routing", Source: source}); err != nil {
		b.Fatal(err)
	}
	svc := NewService(storage.NewMemoryStore(), Config{})
	if _, err := svc.Publish(ctx, PublishRequest{Name: "routing", Source: source}); err != nil {
		b.Fatal(err)
	}
	input := map[string]any{"request": map[string]any{"id": "x"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.Evaluate(ctx, "routing", EvaluateRequest{Decision: "access", Input: input}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoutingMultiRouteNoMatch(b *testing.B) {
	ctx := context.Background()
	var routes strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&routes, `route "r-%d" { method "GET" pattern "/api/resource/%d" decisions ["access"] }`, i, i)
		routes.WriteByte('\n')
	}
	source := fmt.Sprintf(`module "routing" {
  decision_schema "access" { effects [allow, deny] default allow strategy first_match }
  decision_table "access" { default allow }
  routes "http" { %s }
}`, routes.String())
	svc := NewService(storage.NewMemoryStore(), Config{})
	if _, err := svc.Publish(ctx, PublishRequest{Name: "routing", Source: source}); err != nil {
		b.Fatal(err)
	}
	input := map[string]any{"request": map[string]any{"id": "x"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.Evaluate(ctx, "routing", EvaluateRequest{Decision: "access", Input: input}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecisionTable100Rows(b *testing.B) {
	ctx := context.Background()
	var rows strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&rows, `row "r-%d" { when { request.key == "%d" } then { decision allow reason "hit" } reason "hit" reason_code "HIT_%d" }`, i, i, i)
		rows.WriteByte('\n')
	}
	source := `module "dt" { decision_table "access" { default deny hit_policy first ` + rows.String() + ` } }`
	svc := NewService(storage.NewMemoryStore(), Config{})
	if _, err := svc.Publish(ctx, PublishRequest{Name: "dt", Source: source}); err != nil {
		b.Fatal(err)
	}
	b.Run("first-row", func(b *testing.B) {
		input := map[string]any{"request": map[string]any{"key": "0"}}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := svc.Evaluate(ctx, "dt", EvaluateRequest{Decision: "access", Input: input}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("last-row", func(b *testing.B) {
		input := map[string]any{"request": map[string]any{"key": "99"}}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := svc.Evaluate(ctx, "dt", EvaluateRequest{Decision: "access", Input: input}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("default-deny", func(b *testing.B) {
		input := map[string]any{"request": map[string]any{"key": "999"}}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := svc.Evaluate(ctx, "dt", EvaluateRequest{Decision: "access", Input: input}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkDecisionTable1000Rows(b *testing.B) {
	ctx := context.Background()
	var rows strings.Builder
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&rows, `row "r-%d" { when { request.key == "%d" } then { decision allow reason "hit" } reason "hit" reason_code "HIT_%d" }`, i, i, i)
		rows.WriteByte('\n')
	}
	source := `module "dt1k" { decision_table "access" { default deny hit_policy first ` + rows.String() + ` } }`
	svc := NewService(storage.NewMemoryStore(), Config{})
	if _, err := svc.Publish(ctx, PublishRequest{Name: "dt1k", Source: source}); err != nil {
		b.Fatal(err)
	}
	input := map[string]any{"request": map[string]any{"key": "999"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.Evaluate(ctx, "dt1k", EvaluateRequest{Decision: "access", Input: input}); err != nil {
			b.Fatal(err)
		}
	}
}

func strictDemoSource() string {
	return `bcl {
  version "1.0"
  strict true
}

module "demo" {
  source "./module.bcl"
  decision_schema "access" { effects [allow, deny] default deny strategy first_match }
  decision_table "access" {
    default deny
    hit_policy first
    row "allow-ok" {
      when { request.ok == true }
      then { decision allow reason "ok" }
      reason "ok"
      reason_code "OK"
    }
  }
  test "ok" {
    decision "access"
    input { request.ok true }
    expect { effect "allow" reason_code "OK" diagnostics "none" }
  }
}`
}

func benchmarkModuleDir(b *testing.B) string {
	b.Helper()
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "module.bcl"), []byte(`bcl { version "1.0" }`), 0o644); err != nil {
		b.Fatal(err)
	}
	return dir
}
