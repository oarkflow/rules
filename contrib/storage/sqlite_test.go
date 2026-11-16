package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/oarkflow/rules/pkg/audit"
)

func TestSQLiteStorePersistsAndIsolatesTenants(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctxA := ContextWithTenant(context.Background(), "tenant-a")
	ctxB := ContextWithTenant(context.Background(), "tenant-b")
	record := DefinitionRecord{Name: "demo", Version: "1", Digest: "abc", PublishedAt: time.Now()}
	if err := store.SaveDefinition(ctxA, record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetDefinition(ctxB, "demo"); err == nil {
		t.Fatal("expected tenant-b lookup to fail")
	}
	got, err := store.GetDefinition(ctxA, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if got.TenantID != "tenant-a" || got.Digest != "abc" {
		t.Fatalf("definition = %#v", got)
	}

	envelope := audit.Seal(audit.Envelope{ID: "audit-1", Operation: "publish"}, "")
	if err := store.AppendAudit(ctxA, envelope); err != nil {
		t.Fatal(err)
	}
	audits, err := store.ListAudits(ctxA)
	if err != nil {
		t.Fatal(err)
	}
	if len(audits) != 1 {
		t.Fatalf("audits = %d", len(audits))
	}
}

func TestSQLiteStoreConfiguresOperationalPragmas(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	var busyTimeout, foreignKeys int
	if err := store.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if busyTimeout <= 0 || foreignKeys != 1 {
		t.Fatalf("busy_timeout = %d, foreign_keys = %d", busyTimeout, foreignKeys)
	}
}

func TestSQLiteStoreEntityLockHonorsCancellation(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	unlock, err := store.LockEntity(context.Background(), "entity-1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlock() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.LockEntity(ctx, "entity-1"); err == nil {
		t.Fatal("expected canceled lock acquisition to fail")
	}
}

func TestSQLiteStoreStateRetentionConformance(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctxA := ContextWithTenant(context.Background(), "tenant-a")
	ctxB := ContextWithTenant(context.Background(), "tenant-b")
	now := time.Now().UTC()
	old := now.Add(-2 * time.Hour)
	before := now.Add(-time.Hour)
	if err := store.AppendChainEvent(ctxA, ChainEventRecord{ID: "old", Definition: "demo", Environment: "test", Chain: "auth", EntityKey: "u-1", EventType: "failed_login", CreatedAt: old}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendChainEvent(ctxA, ChainEventRecord{ID: "new", Definition: "demo", Environment: "test", Chain: "auth", EntityKey: "u-1", EventType: "failed_login", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendChainEvent(ctxB, ChainEventRecord{ID: "other-tenant", Definition: "demo", Environment: "test", Chain: "auth", EntityKey: "u-1", EventType: "failed_login", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertChainState(ctxA, ChainStateRecord{Definition: "demo", Environment: "test", Chain: "auth", Watch: "failed", EntityKey: "u-1", Counters: map[string]int{"failed_login": 2}, UpdatedAt: now, ExpiresAt: &old}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetChainState(ctxB, "auth", "failed", "u-1"); err == nil {
		t.Fatal("tenant-b read tenant-a chain state")
	}
	result, err := store.Compact(ctxA, RetentionRequest{Definition: "demo", Environment: "test", Before: before})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainEvents != 1 || result.ChainStates != 1 {
		t.Fatalf("compact result = %#v", result)
	}
	events, err := store.QueryChainEvents(ctxA, ChainEventQuery{Definition: "demo", Environment: "test", Chain: "auth", EntityKey: "u-1", IncludeExpired: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != "new" {
		t.Fatalf("events after compaction = %#v", events)
	}
	otherTenantEvents, err := store.QueryChainEvents(ctxB, ChainEventQuery{Definition: "demo", Environment: "test", Chain: "auth", EntityKey: "u-1", IncludeExpired: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(otherTenantEvents) != 1 || otherTenantEvents[0].ID != "other-tenant" {
		t.Fatalf("tenant-b events = %#v", otherTenantEvents)
	}
}

func TestSQLiteStorePersistsChainStateAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.db")
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithTenant(context.Background(), "tenant-a")
	state := ChainStateRecord{Definition: "demo", Environment: "test", Chain: "auth", Watch: "failed", EntityKey: "u-1", Counters: map[string]int{"failed_login": 3}, UpdatedAt: time.Now().UTC()}
	if err := store.UpsertChainState(ctx, state); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	got, err := store.GetChainState(ctx, "auth", "failed", "u-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Counters["failed_login"] != 3 {
		t.Fatalf("reopened chain state = %#v", got)
	}
}

func BenchmarkSQLiteStoreAppendAndQueryChainEvents(b *testing.B) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	ctx := ContextWithTenant(context.Background(), "tenant-a")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := store.AppendChainEvent(ctx, ChainEventRecord{
			ID: fmt.Sprintf("event-%d", i), Definition: "bench", Chain: "auth",
			EntityKey: "user-1", EventType: "failed_login", CreatedAt: time.Now().UTC(),
		}); err != nil {
			b.Fatal(err)
		}
		if _, err := store.QueryChainEvents(ctx, ChainEventQuery{Definition: "bench", Chain: "auth", EntityKey: "user-1", Limit: 100}); err != nil {
			b.Fatal(err)
		}
	}
}

var _ Store = (*SQLiteStore)(nil)
