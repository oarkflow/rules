package storage

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestPostgresStoreStateRetentionConformance(t *testing.T) {
	dsn := os.Getenv("RULES_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set RULES_POSTGRES_TEST_DSN to run PostgreSQL storage conformance")
	}
	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	tenant := "conformance-" + time.Now().UTC().Format("20060102150405.000000000")
	ctx := ContextWithTenant(context.Background(), tenant)
	now := time.Now().UTC()
	old := now.Add(-2 * time.Hour)
	before := now.Add(-time.Hour)
	if err := store.AppendChainEvent(ctx, ChainEventRecord{ID: "old", Definition: "demo", Environment: "test", Chain: "auth", EntityKey: "u-1", EventType: "failed_login", CreatedAt: old}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendChainEvent(ctx, ChainEventRecord{ID: "new", Definition: "demo", Environment: "test", Chain: "auth", EntityKey: "u-1", EventType: "failed_login", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertChainState(ctx, ChainStateRecord{Definition: "demo", Environment: "test", Chain: "auth", Watch: "failed", EntityKey: "u-1", Counters: map[string]int{"failed_login": 2}, UpdatedAt: now, ExpiresAt: &old}); err != nil {
		t.Fatal(err)
	}
	result, err := store.Compact(ctx, RetentionRequest{Definition: "demo", Environment: "test", Before: before})
	if err != nil {
		t.Fatal(err)
	}
	if result.ChainEvents != 1 || result.ChainStates != 1 {
		t.Fatalf("compact result = %#v", result)
	}
	events, err := store.QueryChainEvents(ctx, ChainEventQuery{Definition: "demo", Environment: "test", Chain: "auth", EntityKey: "u-1", IncludeExpired: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != "new" {
		t.Fatalf("events after compaction = %#v", events)
	}
	otherTenant := ContextWithTenant(context.Background(), tenant+"-other")
	otherTenantEvents, err := store.QueryChainEvents(otherTenant, ChainEventQuery{Definition: "demo", Environment: "test", Chain: "auth", EntityKey: "u-1", IncludeExpired: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(otherTenantEvents) != 0 {
		t.Fatalf("other tenant observed conformance events: %#v", otherTenantEvents)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewPostgresStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	events, err = store.QueryChainEvents(ctx, ChainEventQuery{Definition: "demo", Environment: "test", Chain: "auth", EntityKey: "u-1", IncludeExpired: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != "new" {
		t.Fatalf("events after reopening PostgreSQL store = %#v", events)
	}
}
