package storage

import (
	"context"
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

var _ Store = (*SQLiteStore)(nil)
