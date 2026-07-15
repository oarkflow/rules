package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oarkflow/rules/pkg/server"
)

func TestLoadConfigBCLProductionExample(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "production-server", "condition.local.bcl")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != ":8080" {
		t.Fatalf("address = %q", cfg.Address)
	}
	if cfg.Store.Kind != "file" || cfg.Store.Path == "" {
		t.Fatalf("store = %#v", cfg.Store)
	}
	if cfg.Service.Environment != "production" ||
		!cfg.Service.StrictValidation ||
		!cfg.Service.StrictEvaluation ||
		!cfg.Service.RequireTests ||
		!cfg.Service.RequireActivationApproval {
		t.Fatalf("service = %#v", cfg.Service)
	}
	if cfg.RateLimit.Limit != 60 || cfg.RateLimit.Window != "1m" {
		t.Fatalf("rate limit = %#v", cfg.RateLimit)
	}
	if len(cfg.TrustedProxies) != 1 || cfg.TrustedProxies[0] != "127.0.0.1" {
		t.Fatalf("trusted proxies = %#v", cfg.TrustedProxies)
	}
}

func TestLoadConfigYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte("address: ':9090'\nstore:\n  kind: memory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != ":9090" || cfg.Store.Kind != "memory" {
		t.Fatalf("config = %#v", cfg)
	}
}

func TestProductionExampleAuthzLoads(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "production-server", "condition.authz")
	if _, err := server.AuthzEngineFromFile(path); err != nil {
		t.Fatal(err)
	}
}
