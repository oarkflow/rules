package server

import (
	"context"
	"os"
	"time"

	"github.com/oarkflow/authz"
	authzstores "github.com/oarkflow/authz/pkg/stores"
)

func AuthzEngineFromFile(path string) (*authz.Engine, error) {
	if path == "" {
		return DefaultAuthzEngine(), nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := authz.NewDSLParser().Parse(payload)
	if err != nil {
		return nil, err
	}
	policies := authzstores.NewMemoryPolicyStore()
	roles := authzstores.NewMemoryRoleStore()
	acls := authzstores.NewMemoryACLStore()
	audits := authzstores.NewMemoryAuditStore()
	members := authzstores.NewMemoryRoleMembershipStore()
	// The authz audit worker starts inside NewEngine, so its batching settings
	// must be supplied as constructor options rather than changed afterward.
	engine := authz.NewEngine(
		policies,
		roles,
		acls,
		audits,
		authz.WithRoleMembershipStore(members),
		authz.WithAuditBatching(cfg.Engine.AuditBatchSize, time.Duration(cfg.Engine.AuditFlushInterval)*time.Millisecond),
	)
	cfg.Engine.AuditBatchSize = 0
	cfg.Engine.AuditFlushInterval = 0
	if err := engine.ApplyConfig(context.Background(), cfg); err != nil {
		return nil, err
	}
	return engine, nil
}
