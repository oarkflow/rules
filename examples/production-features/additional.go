package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/oarkflow/rules"
	"github.com/oarkflow/rules/pkg/storage"
)

func demonstrateApprovalGate(ctx context.Context, source string, now time.Time) {
	service := rules.NewService(storage.NewMemoryStore(), rules.Config{
		Environment:               "example",
		RequireActivationApproval: true,
		Clock:                     func() time.Time { return now },
	})
	published, err := service.Publish(ctx, rules.PublishRequest{
		Name: "approval-example", Version: "1", Source: source,
		Metadata: map[string]any{
			"review_required": true,
			"last_reviewed":   now.Format(time.RFC3339Nano),
			"review_interval": "24h",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	_, blockedErr := service.Activate(ctx, "approval-example", "1", "example")
	if _, err := service.Approve(ctx, "approval-example", "1", rules.ApprovalRequest{ApprovedBy: "release-manager", Reason: "reviewed production controls"}); err != nil {
		log.Fatal(err)
	}
	activated, err := service.Activate(ctx, "approval-example", "1", "example")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("governance activation_pending=%v blocked_before_approval=%v active_version=%s\n", published.Definition.Metadata["activation_pending"], blockedErr != nil, activated.Definition.Version)
}

func demonstrateTenantQuota(ctx context.Context) {
	service := rules.NewService(storage.NewMemoryStore(), rules.Config{
		Runtime: rules.RuntimePolicy{TenantQuotas: []rules.TenantQuota{{
			TenantID: "default", Environment: "development", MaxEvents: 1,
		}}},
	})
	if _, err := service.Publish(ctx, rules.PublishRequest{Name: "quota-example", Source: quotaPolicy}); err != nil {
		log.Fatal(err)
	}
	request := rules.ChainEvaluateRequest{
		EventID: "quota-event-1", Event: "signal", EntityKey: "quota-user",
		Input: map[string]any{"request": map[string]any{"actor": "quota-user", "signal": false}},
	}
	if _, err := service.EvaluateChain(ctx, "quota-example", "signals", request); err != nil {
		log.Fatal(err)
	}
	request.EventID = "quota-event-2"
	_, quotaErr := service.EvaluateChain(ctx, "quota-example", "signals", request)
	fmt.Printf("tenant_quota first_event_accepted=true second_event_rejected=%v\n", quotaErr != nil)
}

func demonstrateCrossWorkerLocking(ctx context.Context) {
	dir, err := os.MkdirTemp("", "condition-locking-example-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	firstStore, err := storage.NewFileStore(dir)
	if err != nil {
		log.Fatal(err)
	}
	secondStore, err := storage.NewFileStore(dir)
	if err != nil {
		log.Fatal(err)
	}
	first := rules.NewService(firstStore, rules.Config{})
	second := rules.NewService(secondStore, rules.Config{})
	if _, err := first.Publish(ctx, rules.PublishRequest{Name: "locking-example", Source: lockingPolicy}); err != nil {
		log.Fatal(err)
	}

	const workers = 12
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			service := first
			if index%2 == 1 {
				service = second
			}
			_, err := service.EvaluateChain(ctx, "locking-example", "signals", rules.ChainEvaluateRequest{
				EventID: fmt.Sprintf("worker-event-%02d", index), Event: "signal", EntityKey: "shared-entity",
				Input: map[string]any{"request": map[string]any{"actor": "shared-entity"}},
			})
			errors <- err
		}(index)
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			log.Fatal(err)
		}
	}
	events, err := firstStore.QueryChainEvents(ctx, storage.ChainEventQuery{Definition: "locking-example", Chain: "signals", EntityKey: "shared-entity", IncludeExpired: true})
	if err != nil {
		log.Fatal(err)
	}
	states, err := first.ListChainStates(ctx, storage.ChainStateQuery{Definition: "locking-example", Chain: "signals", EntityKey: "shared-entity", IncludeExpired: true})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("cross_worker_locking workers=%d durable_events=%d state_records=%d\n", workers, len(events), len(states))
}

const quotaPolicy = `module "quota" {
  decision_table "signal" {
    default allow
    row "observe" { when { request.signal == true } then { decision require_review } }
  }
  chain "signals" {
    entity "request.actor"
    decision "signal"
    watch "signals" { event "signal" window "5m" step "seen" { threshold 100 action "log" } }
  }
}`

const lockingPolicy = `module "locking" {
  decision_table "signal" { default allow }
  chain "signals" {
    entity "request.actor"
    decision "signal"
    watch "signals" { event "signal" window "5m" step "seen" { threshold 100 action "log" } }
  }
}`
