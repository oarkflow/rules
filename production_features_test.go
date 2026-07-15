package rules

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/oarkflow/rules/pkg/storage"
)

func TestSignedPublishMutationAndLatency(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	publicDER, _ := x509.MarshalPKIXPublicKey(publicKey)
	signer, err := NewBundleSigner(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), "test-signer")
	if err != nil {
		t.Fatal(err)
	}
	source := `module "signed" {
  decision_table "access" {
    default deny
    row "allow" {
      when { request.ok == true }
      then { decision allow }
    }
  }
  test "allows" { decision "access" input { request.ok true } expect { effect "allow" } }
}`
	bundle, err := signer.SignBundle(SignedPolicyPayload{Source: source, Name: "signed", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(storage.NewMemoryStore(), Config{SignaturePolicy: SignatureVerificationPolicy{Required: true, AllowedSigners: []string{"test-signer"}, MinimumAlgo: "Ed25519"}, TrustedPublicKeys: map[string]string{"test-signer": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))}})
	if _, err := svc.Publish(context.Background(), PublishRequest{Name: "signed", Version: "1", SignedBundle: bundle}); err != nil {
		t.Fatal(err)
	}
	if valid, err := svc.VerifyBundle(context.Background(), "signed"); err != nil || !valid {
		t.Fatalf("valid=%v err=%v", valid, err)
	}
	if _, err := svc.Evaluate(context.Background(), "signed", EvaluateRequest{Decision: "access", Input: map[string]any{"request": map[string]any{"ok": true}}}); err != nil {
		t.Fatal(err)
	}
	if histograms := svc.GetLatencyHistograms(context.Background()); len(histograms) == 0 || histograms[0].Count == 0 {
		t.Fatalf("histograms = %#v", histograms)
	}
	report, err := svc.MutationTest(context.Background(), "signed")
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 1 || report.Killed != 1 || report.Score != 100 {
		t.Fatalf("mutation report = %#v", report)
	}

	tampered := *bundle
	tampered.Payload = append([]byte(nil), bundle.Payload...)
	tampered.Payload[0] ^= 1
	if _, err := svc.PublishVersion(context.Background(), PublishRequest{Name: "tampered", Version: "1", SignedBundle: &tampered}); err == nil {
		t.Fatal("tampered signed bundle was accepted")
	}
}

func TestTenantQuotaAndIncidentLifecycle(t *testing.T) {
	store := storage.NewMemoryStore()
	svc := NewService(store, Config{Runtime: RuntimePolicy{TenantQuotas: []TenantQuota{{TenantID: "default", Environment: "development", MaxEvents: 1}}}})
	source := `module "quota" {
  decision_table "signal" { default allow row "event" { when { request.signal == true } then { decision require_review attributes { event "signal" } } } }
  chain "signals" { entity "request.actor" decision "signal" watch "signal" { event "signal" window "5m" step "seen" { threshold 1 action "notify" } } }
}`
	if _, err := svc.Publish(context.Background(), PublishRequest{Name: "quota", Source: source}); err != nil {
		t.Fatal(err)
	}
	request := ChainEvaluateRequest{Event: "signal", EventID: "evt-1", EntityKey: "alice", Input: map[string]any{"request": map[string]any{"actor": "alice", "signal": false}}}
	if _, err := svc.EvaluateChain(context.Background(), "quota", "signals", request); err != nil {
		t.Fatal(err)
	}
	request.EventID = "evt-2"
	if _, err := svc.EvaluateChain(context.Background(), "quota", "signals", request); err == nil {
		t.Fatal("event quota was not enforced")
	}

	incident := storage.IncidentRecord{ID: "incident-1", Definition: "quota", Environment: "development", GroupKey: "quota|alice", Status: "open", Count: 1, FirstSeen: time.Now(), LastSeen: time.Now()}
	if err := store.UpsertIncident(context.Background(), incident); err != nil {
		t.Fatal(err)
	}
	updated, err := svc.UpdateIncident(context.Background(), incident.ID, IncidentUpdateRequest{Status: "acknowledged", Actor: "operator", Reason: "investigating"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "acknowledged" || updated.Metadata["resolution_actor"] != "operator" {
		t.Fatalf("incident = %#v", updated)
	}
}
