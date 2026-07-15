package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/oarkflow/bcl"
	"github.com/oarkflow/rules"
	"github.com/oarkflow/rules/pkg/routing"
	"github.com/oarkflow/rules/pkg/server"
	"github.com/oarkflow/rules/pkg/storage"
	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "serve":
		return runServe(args[1:])
	case "publish":
		return runPublish(args[1:])
	case "validate":
		return runValidate(args[1:])
	case "evaluate":
		return runEvaluate(args[1:])
	case "test":
		return runTest(args[1:])
	case "gates":
		return runGates(args[1:])
	case "versions":
		return runVersions(args[1:])
	case "activate":
		return runActivate(args[1:])
	case "rollback":
		return runRollback(args[1:])
	case "simulate":
		return runSimulate(args[1:], false)
	case "compare":
		return runSimulate(args[1:], true)
	case "canary":
		return runCanary(args[1:])
	case "audits":
		return runAudits(args[1:])
	case "reports":
		return runReports(args[1:])
	case "audit":
		return runAudit(args[1:])
	case "route-coverage", "ir", "verify-bundle", "mutation-test", "retry-actions", "tick-workflows":
		return runOperational(args[0], args[1:])
	case "chain-evaluate":
		return runChainEvaluate(args[1:])
	case "lifecycle-evaluate":
		return runLifecycleEvaluate(args[1:])
	case "routes-import":
		return runRoutesImport(args[1:])
	case "compact", "blast-radius", "incident-update", "workflow-start", "workflow-advance", "disable", "enable", "approve":
		return runPlatformOperation(args[0], args[1:])
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runPlatformOperation(command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	tenant := fs.String("tenant", "", "tenant id")
	environment := fs.String("env", "", "environment")
	version := fs.String("version", "", "definition version")
	reason := fs.String("reason", "", "operation reason")
	actor := fs.String("actor", "", "operator identity")
	status := fs.String("status", "", "target status")
	inputPath := fs.String("input", "", "input JSON path")
	candidate := fs.String("candidate", "", "candidate BCL path")
	decision := fs.String("decision", "", "decision id")
	beforeText := fs.String("before", "", "retention cutoff RFC3339")
	deleteOpen := fs.Bool("delete-open-incidents", false, "delete open incidents during compaction")
	deleteActive := fs.Bool("delete-active-deliveries", false, "delete active deliveries during compaction")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	ctx := cliContext(cfg, *tenant)
	arg := func(index int, label string) (string, error) {
		if fs.NArg() <= index {
			return "", fmt.Errorf("%s requires %s", command, label)
		}
		return fs.Arg(index), nil
	}
	switch command {
	case "compact":
		before := time.Now().UTC()
		if *beforeText != "" {
			before, err = time.Parse(time.RFC3339, *beforeText)
			if err != nil {
				return err
			}
		}
		result, err := svc.Compact(ctx, storage.RetentionRequest{TenantID: *tenant, Definition: func() string {
			if fs.NArg() > 0 {
				return fs.Arg(0)
			}
			return ""
		}(), Environment: *environment, Before: before, DeleteOpenIncidents: *deleteOpen, DeleteActiveDeliveries: *deleteActive})
		printJSON(result)
		return err
	case "blast-radius":
		definition, argErr := arg(0, "a definition")
		if argErr != nil {
			return argErr
		}
		if *candidate == "" {
			return fmt.Errorf("blast-radius requires --candidate candidate.bcl")
		}
		result, err := svc.BlastRadius(ctx, definition, rules.SimulationRequest{TenantID: *tenant, CandidatePath: *candidate, Decision: *decision})
		printJSON(result)
		return err
	case "incident-update":
		id, argErr := arg(0, "an incident id")
		if argErr != nil {
			return argErr
		}
		result, err := svc.UpdateIncident(ctx, id, rules.IncidentUpdateRequest{TenantID: *tenant, Status: *status, Reason: *reason, Actor: *actor})
		printJSON(result)
		return err
	case "workflow-start":
		definition, argErr := arg(0, "a definition and workflow")
		if argErr != nil {
			return argErr
		}
		workflow, argErr := arg(1, "a definition and workflow")
		if argErr != nil {
			return argErr
		}
		input, readErr := readOptionalInput(*inputPath)
		if readErr != nil {
			return readErr
		}
		result, err := svc.StartWorkflow(ctx, definition, workflow, input)
		printJSON(result)
		return err
	case "workflow-advance":
		id, argErr := arg(0, "a workflow run id")
		if argErr != nil {
			return argErr
		}
		input, readErr := readOptionalInput(*inputPath)
		if readErr != nil {
			return readErr
		}
		result, err := svc.AdvanceWorkflow(ctx, id, input)
		printJSON(result)
		return err
	case "disable", "enable":
		definition, argErr := arg(0, "a definition")
		if argErr != nil {
			return argErr
		}
		req := rules.DisableRequest{TenantID: *tenant, Version: *version, Environment: *environment, Reason: *reason}
		var result *rules.LifecycleResponse
		if command == "disable" {
			result, err = svc.Disable(ctx, definition, req)
		} else {
			result, err = svc.Enable(ctx, definition, req)
		}
		printJSON(result)
		return err
	case "approve":
		definition, argErr := arg(0, "a definition and version")
		if argErr != nil {
			return argErr
		}
		approvalVersion := *version
		if approvalVersion == "" && fs.NArg() > 1 {
			approvalVersion = fs.Arg(1)
		}
		if approvalVersion == "" {
			return fmt.Errorf("approve requires a version argument or --version")
		}
		result, err := svc.Approve(ctx, definition, approvalVersion, rules.ApprovalRequest{TenantID: *tenant, Environment: *environment, ApprovedBy: *actor, Reason: *reason})
		printJSON(result)
		return err
	}
	return fmt.Errorf("unknown platform operation %q", command)
}

func readOptionalInput(path string) (map[string]any, error) {
	input := map[string]any{}
	if path != "" {
		if err := readJSON(path, &input); err != nil {
			return nil, err
		}
	}
	return input, nil
}

func runRoutesImport(args []string) error {
	fs := flag.NewFlagSet("routes-import", flag.ExitOnError)
	input := fs.String("input", "", "OpenAPI YAML/JSON path")
	output := fs.String("output", "", "output path; stdout when omitted")
	catalog := fs.String("catalog", "http", "BCL route catalog id")
	format := fs.String("format", "bcl", "output format: bcl or openapi")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("routes-import requires --input openapi.yaml")
	}
	payload, err := os.ReadFile(*input)
	if err != nil {
		return err
	}
	routes, diagnostics, err := routing.ImportOpenAPI(payload)
	if err != nil {
		return err
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == "error" {
			return fmt.Errorf("route import: %s", diagnostic.Message)
		}
	}
	var generated []byte
	switch strings.ToLower(*format) {
	case "bcl":
		generated = []byte(routing.FormatBCLRouteCatalog(*catalog, routes))
	case "openapi":
		generated, err = routing.ExportOpenAPI(*catalog, "1.0.0", routes)
	default:
		return fmt.Errorf("unsupported route output format %q", *format)
	}
	if err != nil {
		return err
	}
	if *output == "" {
		fmt.Print(string(generated))
		return nil
	}
	return os.WriteFile(*output, generated, 0o600)
}

func runOperational(command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	tenant := fs.String("tenant", "", "tenant id")
	limit := fs.Int("limit", 100, "maximum records")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	ctx := cliContext(cfg, *tenant)
	switch command {
	case "retry-actions":
		result, err := svc.RetryActions(ctx, rules.ActionRetryRequest{TenantID: *tenant, Limit: *limit})
		printJSON(result)
		return err
	case "tick-workflows":
		result, err := svc.TickWorkflows(ctx, rules.WorkflowTickRequest{TenantID: *tenant, Limit: *limit})
		printJSON(result)
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("%s requires a definition name", command)
	}
	definition := fs.Arg(0)
	switch command {
	case "route-coverage":
		result, err := svc.RouteCoverage(ctx, definition)
		printJSON(result)
		return err
	case "ir":
		result, err := svc.PolicyIR(ctx, definition)
		printJSON(result)
		return err
	case "verify-bundle":
		result, err := svc.VerifyBundle(ctx, definition)
		printJSON(map[string]any{"valid": result})
		return err
	case "mutation-test":
		result, err := svc.MutationTest(ctx, definition)
		printJSON(result)
		return err
	default:
		return fmt.Errorf("unknown operational command %q", command)
	}
}

func runChainEvaluate(args []string) error {
	fs := flag.NewFlagSet("chain-evaluate", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	tenant := fs.String("tenant", "", "tenant id")
	inputPath := fs.String("input", "", "input JSON path")
	event := fs.String("event", "", "event name")
	eventID := fs.String("event-id", "", "idempotency event id")
	entity := fs.String("entity", "", "entity key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("chain-evaluate requires a definition and chain")
	}
	input := map[string]any{}
	if *inputPath != "" {
		if err := readJSON(*inputPath, &input); err != nil {
			return err
		}
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	result, err := svc.EvaluateChain(cliContext(cfg, *tenant), fs.Arg(0), fs.Arg(1), rules.ChainEvaluateRequest{TenantID: *tenant, Input: input, Event: *event, EventID: *eventID, EntityKey: *entity})
	printJSON(result)
	return err
}

func runLifecycleEvaluate(args []string) error {
	fs := flag.NewFlagSet("lifecycle-evaluate", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	tenant := fs.String("tenant", "", "tenant id")
	inputPath := fs.String("input", "", "lifecycle request JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 || *inputPath == "" {
		return fmt.Errorf("lifecycle-evaluate requires a definition, lifecycle, and --input request.json")
	}
	var request rules.LifecycleEvaluateRequest
	if err := readJSON(*inputPath, &request); err != nil {
		return err
	}
	request.TenantID = firstNonEmpty(request.TenantID, *tenant)
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	result, err := svc.EvaluateLifecycle(cliContext(cfg, *tenant), fs.Arg(0), fs.Arg(1), request)
	printJSON(result)
	return err
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	addr := fs.String("addr", ":8080", "listen address")
	storeKind := fs.String("store", "file", "store kind: file, memory")
	storePath := fs.String("store-path", ".condition", "file root")
	authzPath := fs.String("authz", "", "authz DSL config path")
	tlsCert := fs.String("tls-cert", "", "TLS certificate path")
	tlsKey := fs.String("tls-key", "", "TLS private key path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Address, *addr, ":8080")
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	applyString(&cfg.AuthzPath, *authzPath, "")
	applyString(&cfg.TLS.CertFile, *tlsCert, "")
	applyString(&cfg.TLS.KeyFile, *tlsKey, "")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	authzEngine, err := server.AuthzEngineFromFile(cfg.AuthzPath)
	if err != nil {
		return err
	}
	var opts []server.Option
	opts = append(opts, server.WithAuthzEngine(authzEngine))
	if cfg.RateLimit.Limit > 0 && cfg.RateLimit.Window != "" {
		if d, err := time.ParseDuration(cfg.RateLimit.Window); err == nil {
			opts = append(opts, server.WithRateLimit(cfg.RateLimit.Limit, d))
		}
	}
	opts = append(opts, server.WithTrustedProxies(cfg.TrustedProxies))
	fmt.Printf("condition listening on %s\n", cfg.Address)
	srv := &http.Server{
		Addr:              cfg.Address,
		Handler:           server.New(svc, opts...).Handler(),
		ReadHeaderTimeout: durationOrDefault(cfg.HTTP.ReadHeaderTimeout, 5*time.Second),
		ReadTimeout:       durationOrDefault(cfg.HTTP.ReadTimeout, 15*time.Second),
		WriteTimeout:      durationOrDefault(cfg.HTTP.WriteTimeout, 30*time.Second),
		IdleTimeout:       durationOrDefault(cfg.HTTP.IdleTimeout, 60*time.Second),
		MaxHeaderBytes:    cfg.HTTP.MaxHeaderBytes,
	}
	errCh := make(chan error, 1)
	go func() {
		if cfg.TLS.CertFile != "" || cfg.TLS.KeyFile != "" {
			errCh <- srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
			return
		}
		errCh <- srv.ListenAndServe()
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), durationOrDefault(cfg.HTTP.ShutdownTimeout, 10*time.Second))
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

func runPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	name := fs.String("name", "", "definition name")
	version := fs.String("version", "1", "definition version")
	env := fs.String("env", "", "environment")
	tenant := fs.String("tenant", "", "tenant id")
	runTests := fs.Bool("tests", false, "run tests before publishing")
	signedBundlePath := fs.String("signed-bundle", "", "signed bundle JSON path")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 && *signedBundlePath == "" {
		return fmt.Errorf("publish requires a decision.bcl path or --signed-bundle bundle.json")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	var signedBundle *rules.SignedBundle
	if *signedBundlePath != "" {
		signedBundle = &rules.SignedBundle{}
		if err := readJSON(*signedBundlePath, signedBundle); err != nil {
			return err
		}
	}
	path := ""
	if fs.NArg() == 1 {
		path = fs.Arg(0)
	}
	resp, err := svc.Publish(cliContext(cfg, *tenant), rules.PublishRequest{Name: *name, Version: *version, Environment: *env, Path: path, RunTests: *runTests, SignedBundle: signedBundle})
	if err != nil {
		return err
	}
	printJSON(resp)
	return nil
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	name := fs.String("name", "", "definition name")
	version := fs.String("version", "1", "definition version")
	env := fs.String("env", "", "environment")
	tenant := fs.String("tenant", "", "tenant id")
	runTests := fs.Bool("tests", false, "run tests")
	bundle := fs.String("bundle", "", "bundle id")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("validate requires a decision.bcl path")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	resp, err := svc.Validate(cliContext(cfg, *tenant), rules.ValidationRequest{Name: *name, Version: *version, Environment: *env, Path: fs.Arg(0), RunTests: *runTests, Bundle: *bundle})
	printJSON(resp)
	return err
}

func runEvaluate(args []string) error {
	fs := flag.NewFlagSet("evaluate", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	inputPath := fs.String("input", "", "input JSON path")
	decision := fs.String("decision", "", "decision id")
	tenant := fs.String("tenant", "", "tenant id")
	compact := fs.Bool("compact", false, "print only decision answer")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("evaluate requires a definition name")
	}
	var input map[string]any
	if *inputPath != "" {
		if err := readJSON(*inputPath, &input); err != nil {
			return err
		}
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	resp, err := svc.Evaluate(cliContext(cfg, *tenant), fs.Arg(0), rules.EvaluateRequest{Decision: *decision, Input: input, IncludeFeatures: true, Counterfactuals: true})
	if err != nil {
		return err
	}
	if *compact && resp != nil && resp.Report != nil && resp.Report.Decision != nil {
		printJSON(resp.Report.Decision.Answer())
	} else {
		printJSON(resp)
	}
	return nil
}

func runTest(args []string) error {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	bundle := fs.String("bundle", "", "bundle id")
	tenant := fs.String("tenant", "", "tenant id")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("test requires a definition name")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	resp, err := svc.Test(cliContext(cfg, *tenant), fs.Arg(0), *bundle)
	printJSON(resp)
	return err
}

func runGates(args []string) error {
	fs := flag.NewFlagSet("gates", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	bundle := fs.String("bundle", "", "bundle id")
	tenant := fs.String("tenant", "", "tenant id")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("gates requires a definition name")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	resp, err := svc.Gates(cliContext(cfg, *tenant), fs.Arg(0), *bundle)
	printJSON(resp)
	return err
}

func runVersions(args []string) error {
	fs := flag.NewFlagSet("versions", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	env := fs.String("env", "", "environment")
	tenant := fs.String("tenant", "", "tenant id")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("versions requires a definition name")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	resp, err := svc.ListVersions(cliContext(cfg, *tenant), fs.Arg(0), *env)
	printJSON(resp)
	return err
}

func runActivate(args []string) error {
	fs := flag.NewFlagSet("activate", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	env := fs.String("env", "", "environment")
	tenant := fs.String("tenant", "", "tenant id")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("activate requires definition and version")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	resp, err := svc.Activate(cliContext(cfg, *tenant), fs.Arg(0), fs.Arg(1), *env)
	printJSON(resp)
	return err
}

func runRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	env := fs.String("env", "", "environment")
	tenant := fs.String("tenant", "", "tenant id")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("rollback requires definition and version")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	resp, err := svc.Rollback(cliContext(cfg, *tenant), fs.Arg(0), fs.Arg(1), *env)
	printJSON(resp)
	return err
}

func runSimulate(args []string, compare bool) error {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	candidate := fs.String("candidate", "", "candidate decision.bcl path")
	decision := fs.String("decision", "", "decision id")
	dataset := fs.String("dataset", "", "dataset id")
	casesPath := fs.String("cases", "", "cases JSON path")
	tenant := fs.String("tenant", "", "tenant id")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("simulate requires a definition name")
	}
	var cases []bcl.DecisionBatchCase
	if *casesPath != "" {
		if err := readJSON(*casesPath, &cases); err != nil {
			return err
		}
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	req := rules.SimulationRequest{CandidatePath: *candidate, Decision: *decision, Dataset: *dataset, Cases: cases}
	var resp *rules.SimulationResponse
	if compare {
		resp, err = svc.Compare(cliContext(cfg, *tenant), fs.Arg(0), req)
	} else {
		resp, err = svc.Simulate(cliContext(cfg, *tenant), fs.Arg(0), req)
	}
	if resp != nil {
		printJSON(resp)
	}
	return err
}

func runCanary(args []string) error {
	fs := flag.NewFlagSet("canary", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	candidate := fs.String("candidate", "", "candidate decision.bcl path")
	decision := fs.String("decision", "", "decision id")
	dataset := fs.String("dataset", "", "dataset id")
	casesPath := fs.String("cases", "", "cases JSON path")
	maxChanged := fs.Int("max-changed", 0, "maximum changed cases")
	requireNoErrors := fs.Bool("require-no-errors", true, "fail canary on diagnostics")
	promote := fs.Bool("promote", false, "publish candidate when canary passes")
	promoteVersion := fs.String("promote-version", "", "candidate version to publish when promotion is enabled")
	tenant := fs.String("tenant", "", "tenant id")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("canary requires a definition name")
	}
	var cases []bcl.DecisionBatchCase
	if *casesPath != "" {
		if err := readJSON(*casesPath, &cases); err != nil {
			return err
		}
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	resp, err := svc.Canary(cliContext(cfg, *tenant), fs.Arg(0), rules.CanaryRequest{
		SimulationRequest: rules.SimulationRequest{CandidatePath: *candidate, Decision: *decision, Dataset: *dataset, Cases: cases},
		MaxChangedCases:   *maxChanged,
		RequireNoErrors:   *requireNoErrors,
		Promote:           *promote,
		PromoteVersion:    *promoteVersion,
	})
	if resp != nil {
		printJSON(resp)
	}
	return err
}

func runAudits(args []string) error {
	fs := flag.NewFlagSet("audits", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	definition := fs.String("definition", "", "definition filter")
	operation := fs.String("operation", "", "operation filter")
	limit := fs.Int("limit", 0, "limit")
	tenant := fs.String("tenant", "", "tenant id")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	resp, err := svc.QueryAudits(cliContext(cfg, *tenant), storage.ListOptions{Definition: *definition, Operation: *operation, Limit: *limit})
	printJSON(resp)
	return err
}

func runReports(args []string) error {
	fs := flag.NewFlagSet("reports", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	kind := fs.String("kind", "", "report kind")
	definition := fs.String("definition", "", "definition filter")
	limit := fs.Int("limit", 0, "limit")
	tenant := fs.String("tenant", "", "tenant id")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	resp, err := svc.QueryReports(cliContext(cfg, *tenant), storage.ListOptions{Kind: *kind, Definition: *definition, Limit: *limit})
	printJSON(resp)
	return err
}

func runAudit(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return fmt.Errorf("usage: condition audit verify")
	}
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	configPath := fs.String("config", "", "condition config path")
	storeKind := fs.String("store", "file", "store kind")
	storePath := fs.String("store-path", ".condition", "store path")
	tenant := fs.String("tenant", "", "tenant id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	applyString(&cfg.Store.Kind, *storeKind, "file")
	applyString(&cfg.Store.Path, *storePath, ".condition")
	svc, closer, err := newServiceFromConfig(cfg)
	if err != nil {
		return err
	}
	defer closer()
	if err := svc.VerifyAudits(cliContext(cfg, *tenant)); err != nil {
		return err
	}
	fmt.Println("audit chain verified")
	return nil
}

func newService(kind, path string) (*rules.Service, func(), error) {
	cfg := RuntimeConfig{}
	cfg.Store.Kind = kind
	cfg.Store.Path = path
	return newServiceFromConfig(cfg)
}

func newServiceFromConfig(cfg RuntimeConfig) (*rules.Service, func(), error) {
	kind := cfg.Store.Kind
	path := cfg.Store.Path
	switch strings.ToLower(kind) {
	case "memory":
		return rules.NewService(storage.NewMemoryStore(), serviceConfig(cfg)), func() {}, nil
	case "file", "":
		store, err := storage.NewFileStore(path)
		if err != nil {
			return nil, nil, err
		}
		return rules.NewService(store, serviceConfig(cfg)), func() {}, nil
	default:
		return nil, nil, fmt.Errorf("unknown store kind %q", kind)
	}
}

type RuntimeConfig struct {
	Address        string   `json:"address" yaml:"address" bcl:"address"`
	AuthzPath      string   `json:"authz_path" yaml:"authz_path" bcl:"authz_path"`
	TrustedProxies []string `json:"trusted_proxies" yaml:"trusted_proxies" bcl:"trusted_proxies"`
	Store          struct {
		Kind string `json:"kind" yaml:"kind" bcl:"kind"`
		Path string `json:"path" yaml:"path" bcl:"path"`
	} `json:"store" yaml:"store" bcl:"store"`
	TLS struct {
		CertFile string `json:"cert_file" yaml:"cert_file" bcl:"cert_file"`
		KeyFile  string `json:"key_file" yaml:"key_file" bcl:"key_file"`
	} `json:"tls" yaml:"tls" bcl:"tls"`
	HTTP struct {
		ReadHeaderTimeout string `json:"read_header_timeout" yaml:"read_header_timeout" bcl:"read_header_timeout"`
		ReadTimeout       string `json:"read_timeout" yaml:"read_timeout" bcl:"read_timeout"`
		WriteTimeout      string `json:"write_timeout" yaml:"write_timeout" bcl:"write_timeout"`
		IdleTimeout       string `json:"idle_timeout" yaml:"idle_timeout" bcl:"idle_timeout"`
		ShutdownTimeout   string `json:"shutdown_timeout" yaml:"shutdown_timeout" bcl:"shutdown_timeout"`
		MaxHeaderBytes    int    `json:"max_header_bytes" yaml:"max_header_bytes" bcl:"max_header_bytes"`
	} `json:"http" yaml:"http" bcl:"http"`
	Service struct {
		Environment               string `json:"environment" yaml:"environment" bcl:"environment"`
		DefaultTenant             string `json:"default_tenant" yaml:"default_tenant" bcl:"default_tenant"`
		RequestTimeout            string `json:"request_timeout" yaml:"request_timeout" bcl:"request_timeout"`
		MaxRequestBytes           int64  `json:"max_request_bytes" yaml:"max_request_bytes" bcl:"max_request_bytes"`
		StrictValidation          bool   `json:"strict_validation" yaml:"strict_validation" bcl:"strict_validation"`
		StrictEvaluation          bool   `json:"strict_evaluation" yaml:"strict_evaluation" bcl:"strict_evaluation"`
		RequireTests              bool   `json:"require_tests" yaml:"require_tests" bcl:"require_tests"`
		RequireActivationApproval bool   `json:"require_activation_approval" yaml:"require_activation_approval" bcl:"require_activation_approval"`
		Runtime                   struct {
			AllowTime              bool                `json:"allow_time" yaml:"allow_time" bcl:"allow_time"`
			FixedTime              string              `json:"fixed_time" yaml:"fixed_time" bcl:"fixed_time"`
			AllowEnv               bool                `json:"allow_env" yaml:"allow_env" bcl:"allow_env"`
			AllowedDatasetAdapters []string            `json:"allowed_dataset_adapters" yaml:"allowed_dataset_adapters" bcl:"allowed_dataset_adapters"`
			AllowedHTTPHosts       []string            `json:"allowed_http_hosts" yaml:"allowed_http_hosts" bcl:"allowed_http_hosts"`
			AllowedHTTPMethods     []string            `json:"allowed_http_methods" yaml:"allowed_http_methods" bcl:"allowed_http_methods"`
			ExternalTimeout        string              `json:"external_timeout" yaml:"external_timeout" bcl:"external_timeout"`
			AllowedActionSinks     []string            `json:"allowed_action_sinks" yaml:"allowed_action_sinks" bcl:"allowed_action_sinks"`
			AllowedWebhookHosts    []string            `json:"allowed_webhook_hosts" yaml:"allowed_webhook_hosts" bcl:"allowed_webhook_hosts"`
			AllowedWebhookMethods  []string            `json:"allowed_webhook_methods" yaml:"allowed_webhook_methods" bcl:"allowed_webhook_methods"`
			WebhookTimeout         string              `json:"webhook_timeout" yaml:"webhook_timeout" bcl:"webhook_timeout"`
			MaxStateRecords        int                 `json:"max_state_records" yaml:"max_state_records" bcl:"max_state_records"`
			TenantQuotas           []rules.TenantQuota `json:"tenant_quotas" yaml:"tenant_quotas" bcl:"tenant_quotas"`
		} `json:"runtime" yaml:"runtime" bcl:"runtime"`
	} `json:"service" yaml:"service" bcl:"service"`
	SignaturePolicy   rules.SignatureVerificationPolicy `json:"signature_policy" yaml:"signature_policy" bcl:"signature_policy"`
	TrustedPublicKeys map[string]string                 `json:"trusted_public_keys" yaml:"trusted_public_keys" bcl:"trusted_public_keys"`
	RateLimit         struct {
		Limit  int    `json:"limit" yaml:"limit" bcl:"limit"`
		Window string `json:"window" yaml:"window" bcl:"window"`
	} `json:"rate_limit" yaml:"rate_limit" bcl:"rate_limit"`
}

func loadConfig(path string) (RuntimeConfig, error) {
	cfg := RuntimeConfig{Address: ":8080"}
	cfg.Store.Kind = "file"
	cfg.Store.Path = ".condition"
	cfg.Service.Environment = "development"
	cfg.Service.DefaultTenant = "default"
	cfg.HTTP.ReadHeaderTimeout = "5s"
	cfg.HTTP.ReadTimeout = "15s"
	cfg.HTTP.WriteTimeout = "30s"
	cfg.HTTP.IdleTimeout = "60s"
	cfg.HTTP.ShutdownTimeout = "10s"
	cfg.HTTP.MaxHeaderBytes = 1 << 20
	if path == "" {
		return cfg, nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if strings.HasSuffix(path, ".json") {
		return cfg, json.Unmarshal(payload, &cfg)
	}
	if strings.HasSuffix(path, ".bcl") {
		return cfg, bcl.UnmarshalWithOptions(payload, &cfg, &bcl.Options{AllowEnv: true, BaseDir: filepath.Dir(path)})
	}
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		return cfg, yaml.Unmarshal(payload, &cfg)
	}
	return cfg, errors.New("unsupported config file format, must be .json, .yaml, .yml, or .bcl")
}

func serviceConfig(cfg RuntimeConfig) rules.Config {
	out := rules.Config{
		Environment:               cfg.Service.Environment,
		DefaultTenant:             cfg.Service.DefaultTenant,
		MaxRequestBytes:           cfg.Service.MaxRequestBytes,
		StrictValidation:          cfg.Service.StrictValidation,
		StrictEvaluation:          cfg.Service.StrictEvaluation,
		RequireTests:              cfg.Service.RequireTests,
		RequireActivationApproval: cfg.Service.RequireActivationApproval,
		SignaturePolicy:           cfg.SignaturePolicy,
		TrustedPublicKeys:         cfg.TrustedPublicKeys,
	}
	if cfg.Service.RequestTimeout != "" {
		if d, err := time.ParseDuration(cfg.Service.RequestTimeout); err == nil {
			out.RequestTimeout = d
		}
	}
	out.Runtime = rules.RuntimePolicy{
		AllowTime:              cfg.Service.Runtime.AllowTime,
		FixedTime:              cfg.Service.Runtime.FixedTime,
		AllowEnv:               cfg.Service.Runtime.AllowEnv,
		AllowedDatasetAdapters: cfg.Service.Runtime.AllowedDatasetAdapters,
		AllowedHTTPHosts:       cfg.Service.Runtime.AllowedHTTPHosts,
		AllowedHTTPMethods:     cfg.Service.Runtime.AllowedHTTPMethods,
		AllowedActionSinks:     cfg.Service.Runtime.AllowedActionSinks,
		AllowedWebhookHosts:    cfg.Service.Runtime.AllowedWebhookHosts,
		AllowedWebhookMethods:  cfg.Service.Runtime.AllowedWebhookMethods,
		MaxStateRecords:        cfg.Service.Runtime.MaxStateRecords,
		TenantQuotas:           cfg.Service.Runtime.TenantQuotas,
	}
	if cfg.Service.Runtime.ExternalTimeout != "" {
		if d, err := time.ParseDuration(cfg.Service.Runtime.ExternalTimeout); err == nil {
			out.Runtime.ExternalTimeout = d
		}
	}
	if cfg.Service.Runtime.WebhookTimeout != "" {
		if d, err := time.ParseDuration(cfg.Service.Runtime.WebhookTimeout); err == nil {
			out.Runtime.WebhookTimeout = d
		}
	}
	return out
}

func cliContext(cfg RuntimeConfig, tenant string) context.Context {
	return rules.ContextWithTenant(context.Background(), firstNonEmpty(tenant, cfg.Service.DefaultTenant, "default"))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func applyString(dst *string, value, zero string) {
	if value != zero && value != "" {
		*dst = value
	}
}

func durationOrDefault(value string, fallback time.Duration) time.Duration {
	if value == "" {
		return fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return d
}

func readJSON(path string, out any) error {
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, out)
}

func printJSON(v any) {
	payload, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(payload))
}

func usage() {
	fmt.Println(`condition commands:
  serve [--config rules.yaml] [--tls-cert cert.pem --tls-key key.pem]
  validate <decision.bcl>
  publish <decision.bcl>
  versions <definition>
  activate <definition> <version>
  rollback <definition> <version>
  evaluate <definition> --input input.json [--compact]
  test <definition>
  gates <definition> --bundle bundle
  simulate <definition> --candidate candidate.bcl --cases cases.json
  compare <definition> --candidate candidate.bcl --dataset dataset
  canary <definition> --candidate candidate.bcl --dataset dataset [--max-changed 0] [--promote --promote-version 2]
  chain-evaluate <definition> <chain> [--event name --event-id id --entity key --input input.json]
  lifecycle-evaluate <definition> <lifecycle> --input request.json
  routes-import --input openapi.yaml [--catalog http --format bcl --output routes.bcl]
  compact [definition] [--before RFC3339]
  blast-radius <definition> --candidate candidate.bcl
  incident-update <id> --status acknowledged|resolved|open
  workflow-start <definition> <workflow> [--input input.json]
  workflow-advance <run-id> [--input input.json]
  disable|enable <definition> [--version version --reason text]
  approve <definition> <version> [--actor approver --reason text]
  route-coverage <definition>
  ir <definition>
  verify-bundle <definition>
  mutation-test <definition>
  retry-actions [--limit 100]
  tick-workflows [--limit 100]
  audits [--definition name] [--operation evaluate] [--limit 50]
  reports [--kind simulation]
  audit verify`)
}
