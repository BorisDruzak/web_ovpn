package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type commandDependencies struct {
	now              func() time.Time
	collectInventory func(context.Context) ([]byte, error)
	sourceISO        func() ([]byte, error)
}

func defaultCommandDependencies() commandDependencies {
	return commandDependencies{
		now:              time.Now,
		collectInventory: func(ctx context.Context) ([]byte, error) { return collectSystemInventory(ctx, operatingSystemProbe{}) },
		sourceISO:        func() ([]byte, error) { return readRegularBoundedFile(sourceISOPath) },
	}
}

// Main runs one stable helper command and returns a process exit status.
func Main(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	return runCommand(ctx, arguments, stdout, stderr, defaultCommandDependencies())
}

func runCommand(ctx context.Context, arguments []string, stdout, stderr io.Writer, dependencies commandDependencies) int {
	if len(arguments) == 0 {
		return emitCommandError(stderr, contractError("usage_invalid", "command is required"))
	}
	var result map[string]any
	var err error
	switch arguments[0] {
	case "inventory":
		result, err = runInventoryCommand(ctx, arguments[1:], dependencies)
	case "verify-plan":
		result, err = runVerifyPlanCommand(arguments[1:], dependencies)
	case "disk-preflight":
		result, err = runDiskPreflightCommand(ctx, arguments[1:], dependencies)
	case "download-execution-bundle":
		result, err = runDownloadExecutionBundleCommand(
			ctx, arguments[1:],
		)
	case "verify-execution-bundle":
		result, err = runVerifyExecutionBundleCommand(
			arguments[1:], dependencies,
		)
	case "serve-execution-metadata":
		result, err = runServeExecutionMetadataCommand(
			ctx, arguments[1:], dependencies,
		)
	default:
		err = contractError("usage_invalid", "command is unknown")
	}
	if err != nil {
		return emitCommandError(stderr, err)
	}
	result["ok"] = true
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded)+1 > maxResultBytes {
		return emitCommandError(stderr, contractError("result_invalid", "result object is invalid"))
	}
	encoded = append(encoded, '\n')
	if _, err := stdout.Write(encoded); err != nil {
		return emitCommandError(stderr, contractError("stdout_failed", "cannot write result"))
	}
	return 0
}

func runInventoryCommand(ctx context.Context, arguments []string, dependencies commandDependencies) (map[string]any, error) {
	flags := flag.NewFlagSet("inventory", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	output := flags.String("output", "", "")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *output == "" {
		return nil, contractError("usage_invalid", "inventory arguments are invalid")
	}
	if dependencies.collectInventory == nil {
		return nil, contractError("internal_error", "inventory dependency is unavailable")
	}
	inventory, err := dependencies.collectInventory(ctx)
	if err != nil {
		return nil, err
	}
	canonical, err := CanonicalInventoryBytes(inventory)
	if err != nil {
		return nil, err
	}
	if err := writeAtomicRegularFile(*output, canonical); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	return map[string]any{
		"command": "inventory", "inventory_sha256": hex.EncodeToString(digest[:]),
	}, nil
}

func runVerifyPlanCommand(arguments []string, dependencies commandDependencies) (map[string]any, error) {
	flags := flag.NewFlagSet("verify-plan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planPath := flags.String("plan", "", "")
	signaturePath := flags.String("signature", "", "")
	publicKeyPath := flags.String("public-key", "", "")
	inventoryPath := flags.String("inventory", "", "")
	sessionID := flags.String("session", "", "")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 ||
		*planPath == "" || *signaturePath == "" || *publicKeyPath == "" || *inventoryPath == "" || *sessionID == "" {
		return nil, contractError("usage_invalid", "verify-plan arguments are invalid")
	}
	plan, err := readRegularBoundedFile(*planPath)
	if err != nil {
		return nil, err
	}
	signature, err := readRegularBoundedFile(*signaturePath)
	if err != nil {
		return nil, err
	}
	publicKey, err := readRegularBoundedFile(*publicKeyPath)
	if err != nil {
		return nil, err
	}
	inventory, err := readRegularBoundedFile(*inventoryPath)
	if err != nil {
		return nil, err
	}
	if dependencies.sourceISO == nil || dependencies.now == nil {
		return nil, contractError("internal_error", "verification dependency is unavailable")
	}
	sourceISO, err := dependencies.sourceISO()
	if err != nil {
		return nil, contractError("source_iso_unavailable", "source ISO identity is unavailable")
	}
	verified, err := VerifyPlan(VerifyPlanInput{
		Plan: plan, Signature: signature, PublicKey: publicKey, Inventory: inventory,
		SourceISO: sourceISO, SessionID: *sessionID, Now: dependencies.now(),
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"command": "verify-plan", "plan_sha256": verified.PlanSHA256,
		"inventory_sha256": verified.InventorySHA256, "disk_fingerprint": verified.DiskFingerprint,
		"weak_disk_identity": verified.WeakDiskIdentity,
	}, nil
}

func runDiskPreflightCommand(ctx context.Context, arguments []string, dependencies commandDependencies) (map[string]any, error) {
	flags := flag.NewFlagSet("disk-preflight", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planPath := flags.String("plan", "", "")
	inventoryPath := flags.String("inventory", "", "")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *planPath == "" || *inventoryPath == "" {
		return nil, contractError("usage_invalid", "disk-preflight arguments are invalid")
	}
	plan, err := readRegularBoundedFile(*planPath)
	if err != nil {
		return nil, err
	}
	recorded, err := readRegularBoundedFile(*inventoryPath)
	if err != nil {
		return nil, err
	}
	if dependencies.collectInventory == nil {
		return nil, contractError("internal_error", "inventory dependency is unavailable")
	}
	current, err := dependencies.collectInventory(ctx)
	if err != nil {
		return nil, err
	}
	preflight, err := DiskPreflight(DiskPreflightInput{Plan: plan, RecordedInventory: recorded, CurrentInventory: current})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"command": "disk-preflight", "disk_path": preflight.DiskPath,
		"disk_fingerprint": preflight.DiskFingerprint, "weak_disk_identity": preflight.WeakDiskIdentity,
	}, nil
}

func runDownloadExecutionBundleCommand(
	ctx context.Context,
	arguments []string,
) (map[string]any, error) {
	flags := flag.NewFlagSet(
		"download-execution-bundle", flag.ContinueOnError,
	)
	flags.SetOutput(io.Discard)
	manifestURL := flags.String("manifest", "", "")
	destination := flags.String("destination", "", "")
	caPath := flags.String("ca-certificate", "", "")
	credentialPath := flags.String("credential-file", "", "")
	if err := flags.Parse(arguments); err != nil ||
		flags.NArg() != 0 ||
		*manifestURL == "" ||
		*destination == "" ||
		*caPath == "" ||
		*credentialPath == "" {
		return nil, contractError(
			"usage_invalid",
			"download-execution-bundle arguments are invalid",
		)
	}
	caCertificate, err := readRegularBoundedFile(*caPath)
	if err != nil {
		return nil, err
	}
	credential, err := readRegularBoundedFile(*credentialPath)
	if err != nil {
		return nil, err
	}
	result, err := DownloadExecutionBundle(
		ctx,
		DownloadExecutionBundleInput{
			ManifestURL:   *manifestURL,
			Destination:   *destination,
			CACertificate: caCertificate,
			Credential:    string(credential),
		},
	)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"command":    "download-execution-bundle",
		"session_id": result.SessionID,
	}, nil
}

func runVerifyExecutionBundleCommand(
	arguments []string,
	dependencies commandDependencies,
) (map[string]any, error) {
	flags := flag.NewFlagSet(
		"verify-execution-bundle", flag.ContinueOnError,
	)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "")
	planPath := flags.String("plan", "", "")
	inventoryPath := flags.String("inventory", "", "")
	publicKeyPath := flags.String("public-key", "", "")
	sessionID := flags.String("session", "", "")
	if err := flags.Parse(arguments); err != nil ||
		flags.NArg() != 0 ||
		*manifestPath == "" ||
		*planPath == "" ||
		*inventoryPath == "" ||
		*publicKeyPath == "" ||
		*sessionID == "" {
		return nil, contractError(
			"usage_invalid",
			"verify-execution-bundle arguments are invalid",
		)
	}
	if dependencies.now == nil {
		return nil, contractError(
			"internal_error",
			"verification dependency is unavailable",
		)
	}
	plan, err := readRegularBoundedFile(*planPath)
	if err != nil {
		return nil, err
	}
	inventory, err := readRegularBoundedFile(*inventoryPath)
	if err != nil {
		return nil, err
	}
	publicKey, err := readRegularBoundedFile(*publicKeyPath)
	if err != nil {
		return nil, err
	}
	verified, err := VerifyExecutionBundle(
		VerifyExecutionBundleInput{
			ManifestPath: *manifestPath,
			Plan:         plan,
			Inventory:    inventory,
			PublicKey:    publicKey,
			SessionID:    *sessionID,
			Now:          dependencies.now(),
		},
	)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"command":          "verify-execution-bundle",
		"session_id":       verified.SessionID,
		"plan_sha256":      verified.PlanSHA256,
		"inventory_sha256": verified.InventorySHA256,
		"target_disk":      verified.TargetDisk,
		"disk_fingerprint": verified.DiskFingerprint,
		"expires_at":       verified.ExpiresAt.Format(time.RFC3339),
	}, nil
}

func runServeExecutionMetadataCommand(
	ctx context.Context,
	arguments []string,
	dependencies commandDependencies,
) (map[string]any, error) {
	flags := flag.NewFlagSet(
		"serve-execution-metadata", flag.ContinueOnError,
	)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "")
	port := flags.Int("port", 0, "")
	deadlineText := flags.String("deadline", "", "")
	readyFile := flags.String("ready-file", "", "")
	if err := flags.Parse(arguments); err != nil ||
		flags.NArg() != 0 ||
		*directory == "" ||
		*port != executionRelayPort ||
		*deadlineText == "" ||
		*readyFile == "" {
		return nil, contractError(
			"usage_invalid",
			"serve-execution-metadata arguments are invalid",
		)
	}
	deadline, err := time.Parse(time.RFC3339, *deadlineText)
	if err != nil {
		return nil, contractError(
			"usage_invalid",
			"serve-execution-metadata deadline is invalid",
		)
	}
	if dependencies.now == nil ||
		!dependencies.now().Before(deadline) {
		return nil, contractError(
			"execution_expired",
			"execution relay deadline is expired",
		)
	}
	if err := ServeExecutionMetadata(
		ctx,
		ServeExecutionMetadataInput{
			Directory: *directory,
			Port:      *port,
			Deadline:  deadline,
			ReadyFile: *readyFile,
		},
	); err != nil {
		return nil, err
	}
	return map[string]any{
		"command": "serve-execution-metadata",
	}, nil
}

func emitCommandError(stderr io.Writer, err error) int {
	code := ErrorCode(err)
	_, _ = fmt.Fprintf(stderr, "ALT_INSTALL_ERROR %s\n", code)
	return 1
}

func readRegularBoundedFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxDocumentBytes {
		return nil, contractError("input_file_invalid", "input must be a bounded regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > maxDocumentBytes {
		return nil, contractError("input_file_invalid", "cannot read bounded input")
	}
	return raw, nil
}

func writeAtomicRegularFile(path string, raw []byte) error {
	if len(raw) == 0 || len(raw) > maxDocumentBytes {
		return contractError("output_invalid", "inventory output has invalid size")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return contractError("output_path_unsafe", "inventory output is not a regular file")
		}
	} else if !os.IsNotExist(err) {
		return contractError("output_path_unsafe", "inventory output path is unavailable")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return contractError("output_write_failed", "cannot create inventory output")
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return contractError("output_write_failed", "cannot protect inventory output")
	}
	if _, err := temporary.Write(raw); err != nil {
		return contractError("output_write_failed", "cannot write inventory output")
	}
	if err := temporary.Sync(); err != nil {
		return contractError("output_write_failed", "cannot sync inventory output")
	}
	if err := temporary.Close(); err != nil {
		return contractError("output_write_failed", "cannot close inventory output")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return contractError("output_write_failed", "cannot publish inventory output")
	}
	committed = true
	return nil
}

func sha256Hex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
