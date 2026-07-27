package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadCommandVector(t *testing.T) (inventory, plan, signature, publicKey, sourceISO []byte, session string) {
	t.Helper()
	vector := loadInternalGolden(t)
	return decodeInternalGolden(t, vector.InventoryCanonicalB64),
		decodeInternalGolden(t, vector.PlanCanonicalB64),
		vector.Signature, vector.PublicKey, vector.SourceISO, vector.SessionID
}

func TestInventoryCommandWritesOnlyCanonicalOutputAndBoundedResult(t *testing.T) {
	inventory, _, _, _, _, _ := loadCommandVector(t)
	directory := t.TempDir()
	outputPath := filepath.Join(directory, "inventory.json")
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), []string{"inventory", "--output", outputPath}, &stdout, &stderr, commandDependencies{
		collectInventory: func(context.Context) ([]byte, error) { return inventory, nil },
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	written, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, inventory) {
		t.Fatalf("inventory output differs from canonical bytes")
	}
	assertBoundedSuccessObject(t, stdout.Bytes(), "inventory")
}

func TestVerifyPlanCommandUsesEmbeddedSourceIdentity(t *testing.T) {
	inventory, plan, signature, publicKey, sourceISO, session := loadCommandVector(t)
	directory := t.TempDir()
	paths := writeCommandInputs(t, directory, map[string][]byte{
		"inventory.json":  inventory,
		"plan.json":       plan,
		"signature.json":  signature,
		"public-key.json": publicKey,
	})
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), []string{
		"verify-plan",
		"--plan", paths["plan.json"],
		"--signature", paths["signature.json"],
		"--public-key", paths["public-key.json"],
		"--inventory", paths["inventory.json"],
		"--session", session,
	}, &stdout, &stderr, commandDependencies{
		now:       func() time.Time { return time.Date(2026, 7, 27, 12, 30, 0, 0, time.UTC) },
		sourceISO: func() ([]byte, error) { return sourceISO, nil },
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	assertBoundedSuccessObject(t, stdout.Bytes(), "verify-plan")
}

func TestDiskPreflightCommandDoesNotMutateAnyInputOrTargetFile(t *testing.T) {
	inventory, plan, _, _, _, _ := loadCommandVector(t)
	directory := t.TempDir()
	paths := writeCommandInputs(t, directory, map[string][]byte{
		"inventory.json":  inventory,
		"plan.json":       plan,
		"target-sentinel": []byte("unchanged target bytes"),
	})
	before := snapshotDirectory(t, directory)
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), []string{
		"disk-preflight", "--plan", paths["plan.json"], "--inventory", paths["inventory.json"],
	}, &stdout, &stderr, commandDependencies{
		collectInventory: func(context.Context) ([]byte, error) { return inventory, nil },
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	after := snapshotDirectory(t, directory)
	if !mapsEqualBytes(before, after) {
		t.Fatalf("disk-preflight mutated files: before=%v after=%v", before, after)
	}
	assertBoundedSuccessObject(t, stdout.Bytes(), "disk-preflight")
}

func TestCommandFailureUsesStableStderrCodeAndEmptyStdout(t *testing.T) {
	inventory, _, _, _, _, _ := loadCommandVector(t)
	directory := t.TempDir()
	paths := writeCommandInputs(t, directory, map[string][]byte{
		"inventory.json": inventory,
		"plan.json":      []byte(`{"schema_version":1,"schema_version":1}`),
	})
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), []string{
		"disk-preflight", "--plan", paths["plan.json"], "--inventory", paths["inventory.json"],
	}, &stdout, &stderr, commandDependencies{
		collectInventory: func(context.Context) ([]byte, error) { return inventory, nil },
	})

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if stderr.String() != "ALT_INSTALL_ERROR json_duplicate_key\n" {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCommandUsageFailureIsStableAndBounded(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), []string{"verify-plan", "--plan", "missing"}, &stdout, &stderr, commandDependencies{})

	if code != 1 || stdout.Len() != 0 || stderr.String() != "ALT_INSTALL_ERROR usage_invalid\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() > 128 {
		t.Fatalf("stderr length = %d, want <= 128", stderr.Len())
	}
}

func assertBoundedSuccessObject(t *testing.T, raw []byte, command string) {
	t.Helper()
	if len(raw) == 0 || len(raw) > 4096 {
		t.Fatalf("stdout length = %d, want 1..4096", len(raw))
	}
	var result struct {
		OK      bool   `json:"ok"`
		Command string `json:"command"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Command != command {
		t.Fatalf("unexpected result: %+v", result)
	}
	if decoder.More() {
		t.Fatal("stdout contains more than one JSON value")
	}
}

func writeCommandInputs(t *testing.T, directory string, values map[string][]byte) map[string]string {
	t.Helper()
	paths := make(map[string]string, len(values))
	for name, value := range values {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	return paths
}

func snapshotDirectory(t *testing.T, directory string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		snapshot[entry.Name()] = raw
	}
	return snapshot
}

func mapsEqualBytes(left, right map[string][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if !bytes.Equal(value, right[key]) {
			return false
		}
	}
	return true
}
