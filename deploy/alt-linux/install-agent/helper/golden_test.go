package helper_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	helper "github.com/BorisDruzak/ui_vpn/deploy/alt-linux/install-agent/helper"
)

type goldenVector struct {
	InventoryCanonicalB64     string          `json:"inventory_canonical_b64"`
	InventorySHA256           string          `json:"inventory_sha256"`
	DiskFingerprint           string          `json:"disk_fingerprint"`
	PlanCanonicalB64          string          `json:"plan_canonical_b64"`
	PlanSHA256                string          `json:"plan_sha256"`
	SessionID                 string          `json:"session_id"`
	PublicKey                 json.RawMessage `json:"public_key"`
	Signature                 json.RawMessage `json:"signature"`
	SourceISO                 json.RawMessage `json:"source_iso"`
	WeakInventoryCanonicalB64 string          `json:"weak_inventory_canonical_b64"`
	WeakPlanCanonicalB64      string          `json:"weak_plan_canonical_b64"`
	WeakDiskFingerprint       string          `json:"weak_disk_fingerprint"`
}

func loadGolden(t *testing.T) goldenVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "v1", "golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector goldenVector
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func decodeGolden(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func repoInventoryFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "tests", "alt_linux", "fixtures", "install", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func requireCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", want)
	}
	if got := helper.ErrorCode(err); got != want {
		t.Fatalf("error code = %q, want %q (error: %v)", got, want, err)
	}
}

func TestInventoryCanonicalBytesAndFingerprintMatchPR3Golden(t *testing.T) {
	vector := loadGolden(t)
	input := repoInventoryFixture(t, "inventory-disk-100g.json")
	want := decodeGolden(t, vector.InventoryCanonicalB64)

	got, err := helper.CanonicalInventoryBytes(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical inventory mismatch\n got: %s\nwant: %s", got, want)
	}
	digest := sha256.Sum256(got)
	if gotHash := hex.EncodeToString(digest[:]); gotHash != vector.InventorySHA256 {
		t.Fatalf("inventory SHA-256 = %s, want %s", gotHash, vector.InventorySHA256)
	}
	inventory, err := helper.ParseInventory(input)
	if err != nil {
		t.Fatal(err)
	}
	if gotFingerprint := helper.DiskFingerprint(inventory.Disks[0]); gotFingerprint != vector.DiskFingerprint {
		t.Fatalf("disk fingerprint = %s, want %s", gotFingerprint, vector.DiskFingerprint)
	}
}

func TestStrictInventoryJSONRejectsAmbiguityAndLimits(t *testing.T) {
	vector := loadGolden(t)
	canonical := decodeGolden(t, vector.InventoryCanonicalB64)
	tooManyAddresses := `["x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x"]`
	tests := []struct {
		name string
		raw  []byte
		code string
	}{
		{"duplicate key", []byte(`{"schema_version":1,"schema_version":1}`), "json_duplicate_key"},
		{"unknown field", bytes.Replace(canonical, []byte(`"schema_version":1}`), []byte(`"schema_version":1,"unexpected":true}`), 1), "inventory_unknown_field"},
		{"non integer", bytes.Replace(canonical, []byte(`"size_bytes":107374182400`), []byte(`"size_bytes":107374182400.0`), 1), "json_non_integer"},
		{"invalid UTF-8", bytes.Replace(canonical, []byte("QEMU"), []byte{'Q', 0xff, 'M', 'U'}, 1), "json_invalid_utf8"},
		{"oversized string", bytes.Replace(canonical, []byte("boot-100"), []byte(strings.Repeat("a", 257)), 1), "json_limit_exceeded"},
		{"oversized array", bytes.Replace(canonical, []byte(`["192.0.2.11/24"]`), []byte(tooManyAddresses), 1), "json_limit_exceeded"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := helper.ParseInventory(test.raw)
			requireCode(t, err, test.code)
		})
	}
}

func TestCanonicalInventoryEscapesPythonASCIIUpperBoundary(t *testing.T) {
	vector := loadGolden(t)
	input := bytes.Replace(
		decodeGolden(t, vector.InventoryCanonicalB64),
		[]byte("QEMU HARDDISK"),
		[]byte{'Q', 'E', 'M', 'U', 0x7f, 'H', 'A', 'R', 'D', 'D', 'I', 'S', 'K'},
		1,
	)

	got, err := helper.CanonicalInventoryBytes(input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte{0x7f}) || !bytes.Contains(got, []byte(`QEMU\u007fHARDDISK`)) {
		t.Fatalf("canonical inventory did not use Python ensure_ascii escaping: %q", got)
	}
}
