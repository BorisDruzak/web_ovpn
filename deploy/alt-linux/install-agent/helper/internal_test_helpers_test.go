package helper

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type internalGoldenVector struct {
	InventoryCanonicalB64 string          `json:"inventory_canonical_b64"`
	PlanCanonicalB64      string          `json:"plan_canonical_b64"`
	SessionID             string          `json:"session_id"`
	PublicKey             json.RawMessage `json:"public_key"`
	Signature             json.RawMessage `json:"signature"`
	SourceISO             json.RawMessage `json:"source_iso"`
}

func loadInternalGolden(t *testing.T) internalGoldenVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "v1", "golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector internalGoldenVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func decodeInternalGolden(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
