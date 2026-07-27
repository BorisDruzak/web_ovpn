package helper_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	helper "github.com/BorisDruzak/ui_vpn/deploy/alt-linux/install-agent/helper"
)

func validVerifyInput(t *testing.T) helper.VerifyPlanInput {
	t.Helper()
	vector := loadGolden(t)
	return helper.VerifyPlanInput{
		Plan:      decodeGolden(t, vector.PlanCanonicalB64),
		Signature: vector.Signature,
		PublicKey: vector.PublicKey,
		Inventory: decodeGolden(t, vector.InventoryCanonicalB64),
		SourceISO: vector.SourceISO,
		SessionID: vector.SessionID,
		Now:       time.Date(2026, 7, 27, 12, 30, 0, 0, time.UTC),
	}
}

func TestVerifyPlanAcceptsPR3Ed25519Golden(t *testing.T) {
	vector := loadGolden(t)
	result, err := helper.VerifyPlan(validVerifyInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if result.PlanSHA256 != vector.PlanSHA256 {
		t.Fatalf("plan SHA-256 = %s, want %s", result.PlanSHA256, vector.PlanSHA256)
	}
	if result.InventorySHA256 != vector.InventorySHA256 {
		t.Fatalf("inventory SHA-256 = %s, want %s", result.InventorySHA256, vector.InventorySHA256)
	}
	if result.DiskFingerprint != vector.DiskFingerprint {
		t.Fatalf("disk fingerprint = %s, want %s", result.DiskFingerprint, vector.DiskFingerprint)
	}
}

func TestVerifyPlanRejectsSignatureMutation(t *testing.T) {
	input := validVerifyInput(t)
	var document map[string]any
	if err := json.Unmarshal(input.Signature, &document); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(document["signature_b64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 0x80
	document["signature_b64"] = base64.StdEncoding.EncodeToString(signature)
	input.Signature, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	_, err = helper.VerifyPlan(input)
	requireCode(t, err, "signature_invalid")
}

func TestVerifyPlanRejectsNonCanonicalPlanBytes(t *testing.T) {
	input := validVerifyInput(t)
	input.Plan = append(input.Plan, '\n')

	_, err := helper.VerifyPlan(input)
	requireCode(t, err, "plan_not_canonical")
}

func TestVerifyPlanRejectsDuplicatePlanKey(t *testing.T) {
	input := validVerifyInput(t)
	input.Plan = []byte(`{"schema_version":1,"schema_version":1}`)

	_, err := helper.VerifyPlan(input)
	requireCode(t, err, "json_duplicate_key")
}

func TestVerifyPlanRejectsSourceISOIdentityMismatch(t *testing.T) {
	input := validVerifyInput(t)
	var source map[string]any
	if err := json.Unmarshal(input.SourceISO, &source); err != nil {
		t.Fatal(err)
	}
	source["iso_sha256"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	input.SourceISO, _ = json.Marshal(source)

	_, err := helper.VerifyPlan(input)
	requireCode(t, err, "source_iso_mismatch")
}

func TestVerifyPlanRejectsSignatureMetadataMismatch(t *testing.T) {
	input := validVerifyInput(t)
	var signature map[string]any
	if err := json.Unmarshal(input.Signature, &signature); err != nil {
		t.Fatal(err)
	}
	signature["signed_file"] = "other.json"
	input.Signature, _ = json.Marshal(signature)

	_, err := helper.VerifyPlan(input)
	requireCode(t, err, "signature_metadata_invalid")
}

func TestVerifyPlanRejectsExpiryAndSessionMismatch(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		input := validVerifyInput(t)
		input.Now = time.Date(2026, 7, 27, 13, 0, 0, 0, time.UTC)

		_, err := helper.VerifyPlan(input)
		requireCode(t, err, "plan_expired")
	})
	t.Run("session", func(t *testing.T) {
		input := validVerifyInput(t)
		input.SessionID = "install-20260727T120000Z-different"

		_, err := helper.VerifyPlan(input)
		requireCode(t, err, "plan_session_mismatch")
	})
}

func TestVerifyPlanRejectsPublicKeyMetadataMutation(t *testing.T) {
	input := validVerifyInput(t)
	var publicKey map[string]any
	if err := json.Unmarshal(input.PublicKey, &publicKey); err != nil {
		t.Fatal(err)
	}
	publicKey["key_id"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	input.PublicKey, _ = json.Marshal(publicKey)

	_, err := helper.VerifyPlan(input)
	requireCode(t, err, "public_key_id_mismatch")
}
