package helper

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"
)

type VerifyPlanInput struct {
	Plan      []byte
	Signature []byte
	PublicKey []byte
	Inventory []byte
	SourceISO []byte
	SessionID string
	Now       time.Time
}

type VerifyPlanResult struct {
	PlanSHA256       string `json:"plan_sha256"`
	InventorySHA256  string `json:"inventory_sha256"`
	DiskFingerprint  string `json:"disk_fingerprint"`
	WeakDiskIdentity bool   `json:"weak_disk_identity"`
}

type sourceISOIdentity struct {
	SchemaVersion int64
	ISOID         string
	ISOSHA256     string
}

type publicKeyDocument struct {
	SchemaVersion int64
	Algorithm     string
	KeyID         string
	PublicKey     ed25519.PublicKey
}

type signatureDocument struct {
	SchemaVersion int64
	Algorithm     string
	KeyID         string
	SignedFile    string
	PlanSHA256    string
	Signature     []byte
	CreatedAt     string
}

// VerifyPlan validates exact plan bytes, all PR3 bindings, Ed25519 metadata and
// signature, source ISO identity, and expiry.
func VerifyPlan(input VerifyPlanInput) (VerifyPlanResult, error) {
	plan, err := exactCanonicalPlan(input.Plan)
	if err != nil {
		return VerifyPlanResult{}, err
	}
	inventory, err := ParseInventory(input.Inventory)
	if err != nil {
		return VerifyPlanResult{}, err
	}
	canonicalInventory, err := canonicalJSON(inventoryMap(inventory))
	if err != nil {
		return VerifyPlanResult{}, err
	}
	inventoryDigest := sha256.Sum256(canonicalInventory)
	inventoryHash := hex.EncodeToString(inventoryDigest[:])
	sourceISO, err := parseSourceISO(input.SourceISO)
	if err != nil {
		return VerifyPlanResult{}, err
	}
	if plan.ISOID != sourceISO.ISOID || plan.ISOSHA256 != sourceISO.ISOSHA256 ||
		inventory.Agent.ISOID != sourceISO.ISOID || inventory.Agent.ISOSHA256 != sourceISO.ISOSHA256 {
		return VerifyPlanResult{}, contractError("source_iso_mismatch", "plan or inventory source ISO identity differs")
	}
	if input.SessionID != plan.SessionID {
		return VerifyPlanResult{}, contractError("plan_session_mismatch", "plan session binding differs")
	}
	if inventoryHash != plan.InventorySHA256 {
		return VerifyPlanResult{}, contractError("plan_inventory_mismatch", "plan inventory binding differs")
	}
	selected, routed, err := matchPlanInventory(plan, inventory)
	if err != nil {
		return VerifyPlanResult{}, err
	}
	_ = routed
	publicKey, err := parsePublicKey(input.PublicKey)
	if err != nil {
		return VerifyPlanResult{}, err
	}
	signature, err := parseSignature(input.Signature)
	if err != nil {
		return VerifyPlanResult{}, err
	}
	planDigest := sha256.Sum256(input.Plan)
	planHash := hex.EncodeToString(planDigest[:])
	if signature.Algorithm != "ed25519" || signature.SignedFile != "plan.json" ||
		signature.PlanSHA256 != planHash || signature.CreatedAt != plan.ApprovedAt ||
		signature.KeyID != publicKey.KeyID || signature.SchemaVersion != 1 {
		return VerifyPlanResult{}, contractError("signature_metadata_invalid", "signature metadata does not bind the plan")
	}
	if !ed25519.Verify(publicKey.PublicKey, input.Plan, signature.Signature) {
		return VerifyPlanResult{}, contractError("signature_invalid", "Ed25519 signature is invalid")
	}
	expiresAt, _ := time.Parse(time.RFC3339, plan.ExpiresAt)
	if input.Now.IsZero() || !input.Now.Before(expiresAt) {
		return VerifyPlanResult{}, contractError("plan_expired", "signed plan is expired")
	}
	return VerifyPlanResult{
		PlanSHA256: planHash, InventorySHA256: inventoryHash, DiskFingerprint: plan.TargetDisk.Fingerprint,
		WeakDiskIdentity: selected.Serial == nil && selected.WWN == nil,
	}, nil
}

func parseSourceISO(raw []byte) (sourceISOIdentity, error) {
	value, err := parseStrictJSON(raw)
	if err != nil {
		return sourceISOIdentity{}, err
	}
	object, err := objectValue(value, "source_iso")
	if err != nil {
		return sourceISOIdentity{}, err
	}
	if err := requireFields(object, []string{"schema_version", "iso_id", "iso_sha256"}, "source_iso"); err != nil {
		return sourceISOIdentity{}, err
	}
	version, err := positiveIntegerValue(object["schema_version"], "source_iso")
	if err != nil || version != 1 {
		return sourceISOIdentity{}, contractError("source_iso_invalid", "source ISO schema is invalid")
	}
	isoID, err := stringValue(object["iso_id"], "source_iso")
	if err != nil {
		return sourceISOIdentity{}, err
	}
	isoSHA256, err := stringValue(object["iso_sha256"], "source_iso")
	if err != nil || !sha256Pattern.MatchString(isoSHA256) {
		return sourceISOIdentity{}, contractError("source_iso_invalid", "source ISO SHA-256 is invalid")
	}
	return sourceISOIdentity{SchemaVersion: version, ISOID: isoID, ISOSHA256: isoSHA256}, nil
}

func parsePublicKey(raw []byte) (publicKeyDocument, error) {
	value, err := parseStrictJSON(raw)
	if err != nil {
		return publicKeyDocument{}, err
	}
	object, err := objectValue(value, "public_key")
	if err != nil {
		return publicKeyDocument{}, err
	}
	if err := requireFields(object, []string{"schema_version", "algorithm", "key_id", "public_key_b64"}, "public_key"); err != nil {
		return publicKeyDocument{}, err
	}
	version, err := positiveIntegerValue(object["schema_version"], "public_key")
	if err != nil || version != 1 {
		return publicKeyDocument{}, contractError("public_key_metadata_invalid", "public key schema is invalid")
	}
	algorithm, err := stringValue(object["algorithm"], "public_key")
	if err != nil || algorithm != "ed25519" {
		return publicKeyDocument{}, contractError("public_key_metadata_invalid", "public key algorithm is invalid")
	}
	keyID, err := stringValue(object["key_id"], "public_key")
	if err != nil {
		return publicKeyDocument{}, err
	}
	encoded, err := stringValue(object["public_key_b64"], "public_key")
	if err != nil {
		return publicKeyDocument{}, err
	}
	key, err := decodeCanonicalBase64(encoded, ed25519.PublicKeySize)
	if err != nil {
		return publicKeyDocument{}, contractError("public_key_metadata_invalid", "public key value is invalid")
	}
	digest := sha256.Sum256(key)
	expectedKeyID := "sha256:" + hex.EncodeToString(digest[:])
	if keyID != expectedKeyID {
		return publicKeyDocument{}, contractError("public_key_id_mismatch", "public key ID is invalid")
	}
	return publicKeyDocument{
		SchemaVersion: version, Algorithm: algorithm, KeyID: keyID, PublicKey: ed25519.PublicKey(key),
	}, nil
}

func parseSignature(raw []byte) (signatureDocument, error) {
	value, err := parseStrictJSON(raw)
	if err != nil {
		return signatureDocument{}, err
	}
	object, err := objectValue(value, "signature")
	if err != nil {
		return signatureDocument{}, err
	}
	if err := requireFields(object, []string{
		"schema_version", "algorithm", "key_id", "signed_file", "plan_sha256", "signature_b64", "created_at",
	}, "signature"); err != nil {
		return signatureDocument{}, err
	}
	version, err := positiveIntegerValue(object["schema_version"], "signature")
	if err != nil {
		return signatureDocument{}, err
	}
	values := make(map[string]string, 6)
	for _, name := range []string{"algorithm", "key_id", "signed_file", "plan_sha256", "signature_b64", "created_at"} {
		text, err := stringValue(object[name], "signature")
		if err != nil {
			return signatureDocument{}, err
		}
		values[name] = text
	}
	if !sha256Pattern.MatchString(values["plan_sha256"]) {
		return signatureDocument{}, contractError("signature_metadata_invalid", "signature plan SHA-256 is invalid")
	}
	signature, err := decodeCanonicalBase64(values["signature_b64"], ed25519.SignatureSize)
	if err != nil {
		return signatureDocument{}, contractError("signature_metadata_invalid", "signature value is invalid")
	}
	if _, err := time.Parse(time.RFC3339, values["created_at"]); err != nil {
		return signatureDocument{}, contractError("signature_metadata_invalid", "signature timestamp is invalid")
	}
	return signatureDocument{
		SchemaVersion: version, Algorithm: values["algorithm"], KeyID: values["key_id"],
		SignedFile: values["signed_file"], PlanSHA256: values["plan_sha256"],
		Signature: signature, CreatedAt: values["created_at"],
	}, nil
}

func decodeCanonicalBase64(value string, expectedLength int) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != expectedLength || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, contractError("base64_invalid", "base64 value is invalid")
	}
	return decoded, nil
}

func matchPlanInventory(plan InstallPlan, inventory Inventory) (DiskInventory, InterfaceInventory, error) {
	if plan.Firmware != inventory.Machine.Firmware {
		return DiskInventory{}, InterfaceInventory{}, contractError("plan_firmware_mismatch", "plan firmware binding differs")
	}
	var selected *DiskInventory
	for index := range inventory.Disks {
		if inventory.Disks[index].Path == plan.TargetDisk.Path {
			selected = &inventory.Disks[index]
			break
		}
	}
	if selected == nil || !targetDiskMatches(plan.TargetDisk, *selected) {
		return DiskInventory{}, InterfaceInventory{}, contractError("plan_disk_mismatch", "plan disk binding differs")
	}
	routed := routedInterfaces(inventory)
	if len(routed) != 1 || routed[0].Name != plan.NetworkInterface.Name || routed[0].MAC != plan.NetworkInterface.MAC {
		return DiskInventory{}, InterfaceInventory{}, contractError("plan_network_mismatch", "plan network binding differs")
	}
	return *selected, routed[0], nil
}

func targetDiskMatches(target PlanTargetDisk, disk DiskInventory) bool {
	return target.Path == disk.Path && target.SizeBytes == disk.SizeBytes && target.Model == disk.Model &&
		equalOptionalString(target.Serial, disk.Serial) && equalOptionalString(target.WWN, disk.WWN) &&
		target.Fingerprint == DiskFingerprint(disk)
}

func equalOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func routedInterfaces(inventory Inventory) []InterfaceInventory {
	result := make([]InterfaceInventory, 0, len(inventory.Interfaces))
	for _, item := range inventory.Interfaces {
		if item.RouteToController {
			result = append(result, item)
		}
	}
	return result
}
