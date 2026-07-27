package helper_test

import (
	"encoding/json"
	"testing"

	helper "github.com/BorisDruzak/ui_vpn/deploy/alt-linux/install-agent/helper"
)

func mutateInventory(t *testing.T, raw []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	mutate(document)
	changed, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func TestDiskPreflightAcceptsUnchangedGoldenInventory(t *testing.T) {
	vector := loadGolden(t)
	inventory := decodeGolden(t, vector.InventoryCanonicalB64)
	result, err := helper.DiskPreflight(helper.DiskPreflightInput{
		Plan:              decodeGolden(t, vector.PlanCanonicalB64),
		RecordedInventory: inventory,
		CurrentInventory:  inventory,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.DiskFingerprint != vector.DiskFingerprint || result.WeakDiskIdentity {
		t.Fatalf("unexpected preflight result: %+v", result)
	}
}

func TestDiskPreflightRejectsSelectedDiskIdentityChange(t *testing.T) {
	vector := loadGolden(t)
	recorded := decodeGolden(t, vector.InventoryCanonicalB64)
	current := mutateInventory(t, recorded, func(document map[string]any) {
		document["disks"].([]any)[0].(map[string]any)["serial"] = "changed"
	})

	_, err := helper.DiskPreflight(helper.DiskPreflightInput{
		Plan: decodeGolden(t, vector.PlanCanonicalB64), RecordedInventory: recorded, CurrentInventory: current,
	})
	requireCode(t, err, "preflight_disk_mismatch")
}

func TestDiskPreflightRejectsAmbiguousEligibleDisks(t *testing.T) {
	vector := loadGolden(t)
	recorded := decodeGolden(t, vector.InventoryCanonicalB64)
	current := mutateInventory(t, recorded, func(document map[string]any) {
		first := document["disks"].([]any)[0].(map[string]any)
		second := make(map[string]any, len(first))
		for key, value := range first {
			second[key] = value
		}
		second["path"] = "/dev/vdb"
		second["serial"] = "disk-101"
		document["disks"] = append(document["disks"].([]any), second)
	})

	_, err := helper.DiskPreflight(helper.DiskPreflightInput{
		Plan: decodeGolden(t, vector.PlanCanonicalB64), RecordedInventory: recorded, CurrentInventory: current,
	})
	requireCode(t, err, "preflight_disk_ambiguous")
}

func TestDiskPreflightRejectsBootMediaFirmwareAndRoutedNICDrift(t *testing.T) {
	vector := loadGolden(t)
	recorded := decodeGolden(t, vector.InventoryCanonicalB64)
	tests := []struct {
		name   string
		code   string
		mutate func(map[string]any)
	}{
		{"boot media", "preflight_boot_media_mismatch", func(document map[string]any) {
			document["boot_media"].(map[string]any)["serial"] = "different"
		}},
		{"firmware", "preflight_firmware_mismatch", func(document map[string]any) {
			document["machine"].(map[string]any)["firmware"] = "bios"
		}},
		{"routed NIC", "preflight_network_mismatch", func(document map[string]any) {
			document["interfaces"].([]any)[0].(map[string]any)["mac"] = "52:54:00:aa:bb:cc"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := mutateInventory(t, recorded, test.mutate)
			_, err := helper.DiskPreflight(helper.DiskPreflightInput{
				Plan: decodeGolden(t, vector.PlanCanonicalB64), RecordedInventory: recorded, CurrentInventory: current,
			})
			requireCode(t, err, test.code)
		})
	}
}

func TestDiskPreflightRecordsWeakIdentityWithoutRejectingDryRun(t *testing.T) {
	vector := loadGolden(t)
	inventory := decodeGolden(t, vector.WeakInventoryCanonicalB64)
	result, err := helper.DiskPreflight(helper.DiskPreflightInput{
		Plan:              decodeGolden(t, vector.WeakPlanCanonicalB64),
		RecordedInventory: inventory,
		CurrentInventory:  inventory,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.WeakDiskIdentity || result.DiskFingerprint != vector.WeakDiskFingerprint {
		t.Fatalf("unexpected weak identity result: %+v", result)
	}
}

func TestDiskPreflightIgnoresExtraDiskBelowPR3MinimumSize(t *testing.T) {
	vector := loadGolden(t)
	recorded := decodeGolden(t, vector.InventoryCanonicalB64)
	current := mutateInventory(t, recorded, func(document map[string]any) {
		first := document["disks"].([]any)[0].(map[string]any)
		second := make(map[string]any, len(first))
		for key, value := range first {
			second[key] = value
		}
		second["path"] = "/dev/vdb"
		second["serial"] = "small-disk"
		second["size_bytes"] = float64(10 * 1024 * 1024 * 1024)
		document["disks"] = append(document["disks"].([]any), second)
	})

	result, err := helper.DiskPreflight(helper.DiskPreflightInput{
		Plan: decodeGolden(t, vector.PlanCanonicalB64), RecordedInventory: recorded, CurrentInventory: current,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.DiskFingerprint != vector.DiskFingerprint {
		t.Fatalf("selected fingerprint = %s, want %s", result.DiskFingerprint, vector.DiskFingerprint)
	}
}

func TestDiskPreflightRejectsAnyRemovablePhysicalDiskLikePR3Policy(t *testing.T) {
	vector := loadGolden(t)
	recorded := decodeGolden(t, vector.InventoryCanonicalB64)
	current := mutateInventory(t, recorded, func(document map[string]any) {
		first := document["disks"].([]any)[0].(map[string]any)
		second := make(map[string]any, len(first))
		for key, value := range first {
			second[key] = value
		}
		second["path"] = "/dev/vdb"
		second["serial"] = "removable-disk"
		second["removable"] = true
		document["disks"] = append(document["disks"].([]any), second)
	})

	_, err := helper.DiskPreflight(helper.DiskPreflightInput{
		Plan: decodeGolden(t, vector.PlanCanonicalB64), RecordedInventory: recorded, CurrentInventory: current,
	})
	requireCode(t, err, "preflight_disk_removable")
}
